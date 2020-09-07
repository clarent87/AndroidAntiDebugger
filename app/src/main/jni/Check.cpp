//
// Created by F8LEFT on 2016/11/6.
//
#include "Check.h"
#include "string"
#include <stdio.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "errno.h"
#include <sys/ptrace.h>

//#define DEBUG
#ifdef DEBUG
#include <android/log.h>
#define FLOG_TAG "F8LEFT"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, FLOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, FLOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, FLOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, FLOG_TAG, __VA_ARGS__)
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, FLOG_TAG, __VA_ARGS__)
#else
#include <android/log.h>
#define FLOG_TAG "F8LEFT"
#define LOGE(...)
#define LOGD(...)
#define LOGW(...)
#define LOGI(...)
#define LOGV(...)
#endif

//char sflag[0x10+1] = {
//        0x4A, 0x75, 0x73, 0x74, 0x48, 0x61, 0x76, 0x65,
//        0x41, 0x54, 0x72, 0x79, 0x21, 0x21, 0x21, 0x21,
//        0x00
//};

// 17개 byte
char sflag[0x10 + 1] = {
    0x46, 0x38, 0x4C, 0x45, 0x46, 0x54, 0x00, 0x4A, // 0x00이 가 변하지 않으면 parent 에선 while 진행
    0x4D, 0x50, 0x4F, 0x45, 0x50, 0x34, 0x53, 0x54,
    0x00};

int gpipe[2];

// child에서 한번만 pipe로 data를 받는건데..
// 이거 close한 다음 읽히는거라.. 이러면 eof 읽히고 끝아닌가?
void *parent_read_thread(void *param)
{
    LOGD("wait for child process to write decode data");
    auto readPipe = gpipe[0];
    read(readPipe, sflag, 0x10);
    close(readPipe);
    return 0;
}

// parent process에서 돌리는 thread, param으로는 child pid 들어옴
// attach만 할거라 while없어도 되나? => pipe 핸들링은 위 thread에서만 하고 안하나?
void *child_attach_thread(void *param)
{
    int pid = *(int *)param;
    LOGD("check child status %d", pid); // pid check
    safe_attach(pid);                   // pid에 attach후 cont 진행
    handle_events();                    // 여기서 child의 상태변화를 wait함
    LOGE("watch thread exit");

    kill(getpid(), 9); // 뭔일인지 parent 를 죽임
    return nullptr;    // thread join을 쓴다면 nullptr을 받음 c++ 11이하에서는 NULL 과 같은 취금이지만, 이상에서는 pointer 타입으로 compile시 고려됨
}

/* 이게 기본 */
int checkDebugger(JNIEnv *env, jobject obj)
{
    // use Multi process to protect itself
    int forktime = 0;

FORKLABEL:
    forktime++;
    if (forktime > 5)
    {
        return 0;
    }

    if (pipe(gpipe)) // 전역값
    {
        return 0;
    }
    auto pid = fork();
    prctl(PR_SET_DUMPABLE, 1); // 덤퍼블이 아닌건 ptrace attach도 안됀다고 함, 일단 1로 세팅한건 dump가능 ( ptrace_Scope때문인가.. 실제론 안먹힘 )

    if (pid != 0)
    {
        // parent
        close(gpipe[1]); // 역시 fork후 ...
        LOGD("start new thread to read decode data");
        pthread_t ntid;
        pthread_create(&ntid, nullptr, parent_read_thread, &pid); //아마 fork 성공 여부를 판단하기 위한 thread 같음. sflag에 값받음.

        // 아래 코드는 child fork후 parent thread에 값이 않오는 경우 계속 진행
        // 상황0) 어찌됫건 whild은 무조건 한번 돌고..
        // 상황1) child fork 후 pipe로 data 보냈을때 => 정상 종료
        // 상황2) child fork 후 pipe로 data 보내지 못했을때 => 이건 아마 타이밍상 못보낸 상태? or child 수정된 상태?
        do
        {
            int childstatus;
            auto childpid = waitpid(pid, &childstatus, WNOHANG); // watipid는 정상적으로 처리되면 return은 pid, child 종료안됬으면 0
            bool succ = childpid == 0;                           // fork 성공 여부 check인듯.

            // 아래는 SIGCHLD를 받아서 watipid의 return이 0보다 큰경우 => stop인지 종료 상태인지 판단
            if (childpid > 0)
            {
                succ = childstatus == 1; // child가 kill 상태인 경우.
                LOGD("Child process end!");
            }

            if (!succ) // child가 stop인경우.
            {
                kill(pid, 9);   // 죽이고
                goto FORKLABEL; // 다시 fork
            }
        } while (!sflag[6]);
        LOGD("read decoded data success!!");
        // pid는 thread의 arg => 이부분 bug있음 pid 전역으로 해서 주소 넘겨야지.. 안그러면 parent 의 checkDebugger함수 바로 종료후 스택의 pid에 가비지
        pthread_create(&ntid, nullptr, child_attach_thread, &pid); 
    }
    else
    {
        // child
        // Write key to pipe
        auto cpid = getppid();
        safe_attach(cpid); // 와.. 뭐냐.. 상호 attach 인가?
        LOGD("child process Attach success, try to write data");

        close(gpipe[0]);
        auto writepipe = gpipe[1];

        char tflag[0x10 + 1] = {
            0x4A, 0x75, 0x73, 0x74, 0x48, 0x61, 0x76, 0x65,
            0x41, 0x54, 0x72, 0x79, 0x21, 0x21, 0x21, 0x21};

        write(writepipe, tflag, 0x10);
        close(writepipe);
        handle_events();    // parent의 상태 변화 감시.. ( 이게 참 특이하네.. 자식 process가 아닌데 . tracee면 확인가능한가 보네.. )
        exit(EXIT_FAILURE); // EXIT_FAILURE == 1
        //        return execl("f8left.cm2", "f8left.cm2");
        //              => ? execl로 혹시 apk 실행가능하나?(저자는 그런형태를 확인한듯 한데.. )
        //              => ref https://stackoverflow.com/questions/22832560/execute-android-application-from-native-c-code 실제 그러한 시도 있네.
        //              => ref http://gimite.net/en/index.php?Run%20native%20executable%20in%20Android%20App
    }
    return 0;
}

bool may_cause_group_stop(int signo)
{
    switch (signo)
    {
    case SIGSTOP:
    case SIGTSTP:
    case SIGTTIN:
    case SIGTTOU:
        return true;
        break;
    default:
        break;
    }

    return false;
}

void handle_events()
{
    int status = 0;
    pid_t pid = 0;

    do
    {
        pid = TEMP_FAILURE_RETRY(waitpid(-1, &status, __WALL)); // 임의의 자식 프로세스 전부를 기다림. ( clone or non-clone)
        if (pid < 0)
        {
            perror("waitpid");
            exit(EXIT_FAILURE);
        }

        if (WIFEXITED(status))
        {
            LOGE("%d exited, status=%d\n", pid, WEXITSTATUS(status));
        }
        else if (WIFSIGNALED(status))
        {
            LOGE("%d killed by signal %d\n", pid, WTERMSIG(status));
        }
        else if (WIFSTOPPED(status))
        {
            int signo = WSTOPSIG(status);
            LOGE("%d stopped by signal %d\n", pid, signo);

            if (may_cause_group_stop(signo))
            {
                signo = 0;
            }

            long err = ptrace(PTRACE_CONT, pid, NULL, signo);
            if (err < 0)
            {
                perror("PTRACE_CONT");
                exit(EXIT_FAILURE);
            }
        }

    } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    // 자식이 정상 종료상태가 아니고,
    // 자식이 signal때문에 종료되지 않았을 때 while을 계속 진행
    // 즉 자식이 종료한게 아니라면 계속 자식을 동작시켜주는것.
}

// pid는 child
// 어태치 한후 waitpid로 현 thead는 중지되게 됨.
// 자식이 tracee라고 해서 signal을 못받는건 아님 => signal 받았을시 tracer가 일차적으로 handling하는듯.
// 단순 attach => cont 인데... 약간의 에러 처리 trick이 있는게 아닌가 싶다.
// 혹시 multi thread나.. 그런 환경 때문에 이렇게 된건가?
// 잘 분석 해야하네..
void safe_attach(pid_t pid)
{
    long err = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (err < 0) // 어태치 실패
    {
        LOGE("PTRACE_ATTACH");
        exit(EXIT_FAILURE);
    }

    int status = 0;
    // __WALL 는 모든 child에 대해 기다림, TEMP_FAILURE_RETRY는 안드로이드 macro라고 생각했는데 아닌가 보네.
    // 뭔가 expression동작중 signal 발생시 waitpid를 다시 실행해준다함. ?( expression의 정상적인 실패가 아니라면 계속 expression 시도 해주는듯)
    // 아.. attach하고 sigstop이 child로 날아가지.. 그거 처리하는거네..
    err = TEMP_FAILURE_RETRY(waitpid(pid, &status, __WALL));
    if (err < 0)
    {
        LOGE("waitpid");
        exit(EXIT_FAILURE);
    }

    if (WIFEXITED(status))
    {
        LOGE("%d exited, status=%d\n", pid, WEXITSTATUS(status));
        exit(EXIT_SUCCESS);
    }
    else if (WIFSIGNALED(status))
    {
        LOGE("%d killed by signal %d\n", pid, WTERMSIG(status));
        exit(EXIT_SUCCESS);
    }
    else if (WIFSTOPPED(status))
    {
        // 멈춤 상태인경우
        int signo = WSTOPSIG(status); // 자식 프로세스를 정지 상태로 만든 signal 번호를 반환함.
        LOGE("%d stopped by signal %d\n", pid, signo);

        if (may_cause_group_stop(signo))
        {
            // SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU 인 경우.. => 이건 grup stop 이라는건가?
            // 그외에 다른 signal이 child에 전달되서 멈춘경우는 다시 signal child에 전달하고 실행하는듯.
            // 즉 이러한 방법으로 child의 signal을 핸들링 하는거 같음
            signo = 0;
        }

        // 계속 진행하게 함.
        err = ptrace(PTRACE_CONT, pid, NULL, signo); // tracee 진행시키고, signo는 0이아닌경우 signal을 tracee에 전달.
        if (err < 0)
        {
            LOGE("PTRACE_CONT");
            exit(EXIT_FAILURE);
        }
    }

    LOGD("Debugger: attached to process %d\n", pid); // 이건 잘 붙었다는 의미 같네.
}

// The flag is : "ThatIsEnd,Thanks"
// 위 flag와 child, parent 의 flag xor 해서 나온 값의 비교로 anti-debugging 검출인듯
// flag는 자바단에서 내려옴.
bool check(JNIEnv *env, jobject obj, jstring flag)
{
    LOGD("check flag: current encoded flag is %s", sflag);

    auto pflaglen = env->GetStringLength(flag);
    if (pflaglen != 0x10)
    {
        return false;
    }

    bool ok = false;
    auto pflag = env->GetStringUTFChars(flag, nullptr);

    char tflag[0x10 + 1] = {
        0x1e, 0x1d, 0x12, 0x00, 0x01, 0x12, 0x33, 0x0b,
        0x25, 0x78, 0x26, 0x11, 0x40, 0x4f, 0x4a, 0x52};

    for (auto i = 0; i < 0x10; i++)
    {
        tflag[i] ^= sflag[i];
    }

    LOGD("check flag: decoded flag is %s", tflag);
    if (memcmp(pflag, tflag, 0x10) == 0) // 결국 flag 비교 로직 쓰는건 어쩔수 없네.
    {
        ok = true;
    }

    env->ReleaseStringUTFChars(flag, pflag);
    return ok;
}

// 이건 단순 jni 함수 등록
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env = nullptr;
    jint result = -1;

    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK)
    {
        return -1;
    }

    // java 단에 jni 쓰는 class가 두개라 각각 등록
    {
        auto clazz = env->FindClass("f8left/cm2/App");
        if (clazz == nullptr)
        {
            return -1;
        }
        JNINativeMethod method[] = {
            {"checkDebugger", "()I", (void *)checkDebugger}};
        if (env->RegisterNatives(clazz, method, 1) < 0)
        {
            return -1;
        }
        env->DeleteLocalRef(clazz);
    }
    
    // java 단에 jni 쓰는 class가 두개라 각각 등록
    {
        auto clazz = env->FindClass("f8left/cm2/MainActivity");
        if (clazz == nullptr)
        {
            return -1;
        }
        JNINativeMethod method[] = {
            {"check", "(Ljava/lang/String;)Z", (void *)check}};
        if (env->RegisterNatives(clazz, method, 1) < 0)
        {
            return -1;
        }
        env->DeleteLocalRef(clazz);
    }

    return JNI_VERSION_1_6;
}
