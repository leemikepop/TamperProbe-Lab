// Shadow probes for Ruru's FileDetection (upstream cpp/file_detection.cpp).
//
// Upstream folds every libc failure into NOT_FOUND. These functions make the same calls on the
// same path and return each call's errno instead, so the retrofit can tell ENOENT (an answer) from
// EACCES and the like (no answer). They decide nothing: the upstream verdict decides positives.
//
// Rule 5: the SIGSYS handler is installed only around the raw syscall and the previous disposition
// is restored, and every descriptor opened here is closed.

#include <jni.h>

#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

constexpr jint kNotAttempted = -1;
// Returned by the raw-syscall probe when the call raised SIGSYS (seccomp), which upstream
// reports as METHOD_UNAVAILABLE.
constexpr jint kSigsys = -2;

volatile sig_atomic_t g_sigsys = 0;

void OnSigsys(int) { g_sigsys = 1; }

jint ErrnoOf(int result) { return result == 0 ? 0 : errno; }

}  // namespace

// [access(F_OK), stat, open(O_PATH), fstat on that descriptor]; 0 is success, kNotAttempted
// marks an fstat that could not run because open failed.
extern "C" JNIEXPORT jintArray JNICALL
Java_io_leemikepop_tamperprobe_lab_retrofit_ruru_RuruShadow_libcErrnos(JNIEnv* env, jclass, jstring path) {
    const char* cpath = env->GetStringUTFChars(path, nullptr);
    jint values[4] = {kNotAttempted, kNotAttempted, kNotAttempted, kNotAttempted};

    values[0] = ErrnoOf(access(cpath, F_OK));
    struct stat buffer {};
    values[1] = ErrnoOf(stat(cpath, &buffer));
    int fd = open(cpath, O_PATH | O_CLOEXEC);
    if (fd >= 0) {
        values[2] = 0;
        values[3] = ErrnoOf(fstat(fd, &buffer));
        close(fd);
    } else {
        values[2] = errno;
    }

    env->ReleaseStringUTFChars(path, cpath);
    jintArray result = env->NewIntArray(4);
    if (result != nullptr) env->SetIntArrayRegion(result, 0, 4, values);
    return result;
}

// Raw faccessat(AT_FDCWD, path, F_OK), as upstream's syscall mode: 0, an errno, or kSigsys.
extern "C" JNIEXPORT jint JNICALL
Java_io_leemikepop_tamperprobe_lab_retrofit_ruru_RuruShadow_syscallErrno(JNIEnv* env, jclass, jstring path) {
    const char* cpath = env->GetStringUTFChars(path, nullptr);

    struct sigaction handler {};
    struct sigaction previous {};
    handler.sa_handler = OnSigsys;
    sigemptyset(&handler.sa_mask);
    g_sigsys = 0;
    sigaction(SIGSYS, &handler, &previous);
    long rc = syscall(SYS_faccessat, AT_FDCWD, cpath, F_OK);
    int saved = errno;
    sigaction(SIGSYS, &previous, nullptr);

    env->ReleaseStringUTFChars(path, cpath);
    if (g_sigsys) return kSigsys;
    return rc == 0 ? 0 : saved;
}
