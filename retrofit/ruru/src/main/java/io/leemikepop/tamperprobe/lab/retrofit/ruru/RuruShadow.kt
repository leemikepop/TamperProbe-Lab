package io.leemikepop.tamperprobe.lab.retrofit.ruru

import io.leemikepop.tamperprobe.lab.retrofit.common.PathProbe
import io.leemikepop.tamperprobe.lab.retrofit.common.ProbeAnswer
import io.leemikepop.tamperprobe.lab.retrofit.common.ProbeResult

/**
 * Shadow probes for Ruru's file checks, through `libruru_shadow.so` (src/main/cpp/ruru_shadow.cpp).
 * The classification is pure and JVM-testable; only [libc] and [syscall] call native code.
 */
object RuruShadow {
    @JvmStatic
    private external fun libcErrnos(path: String): IntArray

    @JvmStatic
    private external fun syscallErrno(path: String): Int

    /** Upstream libc mode: access, stat and fstat(open(O_PATH)). */
    fun libc(path: String): ProbeResult = classifyLibc(path, libcErrnos(path))

    /** Upstream syscall mode: raw faccessat. */
    fun syscall(path: String): ProbeResult = classifySyscall(path, syscallErrno(path))

    /**
     * `AbnormalEnvironment.detectFile`: the syscall mode, and the libc mode only when the syscall
     * raised SIGSYS.
     */
    fun detectFile(path: String): ProbeResult {
        val syscall = syscall(path)
        return if (syscall.reason == SIGSYS) libc(path) else syscall
    }

    const val NOT_ATTEMPTED: Int = -1
    const val SIGSYS_MARKER: Int = -2
    const val SIGSYS: String = "SIGSYS"

    /**
     * Any successful call means the path is there. If every attempted call failed with ENOENT or
     * ENOTDIR the path is absent. Any other errno means the channel did not answer; the first
     * such errno is the reason. `errnoName` maps errno numbers to names on the device.
     */
    fun classifyLibc(path: String, errnos: IntArray, errnoName: (Int) -> String = PathProbe::errnoName): ProbeResult {
        val attempted = errnos.filter { it != NOT_ATTEMPTED }
        if (attempted.any { it == 0 }) return ProbeResult(path, ProbeAnswer.PRESENT, "ok")
        val unanswered = attempted.firstOrNull { it !in ABSENT_ERRNOS }
        return if (unanswered == null) {
            ProbeResult(path, ProbeAnswer.ABSENT, errnoName(attempted.first()))
        } else {
            ProbeResult(path, ProbeAnswer.NO_ANSWER, errnoName(unanswered))
        }
    }

    /**
     * Upstream counts success and EPERM as FOUND; both are kept as PRESENT so a positive can be
     * attributed. SIGSYS is upstream's METHOD_UNAVAILABLE.
     */
    fun classifySyscall(path: String, errno: Int, errnoName: (Int) -> String = PathProbe::errnoName): ProbeResult =
        when (errno) {
            0 -> ProbeResult(path, ProbeAnswer.PRESENT, "ok")
            SIGSYS_MARKER -> ProbeResult(path, ProbeAnswer.NO_ANSWER, SIGSYS)
            EPERM -> ProbeResult(path, ProbeAnswer.PRESENT, errnoName(errno))
            in ABSENT_ERRNOS -> ProbeResult(path, ProbeAnswer.ABSENT, errnoName(errno))
            else -> ProbeResult(path, ProbeAnswer.NO_ANSWER, errnoName(errno))
        }

    // Linux errno numbers, identical on every Android ABI.
    private const val EPERM = 1
    private const val ENOENT = 2
    private const val ENOTDIR = 20
    private val ABSENT_ERRNOS = setOf(ENOENT, ENOTDIR)
}
