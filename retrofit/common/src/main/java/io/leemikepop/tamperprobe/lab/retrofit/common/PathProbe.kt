package io.leemikepop.tamperprobe.lab.retrofit.common

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructStat
import java.io.FileDescriptor

/**
 * Shadow probes for filesystem channels. Each repeats one libc call an upstream check makes and
 * keeps the errno the upstream code discards.
 *
 * `ENOENT` and `ENOTDIR` are answers: the path, or one of its parents, is not there. Every other
 * errno (`EACCES`, `EPERM`, `ELOOP`, ...) means the channel did not answer for that path.
 */
object PathProbe {
    /** Present on every Android device; a stat channel that cannot see it is not answering. */
    const val ANCHOR_PATH: String = "/system/bin/sh"

    fun stat(path: String): ProbeResult = probe(path) { Os.stat(path) }

    /** `open(path, O_RDONLY)`, the call behind `fopen(path, "r")`. */
    fun openReadOnly(path: String): ProbeResult = probe(path) {
        val descriptor: FileDescriptor = Os.open(path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC, 0)
        Os.close(descriptor)
    }

    /** The mode of a path that stat can see, or null. */
    fun modeOf(path: String): Int? = try {
        val stat: StructStat = Os.stat(path)
        stat.st_mode
    } catch (_: ErrnoException) {
        null
    }

    /** True for a regular file with at least one execute bit. */
    fun isExecutableRegularFile(mode: Int?): Boolean =
        mode != null && OsConstants.S_ISREG(mode) && (mode and EXECUTE_BITS) != 0

    /**
     * Applies Rule 2 to path probes: if the anchor did not come back [ProbeAnswer.PRESENT] through
     * the same call, no `ENOENT` from that call is an answer.
     */
    fun anchored(anchor: ProbeResult, probes: List<ProbeResult>): List<ProbeResult> =
        if (anchor.answer == ProbeAnswer.PRESENT) {
            probes
        } else {
            probes.map {
                if (it.answer == ProbeAnswer.ABSENT) {
                    it.copy(answer = ProbeAnswer.NO_ANSWER, reason = "anchor_${anchor.reason}")
                } else {
                    it
                }
            }
        }

    fun classifyErrno(path: String, errno: Int): ProbeResult = when (errno) {
        OsConstants.ENOENT, OsConstants.ENOTDIR ->
            ProbeResult(path, ProbeAnswer.ABSENT, errnoName(errno))
        else -> ProbeResult(path, ProbeAnswer.NO_ANSWER, errnoName(errno))
    }

    fun errnoName(errno: Int): String = OsConstants.errnoName(errno) ?: "errno_$errno"

    private inline fun probe(path: String, call: () -> Unit): ProbeResult = try {
        call()
        ProbeResult(path, ProbeAnswer.PRESENT, "ok")
    } catch (error: ErrnoException) {
        classifyErrno(path, error.errno)
    }

    private const val EXECUTE_BITS = 0b001_001_001
}
