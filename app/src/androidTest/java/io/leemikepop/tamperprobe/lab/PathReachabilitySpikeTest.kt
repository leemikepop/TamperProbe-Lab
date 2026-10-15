package io.leemikepop.tamperprobe.lab

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Measurement spike, not a detector and not a regression test.
 *
 * `NATIVE_ROOT_PATHS` probes 21 fixed paths with `stat`, `lstat` and `open(O_PATH)` and
 * counts a hit when two of the three succeed. On failure it discards `errno`, and its
 * `checkedCount` is the number of rules defined rather than the number that produced an
 * answer. So the report cannot tell a path that does not exist (`ENOENT`) from a path this
 * process is not allowed to look at (`EACCES`). Most of the list sits under `/data/adb`,
 * which is `0700 root` on a stock device, so a large share of the probes may be structurally
 * unable to observe anything on every device — a dead channel that reads as a clean result.
 *
 * This measures, from the Sample App's own process, what each path actually returns. It
 * uses `Os.stat`, whose `ErrnoException` carries the errno, and the same path list as the
 * detector, copied here deliberately so the spike does not depend on native code.
 *
 *     adb shell am instrument -w \
 *       -e class io.leemikepop.tamperprobe.lab.PathReachabilitySpikeTest \
 *       io.leemikepop.tamperprobe.lab.test/androidx.test.runner.AndroidJUnitRunner
 *
 * Results are logged under tag `PathReachability`.
 */
@RunWith(AndroidJUnit4::class)
class PathReachabilitySpikeTest {

    private companion object {
        /** Copied from `native_root_paths.cpp`; keep in step if that list changes. */
        val NATIVE_ROOT_PATHS = listOf(
            "/data/adb/ksud", "/data/adb/ksu", "/data/adb/ksu/bin", "/data/adb/ksu/modules",
            "/data/adb/apd", "/data/adb/ap", "/data/adb/ap/bin", "/data/adb/ap/modules",
            "/data/adb/apatch",
            "/data/adb/magisk", "/data/adb/magisk/magiskd", "/sbin/.magisk",
            "/system/bin/magisk", "/system/xbin/magisk",
            "/data/adb", "/data/adb/modules", "/data/local/stryker", "/data/local/tmp/luckys",
            "/data/local/tmp/resetprop", "/data/local/tmp/mount_mask",
            "/data/local/tmp/mount_mark",
        )

        /** Copied from `rw_paths.cpp`. */
        val RW_PATHS = listOf(
            "/system", "/system/bin", "/system/sbin", "/system/xbin", "/vendor/bin", "/sbin", "/etc",
        )
    }

    @Test
    fun measuresWhatEachProbedPathActuallyReturns() {
        report("NATIVE_ROOT_PATHS", NATIVE_ROOT_PATHS) { path -> statOutcome(path) }
        report("RW_PATHS", RW_PATHS) { path -> accessOutcome(path) }
    }

    /**
     * `KERNEL_CHECK` reported `kallsymsReadable=false`, `totalLinesScanned=0`, and empty
     * `procVersion` and `procCmdline` in every ablation cell on both devices, while the
     * `uname` fields were populated. `NATIVE_ROOT_DEVPTS` reported `checkedCount` 1 on the
     * Pixel and 28 on the Redmi in every cell. This measures what those files and
     * directories actually return to the Sample App's process, so an empty field can be
     * told apart from a file that was never read.
     */
    @Test
    fun measuresWhatKernelInterfaceFilesReturn() {
        val files = listOf(
            "/proc/version", "/proc/cmdline", "/proc/kallsyms", "/proc/modules",
            "/proc/sys/kernel/kptr_restrict", "/proc/self/attr/current", "/dev/ptmx",
        )
        files.forEach { path ->
            val stat = statOutcome(path)
            // Device nodes are stat'd only. Opening /dev/ptmx allocates a new pty master,
            // and reading it blocks forever waiting for input that never arrives.
            val read = if (path.startsWith("/dev/")) "read_skipped device_node" else try {
                val bytes = java.io.File(path).inputStream().use { stream ->
                    val buffer = ByteArray(4096)
                    stream.read(buffer).coerceAtLeast(0)
                }
                "read_ok bytes=$bytes"
            } catch (e: java.io.IOException) {
                val cause = generateSequence<Throwable>(e) { it.cause }
                    .filterIsInstance<ErrnoException>().firstOrNull()
                "read_failed ${cause?.let { errnoName(it.errno) } ?: e.javaClass.simpleName}"
            }
            AppLog.info("PathReachability", "kernel_file", "path=$path stat=$stat $read")
        }

        val pts = java.io.File("/dev/pts")
        val listed = pts.list()
        AppLog.info(
            "PathReachability",
            "devpts",
            "stat=${statOutcome("/dev/pts")} listable=${listed != null} " +
                "entries=${listed?.size ?: -1} names=${listed?.sorted()?.take(8)}",
        )
    }

    private fun report(detector: String, paths: List<String>, probe: (String) -> String) {
        val outcomes = paths.associateWith(probe)
        val tally = outcomes.values.groupingBy { it }.eachCount()
        AppLog.info(
            "PathReachability",
            "summary",
            "detector=$detector paths=${paths.size} " +
                tally.entries.sortedBy { it.key }.joinToString(" ") { "${it.key}=${it.value}" },
        )
        outcomes.forEach { (path, outcome) ->
            AppLog.info("PathReachability", "path", "detector=$detector path=$path outcome=$outcome")
        }
    }

    /** `ok`, or the errno name. Distinguishing ENOENT from EACCES is the whole point. */
    private fun statOutcome(path: String): String =
        try {
            Os.stat(path)
            "ok"
        } catch (e: ErrnoException) {
            errnoName(e.errno)
        }

    /** RW_PATHS asks `access(W_OK)`: `writable`, or the errno for why not. */
    private fun accessOutcome(path: String): String =
        try {
            if (Os.access(path, OsConstants.W_OK)) "writable" else "not_writable"
        } catch (e: ErrnoException) {
            errnoName(e.errno)
        }

    private fun errnoName(errno: Int): String = when (errno) {
        OsConstants.ENOENT -> "ENOENT"
        OsConstants.EACCES -> "EACCES"
        OsConstants.EPERM -> "EPERM"
        OsConstants.EROFS -> "EROFS"
        OsConstants.ENOTDIR -> "ENOTDIR"
        else -> "errno_$errno"
    }
}
