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
 * SUSFS `sus_path` makes a hidden path answer `ENOENT` to lookups from app processes. Under
 * `/data/adb` that turns a channel the app could never read (`EACCES`) into one that looks like
 * a genuine absence, and `NATIVE_ROOT_PATHS` then reports a complete, clean result (E2, cell K2).
 * AOSP does not create `/data/adb` on user builds, so "it must exist" is not an anchor.
 *
 * What may still be an anchor is a syscall that checks whether a name exists *before* it checks
 * permission. `mkdir`, `open(O_CREAT | O_EXCL)` and `symlink` all look up the final component and
 * return `EEXIST` for an existing name before the kernel asks whether the caller may write to the
 * parent. If `sus_path` hides the name only from path lookups used by `stat`, `access` and `open`,
 * these calls would still reveal it.
 *
 * Each probe records errno only. None of them can succeed from an app process: the parents are
 * not writable by the app. If one ever does succeed, the created entry is removed at once and the
 * success is logged, because a probe must not change what it observes.
 *
 *     adb shell am instrument -w \
 *       -e class io.leemikepop.tamperprobe.lab.PathExistenceOracleSpikeTest \
 *       io.leemikepop.tamperprobe.lab.test/androidx.test.runner.AndroidJUnitRunner
 *
 * Results are logged under tag `PathExistenceOracle`.
 */
@RunWith(AndroidJUnit4::class)
class PathExistenceOracleSpikeTest {

    private companion object {
        const val TAG = "PathExistenceOracle"

        /**
         * `/data/adb` is the path under test. The others are controls with a known answer on the
         * device being measured, read as root before the run: directories that exist with
         * different owners and labels, and names that do not exist.
         */
        val PATHS = listOf(
            "/data/adb",
            "/data/adb/ksu",
            "/data/misc",
            "/data/vendor",
            "/data/local",
            "/data/tp_oracle_absent",
            "/data/tp_oracle_absent/child",
            "/data/vendor/tp_oracle_absent",
        )
    }

    @Test
    fun measuresWhichSyscallsRevealThatANameExists() {
        PATHS.forEach { path ->
            val results = linkedMapOf(
                "stat" to errnoOf { Os.stat(path) },
                "lstat" to errnoOf { Os.lstat(path) },
                "access" to errnoOf { Os.access(path, OsConstants.F_OK) },
                "mkdir" to errnoOf(cleanup = { Os.remove(path) }) { Os.mkdir(path, 0x1c0) },
                "openExcl" to errnoOf(cleanup = { Os.remove(path) }) {
                    val fd = Os.open(path, OsConstants.O_CREAT or OsConstants.O_EXCL or OsConstants.O_WRONLY, 0x180)
                    Os.close(fd)
                },
                "symlink" to errnoOf(cleanup = { Os.remove(path) }) { Os.symlink("tp_oracle_target", path) },
            )
            AppLog.info(TAG, "path", "path=$path " + results.entries.joinToString(" ") { "${it.key}=${it.value}" })
        }
    }

    /** `ok` if the call succeeded (after running [cleanup]), otherwise the errno name. */
    private fun errnoOf(cleanup: (() -> Unit)? = null, call: () -> Unit): String =
        try {
            call()
            cleanup?.let { runCatching(it) }
            if (cleanup != null) "UNEXPECTED_SUCCESS_REMOVED" else "ok"
        } catch (e: ErrnoException) {
            errnoName(e.errno)
        }

    private fun errnoName(errno: Int): String = when (errno) {
        OsConstants.ENOENT -> "ENOENT"
        OsConstants.EACCES -> "EACCES"
        OsConstants.EEXIST -> "EEXIST"
        OsConstants.EPERM -> "EPERM"
        OsConstants.EROFS -> "EROFS"
        OsConstants.ENOTDIR -> "ENOTDIR"
        else -> "errno_$errno"
    }
}
