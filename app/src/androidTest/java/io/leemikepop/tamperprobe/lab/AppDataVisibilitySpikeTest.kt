package io.leemikepop.tamperprobe.lab

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Measurement spike, not a detector and not a regression test.
 *
 * `DANGEROUS_PACKAGES` has a second unit that looks for each indicator package's private
 * data directory. Across all fourteen `ablation_2026` cells it reported 156 of 156 paths
 * answered and every one of them not found — including at `R0`, where the package unit of
 * the same scan saw `com.topjohnwu.magisk` installed. A directory that exists was reported
 * absent, and the coverage counts called that a completed answer.
 *
 * The suspected cause is app data isolation: on current Android each app's mount namespace
 * shows only its own private data directory, so every other app's directory is ENOENT
 * whether or not it exists. That would make the channel unable to observe anything, while
 * looking like a clean negative.
 *
 * This measures it from the Sample App's own process with two controls that cannot be
 * absent: this app's own data directory (must be visible if the channel works at all), and
 * system packages that are always installed and never concealed. If the controls read
 * ENOENT under a root, that root cannot see other apps' data on this device, and a
 * not-found there carries no information.
 *
 *     adb shell am instrument -w \
 *       -e class io.leemikepop.tamperprobe.lab.AppDataVisibilitySpikeTest \
 *       io.leemikepop.tamperprobe.lab.test/androidx.test.runner.AndroidJUnitRunner
 *
 * Results are logged under tag `AppDataVisibility`.
 */
@RunWith(AndroidJUnit4::class)
class AppDataVisibilitySpikeTest {

    private companion object {
        val ROOTS = listOf(
            "/data/data/",
            "/data/user/0/",
            "/data/user_de/0/",
            "/storage/emulated/0/Android/data/",
            "/sdcard/Android/data/",
        )

        /** Always installed, never a concealment target. */
        val SYSTEM_CONTROLS = listOf(
            "com.android.settings",
            "com.google.android.gms",
            "com.android.vending",
        )

        /** Indicator packages installed on at least one fleet device. */
        val INDICATORS = listOf(
            "com.topjohnwu.magisk",
            "me.weishu.kernelsu",
            "com.termux",
            "org.frknkrc44.hma_oss",
        )
    }

    @Test
    fun measuresWhichAppDataRootsCanSeeOtherPackages() {
        val self = InstrumentationRegistry.getInstrumentation().targetContext.packageName
        val groups = listOf("self" to listOf(self), "system" to SYSTEM_CONTROLS, "indicator" to INDICATORS)
        for (root in ROOTS) {
            val summary = groups.joinToString(" ") { (group, packages) ->
                val outcomes = packages.map { stat(root + it) }
                "$group=" + outcomes.groupingBy { it }.eachCount().entries
                    .sortedBy { it.key }.joinToString(",") { "${it.key}:${it.value}" }
            }
            AppLog.info("AppDataVisibility", "root", "root=$root $summary")
            for ((group, packages) in groups) {
                for (pkg in packages) {
                    AppLog.info(
                        "AppDataVisibility",
                        "path",
                        "root=$root group=$group package=$pkg outcome=${stat(root + pkg)}",
                    )
                }
            }
        }
    }

    private fun stat(path: String): String =
        try {
            Os.stat(path)
            "ok"
        } catch (e: ErrnoException) {
            when (e.errno) {
                OsConstants.ENOENT -> "ENOENT"
                OsConstants.EACCES -> "EACCES"
                OsConstants.EPERM -> "EPERM"
                OsConstants.ENOTDIR -> "ENOTDIR"
                else -> "errno_${e.errno}"
            }
        }
}
