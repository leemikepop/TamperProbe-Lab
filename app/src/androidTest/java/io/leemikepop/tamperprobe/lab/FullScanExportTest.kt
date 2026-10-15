package io.leemikepop.tamperprobe.lab

import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.leemikepop.tamperprobe.lab.api.ScanRequest
import io.leemikepop.tamperprobe.lab.presentation.export.ScanExportProvenanceProvider
import io.leemikepop.tamperprobe.lab.presentation.export.ScanExportSnapshot
import io.leemikepop.tamperprobe.lab.presentation.export.ScanReportJsonEncoder
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Captures a scan of every published detector as an export document, in the same format
 * the probe app's Export JSON action produces.
 *
 * This exists so that a device-matrix cell can be captured by running one command rather
 * than by driving the UI by hand. The research edition has no default selection: every
 * detector runs.
 *
 * Run it with, for example:
 *
 *     gradlew :app:connectedDebugAndroidTest \
 *       -Pandroid.testInstrumentationRunnerArguments.class=io.leemikepop.tamperprobe.lab.FullScanExportTest \
 *       -Pandroid.injected.androidTest.leaveApksInstalledAfterRun=true
 *
 * The last flag is not optional for fleet work. Gradle uninstalls both APKs by default,
 * and the concealment modules on the test devices are configured against the installed
 * package, so an uninstall between runs silently invalidates the next measurement.
 *
 * then pull the file from `/data/local/tmp`:
 *
 *     adb pull /data/local/tmp/<name> <local path>
 *
 * The full path is logged under tag `FullScanExport`.
 *
 * The export is written through the instrumentation's shell, not to the app's own
 * storage, for two reasons: Android 11 and later hide `/sdcard/Android/data` from the
 * adb shell user, and anything in the app's private directory is lost if the APKs are
 * ever uninstalled.
 */
@RunWith(AndroidJUnit4::class)
class FullScanExportTest {

    @Test
    fun capturesEveryPublishedDetectorAsAnExportDocument() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        val detectorIds = client.availableDetectors().mapTo(linkedSetOf()) { it.id }

        val startedAtUtc = Instant.now()
        val provenance = ScanExportProvenanceProvider.capture()
        val report = client.scan(ScanRequest(detectorIds))
        val completedAtUtc = Instant.now()

        assertEquals(detectorIds.size, report.results.size)

        val document = ScanReportJsonEncoder.createDocument(
            ScanExportSnapshot(
                startedAtUtc = startedAtUtc,
                completedAtUtc = completedAtUtc,
                requestedDetectorIds = detectorIds.toList(),
                report = report,
                provenance = provenance,
            ),
            exportedAtUtc = Instant.now(),
        )

        val target = "/data/local/tmp/${document.fileName.removeSuffix(".json")}-full.json"
        writeThroughInstrumentationShell(target, document.bytes)

        AppLog.info(
            "FullScanExport",
            "export_written",
            "path=$target detectors=${detectorIds.size} " +
                "durationMs=${report.durationMillis} " +
                "detectorMicrosTotal=${report.results.sumOf { it.durationMicros }} " +
                "observed=${report.results.count { it.outcome.name == "OBSERVED" }}",
        )
    }

    /**
     * Streams bytes into a file owned by the shell user. `executeShellCommandRw` is the
     * only route that reaches a directory surviving the post-run uninstall.
     */
    private fun writeThroughInstrumentationShell(path: String, bytes: ByteArray) {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        // `dd of=<path>` rather than a redirect: the command is tokenised without a
        // shell, so `>` never reaches one, and dd keeps its output off stdout, which
        // would otherwise fill its pipe and deadlock against our own write.
        val descriptors = automation.executeShellCommandRw("dd of=$path")
        val (stdout, stdin) = descriptors[0] to descriptors[1]
        ParcelFileDescriptor.AutoCloseOutputStream(stdin).use { it.write(bytes) }
        ParcelFileDescriptor.AutoCloseInputStream(stdout).use { it.readBytes() }

        val size = automation.executeShellCommand("stat -c %s $path").let { descriptor ->
            ParcelFileDescriptor.AutoCloseInputStream(descriptor).use {
                it.readBytes().decodeToString().trim()
            }
        }
        assertEquals(bytes.size.toString(), size)
    }
}
