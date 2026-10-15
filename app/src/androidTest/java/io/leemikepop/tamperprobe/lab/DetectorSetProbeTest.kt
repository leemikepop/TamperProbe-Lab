package io.leemikepop.tamperprobe.lab

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.leemikepop.tamperprobe.lab.api.ScanRequest
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Scans an arbitrary detector set named by an instrumentation argument and logs each
 * outcome, so a combination can be tried without editing a test.
 *
 * It lives in the Sample App's test module rather than the library's own because the two
 * run as different applications with different uids, and at least one detector's result
 * depends on which: `KEYSTORE_GRANT_SPLIT` asks Keystore for a grant, and Keystore
 * decides per uid. The library's instrumented tests target themselves, so anything
 * reproduced there is a statement about that test app, not about an integrating app.
 * This test runs in the same process as the exports the device matrix is captured from.
 *
 *     adb shell am instrument -w \
 *       -e class io.leemikepop.tamperprobe.lab.DetectorSetProbeTest \
 *       -e detectors TEE_ATTESTATION,KEYSTORE_GRANT_SPLIT \
 *       io.leemikepop.tamperprobe.lab.test/androidx.test.runner.AndroidJUnitRunner
 *
 * Pass `-e detectors ALL` for the whole published catalog. Results are logged under tag
 * `DetectorSetProbe`.
 *
 * `-e holdBeforeSeconds N` and `-e holdAfterSeconds N` keep the process alive before and
 * after the scan, logging `hold_before` / `hold_after`, so its /proc state can be measured
 * from outside at a known point — for example to tell whether a detector itself changes
 * the memory another detector then observes.
 */
@RunWith(AndroidJUnit4::class)
class DetectorSetProbeTest {

    @Test
    fun scansTheDetectorSetNamedByArgument() = runBlocking {
        val argument = InstrumentationRegistry.getArguments().getString("detectors")
        assertTrue("pass -e detectors A,B,C (or ALL)", !argument.isNullOrBlank())

        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)

        val ids = if (argument!!.trim() == "ALL") {
            client.availableDetectors().mapTo(linkedSetOf()) { it.id }
        } else {
            argument.split(',').map { it.trim() }.filterTo(linkedSetOf()) { it.isNotEmpty() }
        }
        val arguments = InstrumentationRegistry.getArguments()
        val holdBefore = arguments.getString("holdBeforeSeconds")?.toLongOrNull() ?: 0L
        val holdAfter = arguments.getString("holdAfterSeconds")?.toLongOrNull() ?: 0L
        if (holdBefore > 0) {
            AppLog.info("DetectorSetProbe", "hold_before", "seconds=$holdBefore")
            Thread.sleep(holdBefore * 1000)
        }

        val report = client.scan(ScanRequest(ids))

        if (holdAfter > 0) {
            AppLog.info("DetectorSetProbe", "hold_after", "seconds=$holdAfter")
            Thread.sleep(holdAfter * 1000)
        }

        report.results.sortedBy { it.descriptor.id }.forEach { result ->
            AppLog.info(
                "DetectorSetProbe",
                "detector_outcome",
                "selection=${ids.size} detectorId=${result.descriptor.id} " +
                    "outcome=${result.outcome} strength=${result.strength}",
            )
        }
    }
}
