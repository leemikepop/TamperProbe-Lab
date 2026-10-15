package io.leemikepop.tamperprobe.lab.lib

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.leemikepop.tamperprobe.lab.TamperProbe
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.ScanRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Api29CompatibilityInstrumentedTest {
    @Test
    fun api29SensitiveDetectorsDegradeWithoutTerminatingTheHost() {
        assumeTrue(Build.VERSION.SDK_INT == Build.VERSION_CODES.Q)
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        val detectorIds = setOf(
            "MOUNT_INTEGRITY",
            "LSPOSED_SEPOLICY",
            "NATIVE_ROOT_SEPOLICY",
        )

        val report = client.scanBlocking(ScanRequest(detectorIds))

        assertEquals(detectorIds, report.results.map { it.descriptor.id }.toSet())
        val mount = report.results.single { it.descriptor.id == "MOUNT_INTEGRITY" }
        assertNotEquals(DetectionOutcome.FAILED, mount.outcome)
        assertTrue(
            mount.unitResults.flatMap { it.issues }.any {
                it.attributes.values.any { value -> value == "statx" }
            },
        )
        report.results
            .filter { it.descriptor.id != "MOUNT_INTEGRITY" }
            .forEach { result ->
                assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
                assertTrue(result.unitResults.flatMap { it.issues }.isNotEmpty())
            }
    }
}
