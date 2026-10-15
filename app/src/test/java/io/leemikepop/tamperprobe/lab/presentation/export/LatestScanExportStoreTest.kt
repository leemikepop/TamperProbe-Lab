package io.leemikepop.tamperprobe.lab.presentation.export

import io.leemikepop.tamperprobe.lab.api.TamperProbeReport
import io.leemikepop.tamperprobe.lab.api.ScanCompletion
import java.time.Instant
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class LatestScanExportStoreTest {
    @Test
    fun scanLifecycleKeepsLastSuccessfulSnapshotButDisablesItWhileScanning() {
        val store = LatestScanExportStore()
        val first = snapshot("first")
        val second = snapshot("second")

        assertFalse(store.canExport())

        store.onScanStarted()
        assertFalse(store.canExport())
        store.onScanSucceeded(first)
        assertTrue(store.canExport())
        assertSame(first, store.snapshotForExport())

        store.onScanStarted()
        assertFalse(store.canExport())
        store.onScanFailed()
        assertTrue(store.canExport())
        assertSame(first, store.snapshotForExport())

        store.onScanStarted()
        store.onScanSucceeded(second)
        assertSame(second, store.snapshotForExport())

        store.clear()
        assertFalse(store.canExport())
        assertTrue(store.snapshotForExport() == null)
    }

    private fun snapshot(catalogVersion: String): ScanExportSnapshot = ScanExportSnapshot(
        startedAtUtc = Instant.EPOCH,
        completedAtUtc = Instant.EPOCH.plusSeconds(1),
        requestedDetectorIds = listOf("TEST"),
        report = TamperProbeReport(
            wireSchemaVersion = 1,
            engineVersion = "test",
            catalogVersion = catalogVersion,
            completion = ScanCompletion.COMPLETE,
            durationMillis = 1,
            results = emptyList(),
        ),
        provenance = ExportProvenance(
            sampleApp = SampleAppProvenance("1.0.1", 1, "0123456789ab", false, "debug"),
            coreBuild = CoreBuildProvenance("test", catalogVersion, 1, 1, 1),
            device = DeviceProvenance(
                manufacturer = "test",
                brand = "test",
                model = "test",
                device = "test",
                product = "test",
                androidRelease = "14",
                apiLevel = 34,
                supportedAbis = listOf("x86_64"),
                buildFingerprint = "test",
                buildType = "user",
                kernelVersion = "test",
            ),
        ),
    )
}
