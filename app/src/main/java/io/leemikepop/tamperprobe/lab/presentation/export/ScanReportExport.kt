package io.leemikepop.tamperprobe.lab.presentation.export

import android.os.Build
import io.leemikepop.tamperprobe.lab.BuildConfig
import io.leemikepop.tamperprobe.lab.api.TamperProbeReport
import java.time.Instant

internal data class ScanExportSnapshot(
    val startedAtUtc: Instant,
    val completedAtUtc: Instant,
    val requestedDetectorIds: List<String>,
    val report: TamperProbeReport,
    val provenance: ExportProvenance,
)

internal data class ExportProvenance(
    val sampleApp: SampleAppProvenance,
    val coreBuild: CoreBuildProvenance,
    val device: DeviceProvenance,
)

internal data class SampleAppProvenance(
    val versionName: String,
    val versionCode: Int,
    val gitCommit: String,
    val gitDirty: Boolean,
    val buildType: String,
)

internal data class CoreBuildProvenance(
    val engineVersion: String,
    val catalogVersion: String,
    val catalogSchemaVersion: Int,
    val evidenceContractVersion: Int,
    val wireSchemaVersion: Int,
)

internal data class DeviceProvenance(
    val manufacturer: String,
    val brand: String,
    val model: String,
    val device: String,
    val product: String,
    val androidRelease: String,
    val apiLevel: Int,
    val supportedAbis: List<String>,
    val buildFingerprint: String,
    val buildType: String,
    val kernelVersion: String,
)

internal data class ExportDocument(
    val fileName: String,
    val bytes: ByteArray,
)

internal object ScanExportProvenanceProvider {
    fun capture(): ExportProvenance = ExportProvenance(
        sampleApp = SampleAppProvenance(
            versionName = BuildConfig.VERSION_NAME,
            versionCode = BuildConfig.VERSION_CODE,
            gitCommit = BuildConfig.GIT_COMMIT,
            gitDirty = BuildConfig.GIT_DIRTY,
            buildType = BuildConfig.BUILD_TYPE,
        ),
        coreBuild = CoreBuildProvenance(
            engineVersion = BuildConfig.TAMPERPROBE_ENGINE_VERSION,
            catalogVersion = BuildConfig.TAMPERPROBE_CATALOG_VERSION,
            catalogSchemaVersion = BuildConfig.TAMPERPROBE_CATALOG_SCHEMA_VERSION,
            evidenceContractVersion = BuildConfig.TAMPERPROBE_EVIDENCE_CONTRACT_VERSION,
            wireSchemaVersion = BuildConfig.TAMPERPROBE_WIRE_SCHEMA_VERSION,
        ),
        device = DeviceProvenance(
            manufacturer = Build.MANUFACTURER.orEmpty(),
            brand = Build.BRAND.orEmpty(),
            model = Build.MODEL.orEmpty(),
            device = Build.DEVICE.orEmpty(),
            product = Build.PRODUCT.orEmpty(),
            androidRelease = Build.VERSION.RELEASE.orEmpty(),
            apiLevel = Build.VERSION.SDK_INT,
            supportedAbis = Build.SUPPORTED_ABIS.orEmpty().toList(),
            buildFingerprint = Build.FINGERPRINT.orEmpty(),
            buildType = Build.TYPE.orEmpty(),
            kernelVersion = System.getProperty("os.version").orEmpty(),
        ),
    )
}

internal class LatestScanExportStore {
    private var scanInProgress: Boolean = false
    private var latestSnapshot: ScanExportSnapshot? = null

    @Synchronized
    fun onScanStarted() {
        scanInProgress = true
    }

    @Synchronized
    fun onScanSucceeded(snapshot: ScanExportSnapshot) {
        latestSnapshot = snapshot
        scanInProgress = false
    }

    @Synchronized
    fun onScanFailed() {
        scanInProgress = false
    }

    @Synchronized
    fun clear() {
        scanInProgress = false
        latestSnapshot = null
    }

    @Synchronized
    fun canExport(): Boolean = !scanInProgress && latestSnapshot != null

    @Synchronized
    fun snapshotForExport(): ScanExportSnapshot? =
        if (scanInProgress) null else latestSnapshot
}
