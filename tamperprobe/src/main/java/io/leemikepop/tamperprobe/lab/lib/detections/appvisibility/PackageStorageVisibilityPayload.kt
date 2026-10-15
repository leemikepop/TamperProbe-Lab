package io.leemikepop.tamperprobe.lab.lib.detections.appvisibility

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class PackageStorageVisibilityPayload(
    val storageContext: PackageStorageContextPayload,
    val overview: PackageStorageOverviewPayload,
    val packageObservations: List<PackageStorageObservationPayload>,
    val findings: List<PackageStorageFindingPayload>,
    val telemetry: List<PackageStorageTelemetryPayload>,
    val collectionErrors: List<PackageStorageCollectionErrorPayload>,
) : DetectionPayload

@Serializable
internal data class PackageStorageContextPayload(
    val userId: Int,
    val storageRoot: String,
    val statfsAvailable: Boolean,
    val fsType: Long? = null,
    val statfsErrno: Int? = null,
    val fuseBpfState: String,
    val appDataIsolationState: String,
    val rootProbe: PackageStorageProbePayload,
)

@Serializable
internal data class PackageStorageOverviewPayload(
    val targetCount: Int,
    val completedBaselineCount: Int,
    val transformedProbeCount: Int,
    val candidateCount: Int,
    val findingCount: Int,
    val telemetryCount: Int,
    val droppedObservationCount: Int,
    val droppedCollectionErrorCount: Int,
)

@Serializable
internal data class PackageStorageProbePayload(
    val state: String,
    val errno: Int,
    val inode: Long? = null,
    val device: Long? = null,
)

@Serializable
internal data class PackageStorageObservationPayload(
    val `package`: String,
    val protectedRoot: String,
    val variantId: String,
    val variantType: String,
    val codePoint: String,
    val placement: String,
    val canonicalStat: PackageStorageProbePayload,
    val canonicalAccess: PackageStorageProbePayload,
    val canonicalOpen: PackageStorageProbePayload,
    val variantStat: PackageStorageProbePayload,
    val variantAccess: PackageStorageProbePayload,
    val variantOpen: PackageStorageProbePayload,
    val variantList: PackageStorageProbePayload,
    val assessmentImpact: String,
)

@Serializable
internal data class PackageStorageFindingPayload(
    val id: String,
    val `package`: String,
    val protectedRoot: String,
    val variantId: String,
    val codePoint: String? = null,
    val placement: String? = null,
    val strength: String,
    val classification: String,
    val summary: String,
)

@Serializable
internal data class PackageStorageTelemetryPayload(
    val id: String,
    val classification: String,
    val assessmentImpact: String,
    val summary: String,
    val differentialCount: Int,
)

@Serializable
internal data class PackageStorageCollectionErrorPayload(
    val source: String,
    val errno: Int,
    val message: String,
)
