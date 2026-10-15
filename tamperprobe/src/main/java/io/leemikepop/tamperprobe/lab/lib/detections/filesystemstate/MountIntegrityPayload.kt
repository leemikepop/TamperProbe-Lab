package io.leemikepop.tamperprobe.lab.lib.detections.filesystemstate

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class MountIntegrityPayload(
    val findings: List<MountIntegrityFindingPayload> = emptyList(),
    val collectionErrors: List<MountCollectionErrorPayload> = emptyList(),
    val statxChecks: List<MountStatxCheckPayload> = emptyList(),
    val statfsChecks: List<MountStatfsCheckPayload> = emptyList(),
    val directBlockMounts: List<MountRowTelemetryPayload> = emptyList(),
    val genericMountHeuristics: List<AggregatedMountHeuristicPayload> = emptyList(),
    val mountIdSequence: MountIdSequencePayload = MountIdSequencePayload(),
    val mountInfoReadable: Boolean = false,
    val mountInfoEntryCount: Int = 0,
    val overlayDeclared: Boolean = false,
    val rootPropagationPrivate: Boolean = false,
    val selfNamespace: String = "",
    val initNamespace: String = "",
    val sharesInitNamespace: Boolean = false,
    val completedStatxChecks: Int = 0,
    val completedStatfsChecks: Int = 0,
    val hiddenMountIdCount: Int = 0,
    val hiddenOverlayCount: Int = 0,
    val strongFindingCount: Int = 0,
    val moderateFindingCount: Int = 0,
    val weakFindingCount: Int = 0,
    val findingCount: Int = 0
) : DetectionPayload

@Serializable
internal data class MountIntegrityFindingPayload(
    val id: String = "",
    val ruleId: String = "",
    val family: String = "",
    val confidence: String = "",
    val marker: String = "",
    val summary: String = "",
    val path: String = "",
    val detail: String = "",
    val source: String = "",
    val target: String = "",
    val fsType: String = "",
    val options: String = ""
)

@Serializable
internal data class MountRowTelemetryPayload(
    val source: String = "",
    val target: String = "",
    val fsType: String = "",
    val options: String = ""
)

@Serializable
internal data class AggregatedMountHeuristicPayload(
    val ruleId: String = "",
    val partition: String = "",
    val rowCount: Int = 0,
    val assessmentImpact: String = "",
    val representativeSource: String = "",
    val representativeTarget: String = "",
    val fsType: String = "",
    val options: String = ""
)

@Serializable
internal data class MountIdSequencePayload(
    val experimental: Boolean = true,
    val artMountId: Long? = null,
    val dataMirrorMountId: Long? = null,
    val visibleCount: Int = 0,
    val missingCount: Long = 0,
    val maximumGap: Long = 0,
    val gapRanges: List<MountIdGapRangePayload> = emptyList(),
    val assessmentImpact: String = "telemetry_only",
)

@Serializable
internal data class MountIdGapRangePayload(
    val start: Long = 0,
    val end: Long = 0,
    val size: Long = 0
)

@Serializable
internal data class MountCollectionErrorPayload(
    val source: String = "",
    val errno: Int = 0,
    val message: String = ""
)

@Serializable
internal data class MountStatxCheckPayload(
    val path: String = "",
    val succeeded: Boolean = false,
    val mountId: Long? = null,
    val presentInMountInfo: Boolean? = null,
    val errno: Int? = null
)

@Serializable
internal data class MountStatfsCheckPayload(
    val path: String = "",
    val succeeded: Boolean = false,
    val fsType: Long? = null,
    val overlay: Boolean? = null,
    val errno: Int? = null
)
