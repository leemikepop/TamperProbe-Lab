package io.leemikepop.tamperprobe.lab.lib.detections.systemstate

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class BuildPatchCoherencePayload(
    val comparablePartitionCount: Int = 0,
    val maximumSkewDays: Long = 0L,
    val partitions: List<BuildPatchPartitionPayload> = emptyList(),
    val findings: List<BuildPatchFindingPayload> = emptyList(),
    val collectionErrors: List<BuildPatchErrorPayload> = emptyList(),
) : DetectionPayload

@Serializable
internal data class BuildPatchPartitionPayload(
    val partition: String = "",
    val patchProperty: String = "",
    val buildDateProperty: String = "",
    val patchLevel: String = "",
    val comparable: Boolean = false,
    val skewDays: Long = 0L,
    val reason: String = "",
)

@Serializable
internal data class BuildPatchFindingPayload(
    val id: String = "",
    val unitId: String = "",
    val partition: String = "",
    val strength: String = "",
    val skewDays: Long = 0L,
    val patchLevel: String = "",
    val summary: String = "",
    val detail: String = "",
)

@Serializable
internal data class BuildPatchErrorPayload(
    val source: String = "",
    val message: String = "",
)
