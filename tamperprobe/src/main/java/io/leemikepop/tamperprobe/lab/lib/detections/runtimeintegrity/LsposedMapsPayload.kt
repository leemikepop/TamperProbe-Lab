package io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class LsposedMapsPayload(
    val findings: List<LsposedFindingPayload> = emptyList(),
    val hitCount: Int = 0,
    val collectionError: String? = null
) : DetectionPayload

@Serializable
internal data class LsposedFindingPayload(
    val marker: String = "",
    val path: String = ""
)
