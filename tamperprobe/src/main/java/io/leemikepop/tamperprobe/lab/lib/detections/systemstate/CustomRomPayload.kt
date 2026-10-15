package io.leemikepop.tamperprobe.lab.lib.detections.systemstate

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class CustomRomPayload(
    val buildTags: String = "",
    val roDebuggable: String = "",
    val roSecure: String = "",
    val hitCount: Int = 0,
    val findings: List<CustomRomFindingPayload> = emptyList()
) : DetectionPayload

@Serializable
internal data class CustomRomFindingPayload(
    val check: String = "",
    val value: String = "",
    val detail: String = ""
)
