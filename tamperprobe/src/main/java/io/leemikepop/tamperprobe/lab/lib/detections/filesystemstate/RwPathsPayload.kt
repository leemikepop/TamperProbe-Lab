package io.leemikepop.tamperprobe.lab.lib.detections.filesystemstate

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class RwPathsPayload(
    val writablePaths: List<String> = emptyList(),
    val attemptedPathCount: Int = 0,
    val completedPathCount: Int = 0,
    val notFoundPathCount: Int = 0,
    val errorPathCount: Int = 0,
) : DetectionPayload
