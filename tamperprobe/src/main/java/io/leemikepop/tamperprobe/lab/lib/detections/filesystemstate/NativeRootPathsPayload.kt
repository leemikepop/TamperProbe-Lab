package io.leemikepop.tamperprobe.lab.lib.detections.filesystemstate

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class NativeRootPathsPayload(
    val findings: List<NativeRootPathFindingPayload> = emptyList(),
    val hitCount: Int = 0,
    val checkedCount: Int = 0,
    val attemptedPathCount: Int = 0,
    val completedPathCount: Int = 0,
    val notFoundPathCount: Int = 0,
    val errorPathCount: Int = 0,
    val inaccessiblePaths: List<String> = emptyList(),
    val concealableNotFoundPathCount: Int = 0,
    val concealableNotFoundPaths: List<String> = emptyList(),
    val ksuFound: Boolean = false,
    val apatchFound: Boolean = false,
    val magiskFound: Boolean = false,
) : DetectionPayload

@Serializable
internal data class NativeRootPathFindingPayload(
    val path: String = "",
    val label: String = "",
    val rootTool: String = "",
    val confirmations: Int = 0,
    val evidence: String = "",
)
