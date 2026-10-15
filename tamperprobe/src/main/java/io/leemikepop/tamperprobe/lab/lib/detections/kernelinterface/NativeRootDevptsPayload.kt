package io.leemikepop.tamperprobe.lab.lib.detections.kernelinterface

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class NativeRootDevptsPayload(
    val findings: List<NativeRootDevptsFindingPayload> = emptyList(),
    val checkedCount: Int = 0,
    val hitCount: Int = 0,
    val driverFdCount: Int = 0,
    val fdwrapperCount: Int = 0,
) : DetectionPayload

@Serializable
internal data class NativeRootDevptsFindingPayload(
    val path: String = "",
    val owner: String? = null,
    val selinuxContext: String? = null,
    val ksuFileContext: Boolean = false,
    val freshPty: Boolean = false,
    val fdTarget: String? = null,
    val driverType: String? = null,
)
