package io.leemikepop.tamperprobe.lab.lib.detections.kernelinterface

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class NativeRootSusfsPayload(
    val currentUid: Int = 0,
    val targetUid: Int = 0,
    val result: String = "",
    val detail: String = "",
    val susfsDetected: Boolean = false,
    val collectionError: String? = null,
) : DetectionPayload
