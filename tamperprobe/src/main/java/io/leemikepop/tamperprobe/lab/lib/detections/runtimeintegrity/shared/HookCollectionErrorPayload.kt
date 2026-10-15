package io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity.shared

import kotlinx.serialization.Serializable

@Serializable
internal data class HookCollectionErrorPayload(
    val source: String = "",
    val errno: Int = 0,
    val message: String = "",
)
