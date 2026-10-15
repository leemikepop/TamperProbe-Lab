package io.leemikepop.tamperprobe.lab.lib.detections.systemstate.shared

import kotlinx.serialization.Serializable

/**
 * One source read. [state] is `present`, `missing`, `unavailable`, or `redacted_by_platform`;
 * the last is emitted only by DANGEROUS_PROPS for a Settings.Global adb_enabled read of 0 on
 * API 37+, carries the [apiLevel] it was decided on, and never has a [value].
 */
@Serializable
internal data class PropertySourcePayload(
    val property: String = "",
    val source: String = "",
    val state: String = "unavailable",
    val value: String? = null,
    val error: String? = null,
    val errno: Int? = null,
    val apiLevel: Int? = null,
)

@Serializable
internal data class PropertyCollectionErrorPayload(
    val source: String = "",
    val property: String? = null,
    val path: String? = null,
    val errno: Int = 0,
    val message: String = "",
)
