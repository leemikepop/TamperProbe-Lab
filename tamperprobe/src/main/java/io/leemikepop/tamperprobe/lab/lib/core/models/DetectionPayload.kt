package io.leemikepop.tamperprobe.lab.lib.core.models

import kotlinx.serialization.Serializable

/**
 * 檢測項目的 Payload (多型)
 */
internal interface DetectionPayload

@Serializable
internal data class StringPayload(val message: String) : DetectionPayload
