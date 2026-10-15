package io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class ZygiskNamespacePayload(
    val totalLibCount: Int = 0,
    val suspiciousLibs: List<String> = emptyList(),
    val scannedThreadCount: Int = 0,
    val suspiciousThreads: List<String> = emptyList(),
    val fdTrapStatus: String = "not_run",
) : DetectionPayload
