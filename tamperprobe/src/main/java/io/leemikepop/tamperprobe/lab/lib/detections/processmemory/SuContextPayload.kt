package io.leemikepop.tamperprobe.lab.lib.detections.processmemory

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class SuContextPayload(
    val contextScan: ContextScanPayload = ContextScanPayload()
) : DetectionPayload

@Serializable
internal data class ContextScanPayload(
    val selfContext: String = "",
    val selfAbnormal: Boolean = false,
    val procChecked: Int = 0,
    val procDenied: Int = 0,
    val suspiciousProcesses: List<String> = emptyList(),
    val selfContextReadable: Boolean = false,
    val procEnumerated: Boolean = false,
)
