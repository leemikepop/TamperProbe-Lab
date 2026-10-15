package io.leemikepop.tamperprobe.lab.lib.detections.kernelinterface

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class KernelCheckPayload(
    val kernelRelease: String = "",
    val kernelVersion: String = "",
    val procVersion: String = "",
    val procCmdline: String = "",
    val kallsymsReadable: Boolean = false,
    val nonZeroAddresses: Int = 0,
    val totalLinesScanned: Int = 0,
    val kptrExposed: Boolean = false,
    val kptrRestrictDisabled: Boolean = false,
    val nonZeroPointerRatio: Double = 0.0,
    val modulesReadable: Boolean = false,
    val kernelSymbolMatches: List<String> = emptyList(),
    val hasCjk: Boolean = false,
    val hasEmoji: Boolean = false,
    val hasTelegram: Boolean = false,
    val hasAtMention: Boolean = false,
    val customKeywords: List<String> = emptyList(),
    val hitCount: Int = 0,
    val findings: List<KernelCheckFindingPayload> = emptyList(),
) : DetectionPayload

@Serializable
internal data class KernelCheckFindingPayload(
    val check: String = "",
    val marker: String? = null,
    val value: String = "",
    val detail: String? = null,
)
