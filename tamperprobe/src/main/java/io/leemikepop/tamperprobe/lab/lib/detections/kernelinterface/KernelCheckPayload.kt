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
    val bannerSources: List<String> = emptyList(),
    val bannerConcealableNegatives: List<KernelCheckConcealableNegativePayload> = emptyList(),
    val identityCoherence: KernelIdentityCoherencePayload = KernelIdentityCoherencePayload(),
    val identityConcealableNegatives: List<KernelCheckConcealableNegativePayload> = emptyList(),
    val hitCount: Int = 0,
    val findings: List<KernelCheckFindingPayload> = emptyList(),
) : DetectionPayload

@Serializable
internal data class KernelCheckFindingPayload(
    val check: String = "",
    val unitId: String? = null,
    val marker: String? = null,
    val value: String = "",
    val detail: String? = null,
)

/**
 * A not-found the detector could not trust, because concealment produces the same absence: a
 * banner scan that saw only the uname syscall, or release sources that agree.
 */
@Serializable
internal data class KernelCheckConcealableNegativePayload(
    val check: String = "",
    val source: String? = null,
    val comparedSources: List<String> = emptyList(),
    val concealable: Boolean = true,
    val reason: String = "",
)

/** Kernel release as read from each source; `state` is `agree`, `disagree` or `unavailable`. */
@Serializable
internal data class KernelIdentityCoherencePayload(
    val state: String = "unavailable",
    val readableSourceCount: Int = 0,
    val distinctReleaseCount: Int = 0,
    val sources: List<KernelIdentitySourcePayload> = emptyList(),
    val unreadableSources: List<String> = emptyList(),
)

@Serializable
internal data class KernelIdentitySourcePayload(
    val source: String = "",
    val readable: Boolean = false,
    val value: String = "",
)
