package io.leemikepop.tamperprobe.lab.lib.detections.hardwareattestation

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class TeeOversizedChallengePayload(
    val checked: Boolean = false,
    val accepted: Boolean = false,
    val state: String = "not_checked",
    val stage: String = "setup",
    val errorCategory: String = "none",
    val numericErrorCode: Int = -1,
    val aliasCleanupSucceeded: Boolean = false,
    val challengeSize: Int = 0,
    val findings: List<TeeAttestationFindingPayload> = emptyList(),
    val collectionWarnings: List<TeeCollectionWarningPayload> = emptyList(),
    val collectionError: String? = null,
) : DetectionPayload
