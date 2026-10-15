package io.leemikepop.tamperprobe.lab.lib.detections.hardwareattestation

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class KeystoreGrantSplitPayload(
    val available: Boolean = false,
    val apiLevel: Int = 0,
    val grantIssued: Boolean = false,
    val grantReadback: String = "",
    val controlReadback: String = "",
    val split: Boolean = false,
    val splitKind: String = "",
    val mismatchIndex: Int = -1,
    val ownerChain: List<KeystoreCertificateDigestPayload> = emptyList(),
    val granteeChain: List<KeystoreCertificateDigestPayload> = emptyList(),
    val findings: List<KeystoreGrantSplitFindingPayload> = emptyList(),
    val collectionErrors: List<KeystoreGrantSplitErrorPayload> = emptyList(),
) : DetectionPayload

@Serializable
internal data class KeystoreCertificateDigestPayload(
    val length: Int = 0,
    val sha256: String = "",
)

@Serializable
internal data class KeystoreGrantSplitFindingPayload(
    val id: String = "",
    val unitId: String = "",
    val strength: String = "",
    val splitKind: String = "",
    val mismatchIndex: Int = -1,
    val summary: String = "",
    val detail: String = "",
)

@Serializable
internal data class KeystoreGrantSplitErrorPayload(
    val source: String = "",
    val message: String = "",
)
