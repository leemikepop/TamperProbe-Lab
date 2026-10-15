package io.leemikepop.tamperprobe.lab.lib.detections.hardwareattestation

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class DrmCredentialCoherencePayload(
    val schemeSupported: Boolean = false,
    val hardwareSecureAllSupported: Boolean = false,
    val securityLevel: String = "",
    val systemIdState: String = "",
    val systemId: String = "",
    val drmVersion: String = "",
    val sessionStatus: String = "",
    val comparable: Boolean = false,
    val notComparableReason: String = "",
    val bootClaim: DrmBootClaimPayload = DrmBootClaimPayload(),
    val findings: List<DrmCredentialFindingPayload> = emptyList(),
    val collectionErrors: List<DrmCredentialErrorPayload> = emptyList(),
) : DetectionPayload

@Serializable
internal data class DrmBootClaimPayload(
    val verifiedBootState: String = "",
    val flashLocked: String = "",
    val vbmetaDeviceState: String = "",
    val claimsLocked: Boolean = false,
    val claimsUnlocked: Boolean = false,
)

@Serializable
internal data class DrmCredentialFindingPayload(
    val id: String = "",
    val unitId: String = "",
    val strength: String = "",
    val sessionStatus: String = "",
    val corroboratedBySession: Boolean = false,
    val summary: String = "",
    val detail: String = "",
)

@Serializable
internal data class DrmCredentialErrorPayload(
    val source: String = "",
    val message: String = "",
)
