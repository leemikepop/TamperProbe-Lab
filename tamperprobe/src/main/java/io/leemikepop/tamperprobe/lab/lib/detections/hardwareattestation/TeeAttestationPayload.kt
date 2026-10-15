package io.leemikepop.tamperprobe.lab.lib.detections.hardwareattestation

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class TeeAttestationPayload(
    val attestation: AttestationPayload = AttestationPayload(),
    val findings: List<TeeAttestationFindingPayload> = emptyList(),
    val collectionWarnings: List<TeeCollectionWarningPayload> = emptyList(),
    val collectionError: String? = null,
) : DetectionPayload

@Serializable
internal data class AttestationPayload(
    val certificateAvailable: Boolean = false,
    val certificateChainLength: Int = 0,
    val chain: AttestationChainPayload = AttestationChainPayload(),
    val challenge: AttestationChallengePayload = AttestationChallengePayload(),
    val versions: AttestationVersionsPayload = AttestationVersionsPayload(),
    val hasAttestationExtension: Boolean = false,
    val rootOfTrust: RootOfTrustPayload = RootOfTrustPayload(),
    val bootConsistency: BootConsistencyPayload = BootConsistencyPayload(),
    val revocation: RevocationPayload = RevocationPayload(),
)

@Serializable
internal data class AttestationChainPayload(
    val signaturesChecked: Int = 0,
    val signaturesValid: Boolean = false,
    val trustedRootState: String = "unavailable",
    val trustedRootCount: Int = 0,
    val attestationCertificateIndex: Int = -1,
    val attestationExtensionCount: Int = 0,
    val rkpProvisioningExtensionPresent: Boolean = false,
    val rkpProvisioningCertificateIndex: Int = -1,
    val provisioningExpiryState: String = "not_applicable",
    val certificateValidity: List<CertificateValidityPayload> = emptyList(),
)

@Serializable
internal data class CertificateValidityPayload(
    val index: Int = -1,
    val state: String = "unknown",
)

@Serializable
internal data class AttestationChallengePayload(
    val expectedLength: Int = 0,
    val present: Boolean = false,
    val matches: Boolean = false,
)

@Serializable
internal data class AttestationVersionsPayload(
    val attestationVersion: Int = 0,
    val keymasterVersion: Int = 0,
    val attestationSecurityLevel: String = "Unknown",
    val attestationSecurityLevelCode: Int = -1,
    val keymasterSecurityLevel: String = "Unknown",
    val keymasterSecurityLevelCode: Int = -1,
)

@Serializable
internal data class RootOfTrustPayload(
    val parseOk: Boolean = false,
    val deviceLocked: Boolean = false,
    val verifiedBootState: String = "Unknown",
    val verifiedBootStateCode: Int = -1,
    val verifiedBootKeyHex: String = "",
    val verifiedBootHashHex: String = "",
)

@Serializable
internal data class BootConsistencyPayload(
    val runtimeDigestAvailable: Boolean = false,
    val runtimeDigestHex: String = "",
    val attestedDigestHex: String = "",
    val comparable: Boolean = false,
    val matches: Boolean = false,
    val zeroBootKey: Boolean = false,
    val zeroBootHash: Boolean = false,
)

@Serializable
internal data class RevocationPayload(
    val statusJsonLoaded: Boolean = false,
    val validationState: String = "unavailable",
    val revoked: Boolean = false,
    val suspended: Boolean = false,
    val expiredEntryCount: Int = 0,
    val hits: List<RevocationHitPayload> = emptyList(),
)

@Serializable
internal data class RevocationHitPayload(
    val source: String = "",
    val index: Int = -1,
    val status: String = "UNKNOWN",
    val reason: String = "UNKNOWN",
)

@Serializable
internal data class TeeAttestationFindingPayload(
    val id: String = "",
    val summary: String = "",
    val detail: String = "",
    val strength: String = "",
)

@Serializable
internal data class TeeCollectionWarningPayload(
    val source: String = "",
    val state: String = "",
    val detail: String = "",
)
