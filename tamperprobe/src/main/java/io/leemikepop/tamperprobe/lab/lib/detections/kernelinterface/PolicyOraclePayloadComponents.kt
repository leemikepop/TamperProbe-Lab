package io.leemikepop.tamperprobe.lab.lib.detections.kernelinterface

import kotlinx.serialization.Serializable

@Serializable
internal data class PolicyOracleOverviewPayload(
    val oracleState: String = "inconclusive",
    val gateCount: Int = 0,
    val passedGateCount: Int = 0,
    val ruleCount: Int = 0,
    val findingCount: Int = 0,
    val trustedNegativeCount: Int = 0,
    val concealableNegativeCount: Int = 0,
)

@Serializable
internal data class PolicyOracleCarrierPayload(
    val state: String = "unavailable",
    val context: String = "",
    val domain: String = "",
    val uid: Int = -1,
    val applicationUid: Int = -1,
    val uidMatches: Boolean = false,
)

@Serializable
internal data class PolicyOracleDevicePayload(
    val buildType: String = "",
)

@Serializable
internal data class PolicyOracleTrustPayload(
    val nativeTrusted: Boolean = false,
    val javaControlled: Boolean = false,
    val contradiction: Boolean = false,
)

@Serializable
internal data class PolicyOracleEnforcementPayload(
    val source: String = "",
    val state: String = "unavailable",
    val enabled: Boolean? = null,
    val mode: String = "unknown",
)

@Serializable
internal data class PolicyOracleQuerySourcePayload(
    val source: String = "",
    val state: String = "unavailable",
    val required: Boolean = false,
)

@Serializable
internal data class PolicyOracleControlPayload(
    val id: String = "",
    val sourceContext: String = "",
    val targetContext: String = "",
    val targetClass: String = "",
    val permission: String = "",
    val expected: String = "",
    val contextsValid: Boolean = false,
    val nativeAvailable: Boolean = false,
    val nativeDecisions: List<String> = emptyList(),
    val javaAvailable: Boolean = false,
    val javaDecisions: List<String> = emptyList(),
    val nativeStable: Boolean = false,
    val javaStable: Boolean = false,
    val stable: Boolean = false,
    val sourcesAgree: Boolean = false,
    val contradiction: Boolean = false,
    val observationAvailable: Boolean = false,
    val decision: String = "unavailable",
    val trustedTier: String = "untrusted",
    val nativePassed: Boolean = false,
    val javaPassed: Boolean = false,
)

@Serializable
internal data class PolicyOracleRulePayload(
    val id: String = "",
    val sourceContext: String = "",
    val targetContext: String = "",
    val targetClass: String = "",
    val permission: String = "",
    val sourceContextState: String = "unavailable",
    val targetContextState: String = "unavailable",
    val nativeAvailable: Boolean = false,
    val nativeDecisions: List<String> = emptyList(),
    val javaAvailable: Boolean = false,
    val javaDecisions: List<String> = emptyList(),
    val nativeStable: Boolean = false,
    val javaStable: Boolean = false,
    val stable: Boolean = false,
    val sourcesAgree: Boolean = false,
    val contradiction: Boolean = false,
    val observationAvailable: Boolean = false,
    val decision: String = "unavailable",
    val trustedTier: String = "untrusted",
    val assessmentImpact: String = "diagnostic_only",
)

@Serializable
internal data class PolicyOracleFindingPayload(
    val id: String = "",
    val ruleId: String = "",
    val strength: String = "",
    val trustTier: String = "untrusted",
    val summary: String = "",
    val detail: String = "",
)

/**
 * A required rule whose target type the loaded policy does not define. It supports a
 * NOT_OBSERVED, but hiding tools can manufacture the absence, so it is never a trusted answer.
 */
@Serializable
internal data class PolicyOracleConcealableNegativePayload(
    val ruleId: String = "",
    val targetContext: String = "",
    val targetContextState: String = "absent",
    val concealable: Boolean = true,
    val trustedTier: String = "untrusted",
)

@Serializable
internal data class PolicyOracleCollectionErrorPayload(
    val source: String = "",
    val errno: Int = 0,
    val message: String = "",
)
