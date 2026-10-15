package io.leemikepop.tamperprobe.lab.lib.detections.kernelinterface

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class NativeRootSepolicyPayload(
    val overview: PolicyOracleOverviewPayload = PolicyOracleOverviewPayload(),
    val carrier: PolicyOracleCarrierPayload = PolicyOracleCarrierPayload(),
    val device: PolicyOracleDevicePayload = PolicyOracleDevicePayload(),
    val trust: PolicyOracleTrustPayload = PolicyOracleTrustPayload(),
    val enforcementSources: List<PolicyOracleEnforcementPayload> = emptyList(),
    val querySources: List<PolicyOracleQuerySourcePayload> = emptyList(),
    val controls: List<PolicyOracleControlPayload> = emptyList(),
    val rules: List<PolicyOracleRulePayload> = emptyList(),
    val findings: List<PolicyOracleFindingPayload> = emptyList(),
    val concealableNegatives: List<PolicyOracleConcealableNegativePayload> = emptyList(),
    val collectionErrors: List<PolicyOracleCollectionErrorPayload> = emptyList(),
) : DetectionPayload
