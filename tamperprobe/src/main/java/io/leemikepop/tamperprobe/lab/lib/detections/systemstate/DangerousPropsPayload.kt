package io.leemikepop.tamperprobe.lab.lib.detections.systemstate

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import io.leemikepop.tamperprobe.lab.lib.detections.systemstate.shared.PropertyCollectionErrorPayload
import io.leemikepop.tamperprobe.lab.lib.detections.systemstate.shared.PropertySourcePayload
import kotlinx.serialization.Serializable

@Serializable
internal data class DangerousPropsPayload(
    val overview: DangerousPropsOverviewPayload = DangerousPropsOverviewPayload(),
    val observations: List<PropertySourcePayload> = emptyList(),
    val findings: List<DangerousPropertyFindingPayload> = emptyList(),
    val telemetry: List<DangerousPropertyTelemetryPayload> = emptyList(),
    val collectionErrors: List<PropertyCollectionErrorPayload> = emptyList(),
    val collectionWarnings: List<DangerousPropsCollectionWarningPayload> = emptyList(),
) : DetectionPayload

/**
 * A read that completed but did not answer. The one producer is the Settings.Global adb_enabled
 * read on API 37+: state `redacted_by_platform`, because Android 17 QPR1 returns 0 for it to
 * every third-party app. It carries property=adb_enabled, so it routes to environment-posture.
 */
@Serializable
internal data class DangerousPropsCollectionWarningPayload(
    val source: String = "",
    val property: String = "",
    val state: String = "",
    val apiLevel: Int = 0,
    val detail: String = "",
)

@Serializable
internal data class DangerousPropsOverviewPayload(
    val checkedRuleCount: Int = 0,
    val availableRuleCount: Int = 0,
    val findingCount: Int = 0,
    val telemetryCount: Int = 0,
    val weakFindingCount: Int = 0,
    val moderateFindingCount: Int = 0,
)

@Serializable
internal data class DangerousPropertyFindingPayload(
    val id: String = "",
    val property: String = "",
    val expected: String = "",
    val actual: String = "",
    val comparison: String = "",
    val strength: String = "",
    val summary: String = "",
    val detail: String = "",
)

@Serializable
internal data class DangerousPropertyTelemetryPayload(
    val id: String = "",
    val classification: String = "device_posture",
    val assessmentImpact: String = "telemetry_only",
    val summary: String = "",
    val detail: String = "",
    val properties: List<String> = emptyList(),
    val values: List<String> = emptyList(),
)
