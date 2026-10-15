package io.leemikepop.tamperprobe.lab.lib.detections.systemstate

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class EmulatorSystemProfilePayload(
    val overview: EmulatorProfileOverviewPayload = EmulatorProfileOverviewPayload(),
    val properties: List<EmulatorPropertyEntryPayload> = emptyList(),
    val buildFingerprint: String = "",
    val fingerprintMatched: Boolean = false,
    val findings: List<EmulatorProfileFindingPayload> = emptyList(),
    val collectionErrors: List<EmulatorProfileCollectionErrorPayload> = emptyList(),
) : DetectionPayload

@Serializable
internal data class EmulatorProfileOverviewPayload(
    val checkedPropertyCount: Int = 0,
    val matchedPropertyCount: Int = 0,
    val findingCount: Int = 0,
    val strongFindingCount: Int = 0,
    val moderateFindingCount: Int = 0,
    val weakFindingCount: Int = 0,
)

@Serializable
internal data class EmulatorPropertyEntryPayload(
    val property: String = "",
    val value: String = "",
    val matched: Boolean = false,
    val severity: String = "",
)

@Serializable
internal data class EmulatorProfileFindingPayload(
    val id: String = "",
    val unitId: String = "",
    val property: String = "",
    val value: String = "",
    val strength: String = "",
    val summary: String = "",
    val detail: String = "",
)

@Serializable
internal data class EmulatorProfileCollectionErrorPayload(
    val source: String = "",
    val property: String = "",
    val errno: Int = 0,
    val message: String = "",
)
