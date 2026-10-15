package io.leemikepop.tamperprobe.lab.lib.detections.systemstate

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class EmulatorHardwareIndicatorsPayload(
    val overview: EmulatorHardwareOverviewPayload = EmulatorHardwareOverviewPayload(),
    val egl: EmulatorEglPayload = EmulatorEglPayload(),
    val timer: EmulatorTimerPayload = EmulatorTimerPayload(),
    val schedJitter: EmulatorSchedJitterPayload = EmulatorSchedJitterPayload(),
    val findings: List<EmulatorHardwareFindingPayload> = emptyList(),
    val collectionErrors: List<EmulatorHardwareCollectionErrorPayload> = emptyList(),
) : DetectionPayload

@Serializable
internal data class EmulatorHardwareOverviewPayload(
    val findingCount: Int = 0,
    val strongFindingCount: Int = 0,
    val moderateFindingCount: Int = 0,
    val weakFindingCount: Int = 0,
)

@Serializable
internal data class EmulatorEglPayload(
    val available: Boolean = false,
    val renderer: String = "",
    val vendor: String = "",
    val version: String = "",
    val isEmulator: Boolean = false,
    val matchedMarker: String = "",
)

@Serializable
internal data class EmulatorTimerPayload(
    val supported: Boolean = false,
    val frequencyHz: Long = 0L,
    val counterDelta: Long = 0L,
    val counterNs: Long = 0L,
    val wallDeltaNs: Long = 0L,
    val driftNs: Long = 0L,
    val isAnomalous: Boolean = false,
    val detail: String = "",
)

@Serializable
internal data class EmulatorSchedJitterPayload(
    val sampleCount: Int = 0,
    val meanNs: Double = 0.0,
    val stdDevNs: Double = 0.0,
    val cv: Double = 0.0,
    val uniqueMicrosecondBuckets: Int = 0,
    val isAnomalous: Boolean = false,
    val detail: String = "",
)

@Serializable
internal data class EmulatorHardwareFindingPayload(
    val id: String = "",
    val unitId: String = "",
    val strength: String = "",
    val summary: String = "",
    val detail: String = "",
)

@Serializable
internal data class EmulatorHardwareCollectionErrorPayload(
    val source: String = "",
    val message: String = "",
)
