package io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity.shared.HookCollectionErrorPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class RuntimeInstrumentationPayload(
    val directMarkers: List<RuntimeObservationPayload> = emptyList(),
    val genericAnomalies: List<RuntimeObservationPayload> = emptyList(),
    val collectionErrors: List<HookCollectionErrorPayload> = emptyList(),
    val mapsReadable: Boolean = false,
    val fdDirectoryReadable: Boolean = false,
    val taskDirectoryReadable: Boolean = false,
    val scannedMappings: Int = 0,
    val scannedFds: Int = 0,
    val scannedThreads: Int = 0,
    val malformedMapLines: Int = 0,
    val linkerObjectCount: Int = 0,
    val directMarkerCount: Int = 0,
    val genericAnomalyCount: Int = 0,
) : DetectionPayload

@Serializable
internal data class RuntimeObservationPayload(
    val channel: String = "",
    val value: String = "",
    val classification: String = "",
    val marker: String? = null,
    val attribution: String? = null,
    val assessmentImpact: String = "",
)
