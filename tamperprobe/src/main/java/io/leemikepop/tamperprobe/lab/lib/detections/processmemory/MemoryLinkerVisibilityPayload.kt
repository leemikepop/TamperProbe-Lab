package io.leemikepop.tamperprobe.lab.lib.detections.processmemory

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class MemoryLinkerVisibilityPayload(
    val linkerOnlyModules: List<MemoryLinkerModulePayload> = emptyList(),
    val mapsOnlyModules: List<MemoryLinkerModulePayload> = emptyList(),
    val gotPltEscapes: List<GotPltEscapePayload> = emptyList(),
    val collectionErrors: List<MemoryCollectionErrorPayload> = emptyList(),
    val mapsReadable: Boolean = false,
    val scannedMappings: Int = 0,
    val malformedMapLines: Int = 0,
    val linkerObjectCount: Int = 0,
    val findingCount: Int = 0,
) : DetectionPayload

@Serializable
internal data class MemoryLinkerModulePayload(
    val path: String = "",
    val loadRangeCount: Int? = null,
    val assessmentImpact: String = "",
)

@Serializable
internal data class GotPltEscapePayload(
    val symbol: String = "",
    val address: Long = 0,
    val resolvedPath: String = "",
    val expectedLibrary: String = "",
    val assessmentImpact: String = "strong",
)
