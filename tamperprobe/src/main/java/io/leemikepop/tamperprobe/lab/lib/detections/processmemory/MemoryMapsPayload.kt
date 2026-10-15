package io.leemikepop.tamperprobe.lab.lib.detections.processmemory

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class MemoryMapsPayload(
    val findings: List<MemoryMapFindingPayload> = emptyList(),
    val collectionErrors: List<MemoryCollectionErrorPayload> = emptyList(),
    val mapsReadable: Boolean = false,
    val scannedMappings: Int = 0,
    val malformedMapLines: Int = 0,
    val findingCount: Int = 0,
    val assessmentBearingFindingCount: Int = 0,
    val smapsReadable: Boolean = false,
) : DetectionPayload

@Serializable
internal data class MemoryMapFindingPayload(
    val type: String = "",
    val path: String = "",
    val permissions: String = "",
    val start: Long = 0,
    val end: Long = 0,
    val assessmentImpact: String = "",
    val signum: Int? = null,
    val signalName: String? = null,
    val handlerAddress: Long? = null,
    val privateDirtyKB: Long? = null,
    val sharedDirtyKB: Long? = null,
)
