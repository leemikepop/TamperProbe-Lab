package io.leemikepop.tamperprobe.lab.lib.detections.processmemory

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class MemoryFdPayload(
    val findings: List<MemoryFdFindingPayload> = emptyList(),
    val candidates: List<MemoryFdFindingPayload> = emptyList(),
    val collectionErrors: List<MemoryCollectionErrorPayload> = emptyList(),
    val mapsReadable: Boolean = false,
    val fdDirectoryReadable: Boolean = false,
    val scannedMappings: Int = 0,
    val scannedFds: Int = 0,
    val malformedMapLines: Int = 0,
    val findingCount: Int = 0,
    val candidateCount: Int = 0,
) : DetectionPayload

@Serializable
internal data class MemoryFdFindingPayload(
    val type: String = "",
    val source: String = "",
    val classification: String = "",
    val path: String? = null,
    val permissions: String? = null,
    val start: Long? = null,
    val end: Long? = null,
    val fd: String? = null,
    val target: String? = null,
)

@Serializable
internal data class MemoryCollectionErrorPayload(
    val source: String = "",
    val errno: Int = 0,
    val message: String = "",
)
