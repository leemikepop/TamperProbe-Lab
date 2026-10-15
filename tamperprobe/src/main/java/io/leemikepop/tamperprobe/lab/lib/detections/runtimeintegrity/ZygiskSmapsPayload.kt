package io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class ZygiskSmapsPayload(
    val dirtyMappings: List<DirtyMappingPayload> = emptyList(),
    val hitCount: Int = 0,
    val systemLibraryDirt: List<LibraryDirtPayload> = emptyList(),
    val dirtySystemLibraryCount: Int = 0,
    val singlePageDirtyRegionCount: Int = 0,
    val heapAllocatedBytes: Long = 0,
    val heapFreeKeptBytes: Long = 0,
    val heapFreeRatio: Double = 0.0,
    val heapEntropyAnomaly: Boolean = false,
    val dirtyMappingImpact: String = "telemetry_only",
    val singlePageDirtyImpact: String = "moderate",
    val heapEntropyImpact: String = "telemetry_only",
    val collectionError: String? = null,
) : DetectionPayload

@Serializable
internal data class DirtyMappingPayload(
    val path: String = "",
    val privateDirtyKB: Long = 0,
    val sharedDirtyKB: Long = 0,
)

@Serializable
internal data class LibraryDirtPayload(
    val path: String = "",
    val executableRegionCount: Int = 0,
    val dirtyRegionCount: Int = 0,
    val singlePageDirtyRegionCount: Int = 0,
    val privateDirtyKB: Long = 0,
    val sharedDirtyKB: Long = 0,
    val largestDirtyRegionKB: Long = 0,
)
