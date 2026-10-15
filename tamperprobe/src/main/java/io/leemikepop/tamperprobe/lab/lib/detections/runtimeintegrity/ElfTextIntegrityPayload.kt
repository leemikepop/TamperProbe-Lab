package io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity.shared.HookCollectionErrorPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class ElfTextIntegrityPayload(
    val targetLibraries: List<String> = emptyList(),
    val requiredLibraries: List<String> = emptyList(),
    val resolvedModules: List<ElfResolvedModulePayload> = emptyList(),
    val missingRequiredLibraries: List<String> = emptyList(),
    val missingOptionalLibraries: List<String> = emptyList(),
    val comparisonMethod: String = "",
    val checkedSegments: List<ElfSegmentPayload> = emptyList(),
    val modifiedSegments: List<ElfSegmentPayload> = emptyList(),
    val unavailableSegments: List<ElfSegmentPayload> = emptyList(),
    val collectionErrors: List<HookCollectionErrorPayload> = emptyList(),
    val mapsReadable: Boolean = false,
    val malformedMapLines: Int = 0,
    val checkedSegmentCount: Int = 0,
    val modifiedSegmentCount: Int = 0,
    val unavailableSegmentCount: Int = 0,
) : DetectionPayload

@Serializable
internal data class ElfResolvedModulePayload(
    val library: String = "",
    val path: String = "",
    val required: Boolean = false,
    val executableSegmentCount: Int = 0,
)

@Serializable
internal data class ElfSegmentPayload(
    val library: String = "",
    val path: String = "",
    val segmentIndex: Int = 0,
    val memoryStart: Long = 0,
    val fileOffset: Long = 0,
    val byteCount: Long = 0,
    val comparedBytes: Long = 0,
    val firstMismatchOffset: Long = 0,
    val reason: String = "",
)
