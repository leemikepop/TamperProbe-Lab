package io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class PrologueScannerPayload(
    val targetLibraries: List<String> = emptyList(),
    val checkedLibraries: List<String> = emptyList(),
    val unavailableLibraries: List<String> = emptyList(),
    val comparisonMethod: String = "",
    val entryPatternPolicy: String = "",
    val entryPatternArchitecture: String = "",
    val patternObservationCount: Int = 0,
    val branchLikeFunctionCount: Int = 0,
    val trampolineFunctionCount: Int = 0,
    val checks: List<PrologueCheckPayload> = emptyList(),
    /** The entry-pattern unit's own view: per-function pattern bytes, diagnostic only. */
    val patterns: List<ProloguePatternPayload> = emptyList(),
    val checkedFunctions: List<String> = emptyList(),
    val triggeredFunctions: List<String> = emptyList(),
    val unavailableFunctions: List<String> = emptyList(),
) : DetectionPayload

@Serializable
internal data class PrologueCheckPayload(
    val targetLibrary: String = "",
    val expectedLibraries: List<String> = emptyList(),
    val function: String = "",
    val status: String = "",
    val reason: String = "",
    val resolvedPath: String = "",
    val backingFileOffset: Long = 0,
    val patternArchitecture: String = "",
    val patternSupported: Boolean = false,
    val patternAvailable: Boolean = false,
    val branchLike: Boolean = false,
    val expectedPrologue: Boolean = false,
    val trampolineLike: Boolean = false,
    val suspiciousJump: Boolean = false,
    val entryPattern: String = "",
    val entryBytesHex: String = "",
    val patternAssessmentImpact: String = "",
)

@Serializable
internal data class ProloguePatternPayload(
    val targetLibrary: String = "",
    val function: String = "",
    val patternArchitecture: String = "",
    val patternSupported: Boolean = false,
    val patternAvailable: Boolean = false,
    val branchLike: Boolean = false,
    val expectedPrologue: Boolean = false,
    val trampolineLike: Boolean = false,
    val suspiciousJump: Boolean = false,
    val entryPattern: String = "",
    val entryBytesHex: String = "",
    val patternAssessmentImpact: String = "",
)
