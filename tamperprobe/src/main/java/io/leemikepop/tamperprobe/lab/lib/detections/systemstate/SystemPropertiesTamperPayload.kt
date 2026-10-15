package io.leemikepop.tamperprobe.lab.lib.detections.systemstate

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import io.leemikepop.tamperprobe.lab.lib.detections.systemstate.shared.PropertyCollectionErrorPayload
import io.leemikepop.tamperprobe.lab.lib.detections.systemstate.shared.PropertySourcePayload
import kotlinx.serialization.Serializable

@Serializable
internal data class SystemPropertiesTamperPayload(
    val overview: SystemPropertiesOverviewPayload = SystemPropertiesOverviewPayload(),
    val sources: List<PropertySourcePayload> = emptyList(),
    val comparisons: List<PropertyComparisonPayload> = emptyList(),
    val areaSummary: PropertyAreaSummaryPayload = PropertyAreaSummaryPayload(),
    val propertyAreas: List<PropertyAreaPayload> = emptyList(),
    val findings: List<SystemPropertiesFindingPayload> = emptyList(),
    val collectionErrors: List<PropertyCollectionErrorPayload> = emptyList(),
) : DetectionPayload

@Serializable
internal data class PropertyAreaSummaryPayload(
    val discoveredAreaCount: Int = 0,
    val parsedAreaCount: Int = 0,
    val unreferencedHoleAreaCount: Int = 0,
    val reportedAreaCount: Int = 0,
)

@Serializable
internal data class SystemPropertiesOverviewPayload(
    val comparedPropertyCount: Int = 0,
    val mismatchCount: Int = 0,
    val unreferencedHoleCount: Int = 0,
    val strongestFinding: String = "",
)

@Serializable
internal data class PropertyComparisonPayload(
    val property: String = "",
    val availableSourceCount: Int = 0,
    val distinctValueCount: Int = 0,
    val comparable: Boolean = false,
    val mismatch: Boolean = false,
    val strength: String = "",
    val outlierSources: List<String> = emptyList(),
    val majorityValue: String = "",
    val sources: List<String> = emptyList(),
    val values: List<String> = emptyList(),
)

@Serializable
internal data class PropertyAreaPayload(
    val path: String = "",
    val context: String = "",
    val status: String = "unavailable",
    val magic: Long = 0,
    val version: Long = 0,
    val bytesUsed: Int = 0,
    val referencedBytes: Int = 0,
    val unreferencedBytes: Int = 0,
    val unreferencedRanges: List<PropertyAreaRangePayload> = emptyList(),
    val error: String? = null,
    val errno: Int? = null,
)

@Serializable
internal data class PropertyAreaRangePayload(
    val offset: Int = 0,
    val length: Int = 0,
)

@Serializable
internal data class SystemPropertiesFindingPayload(
    val id: String = "",
    val outlierSources: List<String> = emptyList(),
    val property: String = "",
    val strength: String = "",
    val summary: String = "",
    val detail: String = "",
    val sources: List<String> = emptyList(),
    val values: List<String> = emptyList(),
)
