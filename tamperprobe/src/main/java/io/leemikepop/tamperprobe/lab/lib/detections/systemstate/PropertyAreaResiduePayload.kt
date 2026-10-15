package io.leemikepop.tamperprobe.lab.lib.detections.systemstate

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class PropertyAreaResiduePayload(
    val parsedAreaCount: Int = 0,
    val totalPropertiesInspected: Int = 0,
    val serialAnomalyCount: Int = 0,
    val trailingResidueCount: Int = 0,
    val readOnlyTrailingResidueCount: Int = 0,
    val writableTrailingResidueCount: Int = 0,
    val findings: List<PropertyAreaResidueFindingPayload> = emptyList(),
    val collectionErrors: List<PropertyAreaResidueErrorPayload> = emptyList(),
) : DetectionPayload

@Serializable
internal data class PropertyAreaResidueFindingPayload(
    val property: String = "",
    val unitId: String = "",
    val anomalyType: String = "",
    val strength: String = "",
    val areaContext: String = "",
    val serial: Long = 0L,
    val serialLength: Int = 0,
    val actualLength: Int = 0,
    val serialCounter: Long = 0L,
    val trailingBytesCount: Int = 0,
    val trailingSnippet: String = "",
    val detail: String = "",
)

@Serializable
internal data class PropertyAreaResidueErrorPayload(
    val path: String = "",
    val context: String = "",
    val status: String = "",
    val errno: Int = 0,
    val message: String = "",
)
