package io.leemikepop.tamperprobe.lab.presentation.model

import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus

data class EvidenceDomainTagUiModel(
    val id: String,
    val title: String,
    val shortTitle: String,
    val isPrimary: Boolean,
)

data class DetectionCardUiModel(
    val id: String,
    val title: String,
    val description: String,
    val primaryEvidenceDomainId: String,
    val evidenceDomainTags: List<EvidenceDomainTagUiModel>,
    val outcome: DetectionOutcome,
    val evidenceStrength: EvidenceStrength,
    val detail: DetectionDetailUiModel,
)

data class DetectionDetailUiModel(
    val id: String,
    val title: String,
    val description: String,
    val outcome: DetectionOutcome,
    val evidenceStrength: EvidenceStrength,
    val payloadSchemaVersion: Int,
    val primaryEvidenceDomainTitle: String,
    val evidenceDomainTags: List<EvidenceDomainTagUiModel>,
    val collectionError: DetectorCollectionErrorUiModel?,
    val units: List<EvidenceUnitDetailUiModel>,
) {
    val signalCount: Int get() = units.sumOf { it.signals.size }
    val observationCount: Int get() = units.sumOf { it.observations.size }
    val researchCount: Int get() = units.sumOf { it.researchRecords.size }
    val issueCount: Int get() = units.sumOf { it.issues.size } + if (collectionError == null) 0 else 1
}

data class DetectorCollectionErrorUiModel(
    val code: String,
    val message: String,
    val recoverable: Boolean,
)

data class EvidenceUnitDetailUiModel(
    val id: String,
    val title: String,
    val domainId: String,
    val domainTitle: String,
    val domainShortTitle: String,
    val collectionStatus: EvidenceUnitCollectionStatus,
    val observedObject: String,
    val proposition: String,
    val observationChannel: String,
    val availability: String,
    val trustBoundary: String,
    val inferenceLimit: String,
    val signals: List<EvidenceRecordDetailUiModel>,
    val observations: List<EvidenceRecordDetailUiModel>,
    val researchRecords: List<EvidenceRecordDetailUiModel>,
    val issues: List<EvidenceIssueDetailUiModel>,
    val initiallyExpanded: Boolean,
)

data class EvidenceRecordDetailUiModel(
    val code: String,
    val kind: EvidenceRecordKind,
    val summary: String,
    val signalStrength: EvidenceStrength?,
    val attributes: List<DetailValueUiModel>,
    val attributeTree: List<AttributeNodeUiModel> = emptyList(),
) {
    /** A `.concealable-negative` record is an absence that a hiding tool can also produce. */
    val isConcealableNegative: Boolean get() = code.endsWith(CONCEALABLE_NEGATIVE_SUFFIX)

    companion object {
        const val CONCEALABLE_NEGATIVE_SUFFIX = ".concealable-negative"
    }
}

data class EvidenceIssueDetailUiModel(
    val code: String,
    val message: String,
    val attributes: List<DetailValueUiModel>,
    val attributeTree: List<AttributeNodeUiModel> = emptyList(),
)

data class DetailValueUiModel(
    val label: String,
    val value: String,
    val isMonospace: Boolean = false,
)

/**
 * Attributes regrouped by their dotted key path for display. Every attribute value appears in
 * exactly one [Field], either directly or inside a [ValueList]; nothing is dropped.
 */
sealed interface AttributeNodeUiModel {
    /** A single `key -> value` attribute. [value] is the raw value (possibly blank). */
    data class Field(
        val label: String,
        val value: String,
        val isMonospace: Boolean,
    ) : AttributeNodeUiModel

    /** An indexed list of plain values (`x.0`, `x.1`, ...), shown as one row. */
    data class ValueList(
        val label: String,
        val values: List<Field>,
    ) : AttributeNodeUiModel

    /** A nested object (`a.b.*`), an indexed list of objects, or one item of such a list. */
    data class Group(
        val title: String,
        val kind: GroupKind,
        val children: List<AttributeNodeUiModel>,
    ) : AttributeNodeUiModel

    enum class GroupKind { SECTION, LIST, LIST_ITEM }
}
