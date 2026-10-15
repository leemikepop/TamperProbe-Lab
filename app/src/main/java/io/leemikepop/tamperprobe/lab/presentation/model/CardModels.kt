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
)

data class EvidenceIssueDetailUiModel(
    val code: String,
    val message: String,
    val attributes: List<DetailValueUiModel>,
)

data class DetailValueUiModel(
    val label: String,
    val value: String,
    val isMonospace: Boolean = false,
)
