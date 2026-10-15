package io.leemikepop.tamperprobe.lab.presentation.components.details

import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.presentation.model.DetailValueUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.DetectionDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceDomainTagUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceIssueDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceRecordDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceUnitDetailUiModel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DetectorDetailContentTest {
    @Test
    fun recordGroupTitlesUseBilingualContractTerms() {
        assertEquals("判定依據 Signal (2)", recordGroupTitle(EvidenceRecordKind.SIGNAL, 2))
        assertEquals("觀察內容 Observation (1)", recordGroupTitle(EvidenceRecordKind.OBSERVATION, 1))
        assertEquals("研究資料 Research (3)", recordGroupTitle(EvidenceRecordKind.RESEARCH, 3))
    }

    @Test
    fun detectorAndUnitSummariesOnlyIncludePublishedContent() {
        val unit = unit()
        val detail = DetectionDetailUiModel(
            id = "TEST",
            title = "Test",
            description = "Description",
            outcome = DetectionOutcome.OBSERVED,
            evidenceStrength = EvidenceStrength.MODERATE,
            payloadSchemaVersion = 1,
            primaryEvidenceDomainTitle = "Runtime Integrity",
            evidenceDomainTags = listOf(
                EvidenceDomainTagUiModel(
                    "runtime-integrity",
                    "Runtime Integrity",
                    "Runtime",
                    true,
                ),
            ),
            collectionError = null,
            units = listOf(unit),
        )

        assertEquals("1 Unit · 1 Signal · 1 Observation · 1 Research record · 1 Issue", detailSummaryText(detail))
        assertEquals("1 Signal · 1 Observation · 1 Research record · 1 Issue", unitSummaryText(unit))
    }

    @Test
    fun copyActionIsLimitedToLongOrTechnicalValues() {
        assertFalse(shouldOfferCopy(DetailValueUiModel("Value", "Short value")))
        assertTrue(shouldOfferCopy(DetailValueUiModel("Path", "/system/bin/su", isMonospace = true)))
        assertTrue(shouldOfferCopy(DetailValueUiModel("Text", "a\nb")))
        assertTrue(shouldOfferCopy(DetailValueUiModel("Text", "x".repeat(81))))
    }

    private fun unit(): EvidenceUnitDetailUiModel = EvidenceUnitDetailUiModel(
        id = "test.unit",
        title = "Test Unit",
        domainId = "runtime-integrity",
        domainTitle = "Runtime Integrity",
        domainShortTitle = "Runtime",
        collectionStatus = EvidenceUnitCollectionStatus.PARTIAL,
        observedObject = "Object",
        proposition = "Proposition",
        observationChannel = "Channel",
        availability = "Availability",
        trustBoundary = "Boundary",
        inferenceLimit = "Limit",
        signals = listOf(record(EvidenceRecordKind.SIGNAL, EvidenceStrength.MODERATE)),
        observations = listOf(record(EvidenceRecordKind.OBSERVATION)),
        researchRecords = listOf(record(EvidenceRecordKind.RESEARCH)),
        issues = listOf(EvidenceIssueDetailUiModel("TEST.issue", "Partial view", emptyList())),
        initiallyExpanded = true,
    )

    private fun record(
        kind: EvidenceRecordKind,
        strength: EvidenceStrength? = null,
    ): EvidenceRecordDetailUiModel = EvidenceRecordDetailUiModel(
        code = "TEST.unit.${kind.name.lowercase()}",
        kind = kind,
        summary = kind.name,
        signalStrength = strength,
        attributes = emptyList(),
    )
}
