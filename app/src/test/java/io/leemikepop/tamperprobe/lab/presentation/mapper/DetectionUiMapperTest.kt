package io.leemikepop.tamperprobe.lab.presentation.mapper

import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.CollectionError
import io.leemikepop.tamperprobe.lab.api.DetectorDescriptor
import io.leemikepop.tamperprobe.lab.api.DetectorResult
import io.leemikepop.tamperprobe.lab.api.EvidenceDomainDescriptor
import io.leemikepop.tamperprobe.lab.api.EvidenceIssue
import io.leemikepop.tamperprobe.lab.api.EvidenceRecord
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitDescriptor
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DetectionUiMapperTest {
    private val domains = listOf(
        EvidenceDomainDescriptor("runtime-integrity", "Runtime Integrity", "Runtime", "Runtime state"),
        EvidenceDomainDescriptor("process-memory", "Process and Memory", "Process", "Process state"),
    )

    @Test
    fun nestedUnitReportsPreserveHierarchyKindsAndCollectionStatus() {
        val direct = unit("runtime.direct", "runtime-integrity")
        val research = unit("runtime.generic", "process-memory")
        val result = result(
            id = "RUNTIME_INSTRUMENTATION",
            primaryDomain = "runtime-integrity",
            units = listOf(direct, research),
            unitResults = listOf(
                EvidenceUnitResult(
                    direct,
                    EvidenceUnitCollectionStatus.COMPLETE,
                    listOf(
                        EvidenceRecord(
                            "RUNTIME_INSTRUMENTATION.direct.signal",
                            EvidenceRecordKind.SIGNAL,
                            "Direct marker",
                            EvidenceStrength.MODERATE,
                            mapOf("zValue" to "last", "path" to "/system/lib64/libc.so"),
                        ),
                    ),
                    emptyList(),
                ),
                EvidenceUnitResult(
                    research,
                    EvidenceUnitCollectionStatus.PARTIAL,
                    listOf(
                        EvidenceRecord(
                            "RUNTIME_INSTRUMENTATION.generic.snapshot",
                            EvidenceRecordKind.RESEARCH,
                            "Generic anomaly baseline",
                        ),
                    ),
                    listOf(
                        EvidenceIssue(
                            "RUNTIME_INSTRUMENTATION.generic.unavailable",
                            "Partial view",
                            mapOf("source" to "/proc/self/maps"),
                        ),
                    ),
                ),
            ),
        )

        val card = DetectionUiMapper.map(result, domains)
        val directUnit = card.detail.units.single { it.id == direct.id }
        val researchUnit = card.detail.units.single { it.id == research.id }

        assertEquals(listOf("runtime-integrity", "process-memory"), card.evidenceDomainTags.map { it.id })
        assertEquals(2, card.detail.units.size)
        assertEquals(EvidenceUnitCollectionStatus.COMPLETE, directUnit.collectionStatus)
        assertEquals(EvidenceUnitCollectionStatus.PARTIAL, researchUnit.collectionStatus)
        assertEquals(listOf("RUNTIME_INSTRUMENTATION.direct.signal"), directUnit.signals.map { it.code })
        assertEquals(emptyList<String>(), directUnit.observations.map { it.code })
        assertEquals(
            listOf("Path", "Z Value"),
            directUnit.signals.single().attributes.map { it.label },
        )
        assertEquals(
            listOf("RUNTIME_INSTRUMENTATION.generic.snapshot"),
            researchUnit.researchRecords.map { it.code },
        )
        assertEquals(1, researchUnit.issues.size)
        assertTrue(directUnit.initiallyExpanded)
        assertTrue(researchUnit.initiallyExpanded)
        assertEquals(1, card.detail.signalCount)
        assertEquals(1, card.detail.researchCount)
        assertEquals(1, card.detail.issueCount)
    }

    @Test
    fun neutralUnitExpansionPrefersSingleUnitButKeepsMultiUnitOverviewCompact() {
        val first = unit("neutral.first", "runtime-integrity")
        val second = unit("neutral.second", "runtime-integrity")
        fun neutralResult(units: List<EvidenceUnitDescriptor>) = result(
            id = "NEUTRAL",
            primaryDomain = "runtime-integrity",
            units = units,
            unitResults = units.map { descriptor ->
                EvidenceUnitResult(
                    descriptor,
                    EvidenceUnitCollectionStatus.COMPLETE,
                    listOf(
                        EvidenceRecord(
                            "NEUTRAL.${descriptor.id}.complete",
                            EvidenceRecordKind.OBSERVATION,
                            "Completed",
                        ),
                    ),
                    emptyList(),
                )
            },
            outcome = DetectionOutcome.NOT_OBSERVED,
            strength = EvidenceStrength.NONE,
        )

        assertTrue(DetectionUiMapper.map(neutralResult(listOf(first)), domains).detail.units.single().initiallyExpanded)
        assertTrue(
            DetectionUiMapper.map(neutralResult(listOf(first, second)), domains)
                .detail.units.none { it.initiallyExpanded },
        )
    }

    @Test
    fun failedDetectorKeepsCollectionErrorWithoutPublishingUnits() {
        val descriptorUnit = unit("failed.unit", "runtime-integrity")
        val descriptor = DetectorDescriptor(
            "FAILED_DETECTOR",
            "Failed Detector",
            "Description",
            "runtime-integrity",
            1,
            listOf(descriptorUnit),
        )
        val card = DetectionUiMapper.map(
            DetectorResult(
                descriptor = descriptor,
                outcome = DetectionOutcome.FAILED,
                strength = EvidenceStrength.NONE,
                unitResults = emptyList(),
                collectionError = CollectionError("COLLECTION_FAILED", "Source unavailable", true),
            ),
            domains,
        )

        assertTrue(card.detail.units.isEmpty())
        assertEquals("COLLECTION_FAILED", card.detail.collectionError?.code)
        assertEquals(1, card.detail.issueCount)
    }

    @Test
    fun domainFilterKeepsEachDetectorAtMostOnce() {
        val cards = (1..31).map { index ->
            val domain = if (index == 1) "process-memory" else "runtime-integrity"
            val descriptorUnit = unit("detector-$index.unit", domain)
            DetectionUiMapper.map(
                result(
                    "DETECTOR_$index",
                    domain,
                    listOf(descriptorUnit),
                    listOf(
                        EvidenceUnitResult(
                            descriptorUnit,
                            EvidenceUnitCollectionStatus.COMPLETE,
                            listOf(
                                EvidenceRecord(
                                    "DETECTOR_$index.unit.complete",
                                    EvidenceRecordKind.OBSERVATION,
                                    "Completed",
                                ),
                            ),
                            emptyList(),
                        ),
                    ),
                    DetectionOutcome.NOT_OBSERVED,
                    EvidenceStrength.NONE,
                ),
                domains,
            )
        }

        assertEquals(31, DetectionUiMapper.filterByEvidenceDomain(cards, null).distinctBy { it.id }.size)
        assertEquals(
            listOf("DETECTOR_1"),
            DetectionUiMapper.filterByEvidenceDomain(cards, "process-memory").map { it.id },
        )
    }

    private fun unit(id: String, domainId: String) = EvidenceUnitDescriptor(
        id = id,
        title = id,
        domainId = domainId,
        observedObject = "object",
        proposition = "proposition",
        observationChannel = "channel",
        availability = "available",
        trustBoundary = "boundary",
        inferenceLimit = "limit",
    )

    private fun result(
        id: String,
        primaryDomain: String,
        units: List<EvidenceUnitDescriptor>,
        unitResults: List<EvidenceUnitResult>,
        outcome: DetectionOutcome = DetectionOutcome.OBSERVED,
        strength: EvidenceStrength = EvidenceStrength.MODERATE,
    ) = DetectorResult(
        descriptor = DetectorDescriptor(
            id,
            id,
            id,
            primaryDomain,
            1,
            units,
        ),
        outcome = outcome,
        strength = strength,
        unitResults = unitResults,
    )
}
