package io.leemikepop.tamperprobe.lab.api

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ReferenceTamperScorerTest {
    @Test
    fun defaultPolicyScoresObservedAndEveryInconclusiveWithoutMutatingReport() {
        val results = listOf(
            result("weak", DetectionOutcome.OBSERVED, EvidenceStrength.WEAK),
            result("moderate", DetectionOutcome.OBSERVED, EvidenceStrength.MODERATE),
            result("strong", DetectionOutcome.OBSERVED, EvidenceStrength.STRONG),
            result("unknown-1", DetectionOutcome.INCONCLUSIVE, EvidenceStrength.NONE),
            result("unknown-2", DetectionOutcome.INCONCLUSIVE, EvidenceStrength.NONE),
            result("clean", DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE),
            result(
                "failed",
                DetectionOutcome.FAILED,
                EvidenceStrength.NONE,
                CollectionError("COLLECTION_FAILED", "unavailable", true),
            ),
        )
        val report = report(results)

        val decision = ReferenceTamperScorer.score(report)

        assertEquals(9, decision.score)
        assertEquals(4, decision.threshold)
        assertTrue(decision.thresholdReached)
        assertEquals(listOf("weak", "moderate", "strong"), decision.observedDetectorIds)
        assertEquals(listOf("unknown-1", "unknown-2"), decision.inconclusiveDetectorIds)
        assertEquals(listOf("failed"), decision.failedDetectorIds)
        assertEquals(results, report.results)
        assertEquals(EvidenceStrength.NONE, report.results[3].strength)
    }

    @Test
    fun customPolicyCanRaiseThresholdAndChangeWeights() {
        val policy = ReferenceTamperScoringPolicy(
            weakWeight = 0,
            moderateWeight = 1,
            strongWeight = 2,
            inconclusiveWeight = 0,
            threshold = 3,
        )

        val decision = ReferenceTamperScorer.score(
            report(listOf(result("strong", DetectionOutcome.OBSERVED, EvidenceStrength.STRONG))),
            policy,
        )

        assertEquals(2, decision.score)
        assertFalse(decision.thresholdReached)
    }

    @Test
    fun policyRejectsNegativeWeightsAndNonPositiveThreshold() {
        assertThrows(IllegalArgumentException::class.java) {
            ReferenceTamperScoringPolicy(weakWeight = -1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ReferenceTamperScoringPolicy(threshold = 0)
        }
    }

    private fun report(results: List<DetectorResult>) = TamperProbeReport(
        wireSchemaVersion = 1,
        engineVersion = "test",
        catalogVersion = "test",
        completion = ScanCompletion.COMPLETE,
        durationMillis = 1,
        results = results,
    )

    private fun result(
        id: String,
        outcome: DetectionOutcome,
        strength: EvidenceStrength,
        error: CollectionError? = null,
    ): DetectorResult {
        val unit = EvidenceUnitDescriptor(
            id = "$id.unit",
            title = id,
            domainId = "binary-artifact",
            observedObject = id,
            proposition = id,
            observationChannel = id,
            availability = id,
            trustBoundary = id,
            inferenceLimit = id,
        )
        val descriptor = DetectorDescriptor(
            id = id,
            name = id,
            description = id,
            primaryEvidenceDomainId = "binary-artifact",
            payloadSchemaVersion = 1,
            evidenceUnits = listOf(unit),
        )
        val unitResults = when (outcome) {
            DetectionOutcome.FAILED -> emptyList()
            DetectionOutcome.INCONCLUSIVE -> listOf(
                EvidenceUnitResult(
                    unit,
                    EvidenceUnitCollectionStatus.UNAVAILABLE,
                    emptyList(),
                    listOf(EvidenceIssue("$id.unit.unavailable", "unavailable")),
                ),
            )
            DetectionOutcome.OBSERVED -> listOf(
                EvidenceUnitResult(
                    unit,
                    EvidenceUnitCollectionStatus.COMPLETE,
                    listOf(EvidenceRecord("$id.unit.signal", EvidenceRecordKind.SIGNAL, id, strength)),
                    emptyList(),
                ),
            )
            DetectionOutcome.NOT_OBSERVED -> listOf(
                EvidenceUnitResult(
                    unit,
                    EvidenceUnitCollectionStatus.COMPLETE,
                    listOf(EvidenceRecord("$id.unit.complete", EvidenceRecordKind.OBSERVATION, id)),
                    emptyList(),
                ),
            )
        }
        return DetectorResult(descriptor, outcome, strength, unitResults, error)
    }
}
