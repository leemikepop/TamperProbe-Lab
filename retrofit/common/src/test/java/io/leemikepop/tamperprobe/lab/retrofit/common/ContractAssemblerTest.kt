package io.leemikepop.tamperprobe.lab.retrofit.common

import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ContractAssemblerTest {
    private fun unit(id: String, concealment: String? = "hidden by a module") = UnitSpec(
        id = id,
        title = "t",
        observedObject = "o",
        proposition = "p",
        observationChannel = "c",
        availability = "a",
        trustBoundary = "b",
        inferenceLimit = "l",
        concealment = concealment,
        fallbackStrength = EvidenceStrength.WEAK,
    )

    private val spec = CheckSpec(
        detectorId = "UPSTREAM_CHECK",
        name = "n",
        description = "d",
        domainId = "binary-artifact",
        upstreamMethod = "check()",
        units = listOf(unit("upstream-check.channel")),
    )

    private fun evaluation(positive: Boolean, vararg probes: ProbeResult, findings: List<Finding> = emptyList()) =
        CheckEvaluation(
            spec = spec,
            upstreamVerdict = positive.toString(),
            upstreamPositive = positive,
            units = listOf(UnitEvaluation("upstream-check.channel", positive.toString(), positive, probes.toList(), findings)),
        )

    private fun absent(target: String) = ProbeResult(target, ProbeAnswer.ABSENT, "ENOENT")
    private fun noAnswer(target: String, reason: String = "EACCES") = ProbeResult(target, ProbeAnswer.NO_ANSWER, reason)

    @Test
    fun anUpstreamFalseFromAChannelThatNeverAnsweredIsInconclusive() {
        val result = ContractAssembler.assemble(evaluation(false, noAnswer("/a"), noAnswer("/b")))

        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
        val unit = result.unitResults.single()
        assertEquals(EvidenceUnitCollectionStatus.UNAVAILABLE, unit.collectionStatus)
        assertEquals("EACCES", unit.issues.single().attributes["reason"])
        assertEquals("/a,/b", unit.issues.single().attributes["targets"])
    }

    @Test
    fun anAnsweredNegativeFromAConcealableUnitIsMarkedConcealable() {
        val result = ContractAssembler.assemble(evaluation(false, absent("/a"), noAnswer("/b")))

        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
        val unit = result.unitResults.single()
        assertEquals(EvidenceUnitCollectionStatus.PARTIAL, unit.collectionStatus)
        val concealable = unit.records.single { it.code == "UPSTREAM_CHECK.channel.concealable-negative" }
        assertEquals("1", concealable.attributes["answeredCount"])
        val coverage = unit.records.single { it.code == "UPSTREAM_CHECK.channel.coverage" }
        assertEquals("2", coverage.attributes["attemptedCount"])
        assertEquals("1", coverage.attributes["noAnswerCount"])
    }

    @Test
    fun aNegativeFromAUnitWithoutAConcealmentDeclarationIsTrusted() {
        val trusted = spec.copy(units = listOf(unit("upstream-check.channel", concealment = null)))
        val result = ContractAssembler.assemble(evaluation(false, absent("/a")).copy(spec = trusted))

        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
        assertFalse(result.unitResults.single().records.any { it.code.endsWith("concealable-negative") })
    }

    @Test
    fun anUpstreamPositiveIsKeptEvenWhenTheShadowCouldNotAttributeIt() {
        val result = ContractAssembler.assemble(evaluation(true, noAnswer("/a")))

        assertEquals(DetectionOutcome.OBSERVED, result.outcome)
        assertEquals(EvidenceStrength.WEAK, result.strength)
        val signal = result.unitResults.single().records.single { it.kind == EvidenceRecordKind.SIGNAL }
        assertEquals("UPSTREAM_CHECK.channel.upstream-positive", signal.code)
    }

    @Test
    fun theStrongestFindingSetsTheStrength() {
        val result = ContractAssembler.assemble(
            evaluation(
                true,
                ProbeResult("/a", ProbeAnswer.PRESENT, "ok"),
                findings = listOf(
                    Finding("visible-path", "s", EvidenceStrength.WEAK),
                    Finding("executable-at-fixed-path", "s", EvidenceStrength.STRONG),
                ),
            ),
        )
        assertEquals(EvidenceStrength.STRONG, result.strength)
    }

    @Test
    fun aTargetOnlyTheShadowSawIsAnIssueNotAPositive() {
        val result = ContractAssembler.assemble(evaluation(false, ProbeResult("/a", ProbeAnswer.PRESENT, "ok")))

        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
        assertEquals(
            "shadow_present_upstream_absent",
            result.unitResults.single().issues.single().attributes["reason"],
        )
    }

    @Test
    fun anUpstreamExceptionFailsTheDetector() {
        val result = ContractAssembler.assemble(
            CheckEvaluation(spec, "threw", false, emptyList(), upstreamFailure = SecurityException("denied")),
        )
        assertEquals(DetectionOutcome.FAILED, result.outcome)
        assertTrue(result.collectionError!!.message.contains("SecurityException"))
    }

    @Test
    fun redactedUnitsListNoTargets() {
        val redacted = spec.copy(units = listOf(unit("upstream-check.channel").copy(redactTargets = true)))
        val result = ContractAssembler.assemble(evaluation(false, noAnswer("com.example.private")).copy(spec = redacted))
        assertFalse(result.unitResults.single().issues.single().attributes.containsKey("targets"))
    }
}
