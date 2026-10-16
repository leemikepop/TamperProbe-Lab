package io.leemikepop.tamperprobe.lab.retrofit.common

import io.leemikepop.tamperprobe.lab.api.CollectionError
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.DetectorDescriptor
import io.leemikepop.tamperprobe.lab.api.DetectorResult
import io.leemikepop.tamperprobe.lab.api.EvidenceIssue
import io.leemikepop.tamperprobe.lab.api.EvidenceRecord
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitDescriptor
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitResult

/**
 * Turns the evaluation of one upstream check into an Evidence Contract [DetectorResult].
 *
 * The rules, in order:
 * - the upstream method threw → `FAILED`;
 * - any unit's upstream verdict is a positive → `OBSERVED`; a positive is never dropped, even
 *   when the shadow probe could not attribute it;
 * - a target the shadow saw but the upstream check missed is not turned into a positive; it is
 *   reported as an issue (`shadow_present_upstream_absent`), because the retrofit changes only
 *   how results are reported, not what is detected;
 * - a unit with no answered target is `UNAVAILABLE` (Rule 1); when no unit answered the detector
 *   is `INCONCLUSIVE`, never `NOT_OBSERVED`;
 * - an answered negative from a unit with a concealment declaration is published with a
 *   `concealable-negative` record (Rule 3);
 * - every unit that answered lists how many targets it tried and how many answered (Rule 6).
 */
object ContractAssembler {
    const val PAYLOAD_SCHEMA_VERSION: Int = 1

    fun descriptor(spec: CheckSpec): DetectorDescriptor = DetectorDescriptor(
        id = spec.detectorId,
        name = spec.name,
        description = spec.description,
        primaryEvidenceDomainId = spec.domainId,
        payloadSchemaVersion = PAYLOAD_SCHEMA_VERSION,
        evidenceUnits = spec.units.map { it.descriptor(spec.domainId) },
    )

    fun assemble(evaluation: CheckEvaluation): DetectorResult {
        val spec = evaluation.spec
        val descriptor = descriptor(spec)
        evaluation.upstreamFailure?.let { failure ->
            return DetectorResult(
                descriptor = descriptor,
                outcome = DetectionOutcome.FAILED,
                strength = EvidenceStrength.NONE,
                unitResults = emptyList(),
                collectionError = CollectionError(
                    code = "upstream_exception",
                    message = "${spec.upstreamMethod} threw ${failure.javaClass.name}: ${failure.message}",
                    recoverable = false,
                ),
                durationMicros = evaluation.durationMicros,
            )
        }
        val evaluations = evaluation.units.associateBy { it.unitId }
        require(evaluations.keys == spec.units.map { it.id }.toSet()) {
            "${spec.detectorId}: evaluated units ${evaluations.keys} do not match declared units"
        }

        val positive = evaluation.units.any { it.upstreamPositive }
        val answeredAny = evaluation.units.any { unit -> unit.normalizedProbes().any { it.answer == ProbeAnswer.ABSENT } }
        val outcome = when {
            positive -> DetectionOutcome.OBSERVED
            answeredAny -> DetectionOutcome.NOT_OBSERVED
            else -> DetectionOutcome.INCONCLUSIVE
        }

        val unitResults = spec.units.map { unitSpec ->
            unitResult(spec, unitSpec, evaluations.getValue(unitSpec.id), descriptor, outcome)
        }
        val strength = if (outcome == DetectionOutcome.OBSERVED) {
            unitResults.flatMap { it.records }.mapNotNull { it.signalStrength }.maxBy { it.ordinal }
        } else {
            EvidenceStrength.NONE
        }
        return DetectorResult(
            descriptor = descriptor,
            outcome = outcome,
            strength = strength,
            unitResults = unitResults,
            durationMicros = evaluation.durationMicros,
        )
    }

    private fun unitResult(
        spec: CheckSpec,
        unitSpec: UnitSpec,
        unit: UnitEvaluation,
        detectorDescriptor: DetectorDescriptor,
        outcome: DetectionOutcome,
    ): EvidenceUnitResult {
        val unitDescriptor = detectorDescriptor.evidenceUnits.single { it.id == unitSpec.id }
        val codePrefix = "${spec.detectorId}.${unitSpec.id.substringAfter('.')}"
        val probes = unit.normalizedProbes()
        val present = probes.count { it.answer == ProbeAnswer.PRESENT }
        val absent = probes.count { it.answer == ProbeAnswer.ABSENT }
        val noAnswer = probes.filter { it.answer == ProbeAnswer.NO_ANSWER }
        val issues = noAnswerIssues(unitSpec, unit, noAnswer)

        if (!unit.upstreamPositive && absent == 0) {
            return EvidenceUnitResult(
                descriptor = unitDescriptor,
                collectionStatus = EvidenceUnitCollectionStatus.UNAVAILABLE,
                records = emptyList(),
                issues = issues.ifEmpty {
                    listOf(
                        EvidenceIssue(
                            code = "channel-no-answer",
                            message = "The channel had no target to answer for",
                            attributes = mapOf("reason" to "no_targets", "upstreamVerdict" to unit.upstreamVerdict),
                        ),
                    )
                },
            )
        }

        val records = buildList {
            add(
                EvidenceRecord(
                    code = "$codePrefix.upstream-verdict",
                    kind = EvidenceRecordKind.OBSERVATION,
                    summary = "Verdict of the unmodified upstream code for this channel",
                    attributes = linkedMapOf(
                        "upstreamMethod" to spec.upstreamMethod,
                        "upstreamVerdict" to unit.upstreamVerdict,
                        "upstreamPositive" to unit.upstreamPositive.toString(),
                    ),
                ),
            )
            add(
                EvidenceRecord(
                    code = "$codePrefix.coverage",
                    kind = EvidenceRecordKind.OBSERVATION,
                    summary = "Targets the channel was asked about and how many it answered",
                    attributes = linkedMapOf(
                        "attemptedCount" to probes.size.toString(),
                        "answeredCount" to (present + absent).toString(),
                        "presentCount" to present.toString(),
                        "absentCount" to absent.toString(),
                        "noAnswerCount" to noAnswer.size.toString(),
                        "concealable" to (unitSpec.concealment != null).toString(),
                    ),
                ),
            )
            if (unit.upstreamPositive) {
                val findings = unit.findings.ifEmpty {
                    listOf(
                        Finding(
                            code = "upstream-positive",
                            summary = "The upstream check reported a positive the shadow probe could not attribute",
                            strength = unitSpec.fallbackStrength,
                        ),
                    )
                }
                findings.forEach { finding ->
                    add(
                        EvidenceRecord(
                            code = "$codePrefix.${finding.code}",
                            kind = EvidenceRecordKind.SIGNAL,
                            summary = finding.summary,
                            signalStrength = finding.strength,
                            attributes = finding.attributes,
                        ),
                    )
                }
            } else if (unitSpec.concealment != null && outcome == DetectionOutcome.NOT_OBSERVED) {
                add(
                    EvidenceRecord(
                        code = "$codePrefix.concealable-negative",
                        kind = EvidenceRecordKind.OBSERVATION,
                        summary = "Negative rests on an absence that concealment can produce",
                        attributes = linkedMapOf(
                            "check" to unitSpec.id.substringAfter('.'),
                            "answeredCount" to absent.toString(),
                            "concealable" to "true",
                            "reason" to unitSpec.concealment,
                        ),
                    ),
                )
            }
        }
        return EvidenceUnitResult(
            descriptor = unitDescriptor,
            collectionStatus = if (issues.isEmpty()) {
                EvidenceUnitCollectionStatus.COMPLETE
            } else {
                EvidenceUnitCollectionStatus.PARTIAL
            },
            records = records,
            issues = issues,
        )
    }

    /** One issue per distinct reason a target did not answer. */
    private fun noAnswerIssues(
        unitSpec: UnitSpec,
        unit: UnitEvaluation,
        noAnswer: List<ProbeResult>,
    ): List<EvidenceIssue> = noAnswer.groupBy { it.reason }.map { (reason, probes) ->
        EvidenceIssue(
            code = "channel-no-answer",
            message = "${probes.size} target(s) did not answer: $reason",
            attributes = buildMap {
                put("reason", reason)
                put("count", probes.size.toString())
                put("upstreamVerdict", unit.upstreamVerdict)
                if (!unitSpec.redactTargets) put("targets", probes.joinToString(",") { it.target })
            },
        )
    }

    /**
     * A target the shadow saw while the upstream check reported nothing is not an answer either
     * way: the two calls disagreed, so it is reported as an issue rather than as a positive.
     */
    private fun UnitEvaluation.normalizedProbes(): List<ProbeResult> =
        if (upstreamPositive) {
            probes
        } else {
            probes.map {
                if (it.answer == ProbeAnswer.PRESENT) {
                    it.copy(answer = ProbeAnswer.NO_ANSWER, reason = "shadow_present_upstream_absent")
                } else {
                    it
                }
            }
        }

    private fun UnitSpec.descriptor(domainId: String) = EvidenceUnitDescriptor(
        id = id,
        title = title,
        domainId = domainId,
        observedObject = observedObject,
        proposition = proposition,
        observationChannel = observationChannel,
        availability = availability,
        trustBoundary = trustBoundary,
        inferenceLimit = inferenceLimit,
    )
}
