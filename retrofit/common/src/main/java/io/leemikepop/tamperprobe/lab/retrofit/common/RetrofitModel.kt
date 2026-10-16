package io.leemikepop.tamperprobe.lab.retrofit.common

import io.leemikepop.tamperprobe.lab.api.EvidenceStrength

/**
 * What a shadow probe learned about one target of an upstream check.
 *
 * The upstream check decides whether something was found; the retrofit never changes that.
 * The shadow probe repeats the upstream check's call on the same channel only to learn what the
 * upstream code throws away: whether the channel answered at all.
 */
enum class ProbeAnswer {
    /** The channel answered and the target is there. */
    PRESENT,

    /** The channel answered and the target is not there. */
    ABSENT,

    /** The channel did not answer for this target (Rule 1), or its anchor failed (Rule 2). */
    NO_ANSWER,
}

/**
 * One probe of one target. [reason] is the raw cause: an errno name (`ENOENT`, `EACCES`), an
 * exception class, or a named condition such as `outside_package_visibility_scope`.
 */
data class ProbeResult(
    val target: String,
    val answer: ProbeAnswer,
    val reason: String,
)

/**
 * Declares one evidence unit of a retrofitted check: one observation channel.
 *
 * [concealment] is the unit's concealability declaration (Rule 3), made in advance against the
 * threat model: when it is not null, a negative from this unit is an absence that the named
 * mechanism can manufacture, and it is published as a concealable negative, never as a trusted
 * one. Each declaration is meant to be falsified by a ladder cell that switches the mechanism on.
 *
 * [fallbackStrength] grades an upstream positive that the shadow probe could not attribute to a
 * target. [redactTargets] keeps target names out of issues when they would list the device's apps.
 */
data class UnitSpec(
    val id: String,
    val title: String,
    val observedObject: String,
    val proposition: String,
    val observationChannel: String,
    val availability: String,
    val trustBoundary: String,
    val inferenceLimit: String,
    val concealment: String?,
    val fallbackStrength: EvidenceStrength,
    val redactTargets: Boolean = false,
)

/** Declares one retrofitted upstream check as a detector of its own. */
data class CheckSpec(
    val detectorId: String,
    val name: String,
    val description: String,
    val domainId: String,
    val upstreamMethod: String,
    val units: List<UnitSpec>,
) {
    init {
        require(units.isNotEmpty()) { "$detectorId declares no units" }
        require(units.map { it.id }.toSet().size == units.size) { "$detectorId repeats a unit id" }
    }
}

/** A positive the upstream check reported, attributed to a target where the shadow could. */
data class Finding(
    val code: String,
    val summary: String,
    val strength: EvidenceStrength,
    val attributes: Map<String, String> = emptyMap(),
) {
    init {
        require(strength != EvidenceStrength.NONE) { "A finding needs WEAK, MODERATE or STRONG" }
    }
}

/**
 * What happened on one unit: the upstream verdict for the unit's channel, verbatim, whether it is
 * a positive, the shadow probes and the findings.
 */
data class UnitEvaluation(
    val unitId: String,
    val upstreamVerdict: String,
    val upstreamPositive: Boolean,
    val probes: List<ProbeResult>,
    val findings: List<Finding> = emptyList(),
)

/**
 * The evaluation of one upstream check. [upstreamFailure] is set when the upstream method threw:
 * unmodified upstream code would have crashed or propagated the exception to its caller.
 */
data class CheckEvaluation(
    val spec: CheckSpec,
    val upstreamVerdict: String,
    val upstreamPositive: Boolean,
    val units: List<UnitEvaluation>,
    val upstreamFailure: Throwable? = null,
    val durationMicros: Long = 0,
)
