package io.leemikepop.tamperprobe.lab.api

public data class ReferenceTamperScoringPolicy @JvmOverloads constructor(
    public val weakWeight: Int = 1,
    public val moderateWeight: Int = 2,
    public val strongWeight: Int = 4,
    public val inconclusiveWeight: Int = 1,
    public val threshold: Int = 4,
) {
    init {
        require(weakWeight >= 0) { "weakWeight must be non-negative" }
        require(moderateWeight >= 0) { "moderateWeight must be non-negative" }
        require(strongWeight >= 0) { "strongWeight must be non-negative" }
        require(inconclusiveWeight >= 0) { "inconclusiveWeight must be non-negative" }
        require(threshold > 0) { "threshold must be positive" }
    }
}

public data class ReferenceTamperScore(
    public val policyVersion: Int,
    public val score: Int,
    public val threshold: Int,
    public val thresholdReached: Boolean,
    public val observedDetectorIds: List<String>,
    public val inconclusiveDetectorIds: List<String>,
    public val failedDetectorIds: List<String>,
)

public object ReferenceTamperScorer {
    public const val POLICY_VERSION: Int = 1

    @JvmStatic
    @JvmOverloads
    public fun score(
        report: TamperProbeReport,
        policy: ReferenceTamperScoringPolicy = ReferenceTamperScoringPolicy(),
    ): ReferenceTamperScore {
        var score = 0
        val observed = mutableListOf<String>()
        val inconclusive = mutableListOf<String>()
        val failed = mutableListOf<String>()

        report.results.forEach { result ->
            when (result.outcome) {
                DetectionOutcome.OBSERVED -> {
                    observed += result.descriptor.id
                    score += when (result.strength) {
                        EvidenceStrength.WEAK -> policy.weakWeight
                        EvidenceStrength.MODERATE -> policy.moderateWeight
                        EvidenceStrength.STRONG -> policy.strongWeight
                        EvidenceStrength.NONE -> 0
                    }
                }
                DetectionOutcome.INCONCLUSIVE -> {
                    inconclusive += result.descriptor.id
                    score += policy.inconclusiveWeight
                }
                DetectionOutcome.FAILED -> failed += result.descriptor.id
                DetectionOutcome.NOT_OBSERVED -> Unit
            }
        }

        return ReferenceTamperScore(
            policyVersion = POLICY_VERSION,
            score = score,
            threshold = policy.threshold,
            thresholdReached = score >= policy.threshold,
            observedDetectorIds = observed,
            inconclusiveDetectorIds = inconclusive,
            failedDetectorIds = failed,
        )
    }
}
