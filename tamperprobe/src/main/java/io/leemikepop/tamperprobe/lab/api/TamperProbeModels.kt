package io.leemikepop.tamperprobe.lab.api

public data class ScanRequest @JvmOverloads constructor(
    public val detectorIds: Set<String>? = null,
)

public data class EvidenceDomainDescriptor(
    public val id: String,
    public val title: String,
    public val shortTitle: String,
    public val description: String,
)

public data class EvidenceUnitDescriptor(
    public val id: String,
    public val title: String,
    public val domainId: String,
    public val observedObject: String,
    public val proposition: String,
    public val observationChannel: String,
    public val availability: String,
    public val trustBoundary: String,
    public val inferenceLimit: String,
)

public data class DetectorDescriptor @JvmOverloads constructor(
    public val id: String,
    public val name: String,
    public val description: String,
    public val primaryEvidenceDomainId: String,
    public val payloadSchemaVersion: Int,
    public val evidenceUnits: List<EvidenceUnitDescriptor> = emptyList(),
)

public enum class ScanCompletion {
    COMPLETE,
    PARTIAL,
}

public enum class DetectionOutcome {
    OBSERVED,
    NOT_OBSERVED,
    INCONCLUSIVE,
    FAILED,
}

public enum class EvidenceStrength {
    NONE,
    WEAK,
    MODERATE,
    STRONG,
}

public enum class EvidenceRecordKind {
    SIGNAL,
    OBSERVATION,
    RESEARCH,
}

public enum class EvidenceUnitCollectionStatus {
    COMPLETE,
    PARTIAL,
    UNAVAILABLE,
}

public data class EvidenceRecord @JvmOverloads constructor(
    public val code: String,
    public val kind: EvidenceRecordKind,
    public val summary: String,
    public val signalStrength: EvidenceStrength? = null,
    public val attributes: Map<String, String> = emptyMap(),
) {
    init {
        require(code.isNotBlank()) { "Evidence record code must not be blank" }
        require(summary.isNotBlank()) { "Evidence record summary must not be blank" }
        when (kind) {
            EvidenceRecordKind.SIGNAL -> require(
                signalStrength != null && signalStrength != EvidenceStrength.NONE,
            ) { "SIGNAL records require WEAK, MODERATE, or STRONG signalStrength" }

            EvidenceRecordKind.OBSERVATION,
            EvidenceRecordKind.RESEARCH,
            -> require(signalStrength == null) {
                "OBSERVATION and RESEARCH records cannot carry signalStrength"
            }
        }
    }
}

public data class EvidenceIssue @JvmOverloads constructor(
    public val code: String,
    public val message: String,
    public val attributes: Map<String, String> = emptyMap(),
) {
    init {
        require(code.isNotBlank()) { "Evidence issue code must not be blank" }
        require(message.isNotBlank()) { "Evidence issue message must not be blank" }
    }
}

public data class EvidenceUnitResult(
    public val descriptor: EvidenceUnitDescriptor,
    public val collectionStatus: EvidenceUnitCollectionStatus,
    public val records: List<EvidenceRecord>,
    public val issues: List<EvidenceIssue>,
) {
    init {
        when (collectionStatus) {
            EvidenceUnitCollectionStatus.COMPLETE -> {
                require(records.isNotEmpty()) { "COMPLETE units require at least one record" }
                require(issues.isEmpty()) { "COMPLETE units cannot contain issues" }
            }

            EvidenceUnitCollectionStatus.PARTIAL -> {
                require(records.isNotEmpty()) { "PARTIAL units require at least one record" }
                require(issues.isNotEmpty()) { "PARTIAL units require at least one issue" }
            }

            EvidenceUnitCollectionStatus.UNAVAILABLE -> {
                require(records.isEmpty()) { "UNAVAILABLE units cannot contain records" }
                require(issues.isNotEmpty()) { "UNAVAILABLE units require at least one issue" }
            }
        }
    }
}

public data class CollectionError(
    public val code: String,
    public val message: String,
    public val recoverable: Boolean,
)

public data class DetectorResult @JvmOverloads constructor(
    public val descriptor: DetectorDescriptor,
    public val outcome: DetectionOutcome,
    public val strength: EvidenceStrength,
    public val unitResults: List<EvidenceUnitResult>,
    public val collectionError: CollectionError? = null,
    /** Wall time this detector spent executing, in microseconds. */
    public val durationMicros: Long = 0,
) {
    init {
        if (outcome == DetectionOutcome.FAILED) {
            require(strength == EvidenceStrength.NONE) { "FAILED results require NONE strength" }
            require(unitResults.isEmpty()) { "FAILED results cannot publish unit reports" }
            require(collectionError != null) { "FAILED results require CollectionError" }
        } else {
            require(collectionError == null) { "Successful detector assessments cannot carry CollectionError" }
            require(unitResults.map { it.descriptor } == descriptor.evidenceUnits) {
                "Successful detector results must publish every declared unit exactly once"
            }
            val signals = unitResults.flatMap { it.records }
                .filter { it.kind == EvidenceRecordKind.SIGNAL }
            if (outcome == DetectionOutcome.OBSERVED) {
                require(signals.isNotEmpty()) { "OBSERVED results require at least one SIGNAL record" }
                require(strength != EvidenceStrength.NONE) { "OBSERVED results require non-NONE strength" }
                require(signals.all { it.signalStrength!!.ordinal <= strength.ordinal }) {
                    "Detector strength cannot be lower than a unit signal"
                }
            } else {
                require(signals.isEmpty()) { "$outcome results cannot publish SIGNAL records" }
                require(strength == EvidenceStrength.NONE) { "$outcome results require NONE strength" }
            }
            require(unitResults.flatMap { it.records }.all { it.code.startsWith("${descriptor.id}.") }) {
                "Evidence record codes must be scoped to the detector ID"
            }
        }
    }
}

public data class TamperProbeReport(
    public val wireSchemaVersion: Int,
    public val engineVersion: String,
    public val catalogVersion: String,
    public val completion: ScanCompletion,
    public val durationMillis: Long,
    public val results: List<DetectorResult>,
)
