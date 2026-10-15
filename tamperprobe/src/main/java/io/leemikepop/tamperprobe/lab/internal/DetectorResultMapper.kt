package io.leemikepop.tamperprobe.lab.internal

import io.leemikepop.tamperprobe.lab.api.CollectionError
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.DetectorDescriptor
import io.leemikepop.tamperprobe.lab.api.DetectorResult
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.TamperProbeException

internal object DetectorResultMapper {
    fun map(descriptor: DetectorDescriptor, wire: WireDetectorResult): DetectorResult {
        if (wire.detectorId != descriptor.id) {
            throw TamperProbeException(
                "DETECTOR_ID_MISMATCH",
                "Native detector ID ${wire.detectorId} does not match catalog detector ${descriptor.id}",
            )
        }
        val wireError = wire.collectionError?.takeIf { it.isNotBlank() }
        validateAssessment(descriptor.id, wire, wireError)
        val adaptation = if (wireError == null) {
            runCatching {
                EvidenceAdapterRegistry.map(
                    EvidenceAdapterInput(
                        descriptor = descriptor,
                        outcome = wire.outcome,
                        strength = wire.evidenceStrength,
                        payload = wire.payload,
                    ),
                )
            }
        } else {
            null
        }
        val adaptationError = adaptation?.exceptionOrNull()
        val collectionError = when {
            wireError != null -> CollectionError("COLLECTION_FAILED", wireError, recoverable = true)
            adaptationError is EvidenceAdaptationException -> CollectionError(
                adaptationError.code,
                adaptationError.message ?: "Payload adaptation failed for ${descriptor.id}",
                recoverable = false,
            )
            adaptationError != null -> CollectionError(
                "PAYLOAD_ADAPTATION_FAILED",
                adaptationError.message ?: "Payload adaptation failed for ${descriptor.id}",
                recoverable = false,
            )
            else -> null
        }

        return DetectorResult(
            descriptor = descriptor,
            outcome = if (collectionError == null) wire.outcome else DetectionOutcome.FAILED,
            strength = if (collectionError == null) wire.evidenceStrength else EvidenceStrength.NONE,
            unitResults = if (collectionError == null) adaptation!!.getOrThrow() else emptyList(),
            collectionError = collectionError,
            durationMicros = wire.durationMicros,
        )
    }

    private fun validateAssessment(
        detectorId: String,
        wire: WireDetectorResult,
        collectionError: String?,
    ) {
        val valid = when (wire.outcome) {
            DetectionOutcome.OBSERVED ->
                wire.evidenceStrength != EvidenceStrength.NONE && collectionError == null
            DetectionOutcome.NOT_OBSERVED,
            DetectionOutcome.INCONCLUSIVE,
            -> wire.evidenceStrength == EvidenceStrength.NONE && collectionError == null
            DetectionOutcome.FAILED ->
                wire.evidenceStrength == EvidenceStrength.NONE && collectionError != null
        }
        if (!valid) {
            throw TamperProbeException(
                "INVALID_WIRE_ASSESSMENT",
                "Detector $detectorId returned an invalid outcome, evidence strength, and error combination",
            )
        }
    }
}
