package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceIssue
import io.leemikepop.tamperprobe.lab.api.EvidenceRecord
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitDescriptor
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitResult
import io.leemikepop.tamperprobe.lab.internal.EvidenceAdaptationException
import io.leemikepop.tamperprobe.lab.internal.EvidenceAdapterInput
import io.leemikepop.tamperprobe.lab.internal.TypedDetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.lib.detections.appvisibility.DangerousPackagesPayload
import io.leemikepop.tamperprobe.lab.lib.detections.appvisibility.UnitCollectionIssuePayload

internal object DangerousPackagesEvidenceAdapter : TypedDetectorEvidenceAdapter<DangerousPackagesPayload> {
    private const val PACKAGE_UNIT_ID = "dangerous-packages.package-identity-visibility"
    private const val PATH_UNIT_ID = "dangerous-packages.app-data-path-visibility"

    override fun map(
        input: EvidenceAdapterInput,
        payload: DangerousPackagesPayload,
    ): List<EvidenceUnitResult> {
        val descriptors = input.descriptor.evidenceUnits.associateBy { it.id }
        if (descriptors.keys != setOf(PACKAGE_UNIT_ID, PATH_UNIT_ID)) {
            throw EvidenceAdaptationException(
                "EVIDENCE_UNIT_BINDING_FAILED",
                "DANGEROUS_PACKAGES adapter units do not match the catalog descriptor",
            )
        }

        val packageSignal = payload.packageIdentity.detectedPackages.isNotEmpty()
        val pathSignal = payload.appDataPath.foundPaths.isNotEmpty()
        val hasSignalFact = packageSignal || pathSignal
        val expectedOutcome = when {
            hasSignalFact -> DetectionOutcome.OBSERVED
            // Mirrors aggregateAssessment in dangerous_packages.cpp: app data isolation
            // leaves the path unit unable to answer, and must not block the verdict.
            payload.packageIdentity.completedQueryCount > 0 &&
                (payload.appDataPath.completedPathCount > 0 || payload.appDataPath.isolationDetected) ->
                DetectionOutcome.NOT_OBSERVED
            else -> DetectionOutcome.INCONCLUSIVE
        }
        val expectedStrength = if (hasSignalFact) EvidenceStrength.WEAK else EvidenceStrength.NONE
        if (input.outcome != expectedOutcome || input.strength != expectedStrength) {
            throw EvidenceAdaptationException(
                "PAYLOAD_ASSESSMENT_MISMATCH",
                "DANGEROUS_PACKAGES assessment does not match its unit observations",
            )
        }

        val byId = mapOf(
            PACKAGE_UNIT_ID to packageUnitResult(
                descriptors.getValue(PACKAGE_UNIT_ID),
                input,
                payload,
                packageSignal,
            ),
            PATH_UNIT_ID to pathUnitResult(
                descriptors.getValue(PATH_UNIT_ID),
                input,
                payload,
                pathSignal,
            ),
        )
        return input.descriptor.evidenceUnits.map { byId.getValue(it.id) }
    }

    private fun packageUnitResult(
        descriptor: EvidenceUnitDescriptor,
        input: EvidenceAdapterInput,
        payload: DangerousPackagesPayload,
        contributesSignal: Boolean,
    ): EvidenceUnitResult {
        val observation = payload.packageIdentity
        validateCounts(
            unitId = descriptor.id,
            attempted = observation.targetCount,
            completed = observation.completedQueryCount,
        )
        val attributes = linkedMapOf(
            "targetCount" to observation.targetCount.toString(),
            "completedQueryCount" to observation.completedQueryCount.toString(),
            "visiblePackageCount" to observation.visiblePackageCount.toString(),
        ).apply {
            putIndexed("detectedPackages", observation.detectedPackages)
        }
        val records = when {
            contributesSignal -> listOf(
                EvidenceRecord(
                    code = "DANGEROUS_PACKAGES.package-identity-visibility.assessment-signal",
                    kind = EvidenceRecordKind.SIGNAL,
                    summary = "A maintained dangerous-package identity was visible",
                    signalStrength = input.strength,
                    attributes = attributes,
                ),
            )
            observation.completedQueryCount > 0 -> listOf(
                EvidenceRecord(
                    code = "DANGEROUS_PACKAGES.package-identity-visibility.collection-summary",
                    kind = EvidenceRecordKind.OBSERVATION,
                    summary = "Package identity queries completed without a visible maintained identity",
                    attributes = attributes,
                ),
            )
            else -> emptyList()
        }
        return unitResult(descriptor, records, observation.issues)
    }

    private fun pathUnitResult(
        descriptor: EvidenceUnitDescriptor,
        input: EvidenceAdapterInput,
        payload: DangerousPackagesPayload,
        contributesSignal: Boolean,
    ): EvidenceUnitResult {
        val observation = payload.appDataPath
        validateCounts(
            unitId = descriptor.id,
            attempted = observation.attemptedPathCount,
            completed = observation.completedPathCount,
        )
        if (observation.notFoundPathCount > observation.completedPathCount) {
            throw EvidenceAdaptationException(
                "PAYLOAD_DECODE_FAILED",
                "${descriptor.id} notFoundPathCount exceeds completedPathCount",
            )
        }
        val attributes = linkedMapOf(
            "attemptedPathCount" to observation.attemptedPathCount.toString(),
            "completedPathCount" to observation.completedPathCount.toString(),
            "notFoundPathCount" to observation.notFoundPathCount.toString(),
            "unconfirmedNotFoundCount" to observation.unconfirmedNotFoundCount.toString(),
            "selfControl" to observation.selfControl,
            "crossPackageControl" to observation.crossPackageControl,
            "isolationDetected" to observation.isolationDetected.toString(),
        ).apply {
            putIndexed("foundPaths", observation.foundPaths)
            putIndexed("inaccessiblePaths", observation.inaccessiblePaths)
        }
        val records = when {
            contributesSignal -> listOf(
                EvidenceRecord(
                    code = "DANGEROUS_PACKAGES.app-data-path-visibility.assessment-signal",
                    kind = EvidenceRecordKind.SIGNAL,
                    summary = "A package-derived private-data path was visible",
                    signalStrength = input.strength,
                    attributes = attributes,
                ),
            )
            observation.completedPathCount > 0 -> listOf(
                EvidenceRecord(
                    code = "DANGEROUS_PACKAGES.app-data-path-visibility.collection-summary",
                    kind = EvidenceRecordKind.OBSERVATION,
                    summary = "Package-derived path probes completed without a visible path",
                    attributes = attributes,
                ),
            )
            else -> emptyList()
        }
        return unitResult(descriptor, records, observation.issues)
    }

    private fun unitResult(
        descriptor: EvidenceUnitDescriptor,
        records: List<EvidenceRecord>,
        issuePayloads: List<UnitCollectionIssuePayload>,
    ): EvidenceUnitResult {
        val issues = issuePayloads.map { issue ->
            EvidenceIssue(
                code = "DANGEROUS_PACKAGES.${descriptor.id.substringAfter('.')}.${issue.code}",
                message = issue.message,
                attributes = issue.attributes,
            )
        }
        if (records.isEmpty() && issues.isEmpty()) {
            throw EvidenceAdaptationException(
                "PAYLOAD_DECODE_FAILED",
                "${descriptor.id} contains neither a completed observation nor a collection issue",
            )
        }
        val status = when {
            records.isEmpty() -> EvidenceUnitCollectionStatus.UNAVAILABLE
            issues.isNotEmpty() -> EvidenceUnitCollectionStatus.PARTIAL
            else -> EvidenceUnitCollectionStatus.COMPLETE
        }
        return EvidenceUnitResult(descriptor, status, records, issues)
    }

    private fun validateCounts(unitId: String, attempted: Int, completed: Int) {
        if (attempted < 0 || completed < 0 || completed > attempted) {
            throw EvidenceAdaptationException(
                "PAYLOAD_DECODE_FAILED",
                "$unitId contains invalid collection counts",
            )
        }
    }

    private fun MutableMap<String, String>.putIndexed(prefix: String, values: List<String>) {
        values.forEachIndexed { index, value -> put("$prefix.$index", value) }
    }
}
