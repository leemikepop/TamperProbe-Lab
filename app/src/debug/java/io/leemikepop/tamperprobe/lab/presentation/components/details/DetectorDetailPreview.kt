package io.leemikepop.tamperprobe.lab.presentation.components.details

import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview
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
import io.leemikepop.tamperprobe.lab.ui.theme.TamperProbeTheme

@Preview(showBackground = true, widthDp = 412, heightDp = 900)
@Composable
private fun DetectorDetailPreview() {
    TamperProbeTheme(dynamicColor = false) {
        DetectorDetailContent(
            detail = previewDetail(),
            onDismiss = {},
        )
    }
}

private fun previewDetail(): DetectionDetailUiModel = DetectionDetailUiModel(
    id = "RUNTIME_INSTRUMENTATION",
    title = "Runtime Instrumentation",
    description = "Observes maintained runtime markers and generic process anomalies without treating research data as a detector Signal.",
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
        EvidenceDomainTagUiModel(
            "process-memory",
            "Process and Memory",
            "Process",
            false,
        ),
    ),
    collectionError = null,
    units = listOf(
        EvidenceUnitDetailUiModel(
            id = "direct-marker",
            title = "Direct Marker",
            domainId = "runtime-integrity",
            domainTitle = "Runtime Integrity",
            domainShortTitle = "Runtime",
            collectionStatus = EvidenceUnitCollectionStatus.COMPLETE,
            observedObject = "Known instrumentation markers in the current process",
            proposition = "A maintained marker directly supports the detector assessment",
            observationChannel = "Process memory and loaded-module views",
            availability = "Available while the process can enumerate its own runtime state",
            trustBoundary = "In-process observations can be altered by a privileged adversary",
            inferenceLimit = "Marker absence does not establish that instrumentation is absent",
            signals = listOf(
                EvidenceRecordDetailUiModel(
                    code = "RUNTIME_INSTRUMENTATION.direct-marker.marker-visible",
                    kind = EvidenceRecordKind.SIGNAL,
                    summary = "Maintained instrumentation marker is visible",
                    signalStrength = EvidenceStrength.MODERATE,
                    attributes = listOf(
                        DetailValueUiModel(
                            "Module Path",
                            "/data/app/example/base.apk!/lib/arm64-v8a/libinstrumentation.so",
                            isMonospace = true,
                        ),
                    ),
                ),
            ),
            observations = listOf(
                EvidenceRecordDetailUiModel(
                    code = "RUNTIME_INSTRUMENTATION.direct-marker.scan-complete",
                    kind = EvidenceRecordKind.OBSERVATION,
                    summary = "Direct marker scan completed",
                    signalStrength = null,
                    attributes = listOf(DetailValueUiModel("Scanned Modules", "42")),
                ),
            ),
            researchRecords = emptyList(),
            issues = emptyList(),
            initiallyExpanded = true,
        ),
        EvidenceUnitDetailUiModel(
            id = "generic-anomaly",
            title = "Generic Anomaly",
            domainId = "process-memory",
            domainTitle = "Process and Memory",
            domainShortTitle = "Process",
            collectionStatus = EvidenceUnitCollectionStatus.PARTIAL,
            observedObject = "Generic process-memory anomaly candidates",
            proposition = "Candidate anomalies are retained for research but do not affect assessment",
            observationChannel = "Procfs memory maps",
            availability = "Partial when procfs entries cannot all be read",
            trustBoundary = "Procfs is part of the observable process view",
            inferenceLimit = "Candidates require validation before they can become Signals",
            signals = emptyList(),
            observations = emptyList(),
            researchRecords = listOf(
                EvidenceRecordDetailUiModel(
                    code = "RUNTIME_INSTRUMENTATION.generic-anomaly.candidate",
                    kind = EvidenceRecordKind.RESEARCH,
                    summary = "Executable anonymous mapping candidate",
                    signalStrength = null,
                    attributes = emptyList(),
                ),
            ),
            issues = listOf(
                EvidenceIssueDetailUiModel(
                    code = "RUNTIME_INSTRUMENTATION.generic-anomaly.partial-view",
                    message = "One procfs source was unavailable",
                    attributes = emptyList(),
                ),
            ),
            initiallyExpanded = true,
        ),
    ),
)
