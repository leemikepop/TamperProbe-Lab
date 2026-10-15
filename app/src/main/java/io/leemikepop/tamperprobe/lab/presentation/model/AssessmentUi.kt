package io.leemikepop.tamperprobe.lab.presentation.model

import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.ui.theme.LocalDetectionColors

fun assessmentDisplayText(
    outcome: DetectionOutcome,
    evidenceStrength: EvidenceStrength,
): String = "${outcome.name} · ${evidenceStrength.name}"

@Composable
fun assessmentDisplayColor(
    outcome: DetectionOutcome,
    evidenceStrength: EvidenceStrength,
): Color {
    val colors = LocalDetectionColors.current
    return when (outcome) {
        DetectionOutcome.NOT_OBSERVED -> colors.safe
        DetectionOutcome.OBSERVED -> when (evidenceStrength) {
            EvidenceStrength.WEAK -> colors.warning
            EvidenceStrength.MODERATE,
            EvidenceStrength.STRONG,
            -> colors.danger
            EvidenceStrength.NONE -> colors.unknown
        }
        DetectionOutcome.INCONCLUSIVE,
        DetectionOutcome.FAILED,
        -> colors.unknown
    }
}

@Composable
fun assessmentContainerColor(
    outcome: DetectionOutcome,
    evidenceStrength: EvidenceStrength,
): Color {
    val colors = LocalDetectionColors.current
    return when (outcome) {
        DetectionOutcome.NOT_OBSERVED -> colors.safeContainer
        DetectionOutcome.OBSERVED -> when (evidenceStrength) {
            EvidenceStrength.WEAK -> colors.warningContainer
            EvidenceStrength.MODERATE,
            EvidenceStrength.STRONG,
            -> colors.dangerContainer
            EvidenceStrength.NONE -> colors.unknownContainer
        }
        DetectionOutcome.INCONCLUSIVE,
        DetectionOutcome.FAILED,
        -> colors.unknownContainer
    }
}
