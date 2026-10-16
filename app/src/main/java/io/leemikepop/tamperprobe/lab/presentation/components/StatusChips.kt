package io.leemikepop.tamperprobe.lab.presentation.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.presentation.model.assessmentContainerColor
import io.leemikepop.tamperprobe.lab.presentation.model.assessmentDisplayColor
import io.leemikepop.tamperprobe.lab.ui.theme.LocalDetectionColors

/**
 * Small two-part badge: an optional muted [caption] ("Outcome") followed by the [text] value
 * ("OBSERVED"). Filled chips carry assessment values; outlined chips carry collection status.
 */
@Composable
fun InfoChip(
    text: String,
    containerColor: Color,
    contentColor: Color,
    modifier: Modifier = Modifier,
    caption: String? = null,
    borderColor: Color? = null,
    description: String? = null,
    monospace: Boolean = false,
) {
    Surface(
        modifier = if (description != null) {
            modifier.clearAndSetSemantics { contentDescription = description }
        } else {
            modifier
        },
        shape = RoundedCornerShape(6.dp),
        color = containerColor,
        contentColor = contentColor,
        border = borderColor?.let { BorderStroke(1.dp, it) },
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
            horizontalArrangement = Arrangement.spacedBy(5.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (caption != null) {
                Text(
                    text = caption,
                    style = MaterialTheme.typography.labelSmall,
                    color = contentColor.copy(alpha = 0.78f),
                    maxLines = 1,
                )
            }
            Text(
                text = text,
                style = if (monospace) {
                    MaterialTheme.typography.labelMedium.copy(fontFamily = FontFamily.Monospace)
                } else {
                    MaterialTheme.typography.labelMedium
                },
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
            )
        }
    }
}

@Composable
fun OutcomeChip(
    outcome: DetectionOutcome,
    strength: EvidenceStrength,
    modifier: Modifier = Modifier,
) {
    InfoChip(
        text = outcome.name,
        caption = "Outcome",
        containerColor = assessmentContainerColor(outcome, strength),
        contentColor = assessmentDisplayColor(outcome, strength),
        description = "Outcome: ${outcome.name}",
        modifier = modifier,
    )
}

@Composable
fun StrengthChip(
    strength: EvidenceStrength,
    outcome: DetectionOutcome,
    modifier: Modifier = Modifier,
    caption: String = "Strength",
) {
    val color = assessmentDisplayColor(outcome, strength)
    InfoChip(
        text = strength.name,
        caption = caption,
        containerColor = assessmentContainerColor(outcome, strength).copy(alpha = 0.55f),
        contentColor = color,
        description = "$caption: ${strength.name}",
        modifier = modifier,
    )
}

/** Unit collection status is a different layer from outcome, so it is drawn outlined. */
@Composable
fun CollectionStatusChip(
    status: EvidenceUnitCollectionStatus,
    modifier: Modifier = Modifier,
) {
    val colors = LocalDetectionColors.current
    val content = when (status) {
        EvidenceUnitCollectionStatus.COMPLETE -> MaterialTheme.colorScheme.onSurfaceVariant
        EvidenceUnitCollectionStatus.PARTIAL -> colors.warning
        EvidenceUnitCollectionStatus.UNAVAILABLE -> colors.unknown
    }
    InfoChip(
        text = status.name,
        caption = "Collection",
        containerColor = Color.Transparent,
        contentColor = content,
        borderColor = content.copy(alpha = 0.55f),
        description = "Collection status: ${status.name}",
        modifier = modifier,
    )
}

@Composable
fun DomainChip(
    shortTitle: String,
    title: String,
    isPrimary: Boolean,
    modifier: Modifier = Modifier,
    descriptionPrefix: String = if (isPrimary) "Primary evidence domain" else "Direct evidence domain",
) {
    InfoChip(
        text = shortTitle,
        containerColor = if (isPrimary) {
            MaterialTheme.colorScheme.secondaryContainer
        } else {
            MaterialTheme.colorScheme.surfaceContainerHighest
        },
        contentColor = if (isPrimary) {
            MaterialTheme.colorScheme.onSecondaryContainer
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        },
        description = "$descriptionPrefix: $title",
        modifier = modifier,
    )
}
