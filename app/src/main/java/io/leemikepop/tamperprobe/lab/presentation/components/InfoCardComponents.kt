package io.leemikepop.tamperprobe.lab.presentation.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.presentation.model.DetectionCardUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.assessmentContainerColor
import io.leemikepop.tamperprobe.lab.presentation.model.assessmentDisplayColor
import io.leemikepop.tamperprobe.lab.presentation.model.assessmentDisplayText

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun InfoCardItem(
    card: DetectionCardUiModel,
    onCardClick: ((DetectionCardUiModel) -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val icon = when (card.outcome) {
        DetectionOutcome.NOT_OBSERVED -> Icons.Filled.CheckCircle
        DetectionOutcome.OBSERVED -> when (card.evidenceStrength) {
            EvidenceStrength.WEAK -> Icons.Filled.Warning
            EvidenceStrength.MODERATE,
            EvidenceStrength.STRONG,
            -> Icons.Filled.Close
            EvidenceStrength.NONE -> Icons.Filled.Info
        }
        DetectionOutcome.INCONCLUSIVE,
        DetectionOutcome.FAILED,
        -> Icons.Filled.Info
    }
    val iconColor = assessmentDisplayColor(card.outcome, card.evidenceStrength)
    val isObserved = card.outcome == DetectionOutcome.OBSERVED
    val containerColor = if (isObserved) {
        assessmentContainerColor(card.outcome, card.evidenceStrength).copy(alpha = 0.35f)
    } else {
        MaterialTheme.colorScheme.surfaceContainerLow
    }

    Card(
        modifier = modifier.fillMaxWidth().then(
            if (onCardClick != null) {
                Modifier.clickable(role = Role.Button) { onCardClick(card) }
            } else {
                Modifier
            }
        ),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        border = BorderStroke(
            1.dp,
            if (isObserved) iconColor.copy(alpha = 0.45f) else MaterialTheme.colorScheme.outlineVariant,
        ),
        shape = MaterialTheme.shapes.medium,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = card.outcome.name,
                tint = iconColor,
                modifier = Modifier
                    .padding(top = 2.dp)
                    .size(22.dp)
            )
            Spacer(modifier = Modifier.width(14.dp))
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        text = card.title,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = card.id,
                        style = MaterialTheme.typography.labelMedium.copy(
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Normal,
                        ),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    InfoChip(
                        text = assessmentDisplayText(card.outcome, card.evidenceStrength),
                        containerColor = assessmentContainerColor(card.outcome, card.evidenceStrength),
                        contentColor = iconColor,
                        description = "Outcome ${card.outcome.name}, strength ${card.evidenceStrength.name}",
                    )
                    card.evidenceDomainTags.forEach { domain ->
                        DomainChip(
                            shortTitle = domain.shortTitle,
                            title = domain.title,
                            isPrimary = domain.isPrimary,
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun InfoCardStack(
    cards: List<DetectionCardUiModel>,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier.fillMaxWidth().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        cards.forEach { card ->
            InfoCardItem(card = card)
        }
    }
}
