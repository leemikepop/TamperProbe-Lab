package io.leemikepop.tamperprobe.lab.presentation.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.presentation.model.DetectionCardUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.assessmentContainerColor
import io.leemikepop.tamperprobe.lab.presentation.model.assessmentDisplayColor
import io.leemikepop.tamperprobe.lab.presentation.model.assessmentDisplayText
import io.leemikepop.tamperprobe.lab.ui.theme.LocalDetectionColors

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
    val containerColor = assessmentContainerColor(card.outcome, card.evidenceStrength)

    Card(
        modifier = modifier.fillMaxWidth().then(
            if (onCardClick != null) Modifier.clickable { onCardClick(card) } else Modifier
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        colors = CardDefaults.cardColors(containerColor = containerColor.copy(alpha = 0.35f)),
        shape = MaterialTheme.shapes.small,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = card.outcome.name,
                tint = iconColor,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = card.title,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = card.id,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (card.evidenceDomainTags.isNotEmpty()) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        card.evidenceDomainTags.forEach { domain ->
                            Surface(
                                color = if (domain.isPrimary) {
                                    MaterialTheme.colorScheme.primaryContainer
                                } else {
                                    MaterialTheme.colorScheme.secondaryContainer
                                },
                                shape = MaterialTheme.shapes.extraSmall,
                                modifier = Modifier.semantics {
                                    contentDescription = if (domain.isPrimary) {
                                        "Primary Evidence Domain: ${domain.title}"
                                    } else {
                                        "Direct Evidence Domain: ${domain.title}"
                                    }
                                },
                            ) {
                                Text(
                                    text = domain.shortTitle,
                                    modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                )
                            }
                        }
                    }
                }
                Text(
                    text = assessmentDisplayText(card.outcome, card.evidenceStrength),
                    style = MaterialTheme.typography.labelSmall,
                    color = iconColor,
                )
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
