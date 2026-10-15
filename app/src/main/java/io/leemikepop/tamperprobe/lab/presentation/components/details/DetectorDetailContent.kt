package io.leemikepop.tamperprobe.lab.presentation.components.details

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.presentation.model.DetailValueUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.DetectionDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.DetectorCollectionErrorUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceIssueDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceRecordDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceUnitDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.assessmentContainerColor
import io.leemikepop.tamperprobe.lab.presentation.model.assessmentDisplayColor
import io.leemikepop.tamperprobe.lab.ui.theme.LocalDetectionColors

@Composable
fun DetectorDetailContent(
    detail: DetectionDetailUiModel,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp),
        contentPadding = PaddingValues(top = 4.dp, bottom = 32.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item(key = "${detail.id}:header") {
            DetectorDetailHeader(detail = detail, onDismiss = onDismiss)
        }

        detail.collectionError?.let { error ->
            item(key = "${detail.id}:collection-error") {
                DetectorCollectionErrorCard(
                    detectorId = detail.id,
                    error = error,
                )
            }
        }

        items(
            items = detail.units,
            key = { unit -> "${detail.id}:${unit.id}" },
        ) { unit ->
            EvidenceUnitCard(
                detectorId = detail.id,
                unit = unit,
            )
        }

        item(key = "${detail.id}:integration-metadata") {
            DetectorMetadataSection(detail = detail)
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DetectorDetailHeader(
    detail: DetectionDetailUiModel,
    onDismiss: () -> Unit,
) {
    val assessmentColor = assessmentDisplayColor(detail.outcome, detail.evidenceStrength)
    val assessmentContainer = assessmentContainerColor(detail.outcome, detail.evidenceStrength)

    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.Top,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = detail.title,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = detail.id,
                    style = MaterialTheme.typography.labelMedium.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            IconButton(onClick = onDismiss) {
                Icon(
                    imageVector = Icons.Filled.Close,
                    contentDescription = "Close detector details",
                )
            }
        }

        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            DetailBadge(
                label = detail.outcome.name,
                containerColor = assessmentContainer.copy(alpha = 0.75f),
                contentColor = assessmentColor,
                description = "Outcome: ${detail.outcome.name}",
            )
            DetailBadge(
                label = detail.evidenceStrength.name,
                containerColor = assessmentContainer.copy(alpha = 0.45f),
                contentColor = assessmentColor,
                description = "Evidence Strength: ${detail.evidenceStrength.name}",
            )
            detail.evidenceDomainTags.forEach { domain ->
                DetailBadge(
                    label = domain.shortTitle,
                    containerColor = if (domain.isPrimary) {
                        MaterialTheme.colorScheme.primaryContainer
                    } else {
                        MaterialTheme.colorScheme.secondaryContainer
                    },
                    contentColor = if (domain.isPrimary) {
                        MaterialTheme.colorScheme.onPrimaryContainer
                    } else {
                        MaterialTheme.colorScheme.onSecondaryContainer
                    },
                    description = if (domain.isPrimary) {
                        "Primary Evidence Domain: ${domain.title}"
                    } else {
                        "Direct Evidence Domain: ${domain.title}"
                    },
                )
            }
        }

        ExpandableText(
            text = detail.description,
            stateKey = "${detail.id}:description",
            collapsedMaxLines = 3,
            style = MaterialTheme.typography.bodyMedium,
        )

        Text(
            text = detailSummaryText(detail),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    }
}

@Composable
private fun DetectorCollectionErrorCard(
    detectorId: String,
    error: DetectorCollectionErrorUiModel,
) {
    val detectionColors = LocalDetectionColors.current
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = detectionColors.dangerContainer.copy(alpha = 0.45f),
        border = BorderStroke(1.dp, detectionColors.danger.copy(alpha = 0.45f)),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = "資料取得失敗 Collection Error",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = detectionColors.danger,
            )
            ExpandableText(
                text = error.message,
                stateKey = "$detectorId:collection-error:message",
                collapsedMaxLines = 3,
                style = MaterialTheme.typography.bodyMedium,
            )
            DetailValue(
                value = DetailValueUiModel("Error Code", error.code, isMonospace = true),
                stateKey = "$detectorId:collection-error:code",
            )
            DetailValue(
                value = DetailValueUiModel(
                    "Recoverable",
                    if (error.recoverable) "Yes" else "No",
                ),
                stateKey = "$detectorId:collection-error:recoverable",
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun EvidenceUnitCard(
    detectorId: String,
    unit: EvidenceUnitDetailUiModel,
) {
    var expanded by rememberSaveable("$detectorId:${unit.id}:unit") {
        mutableStateOf(unit.initiallyExpanded)
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        tonalElevation = 1.dp,
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(role = Role.Button) { expanded = !expanded }
                    .semantics(mergeDescendants = true) {
                        stateDescription = if (expanded) "Expanded" else "Collapsed"
                        contentDescription = "${unit.title}, ${unit.collectionStatus.name}"
                        role = Role.Button
                    }
                    .padding(horizontal = 14.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(3.dp),
                ) {
                    Text(
                        text = unit.title,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        text = unit.id,
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        UnitStatusBadge(unit.collectionStatus)
                        DetailBadge(
                            label = unit.domainShortTitle,
                            containerColor = MaterialTheme.colorScheme.secondaryContainer,
                            contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                            description = "Evidence Domain: ${unit.domainTitle}",
                        )
                    }
                    Text(
                        text = unitSummaryText(unit),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(modifier = Modifier.width(8.dp))
                ExpandIcon(expanded = expanded)
            }

            if (expanded) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (unit.signals.isNotEmpty()) {
                        RecordGroup(
                            detectorId = detectorId,
                            unitId = unit.id,
                            title = recordGroupTitle(EvidenceRecordKind.SIGNAL, unit.signals.size),
                            records = unit.signals,
                            initiallyExpanded = true,
                            accentColor = LocalDetectionColors.current.danger,
                        )
                    }
                    if (unit.issues.isNotEmpty()) {
                        IssueGroup(
                            detectorId = detectorId,
                            unitId = unit.id,
                            issues = unit.issues,
                        )
                    }
                    if (unit.observations.isNotEmpty()) {
                        RecordGroup(
                            detectorId = detectorId,
                            unitId = unit.id,
                            title = recordGroupTitle(
                                EvidenceRecordKind.OBSERVATION,
                                unit.observations.size,
                            ),
                            records = unit.observations,
                            initiallyExpanded = false,
                            accentColor = MaterialTheme.colorScheme.primary,
                        )
                    }
                    if (unit.researchRecords.isNotEmpty()) {
                        RecordGroup(
                            detectorId = detectorId,
                            unitId = unit.id,
                            title = recordGroupTitle(
                                EvidenceRecordKind.RESEARCH,
                                unit.researchRecords.size,
                            ),
                            records = unit.researchRecords,
                            initiallyExpanded = false,
                            accentColor = MaterialTheme.colorScheme.tertiary,
                        )
                    }
                    UnitTechnicalDefinition(
                        detectorId = detectorId,
                        unit = unit,
                    )
                }
            }
        }
    }
}

@Composable
private fun RecordGroup(
    detectorId: String,
    unitId: String,
    title: String,
    records: List<EvidenceRecordDetailUiModel>,
    initiallyExpanded: Boolean,
    accentColor: Color,
) {
    val kind = records.first().kind
    ExpandableGroup(
        title = title,
        stateKey = "$detectorId:$unitId:${kind.name}:group",
        initiallyExpanded = initiallyExpanded,
        accentColor = accentColor,
    ) {
        records.forEachIndexed { index, record ->
            EvidenceRecordItem(
                record = record,
                stateKey = "$detectorId:$unitId:${record.code}:$index",
                accentColor = accentColor,
            )
        }
    }
}

@Composable
private fun EvidenceRecordItem(
    record: EvidenceRecordDetailUiModel,
    stateKey: String,
    accentColor: Color,
) {
    var expanded by rememberSaveable("$stateKey:record") { mutableStateOf(false) }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surface,
        shape = MaterialTheme.shapes.small,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(role = Role.Button) { expanded = !expanded }
                    .semantics(mergeDescendants = true) {
                        stateDescription = if (expanded) "Expanded" else "Collapsed"
                        contentDescription = "${record.kind.name}: ${record.summary}"
                        role = Role.Button
                    }
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = record.summary,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        maxLines = if (expanded) Int.MAX_VALUE else 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                    record.signalStrength?.let { strength ->
                        Spacer(modifier = Modifier.height(4.dp))
                        SignalStrengthBadge(strength)
                    }
                }
                Spacer(modifier = Modifier.width(8.dp))
                ExpandIcon(expanded = expanded, tint = accentColor)
            }
            if (expanded) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    DetailValue(
                        value = DetailValueUiModel("Record Code", record.code, isMonospace = true),
                        stateKey = "$stateKey:code",
                    )
                    record.attributes.forEachIndexed { index, value ->
                        DetailValue(
                            value = value,
                            stateKey = "$stateKey:attribute:${value.label}:$index",
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun IssueGroup(
    detectorId: String,
    unitId: String,
    issues: List<EvidenceIssueDetailUiModel>,
) {
    val warningColor = LocalDetectionColors.current.warning
    ExpandableGroup(
        title = "資料取得問題 Issues (${issues.size})",
        stateKey = "$detectorId:$unitId:issues:group",
        initiallyExpanded = true,
        accentColor = warningColor,
    ) {
        issues.forEachIndexed { index, issue ->
            EvidenceIssueItem(
                issue = issue,
                stateKey = "$detectorId:$unitId:${issue.code}:$index",
                accentColor = warningColor,
            )
        }
    }
}

@Composable
private fun EvidenceIssueItem(
    issue: EvidenceIssueDetailUiModel,
    stateKey: String,
    accentColor: Color,
) {
    var expanded by rememberSaveable("$stateKey:issue") { mutableStateOf(false) }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surface,
        shape = MaterialTheme.shapes.small,
        border = BorderStroke(1.dp, accentColor.copy(alpha = 0.35f)),
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(role = Role.Button) { expanded = !expanded }
                    .semantics(mergeDescendants = true) {
                        stateDescription = if (expanded) "Expanded" else "Collapsed"
                        contentDescription = "Collection issue: ${issue.message}"
                        role = Role.Button
                    }
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = issue.message,
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    maxLines = if (expanded) Int.MAX_VALUE else 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(modifier = Modifier.width(8.dp))
                ExpandIcon(expanded = expanded, tint = accentColor)
            }
            if (expanded) {
                HorizontalDivider(color = accentColor.copy(alpha = 0.25f))
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    DetailValue(
                        value = DetailValueUiModel("Issue Code", issue.code, isMonospace = true),
                        stateKey = "$stateKey:code",
                    )
                    issue.attributes.forEachIndexed { index, value ->
                        DetailValue(
                            value = value,
                            stateKey = "$stateKey:attribute:${value.label}:$index",
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun UnitTechnicalDefinition(
    detectorId: String,
    unit: EvidenceUnitDetailUiModel,
) {
    val values = listOf(
        DetailValueUiModel("Observed Object", unit.observedObject),
        DetailValueUiModel("Proposition", unit.proposition),
        DetailValueUiModel("Observation Channel", unit.observationChannel),
        DetailValueUiModel("Availability", unit.availability),
        DetailValueUiModel("Trust Boundary", unit.trustBoundary),
        DetailValueUiModel("Inference Limit", unit.inferenceLimit),
    )
    ExpandableGroup(
        title = "技術定義 Evidence Model",
        stateKey = "$detectorId:${unit.id}:evidence-model",
        initiallyExpanded = false,
        accentColor = MaterialTheme.colorScheme.onSurfaceVariant,
    ) {
        DetailValue(
            value = DetailValueUiModel("Evidence Domain", unit.domainTitle),
            stateKey = "$detectorId:${unit.id}:domain",
        )
        values.forEachIndexed { index, value ->
            DetailValue(
                value = value,
                stateKey = "$detectorId:${unit.id}:model:${value.label}:$index",
            )
        }
    }
}

@Composable
private fun DetectorMetadataSection(detail: DetectionDetailUiModel) {
    ExpandableGroup(
        title = "整合資訊 Integration Metadata",
        stateKey = "${detail.id}:integration-metadata",
        initiallyExpanded = false,
        accentColor = MaterialTheme.colorScheme.onSurfaceVariant,
    ) {
        DetailValue(
            value = DetailValueUiModel("Primary Evidence Domain", detail.primaryEvidenceDomainTitle),
            stateKey = "${detail.id}:metadata:primary-domain",
        )
        DetailValue(
            value = DetailValueUiModel(
                "Direct Evidence Domains",
                detail.evidenceDomainTags.joinToString { it.title }.ifBlank { "None" },
            ),
            stateKey = "${detail.id}:metadata:direct-domains",
        )
        DetailValue(
            value = DetailValueUiModel("Payload Schema", detail.payloadSchemaVersion.toString()),
            stateKey = "${detail.id}:metadata:payload-schema",
        )
    }
}

@Composable
private fun ExpandableGroup(
    title: String,
    stateKey: String,
    initiallyExpanded: Boolean,
    accentColor: Color,
    content: @Composable () -> Unit,
) {
    var expanded by rememberSaveable(stateKey) { mutableStateOf(initiallyExpanded) }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.small,
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.28f),
        border = BorderStroke(1.dp, accentColor.copy(alpha = 0.28f)),
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(role = Role.Button) { expanded = !expanded }
                    .semantics(mergeDescendants = true) {
                        stateDescription = if (expanded) "Expanded" else "Collapsed"
                        contentDescription = title
                        role = Role.Button
                    }
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = title,
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = accentColor,
                )
                Spacer(modifier = Modifier.width(8.dp))
                ExpandIcon(expanded = expanded, tint = accentColor)
            }
            if (expanded) {
                HorizontalDivider(color = accentColor.copy(alpha = 0.22f))
                Column(
                    modifier = Modifier.padding(10.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    content()
                }
            }
        }
    }
}

@Composable
private fun DetailValue(
    value: DetailValueUiModel,
    stateKey: String,
) {
    val context = LocalContext.current
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = value.label,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (shouldOfferCopy(value)) {
                TextButton(
                    onClick = { copyToClipboard(context, value.label, value.value) },
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                ) {
                    Text("Copy")
                }
            }
        }
        ExpandableText(
            text = value.value,
            stateKey = "$stateKey:value",
            collapsedMaxLines = 3,
            style = if (value.isMonospace) {
                MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace)
            } else {
                MaterialTheme.typography.bodyMedium
            },
            selectable = true,
        )
    }
}

@Composable
private fun ExpandableText(
    text: String,
    stateKey: String,
    collapsedMaxLines: Int,
    style: TextStyle,
    selectable: Boolean = false,
) {
    var expanded by rememberSaveable(stateKey) { mutableStateOf(false) }
    var hasOverflow by remember(text) { mutableStateOf(false) }

    Column {
        val textContent: @Composable () -> Unit = {
            Text(
                text = text,
                style = style,
                maxLines = if (expanded) Int.MAX_VALUE else collapsedMaxLines,
                overflow = TextOverflow.Ellipsis,
                onTextLayout = { result ->
                    if (!expanded) hasOverflow = result.hasVisualOverflow
                },
            )
        }
        if (selectable) {
            SelectionContainer(content = textContent)
        } else {
            textContent()
        }
        if (hasOverflow || expanded) {
            TextButton(
                onClick = { expanded = !expanded },
                contentPadding = PaddingValues(horizontal = 0.dp, vertical = 0.dp),
            ) {
                Text(if (expanded) "收合全文" else "顯示全文")
            }
        }
    }
}

@Composable
private fun ExpandIcon(
    expanded: Boolean,
    tint: Color = MaterialTheme.colorScheme.onSurfaceVariant,
) {
    Icon(
        imageVector = if (expanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
        contentDescription = null,
        tint = tint,
        modifier = Modifier.size(24.dp),
    )
}

@Composable
private fun DetailBadge(
    label: String,
    containerColor: Color,
    contentColor: Color,
    description: String,
) {
    Surface(
        color = containerColor,
        contentColor = contentColor,
        shape = MaterialTheme.shapes.extraSmall,
        modifier = Modifier.semantics { contentDescription = description },
    ) {
        Text(
            text = label,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Composable
private fun UnitStatusBadge(status: EvidenceUnitCollectionStatus) {
    val colors = LocalDetectionColors.current
    val (container, content) = when (status) {
        EvidenceUnitCollectionStatus.COMPLETE -> colors.safeContainer to colors.safe
        EvidenceUnitCollectionStatus.PARTIAL -> colors.warningContainer to colors.warning
        EvidenceUnitCollectionStatus.UNAVAILABLE -> colors.unknownContainer to colors.unknown
    }
    DetailBadge(
        label = status.name,
        containerColor = container.copy(alpha = 0.7f),
        contentColor = content,
        description = "Collection Status: ${status.name}",
    )
}

@Composable
private fun SignalStrengthBadge(strength: EvidenceStrength) {
    val color = assessmentDisplayColor(DetectionOutcome.OBSERVED, strength)
    val container = assessmentContainerColor(DetectionOutcome.OBSERVED, strength)
    DetailBadge(
        label = strength.name,
        containerColor = container.copy(alpha = 0.55f),
        contentColor = color,
        description = "Signal Strength: ${strength.name}",
    )
}

internal fun recordGroupTitle(kind: EvidenceRecordKind, count: Int): String = when (kind) {
    EvidenceRecordKind.SIGNAL -> "判定依據 Signal ($count)"
    EvidenceRecordKind.OBSERVATION -> "觀察內容 Observation ($count)"
    EvidenceRecordKind.RESEARCH -> "研究資料 Research ($count)"
}

internal fun detailSummaryText(detail: DetectionDetailUiModel): String {
    val parts = mutableListOf(pluralized(detail.units.size, "Unit"))
    if (detail.signalCount > 0) parts += pluralized(detail.signalCount, "Signal")
    if (detail.observationCount > 0) parts += pluralized(detail.observationCount, "Observation")
    if (detail.researchCount > 0) parts += pluralized(detail.researchCount, "Research record")
    if (detail.issueCount > 0) parts += pluralized(detail.issueCount, "Issue")
    return parts.joinToString(" · ")
}

internal fun unitSummaryText(unit: EvidenceUnitDetailUiModel): String {
    val parts = mutableListOf<String>()
    if (unit.signals.isNotEmpty()) parts += pluralized(unit.signals.size, "Signal")
    if (unit.observations.isNotEmpty()) parts += pluralized(unit.observations.size, "Observation")
    if (unit.researchRecords.isNotEmpty()) {
        parts += pluralized(unit.researchRecords.size, "Research record")
    }
    if (unit.issues.isNotEmpty()) parts += pluralized(unit.issues.size, "Issue")
    return parts.ifEmpty { listOf("No published records") }.joinToString(" · ")
}

internal fun shouldOfferCopy(value: DetailValueUiModel): Boolean = value.isMonospace ||
    value.value.length > 80 ||
    value.value.contains('\n')

private fun pluralized(count: Int, singular: String): String =
    "$count $singular${if (count == 1) "" else "s"}"

private fun copyToClipboard(context: Context, label: String, value: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
}
