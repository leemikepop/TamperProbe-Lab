package io.leemikepop.tamperprobe.lab.presentation.components.details

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.AlignmentLine
import androidx.compose.ui.layout.FirstBaseline
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.dp
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.presentation.components.CollectionStatusChip
import io.leemikepop.tamperprobe.lab.presentation.components.DomainChip
import io.leemikepop.tamperprobe.lab.presentation.components.InfoChip
import io.leemikepop.tamperprobe.lab.presentation.components.OutcomeChip
import io.leemikepop.tamperprobe.lab.presentation.components.StrengthChip
import io.leemikepop.tamperprobe.lab.presentation.model.AttributeNodeUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.AttributeNodeUiModel.GroupKind
import io.leemikepop.tamperprobe.lab.presentation.model.DetectionDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.DetectorCollectionErrorUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceIssueDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceRecordDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceUnitDetailUiModel
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
            .padding(horizontal = 16.dp),
        contentPadding = PaddingValues(top = 0.dp, bottom = 32.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item(key = "${detail.id}:header") {
            DetectorDetailHeader(detail = detail, onDismiss = onDismiss)
        }

        detail.collectionError?.let { error ->
            item(key = "${detail.id}:collection-error") {
                DetectorCollectionErrorCard(detectorId = detail.id, error = error)
            }
        }

        if (detail.units.isNotEmpty()) {
            item(key = "${detail.id}:units-heading") {
                SectionHeading(text = "Evidence units", count = detail.units.size)
            }
        }

        items(
            items = detail.units,
            key = { unit -> "${detail.id}:${unit.id}" },
        ) { unit ->
            EvidenceUnitCard(detectorId = detail.id, unit = unit)
        }

        item(key = "${detail.id}:integration-metadata") {
            DetectorMetadataSection(detail = detail)
        }
    }
}

// region Detector level

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DetectorDetailHeader(
    detail: DetectionDetailUiModel,
    onDismiss: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.Top,
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Text(
                    text = detail.title,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.semantics { heading() },
                )
                Text(
                    text = detail.id,
                    style = MonospaceSmall,
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
            OutcomeChip(outcome = detail.outcome, strength = detail.evidenceStrength)
            StrengthChip(strength = detail.evidenceStrength, outcome = detail.outcome)
            detail.evidenceDomainTags.forEach { domain ->
                DomainChip(
                    shortTitle = domain.shortTitle,
                    title = domain.title,
                    isPrimary = domain.isPrimary,
                )
            }
        }

        ExpandableText(
            text = detail.description,
            stateKey = "${detail.id}:description",
            collapsedMaxLines = 3,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
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
private fun SectionHeading(text: String, count: Int? = null) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 2.dp)
            .semantics(mergeDescendants = true) { heading() },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onSurface,
        )
        if (count != null) CountPill(count)
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
        color = detectionColors.dangerContainer.copy(alpha = 0.35f),
        border = BorderStroke(1.dp, detectionColors.danger.copy(alpha = 0.45f)),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = "Collection error",
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
            FieldRow(
                label = "Error code",
                value = error.code,
                isMonospace = true,
                stateKey = "$detectorId:collection-error:code",
            )
            FieldRow(
                label = "Recoverable",
                value = if (error.recoverable) "Yes" else "No",
                isMonospace = false,
                stateKey = "$detectorId:collection-error:recoverable",
            )
        }
    }
}

@Composable
private fun DetectorMetadataSection(detail: DetectionDetailUiModel) {
    ExpandableGroup(
        title = "Integration metadata",
        count = null,
        stateKey = "${detail.id}:integration-metadata",
        initiallyExpanded = false,
        accentColor = MaterialTheme.colorScheme.outline,
    ) {
        FieldRow(
            label = "Primary evidence domain",
            value = detail.primaryEvidenceDomainTitle,
            isMonospace = false,
            stateKey = "${detail.id}:metadata:primary-domain",
        )
        FieldRow(
            label = "Direct evidence domains",
            value = detail.evidenceDomainTags.joinToString { it.title }.ifBlank { "None" },
            isMonospace = false,
            stateKey = "${detail.id}:metadata:direct-domains",
        )
        FieldRow(
            label = "Payload schema",
            value = detail.payloadSchemaVersion.toString(),
            isMonospace = false,
            stateKey = "${detail.id}:metadata:payload-schema",
        )
    }
}

// endregion

// region Unit level

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun EvidenceUnitCard(
    detectorId: String,
    unit: EvidenceUnitDetailUiModel,
) {
    var expanded by rememberSaveable("$detectorId:${unit.id}:unit") {
        mutableStateOf(unit.initiallyExpanded)
    }
    val colors = LocalDetectionColors.current

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(role = Role.Button) { expanded = !expanded }
                    .semantics(mergeDescendants = true) {
                        stateDescription = if (expanded) "Expanded" else "Collapsed"
                        contentDescription =
                            "${unit.title}, collection ${unit.collectionStatus.name}"
                        role = Role.Button
                    }
                    .padding(start = 16.dp, end = 12.dp, top = 14.dp, bottom = 14.dp),
                verticalAlignment = Alignment.Top,
            ) {
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(
                            text = unit.title,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            text = unit.id,
                            style = MonospaceSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        CollectionStatusChip(unit.collectionStatus)
                        DomainChip(
                            shortTitle = unit.domainShortTitle,
                            title = unit.domainTitle,
                            isPrimary = false,
                            descriptionPrefix = "Evidence domain",
                        )
                    }
                    Text(
                        text = unitSummaryText(unit),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(modifier = Modifier.width(8.dp))
                ExpandIcon(expanded = expanded)
            }

            if (expanded) {
                Column(
                    modifier = Modifier.padding(start = 12.dp, end = 12.dp, bottom = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (unit.signals.isNotEmpty()) {
                        RecordGroup(
                            detectorId = detectorId,
                            unitId = unit.id,
                            kind = EvidenceRecordKind.SIGNAL,
                            records = unit.signals,
                            initiallyExpanded = true,
                            accentColor = colors.danger,
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
                            kind = EvidenceRecordKind.OBSERVATION,
                            records = unit.observations,
                            initiallyExpanded = false,
                            accentColor = MaterialTheme.colorScheme.primary,
                        )
                    }
                    if (unit.researchRecords.isNotEmpty()) {
                        RecordGroup(
                            detectorId = detectorId,
                            unitId = unit.id,
                            kind = EvidenceRecordKind.RESEARCH,
                            records = unit.researchRecords,
                            initiallyExpanded = false,
                            accentColor = MaterialTheme.colorScheme.tertiary,
                        )
                    }
                    UnitEvidenceModel(detectorId = detectorId, unit = unit)
                }
            }
        }
    }
}

@Composable
private fun UnitEvidenceModel(
    detectorId: String,
    unit: EvidenceUnitDetailUiModel,
) {
    val values = listOf(
        "Evidence domain" to unit.domainTitle,
        "Observed object" to unit.observedObject,
        "Proposition" to unit.proposition,
        "Observation channel" to unit.observationChannel,
        "Availability" to unit.availability,
        "Trust boundary" to unit.trustBoundary,
        "Inference limit" to unit.inferenceLimit,
    )
    ExpandableGroup(
        title = "Evidence model",
        count = null,
        stateKey = "$detectorId:${unit.id}:evidence-model",
        initiallyExpanded = false,
        accentColor = MaterialTheme.colorScheme.outline,
    ) {
        values.forEach { (label, value) ->
            FieldRow(
                label = label,
                value = value,
                isMonospace = false,
                stateKey = "$detectorId:${unit.id}:model:$label",
                forceStacked = true,
            )
        }
    }
}

// endregion

// region Records and issues

@Composable
private fun RecordGroup(
    detectorId: String,
    unitId: String,
    kind: EvidenceRecordKind,
    records: List<EvidenceRecordDetailUiModel>,
    initiallyExpanded: Boolean,
    accentColor: Color,
) {
    ExpandableGroup(
        title = recordGroupLabel(kind),
        count = records.size,
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

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun EvidenceRecordItem(
    record: EvidenceRecordDetailUiModel,
    stateKey: String,
    accentColor: Color,
) {
    var expanded by rememberSaveable("$stateKey:record") { mutableStateOf(false) }
    val concealable = record.isConcealableNegative
    val warning = LocalDetectionColors.current.warning
    val fieldCount = countValues(record.attributeTree)

    DetailItemSurface(borderColor = if (concealable) warning.copy(alpha = 0.55f) else null) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(role = Role.Button) { expanded = !expanded }
                .semantics(mergeDescendants = true) {
                    stateDescription = if (expanded) "Expanded" else "Collapsed"
                    contentDescription = buildString {
                        append(recordKindLabel(record.kind))
                        if (concealable) append(", concealable negative")
                        append(": ")
                        append(record.summary)
                    }
                    role = Role.Button
                }
                .padding(start = 12.dp, end = 8.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = record.summary,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    maxLines = if (expanded) Int.MAX_VALUE else 3,
                    overflow = TextOverflow.Ellipsis,
                )
                val strength = record.signalStrength
                if (strength != null || concealable || fieldCount > 0) {
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                        itemVerticalAlignment = Alignment.CenterVertically,
                    ) {
                        if (strength != null) {
                            StrengthChip(
                                strength = strength,
                                outcome = DetectionOutcome.OBSERVED,
                                caption = "Signal",
                            )
                        }
                        if (concealable) ConcealableNegativeChip()
                        if (fieldCount > 0) {
                            Text(
                                text = pluralized(fieldCount, "value"),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
            ExpandIcon(expanded = expanded, tint = accentColor)
        }
        if (expanded) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                CodeLine(code = record.code)
                if (concealable) {
                    Text(
                        text = CONCEALABLE_NEGATIVE_NOTE,
                        style = MaterialTheme.typography.bodySmall,
                        color = warning,
                    )
                }
                AttributeTree(nodes = record.attributeTree, stateKey = "$stateKey:attr")
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
        title = "Collection issues",
        count = issues.size,
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
    val fieldCount = countValues(issue.attributeTree)
    DetailItemSurface(borderColor = null) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(role = Role.Button) { expanded = !expanded }
                .semantics(mergeDescendants = true) {
                    stateDescription = if (expanded) "Expanded" else "Collapsed"
                    contentDescription = "Collection issue: ${issue.message}"
                    role = Role.Button
                }
                .padding(start = 12.dp, end = 8.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = issue.message,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    maxLines = if (expanded) Int.MAX_VALUE else 3,
                    overflow = TextOverflow.Ellipsis,
                )
                if (fieldCount > 0) {
                    Text(
                        text = pluralized(fieldCount, "value"),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            ExpandIcon(expanded = expanded, tint = accentColor)
        }
        if (expanded) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                CodeLine(code = issue.code)
                AttributeTree(nodes = issue.attributeTree, stateKey = "$stateKey:attr")
            }
        }
    }
}

@Composable
private fun DetailItemSurface(
    borderColor: Color?,
    content: @Composable () -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surface,
        shape = MaterialTheme.shapes.small,
        border = BorderStroke(1.dp, borderColor ?: MaterialTheme.colorScheme.outlineVariant),
    ) {
        Column { content() }
    }
}

@Composable
private fun ConcealableNegativeChip() {
    val warning = LocalDetectionColors.current.warning
    InfoChip(
        text = "Concealable negative",
        containerColor = Color.Transparent,
        contentColor = warning,
        borderColor = warning.copy(alpha = 0.6f),
        description = "Concealable negative: hiding tools can produce this same absence",
    )
}

@Composable
private fun CodeLine(code: String) {
    Row(verticalAlignment = Alignment.Top) {
        Text(
            text = "Code",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(44.dp),
        )
        SelectionContainer {
            Text(
                text = code,
                style = MonospaceSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// endregion

// region Attribute tree

@Composable
private fun AttributeTree(
    nodes: List<AttributeNodeUiModel>,
    stateKey: String,
) {
    if (nodes.isEmpty()) return
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        nodes.forEachIndexed { index, node ->
            AttributeNode(node = node, stateKey = "$stateKey/$index")
        }
    }
}

@Composable
private fun AttributeNode(
    node: AttributeNodeUiModel,
    stateKey: String,
) {
    when (node) {
        is AttributeNodeUiModel.Field -> FieldRow(
            label = node.label,
            value = node.value,
            isMonospace = node.isMonospace,
            stateKey = stateKey,
        )
        is AttributeNodeUiModel.ValueList -> ValueListRow(node = node, stateKey = stateKey)
        is AttributeNodeUiModel.Group -> when (node.kind) {
            GroupKind.SECTION -> AttributeSection(node = node, stateKey = stateKey)
            GroupKind.LIST -> AttributeList(node = node, stateKey = stateKey)
            GroupKind.LIST_ITEM -> AttributeListItem(node = node, stateKey = stateKey)
        }
    }
}

/** A nested object: a heading, then its fields behind a thin rule. */
@Composable
private fun AttributeSection(
    node: AttributeNodeUiModel.Group,
    stateKey: String,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(
            text = node.title,
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.semantics { heading() },
        )
        RuledBlock {
            AttributeTree(nodes = node.children, stateKey = stateKey)
        }
    }
}

/** An indexed list of objects: one tinted block per item. */
@Composable
private fun AttributeList(
    node: AttributeNodeUiModel.Group,
    stateKey: String,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            modifier = Modifier.semantics(mergeDescendants = true) { heading() },
        ) {
            Text(
                text = node.title,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.primary,
            )
            CountPill(node.children.size)
        }
        node.children.forEachIndexed { index, child ->
            AttributeNode(node = child, stateKey = "$stateKey/$index")
        }
    }
}

@Composable
private fun AttributeListItem(
    node: AttributeNodeUiModel.Group,
    stateKey: String,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.small,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text = node.title,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            AttributeTree(nodes = node.children, stateKey = stateKey)
        }
    }
}

/** Plain indexed values on one row: chips when short, a numbered list when long. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ValueListRow(
    node: AttributeNodeUiModel.ValueList,
    stateKey: String,
) {
    val single = node.values.singleOrNull()
    if (single != null) {
        FieldRow(
            label = node.label,
            value = single.value,
            isMonospace = single.isMonospace,
            stateKey = stateKey,
        )
        return
    }
    val compact = node.values.all { it.value.isNotBlank() && it.value.length <= CHIP_MAX_LENGTH }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            FieldLabel(text = node.label)
            CountPill(node.values.size)
        }
        if (compact) {
            SelectionContainer {
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    node.values.forEach { value ->
                        InfoChip(
                            text = value.value,
                            containerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
                            contentColor = MaterialTheme.colorScheme.onSurface,
                            monospace = value.isMonospace,
                        )
                    }
                }
            }
        } else {
            node.values.forEachIndexed { index, value ->
                Row(verticalAlignment = Alignment.Top) {
                    Text(
                        text = value.label,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier
                            .widthIn(min = 28.dp)
                            .padding(top = 1.dp),
                    )
                    Box(modifier = Modifier.weight(1f)) {
                        ValueText(
                            value = value.value,
                            isMonospace = value.isMonospace,
                            stateKey = "$stateKey/$index",
                        )
                    }
                }
            }
        }
    }
}

/**
 * A label/value pair laid out as two columns when the value fits on one line of the value column;
 * longer values go below the label at full width, collapsed with a "Show more" toggle.
 */
@Composable
private fun FieldRow(
    label: String,
    value: String,
    isMonospace: Boolean,
    stateKey: String,
    forceStacked: Boolean = false,
) {
    val gap = 12.dp
    val stackSpacing = 2.dp
    Layout(
        contents = listOf(
            { FieldLabel(text = label) },
            { ValueText(value = value, isMonospace = isMonospace, stateKey = stateKey) },
        ),
        modifier = Modifier.fillMaxWidth(),
    ) { (labelMeasurables, valueMeasurables), constraints ->
        val labelMeasurable = labelMeasurables.single()
        val valueMeasurable = valueMeasurables.single()
        val width = constraints.maxWidth
        val valueX = (width * LABEL_COLUMN_FRACTION).toInt()
        val valueColumnWidth = width - valueX
        // Two columns when the whole value fits on one line of the value column; otherwise the
        // value goes under the label at full width so long tokens never break mid-word.
        val inline = !forceStacked &&
            !value.contains('\n') &&
            valueMeasurable.maxIntrinsicWidth(Constraints.Infinity) <= valueColumnWidth
        if (inline) {
            val labelPlaceable = labelMeasurable.measure(
                Constraints(maxWidth = (valueX - gap.roundToPx()).coerceAtLeast(0)),
            )
            val valuePlaceable = valueMeasurable.measure(Constraints(maxWidth = valueColumnWidth))
            val labelBaseline = labelPlaceable[FirstBaseline]
            val valueBaseline = valuePlaceable[FirstBaseline]
            val labelOffset = if (labelBaseline != AlignmentLine.Unspecified &&
                valueBaseline != AlignmentLine.Unspecified
            ) {
                (valueBaseline - labelBaseline).coerceAtLeast(0)
            } else {
                0
            }
            val height = maxOf(labelPlaceable.height + labelOffset, valuePlaceable.height)
            layout(width, height) {
                labelPlaceable.place(0, labelOffset)
                valuePlaceable.place(valueX, 0)
            }
        } else {
            val fullWidth = Constraints(maxWidth = width)
            val labelPlaceable = labelMeasurable.measure(fullWidth)
            val valuePlaceable = valueMeasurable.measure(fullWidth)
            val spacing = stackSpacing.roundToPx()
            layout(width, labelPlaceable.height + spacing + valuePlaceable.height) {
                labelPlaceable.place(0, 0)
                valuePlaceable.place(0, labelPlaceable.height + spacing)
            }
        }
    }
}

@Composable
private fun FieldLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        modifier = modifier,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun ValueText(
    value: String,
    isMonospace: Boolean,
    stateKey: String,
) {
    if (value.isBlank()) {
        ValueTextPlain(value = value, isMonospace = false)
        return
    }
    ExpandableText(
        text = value,
        stateKey = "$stateKey:value",
        collapsedMaxLines = if (isMonospace) 2 else 4,
        style = valueStyle(isMonospace),
        selectable = true,
    )
}

@Composable
private fun ValueTextPlain(
    value: String,
    isMonospace: Boolean,
) {
    if (value.isBlank()) {
        Text(
            text = EMPTY_VALUE,
            style = MaterialTheme.typography.bodyMedium,
            fontStyle = FontStyle.Italic,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    } else {
        Text(text = value, style = valueStyle(isMonospace))
    }
}

@Composable
private fun valueStyle(isMonospace: Boolean): TextStyle = if (isMonospace) {
    MonospaceValue
} else {
    MaterialTheme.typography.bodyMedium
}

@Composable
private fun RuledBlock(content: @Composable () -> Unit) {
    Row(modifier = Modifier.height(IntrinsicSize.Min)) {
        Box(
            modifier = Modifier
                .width(2.dp)
                .fillMaxHeight()
                .background(
                    MaterialTheme.colorScheme.outlineVariant,
                    RoundedCornerShape(1.dp),
                ),
        )
        Spacer(modifier = Modifier.width(10.dp))
        Box(modifier = Modifier.weight(1f)) { content() }
    }
}

private fun countValues(nodes: List<AttributeNodeUiModel>): Int = nodes.sumOf { node ->
    when (node) {
        is AttributeNodeUiModel.Field -> 1
        is AttributeNodeUiModel.ValueList -> node.values.size
        is AttributeNodeUiModel.Group -> countValues(node.children)
    }
}

// endregion

// region Shared building blocks

@Composable
private fun ExpandableGroup(
    title: String,
    count: Int?,
    stateKey: String,
    initiallyExpanded: Boolean,
    accentColor: Color,
    content: @Composable () -> Unit,
) {
    var expanded by rememberSaveable(stateKey) { mutableStateOf(initiallyExpanded) }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.small,
        color = MaterialTheme.colorScheme.surfaceContainer,
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(role = Role.Button) { expanded = !expanded }
                    .semantics(mergeDescendants = true) {
                        stateDescription = if (expanded) "Expanded" else "Collapsed"
                        contentDescription = if (count == null) title else "$title ($count)"
                        role = Role.Button
                    }
                    .padding(start = 12.dp, end = 8.dp, top = 10.dp, bottom = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(width = 4.dp, height = 16.dp)
                        .background(accentColor, RoundedCornerShape(2.dp)),
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                if (count != null) {
                    Spacer(modifier = Modifier.width(8.dp))
                    CountPill(count)
                }
                Spacer(modifier = Modifier.weight(1f))
                ExpandIcon(expanded = expanded, tint = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (expanded) {
                Column(
                    modifier = Modifier.padding(start = 8.dp, end = 8.dp, bottom = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    content()
                }
            }
        }
    }
}

@Composable
private fun CountPill(count: Int) {
    Surface(
        shape = RoundedCornerShape(50),
        color = MaterialTheme.colorScheme.surfaceContainerHighest,
        contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
    ) {
        Text(
            text = count.toString(),
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 1.dp),
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Composable
private fun ExpandableText(
    text: String,
    stateKey: String,
    collapsedMaxLines: Int,
    style: TextStyle,
    color: Color = Color.Unspecified,
    selectable: Boolean = false,
) {
    var expanded by rememberSaveable(stateKey) { mutableStateOf(false) }
    var hasOverflow by remember(text) { mutableStateOf(false) }

    Column {
        val textContent: @Composable () -> Unit = {
            Text(
                text = text,
                style = style,
                color = color,
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
            Text(
                text = if (expanded) "Show less" else "Show more",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier
                    .clickable(role = Role.Button) { expanded = !expanded }
                    .padding(top = 4.dp, bottom = 2.dp),
            )
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

private val MonospaceSmall: TextStyle
    @Composable get() = MaterialTheme.typography.labelMedium.copy(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Normal,
    )

private val MonospaceValue: TextStyle
    @Composable get() = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace)

// endregion

/** Share of a field row given to the label column when label and value sit side by side. */
private const val LABEL_COLUMN_FRACTION = 0.45f
private const val CHIP_MAX_LENGTH = 28
private const val EMPTY_VALUE = "(empty)"
internal const val CONCEALABLE_NEGATIVE_NOTE =
    "Concealable negative: a hiding tool can produce this same absence, so it does not show " +
        "that the artifact is absent."

internal fun recordKindLabel(kind: EvidenceRecordKind): String = when (kind) {
    EvidenceRecordKind.SIGNAL -> "Signal"
    EvidenceRecordKind.OBSERVATION -> "Observation"
    EvidenceRecordKind.RESEARCH -> "Research"
}

internal fun recordGroupLabel(kind: EvidenceRecordKind): String = when (kind) {
    EvidenceRecordKind.SIGNAL -> "Signals"
    EvidenceRecordKind.OBSERVATION -> "Observations"
    EvidenceRecordKind.RESEARCH -> "Research records"
}

internal fun recordGroupTitle(kind: EvidenceRecordKind, count: Int): String =
    "${recordGroupLabel(kind)} ($count)"

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

private fun pluralized(count: Int, singular: String): String =
    "$count $singular${if (count == 1) "" else "s"}"
