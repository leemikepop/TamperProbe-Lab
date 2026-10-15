package io.leemikepop.tamperprobe.lab.presentation.screen

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.activity.compose.BackHandler
import androidx.lifecycle.viewmodel.compose.viewModel
import io.leemikepop.tamperprobe.lab.presentation.components.InfoCardItem
import io.leemikepop.tamperprobe.lab.presentation.components.details.DetectorDetailBottomSheet
import io.leemikepop.tamperprobe.lab.presentation.model.DetectionCardUiModel
import io.leemikepop.tamperprobe.lab.presentation.mapper.DetectionUiMapper
import io.leemikepop.tamperprobe.lab.presentation.viewmodel.TamperProbeViewModel
import io.leemikepop.tamperprobe.lab.ui.theme.LocalDetectionColors
import kotlinx.coroutines.flow.collect

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TamperProbeScreen(
    modifier: Modifier = Modifier,
    viewModel: TamperProbeViewModel = viewModel()
) {
    var showVersionInformation by rememberSaveable { mutableStateOf(false) }
    val snackbarHostState = remember { SnackbarHostState() }
    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        if (uri == null) {
            viewModel.cancelPendingExport()
        } else {
            viewModel.writePendingExport(uri)
        }
    }
    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                is TamperProbeViewModel.UiEvent.LaunchExport -> {
                    exportLauncher.launch(event.fileName)
                }
                is TamperProbeViewModel.UiEvent.ShowMessage -> {
                    snackbarHostState.showSnackbar(event.message)
                }
            }
        }
    }
    BackHandler(enabled = showVersionInformation) {
        showVersionInformation = false
    }

    Box(modifier = modifier.fillMaxSize()) {
        if (showVersionInformation) {
            VersionInfoScreen(
                onBack = { showVersionInformation = false },
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            Column(modifier = Modifier.fillMaxSize()) {
                TopAppBar(
                    title = { Text("TamperProbe") },
                    expandedHeight = 52.dp,
                    windowInsets = WindowInsets(0, 0, 0, 0),
                    actions = {
                        IconButton(onClick = { showVersionInformation = true }) {
                            Icon(
                                imageVector = Icons.Filled.Menu,
                                contentDescription = "Version information",
                            )
                        }
                    },
                )
                DashboardTab(viewModel = viewModel)
            }
        }
        SnackbarHost(
            hostState = snackbarHostState,
            modifier = Modifier.align(Alignment.BottomCenter),
        )
    }
}


@Composable
private fun DashboardTab(viewModel: TamperProbeViewModel) {
    val uiState by viewModel.uiState.collectAsState()
    var selectedCard by remember { mutableStateOf<DetectionCardUiModel?>(null) }

    val visibleCards = remember(uiState.cards, uiState.selectedEvidenceDomainId) {
        val selectedDomainId = uiState.selectedEvidenceDomainId
        DetectionUiMapper.filterByEvidenceDomain(uiState.cards, selectedDomainId)
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(vertical = 16.dp),
    ) {
        // === Summary Header ===
        item(key = "summary") {
            SummaryCard(
                isLoading = uiState.isLoading,
                observedCount = uiState.observedCount,
                resultCount = uiState.resultCount,
                scanDurationMillis = uiState.scanDurationMillis,
                canExport = uiState.canExport,
                isExporting = uiState.isExporting,
                error = uiState.error,
                onRescan = { viewModel.scanAllDetectors() },
                onExport = { viewModel.prepareExport() },
            )
        }

        // === Error ===
        if (uiState.error != null) {
            item(key = "error") {
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = "Error: ${uiState.error}",
                        modifier = Modifier.padding(16.dp),
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }
        }

        if (uiState.evidenceDomains.isNotEmpty()) {
            item(key = "evidence-domain-filter") {
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    item(key = "all") {
                        FilterChip(
                            selected = uiState.selectedEvidenceDomainId == null,
                            onClick = { viewModel.selectEvidenceDomain(null) },
                            label = { Text("All") },
                            modifier = Modifier.semantics {
                                contentDescription = "Show all Evidence Domains"
                            },
                        )
                    }
                    items(uiState.evidenceDomains, key = { it.id }) { domain ->
                        FilterChip(
                            selected = uiState.selectedEvidenceDomainId == domain.id,
                            onClick = { viewModel.selectEvidenceDomain(domain.id) },
                            label = { Text(domain.shortTitle) },
                            modifier = Modifier.semantics {
                                contentDescription = "Filter by ${domain.title}"
                            },
                        )
                    }
                }
            }
        }

        if (visibleCards.isNotEmpty()) {
            items(
                items = visibleCards,
                key = { it.id },
            ) { card ->
                InfoCardItem(
                    card = card,
                    onCardClick = { selectedCard = it },
                )
            }
        }
    }

    // Detail bottom sheet
    DetectorDetailBottomSheet(
        card = selectedCard,
        onDismiss = { selectedCard = null }
    )
}


@Composable
private fun SummaryCard(
    isLoading: Boolean,
    observedCount: Int,
    resultCount: Int,
    scanDurationMillis: Long?,
    canExport: Boolean,
    isExporting: Boolean,
    error: String?,
    onRescan: () -> Unit,
    onExport: () -> Unit,
) {
    val detectionColors = LocalDetectionColors.current
    val hasResults = resultCount > 0

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when {
                isLoading -> MaterialTheme.colorScheme.surfaceVariant
                error != null -> MaterialTheme.colorScheme.errorContainer
                hasResults -> detectionColors.safeContainer.copy(alpha = 0.4f)
                else -> MaterialTheme.colorScheme.surfaceVariant
            }
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
        ) {
            if (isLoading) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        strokeWidth = 3.dp,
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(
                        text = "Scanning...",
                        style = MaterialTheme.typography.titleMedium,
                    )
                }
            } else if (hasResults) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "Scan complete",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    SummaryMetricBadge(
                        label = "Observed",
                        value = "$observedCount / $resultCount",
                    )
                    if (scanDurationMillis != null) {
                        val durationText = if (scanDurationMillis >= 1000) {
                            "%.1fs".format(scanDurationMillis / 1000f)
                        } else {
                            "${scanDurationMillis}ms"
                        }
                        SummaryMetricBadge(
                            label = "Time",
                            value = durationText,
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "Raw report · no policy applied",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                    )
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        OutlinedButton(
                            onClick = onExport,
                            enabled = canExport && !isExporting,
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                        ) {
                            if (isExporting) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(14.dp),
                                    strokeWidth = 2.dp,
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                            }
                            Text(text = "Export JSON", maxLines = 1, style = MaterialTheme.typography.labelMedium)
                        }
                        FilledTonalButton(
                            onClick = onRescan,
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                        ) {
                            Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(text = "Re-scan", maxLines = 1, style = MaterialTheme.typography.labelMedium)
                        }
                    }
                }
            } else {
                // Initial state — should auto-trigger, but just in case
                Text(
                    text = "TamperProbe",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Preparing detection engine...",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun SummaryMetricBadge(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        shape = MaterialTheme.shapes.extraSmall,
        color = MaterialTheme.colorScheme.surface.copy(alpha = 0.55f),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = value,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}
