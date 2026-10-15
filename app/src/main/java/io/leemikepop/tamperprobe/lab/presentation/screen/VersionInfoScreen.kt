package io.leemikepop.tamperprobe.lab.presentation.screen

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.leemikepop.tamperprobe.lab.BuildConfig

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VersionInfoScreen(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text("Version Information") },
            expandedHeight = 52.dp,
            windowInsets = WindowInsets(0, 0, 0, 0),
            navigationIcon = {
                IconButton(onClick = onBack) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = "Back",
                    )
                }
            },
        )
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                VersionSection(
                    title = "App Build",
                    rows = listOf(
                        VersionRow("Version", BuildConfig.VERSION_NAME),
                        VersionRow("Version Code", BuildConfig.VERSION_CODE.toString()),
                        VersionRow("Commit", BuildConfig.GIT_COMMIT, isMonospace = true),
                        VersionRow(
                            "Source State",
                            if (BuildConfig.GIT_DIRTY) "Dirty" else "Clean",
                        ),
                        VersionRow("Build Type", BuildConfig.BUILD_TYPE),
                    ),
                )
            }
            item {
                VersionSection(
                    title = "TamperProbe Core",
                    rows = listOf(
                        VersionRow("Engine Version", BuildConfig.TAMPERPROBE_ENGINE_VERSION),
                        VersionRow("Catalog Version", BuildConfig.TAMPERPROBE_CATALOG_VERSION),
                        VersionRow(
                            "Wire Schema",
                            BuildConfig.TAMPERPROBE_WIRE_SCHEMA_VERSION.toString(),
                        ),
                    ),
                )
            }
        }
    }
}

@Composable
private fun VersionSection(
    title: String,
    rows: List<VersionRow>,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = title,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            rows.forEachIndexed { index, row ->
                if (index > 0) {
                    HorizontalDivider()
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = row.label,
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = row.value,
                        style = if (row.isMonospace) {
                            MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace)
                        } else {
                            MaterialTheme.typography.bodyMedium
                        },
                    )
                }
            }
        }
    }
}

private data class VersionRow(
    val label: String,
    val value: String,
    val isMonospace: Boolean = false,
)
