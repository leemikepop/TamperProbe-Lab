package io.leemikepop.tamperprobe.lab.presentation.components.details

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.leemikepop.tamperprobe.lab.presentation.model.DetectionCardUiModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DetectorDetailBottomSheet(
    card: DetectionCardUiModel?,
    onDismiss: () -> Unit,
) {
    if (card == null) return

    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.94f),
            contentAlignment = Alignment.TopCenter,
        ) {
            DetectorDetailContent(
                detail = card.detail,
                onDismiss = onDismiss,
                modifier = Modifier
                    .fillMaxHeight()
                    .widthIn(max = 720.dp)
                    .fillMaxWidth(),
            )
        }
    }
}
