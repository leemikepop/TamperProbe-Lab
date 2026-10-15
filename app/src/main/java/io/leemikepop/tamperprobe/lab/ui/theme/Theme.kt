package io.leemikepop.tamperprobe.lab.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontWeight
import androidx.core.view.WindowCompat

/**
 * Detection-specific semantic colors, separate from MaterialTheme
 */
data class DetectionColorScheme(
    val safe: Color,
    val safeContainer: Color,
    val warning: Color,
    val warningContainer: Color,
    val danger: Color,
    val dangerContainer: Color,
    val unknown: Color,
    val unknownContainer: Color,
    val summaryClean: Color,
    val summaryDanger: Color,
)

val LightDetectionColors = DetectionColorScheme(
    safe = SafeGreenLight,
    safeContainer = SafeGreenContainerLight,
    warning = WarningAmberLight,
    warningContainer = WarningAmberContainerLight,
    danger = DangerRedLight,
    dangerContainer = DangerRedContainerLight,
    unknown = UnknownGrayLight,
    unknownContainer = UnknownGrayContainerLight,
    summaryClean = SummaryCleanLight,
    summaryDanger = SummaryDangerLight,
)

val DarkDetectionColors = DetectionColorScheme(
    safe = SafeGreenDark,
    safeContainer = SafeGreenContainerDark,
    warning = WarningAmberDark,
    warningContainer = WarningAmberContainerDark,
    danger = DangerRedDark,
    dangerContainer = DangerRedContainerDark,
    unknown = UnknownGrayDark,
    unknownContainer = UnknownGrayContainerDark,
    summaryClean = SummaryCleanDark,
    summaryDanger = SummaryDangerDark,
)

val LocalDetectionColors = staticCompositionLocalOf { LightDetectionColors }

private val DarkColorScheme = darkColorScheme()
private val LightColorScheme = lightColorScheme()

private val AppTypography = Typography(
    displayLarge = Typography().displayLarge.copy(fontWeight = FontWeight.Bold),
    headlineLarge = Typography().headlineLarge.copy(fontWeight = FontWeight.SemiBold),
    headlineMedium = Typography().headlineMedium.copy(fontWeight = FontWeight.SemiBold),
    titleLarge = Typography().titleLarge.copy(fontWeight = FontWeight.SemiBold),
    titleMedium = Typography().titleMedium.copy(fontWeight = FontWeight.Medium),
)

@Composable
fun TamperProbeTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !darkTheme
        }
    }

    val detectionColors = if (darkTheme) DarkDetectionColors else LightDetectionColors

    CompositionLocalProvider(LocalDetectionColors provides detectionColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = AppTypography,
            content = content
        )
    }
}
