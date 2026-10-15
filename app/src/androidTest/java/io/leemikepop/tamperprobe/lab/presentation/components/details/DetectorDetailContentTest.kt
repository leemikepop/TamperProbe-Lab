package io.leemikepop.tamperprobe.lab.presentation.components.details

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.presentation.model.DetailValueUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.DetectionDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceDomainTagUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceRecordDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceUnitDetailUiModel
import io.leemikepop.tamperprobe.lab.ui.theme.TamperProbeTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DetectorDetailContentTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun signalIsVisibleAndObservationExpandsOnDemand() {
        composeRule.setContent {
            TamperProbeTheme(dynamicColor = false) {
                DetectorDetailContent(
                    detail = detail(),
                    onDismiss = {},
                )
            }
        }

        composeRule.onNodeWithText("Direct Marker").assertIsDisplayed()
        composeRule.onNodeWithText("判定依據 Signal (1)").assertIsDisplayed()
        composeRule.onNodeWithText("Direct signal").assertIsDisplayed().performClick()
        composeRule.onNodeWithText("TEST.direct.signal").assertIsDisplayed()

        composeRule.onNodeWithText("觀察內容 Observation (1)").assertIsDisplayed().performClick()
        composeRule.onNodeWithText("Neutral observation").assertIsDisplayed()
    }

    private fun detail(): DetectionDetailUiModel = DetectionDetailUiModel(
        id = "TEST",
        title = "Test Detector",
        description = "A detector description that explains the bounded observation.",
        outcome = DetectionOutcome.OBSERVED,
        evidenceStrength = EvidenceStrength.MODERATE,
        payloadSchemaVersion = 1,
        primaryEvidenceDomainTitle = "Runtime Integrity",
        evidenceDomainTags = listOf(
            EvidenceDomainTagUiModel(
                id = "runtime-integrity",
                title = "Runtime Integrity",
                shortTitle = "Runtime",
                isPrimary = true,
            ),
        ),
        collectionError = null,
        units = listOf(
            EvidenceUnitDetailUiModel(
                id = "direct-marker",
                title = "Direct Marker",
                domainId = "runtime-integrity",
                domainTitle = "Runtime Integrity",
                domainShortTitle = "Runtime",
                collectionStatus = EvidenceUnitCollectionStatus.COMPLETE,
                observedObject = "Loaded runtime marker",
                proposition = "A maintained marker is visible",
                observationChannel = "Process memory",
                availability = "Available while procfs is readable",
                trustBoundary = "App process",
                inferenceLimit = "Marker absence does not prove a clean runtime",
                signals = listOf(
                    EvidenceRecordDetailUiModel(
                        code = "TEST.direct.signal",
                        kind = EvidenceRecordKind.SIGNAL,
                        summary = "Direct signal",
                        signalStrength = EvidenceStrength.MODERATE,
                        attributes = listOf(
                            DetailValueUiModel("Path", "/system/lib64/libexample.so", true),
                        ),
                    ),
                ),
                observations = listOf(
                    EvidenceRecordDetailUiModel(
                        code = "TEST.direct.observation",
                        kind = EvidenceRecordKind.OBSERVATION,
                        summary = "Neutral observation",
                        signalStrength = null,
                        attributes = emptyList(),
                    ),
                ),
                researchRecords = emptyList(),
                issues = emptyList(),
                initiallyExpanded = true,
            ),
        ),
    )
}
