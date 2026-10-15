package io.leemikepop.tamperprobe.lab.presentation.export

import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.DetectorDescriptor
import io.leemikepop.tamperprobe.lab.api.DetectorResult
import io.leemikepop.tamperprobe.lab.api.EvidenceRecord
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitDescriptor
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitResult
import io.leemikepop.tamperprobe.lab.api.TamperProbeReport
import io.leemikepop.tamperprobe.lab.api.ScanCompletion
import java.time.Instant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class ScanReportJsonEncoderTest {
    @Test
    fun exportSchemaOnePublishesNestedUnitReportsWithoutLegacySelectors() {
        val unit = EvidenceUnitDescriptor(
            "busybox.visible-artifact",
            "Visible artifact",
            "binary-artifact",
            "artifact",
            "visible",
            "filesystem",
            "path readable",
            "app sandbox",
            "does not prove privilege",
        )
        val report = TamperProbeReport(
            1,
            "1.0.0-SNAPSHOT",
            "1.0",
            ScanCompletion.COMPLETE,
            5,
            listOf(
                DetectorResult(
                    DetectorDescriptor(
                        "BUSYBOX",
                        "BusyBox",
                        "BusyBox artifacts",
                        "binary-artifact",
                        1,
                        listOf(unit),
                    ),
                    DetectionOutcome.OBSERVED,
                    EvidenceStrength.WEAK,
                    listOf(
                        EvidenceUnitResult(
                            unit,
                            EvidenceUnitCollectionStatus.COMPLETE,
                            listOf(
                                EvidenceRecord(
                                    "BUSYBOX.visible-artifact.signal",
                                    EvidenceRecordKind.SIGNAL,
                                    "Visible artifact",
                                    EvidenceStrength.WEAK,
                                ),
                            ),
                            emptyList(),
                        ),
                    ),
                ),
            ),
        )
        val instant = Instant.parse("2026-08-20T00:00:00Z")
        val snapshot = ScanExportSnapshot(
            instant,
            instant,
            listOf("BUSYBOX"),
            report,
            ExportProvenance(
                SampleAppProvenance("1.0", 1, "test", false, "debug"),
                CoreBuildProvenance("1.0.0-SNAPSHOT", "1.0", 1, 1, 1),
                DeviceProvenance("m", "b", "model", "device", "product", "16", 36, listOf("x86_64"), "fp", "user", "kernel"),
            ),
        )

        val document = ScanReportJsonEncoder.createDocument(snapshot, instant)
        val root = Json.parseToJsonElement(document.bytes.toString(Charsets.UTF_8)).jsonObject
        val result = root["scan"]!!.jsonObject["report"]!!.jsonObject["results"]!!
            .jsonArray.single().jsonObject
        val descriptor = result["descriptor"]!!.jsonObject
        val unitResult = result["unitResults"]!!.jsonArray.single().jsonObject

        assertEquals(2, root["exportSchemaVersion"]!!.jsonPrimitive.content.toInt())
        assertEquals("1", descriptor["payloadSchemaVersion"]!!.jsonPrimitive.content)
        assertEquals("COMPLETE", unitResult["collectionStatus"]!!.jsonPrimitive.content)
        assertEquals(
            "SIGNAL",
            unitResult["records"]!!.jsonArray.single().jsonObject["kind"]!!.jsonPrimitive.content,
        )
        val text = document.bytes.toString(Charsets.UTF_8)
        assertFalse(text.contains("evidenceCodeSelectors"))
        assertFalse(text.contains("dependentEvidenceFamilyIds"))
    }
}
