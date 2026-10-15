package io.leemikepop.tamperprobe.lab.presentation.export

import io.leemikepop.tamperprobe.lab.api.CollectionError
import io.leemikepop.tamperprobe.lab.api.DetectorDescriptor
import io.leemikepop.tamperprobe.lab.api.DetectorResult
import io.leemikepop.tamperprobe.lab.api.EvidenceIssue
import io.leemikepop.tamperprobe.lab.api.EvidenceRecord
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitDescriptor
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitResult
import io.leemikepop.tamperprobe.lab.api.TamperProbeReport
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

internal object ScanReportJsonEncoder {
    // 2 adds per-detector durationMicros. Version 1 exports, including the device
    // captures already archived in the thesis workspace, carry no timing.
    const val EXPORT_SCHEMA_VERSION: Int = 2

    private val json = Json {
        prettyPrint = true
        explicitNulls = true
    }
    private val fileTimestampFormatter = DateTimeFormatter
        .ofPattern("yyyyMMdd'T'HHmmss'Z'")
        .withZone(ZoneOffset.UTC)
    private val unsafeFileNameCharacters = Regex("[^A-Za-z0-9._-]")

    fun createDocument(snapshot: ScanExportSnapshot, exportedAtUtc: Instant): ExportDocument {
        val root = buildJsonObject {
            put("exportSchemaVersion", EXPORT_SCHEMA_VERSION)
            put("exportedAtUtc", exportedAtUtc.toString())
            putJsonObject("scan") {
                put("startedAtUtc", snapshot.startedAtUtc.toString())
                put("completedAtUtc", snapshot.completedAtUtc.toString())
                putJsonArray("requestedDetectorIds") { snapshot.requestedDetectorIds.forEach(::add) }
                put("report", snapshot.report.toJson())
            }
            putJsonObject("provenance") {
                put("sampleApp", snapshot.provenance.sampleApp.toJson())
                put("coreBuild", snapshot.provenance.coreBuild.toJson())
                put("device", snapshot.provenance.device.toJson())
            }
        }
        return ExportDocument(
            fileName = fileName(snapshot.completedAtUtc, snapshot.report.catalogVersion),
            bytes = (json.encodeToString(JsonElement.serializer(), root) + "\n")
                .toByteArray(StandardCharsets.UTF_8),
        )
    }

    fun fileName(completedAtUtc: Instant, catalogVersion: String): String {
        val safeCatalog = catalogVersion.ifBlank { "unknown" }.replace(unsafeFileNameCharacters, "_")
        return "tamperprobe-scan-${fileTimestampFormatter.format(completedAtUtc)}-catalog-$safeCatalog.json"
    }

    private fun TamperProbeReport.toJson(): JsonElement = buildJsonObject {
        put("wireSchemaVersion", wireSchemaVersion)
        put("engineVersion", engineVersion)
        put("catalogVersion", catalogVersion)
        put("completion", completion.name)
        put("durationMillis", durationMillis)
        put("results", buildJsonArray { results.forEach { add(it.toJson()) } })
    }

    private fun DetectorResult.toJson(): JsonElement = buildJsonObject {
        put("descriptor", descriptor.toJson())
        put("outcome", outcome.name)
        put("strength", strength.name)
        put("durationMicros", durationMicros)
        put("unitResults", buildJsonArray { unitResults.forEach { add(it.toJson()) } })
        put("collectionError", collectionError?.toJson() ?: JsonNull)
    }

    private fun DetectorDescriptor.toJson(): JsonElement = buildJsonObject {
        put("id", id)
        put("name", name)
        put("description", description)
        put("payloadSchemaVersion", payloadSchemaVersion)
        put("primaryEvidenceDomainId", primaryEvidenceDomainId)
        putJsonArray("evidenceUnits") { evidenceUnits.forEach { add(it.toJson()) } }
    }

    private fun EvidenceUnitDescriptor.toJson(): JsonElement = buildJsonObject {
        put("id", id)
        put("title", title)
        put("domainId", domainId)
        put("observedObject", observedObject)
        put("proposition", proposition)
        put("observationChannel", observationChannel)
        put("availability", availability)
        put("trustBoundary", trustBoundary)
        put("inferenceLimit", inferenceLimit)
    }

    private fun EvidenceUnitResult.toJson(): JsonElement = buildJsonObject {
        put("descriptor", descriptor.toJson())
        put("collectionStatus", collectionStatus.name)
        putJsonArray("records") { records.forEach { add(it.toJson()) } }
        putJsonArray("issues") { issues.forEach { add(it.toJson()) } }
    }

    private fun EvidenceRecord.toJson(): JsonElement = buildJsonObject {
        put("code", code)
        put("kind", kind.name)
        put("summary", summary)
        val recordSignalStrength = signalStrength
        if (recordSignalStrength == null) {
            put("signalStrength", JsonNull)
        } else {
            put("signalStrength", recordSignalStrength.name)
        }
        putJsonObject("attributes") { attributes.toSortedMap().forEach { (key, value) -> put(key, value) } }
    }

    private fun EvidenceIssue.toJson(): JsonElement = buildJsonObject {
        put("code", code)
        put("message", message)
        putJsonObject("attributes") { attributes.toSortedMap().forEach { (key, value) -> put(key, value) } }
    }

    private fun CollectionError.toJson(): JsonElement = buildJsonObject {
        put("code", code)
        put("message", message)
        put("recoverable", recoverable)
    }

    private fun SampleAppProvenance.toJson(): JsonElement = buildJsonObject {
        put("versionName", versionName)
        put("versionCode", versionCode)
        put("gitCommit", gitCommit)
        put("gitDirty", gitDirty)
        put("buildType", buildType)
    }

    private fun CoreBuildProvenance.toJson(): JsonElement = buildJsonObject {
        put("engineVersion", engineVersion)
        put("catalogVersion", catalogVersion)
        put("catalogSchemaVersion", catalogSchemaVersion)
        put("evidenceContractVersion", evidenceContractVersion)
        put("wireSchemaVersion", wireSchemaVersion)
    }

    private fun DeviceProvenance.toJson(): JsonElement = buildJsonObject {
        put("manufacturer", manufacturer)
        put("brand", brand)
        put("model", model)
        put("device", device)
        put("product", product)
        put("androidRelease", androidRelease)
        put("apiLevel", apiLevel)
        putJsonArray("supportedAbis") { supportedAbis.forEach(::add) }
        put("buildFingerprint", buildFingerprint)
        put("buildType", buildType)
        put("kernelVersion", kernelVersion)
    }
}
