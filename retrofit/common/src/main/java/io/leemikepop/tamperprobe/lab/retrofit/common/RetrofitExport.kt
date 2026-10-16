package io.leemikepop.tamperprobe.lab.retrofit.common

import android.os.Build
import io.leemikepop.tamperprobe.lab.api.CollectionError
import io.leemikepop.tamperprobe.lab.api.DetectorDescriptor
import io.leemikepop.tamperprobe.lab.api.DetectorResult
import io.leemikepop.tamperprobe.lab.api.EvidenceIssue
import io.leemikepop.tamperprobe.lab.api.EvidenceRecord
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitDescriptor
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitResult
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

/** The unmodified detector a retrofit wraps, pinned to the revision that was vendored. */
data class UpstreamIdentity(
    val name: String,
    val repository: String,
    val revision: String,
    val aggregateMethod: String,
)

/** The host app that ran the retrofit. Package visibility and target SDK change what it can see. */
data class HostProvenance(
    val applicationId: String,
    val versionName: String,
    val versionCode: Int,
    val gitCommit: String,
    val gitDirty: Boolean,
    val buildType: String,
    val targetSdk: Int,
    val packageVisibility: String,
)

/** One run of a retrofit: the upstream aggregate verdict and every check, assembled. */
data class RetrofitRun(
    val selection: String,
    val upstream: UpstreamIdentity,
    val aggregateVerdict: String,
    val startedAtUtc: Instant,
    val completedAtUtc: Instant,
    val evaluations: List<CheckEvaluation>,
    val host: HostProvenance,
) {
    val results: List<DetectorResult> = evaluations.map(ContractAssembler::assemble)
}

data class RetrofitDocument(val fileName: String, val bytes: ByteArray)

/**
 * Writes a retrofit run as an export document in the probe app's format (`scan.report.results`,
 * `provenance.sampleApp`, `provenance.device`), so `experiments/tools/compare_cells.py` reads it
 * unchanged, plus a `retrofit` block with the upstream verdicts.
 *
 * The file name ends in `-<selection>.json`, so `compare_cells.py --selection <selection>` picks it.
 */
object RetrofitExport {
    const val EXPORT_SCHEMA_VERSION: Int = 2

    private val json = Json {
        prettyPrint = true
        explicitNulls = true
    }
    private val fileTimestampFormatter = DateTimeFormatter
        .ofPattern("yyyyMMdd'T'HHmmss'Z'")
        .withZone(ZoneOffset.UTC)

    fun createDocument(run: RetrofitRun, exportedAtUtc: Instant): RetrofitDocument {
        val root = buildJsonObject {
            put("exportSchemaVersion", EXPORT_SCHEMA_VERSION)
            put("exportedAtUtc", exportedAtUtc.toString())
            putJsonObject("retrofit") {
                put("selection", run.selection)
                putJsonObject("upstream") {
                    put("name", run.upstream.name)
                    put("repository", run.upstream.repository)
                    put("revision", run.upstream.revision)
                }
                putJsonObject("aggregate") {
                    put("method", run.upstream.aggregateMethod)
                    put("verdict", run.aggregateVerdict)
                }
                putJsonArray("checks") {
                    run.evaluations.zip(run.results).forEach { (evaluation, result) ->
                        add(
                            buildJsonObject {
                                put("detectorId", evaluation.spec.detectorId)
                                put("upstreamMethod", evaluation.spec.upstreamMethod)
                                put("upstreamVerdict", evaluation.upstreamVerdict)
                                put("upstreamPositive", evaluation.upstreamPositive)
                                put("upstreamFailed", evaluation.upstreamFailure != null)
                                put("outcome", result.outcome.name)
                            },
                        )
                    }
                }
            }
            putJsonObject("scan") {
                put("startedAtUtc", run.startedAtUtc.toString())
                put("completedAtUtc", run.completedAtUtc.toString())
                putJsonArray("requestedDetectorIds") { run.evaluations.forEach { add(it.spec.detectorId) } }
                putJsonObject("report") {
                    put("wireSchemaVersion", 1)
                    put("engineVersion", "retrofit-${run.selection}")
                    put("catalogVersion", "${run.selection}-${run.upstream.revision.take(12)}")
                    put("completion", "COMPLETE")
                    put("durationMillis", java.time.Duration.between(run.startedAtUtc, run.completedAtUtc).toMillis())
                    put("results", buildJsonArray { run.results.forEach { add(it.toJson()) } })
                }
            }
            putJsonObject("provenance") {
                putJsonObject("sampleApp") {
                    put("applicationId", run.host.applicationId)
                    put("versionName", run.host.versionName)
                    put("versionCode", run.host.versionCode)
                    put("gitCommit", run.host.gitCommit)
                    put("gitDirty", run.host.gitDirty)
                    put("buildType", run.host.buildType)
                }
                putJsonObject("host") {
                    put("targetSdk", run.host.targetSdk)
                    put("packageVisibility", run.host.packageVisibility)
                }
                put("device", deviceJson())
            }
        }
        return RetrofitDocument(
            fileName = "retrofit-${fileTimestampFormatter.format(run.completedAtUtc)}-${run.selection}.json",
            bytes = (json.encodeToString(JsonElement.serializer(), root) + "\n").toByteArray(StandardCharsets.UTF_8),
        )
    }

    private fun deviceJson(): JsonElement = buildJsonObject {
        put("manufacturer", Build.MANUFACTURER.orEmpty())
        put("brand", Build.BRAND.orEmpty())
        put("model", Build.MODEL.orEmpty())
        put("device", Build.DEVICE.orEmpty())
        put("product", Build.PRODUCT.orEmpty())
        put("androidRelease", Build.VERSION.RELEASE.orEmpty())
        put("apiLevel", Build.VERSION.SDK_INT)
        putJsonArray("supportedAbis") { Build.SUPPORTED_ABIS.forEach(::add) }
        put("buildFingerprint", Build.FINGERPRINT.orEmpty())
        put("buildType", Build.TYPE.orEmpty())
        put("kernelVersion", System.getProperty("os.version").orEmpty())
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
        put("signalStrength", signalStrength?.name)
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
}
