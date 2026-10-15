package io.leemikepop.tamperprobe.lab.e2e

import io.leemikepop.tamperprobe.lab.api.CollectionError
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.DetectorDescriptor
import io.leemikepop.tamperprobe.lab.api.DetectorResult
import io.leemikepop.tamperprobe.lab.api.EvidenceIssue
import io.leemikepop.tamperprobe.lab.api.EvidenceRecord
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitDescriptor
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitResult
import io.leemikepop.tamperprobe.lab.api.ScanCompletion
import io.leemikepop.tamperprobe.lab.api.TamperProbeReport
import io.leemikepop.tamperprobe.lab.internal.ParsedCatalog
import io.leemikepop.tamperprobe.lab.internal.CatalogParser
import io.leemikepop.tamperprobe.lab.internal.DetectorResultMapper
import io.leemikepop.tamperprobe.lab.internal.WireDetectorResult
import io.leemikepop.tamperprobe.lab.internal.WireEnvelope
import io.leemikepop.tamperprobe.lab.internal.WireParser
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

internal object E2ETestHelper {
    val catalog: ParsedCatalog by lazy {
        CatalogParser.parse(loadCatalogJson())
    }

    val fixtures: JsonObject by lazy {
        Json.parseToJsonElement(loadFixturesJson()).jsonObject
    }

    fun descriptorFor(detectorId: String): DetectorDescriptor {
        // No synthetic fallback on purpose. A test naming a detector the catalog does
        // not publish must fail, not quietly invent a descriptor and pass. Tests that
        // genuinely want a made-up detector call createSyntheticDescriptor explicitly.
        return catalog.descriptors.firstOrNull { it.id == detectorId }
            ?: error("Detector $detectorId is not published in the catalog")
    }

    fun createSyntheticDescriptor(
        id: String,
        domainId: String = "system-state",
        unitIds: List<String> = listOf("$id.default-unit"),
    ): DetectorDescriptor {
        val units = unitIds.map { unitId ->
            EvidenceUnitDescriptor(
                id = unitId.lowercase().replace('_', '-'),
                title = "$id Unit",
                domainId = domainId,
                observedObject = "Target object for $id",
                proposition = "Proposition for $id",
                observationChannel = "Kernel/User channel",
                availability = "Standard Android environment",
                trustBoundary = "SDK boundary",
                inferenceLimit = "Bounded inference",
            )
        }
        return DetectorDescriptor(
            id = id,
            name = id.replace('_', ' '),
            description = "E2E synthetic descriptor for $id",
            primaryEvidenceDomainId = domainId,
            payloadSchemaVersion = 1,
            evidenceUnits = units,
        )
    }

    fun createUnitResult(
        unit: EvidenceUnitDescriptor,
        outcome: DetectionOutcome,
        strength: EvidenceStrength,
        detectorId: String,
        customAttributes: Map<String, String> = emptyMap(),
        customIssues: List<EvidenceIssue> = emptyList(),
    ): EvidenceUnitResult {
        val recordPrefix = "$detectorId.${unit.id.substringAfter('.', unit.id)}"
        return when (outcome) {
            DetectionOutcome.OBSERVED -> EvidenceUnitResult(
                descriptor = unit,
                collectionStatus = if (customIssues.isEmpty()) EvidenceUnitCollectionStatus.COMPLETE else EvidenceUnitCollectionStatus.PARTIAL,
                records = listOf(
                    EvidenceRecord(
                        code = "$recordPrefix.assessment-signal",
                        kind = EvidenceRecordKind.SIGNAL,
                        summary = "${unit.title} triggered signal",
                        signalStrength = strength,
                        attributes = customAttributes,
                    ),
                ),
                issues = customIssues,
            )
            DetectionOutcome.NOT_OBSERVED -> EvidenceUnitResult(
                descriptor = unit,
                collectionStatus = if (customIssues.isEmpty()) EvidenceUnitCollectionStatus.COMPLETE else EvidenceUnitCollectionStatus.PARTIAL,
                records = listOf(
                    EvidenceRecord(
                        code = "$recordPrefix.collection-summary",
                        kind = EvidenceRecordKind.OBSERVATION,
                        summary = "${unit.title} completed clean observation",
                        attributes = customAttributes,
                    ),
                ),
                issues = customIssues,
            )
            DetectionOutcome.INCONCLUSIVE -> EvidenceUnitResult(
                descriptor = unit,
                collectionStatus = EvidenceUnitCollectionStatus.UNAVAILABLE,
                records = emptyList(),
                issues = customIssues.ifEmpty {
                    listOf(EvidenceIssue("$recordPrefix.inconclusive", "Observation inconclusive"))
                },
            )
            DetectionOutcome.FAILED -> throw IllegalArgumentException("FAILED units cannot have unit results")
        }
    }

    fun createDetectorResult(
        descriptor: DetectorDescriptor,
        outcome: DetectionOutcome,
        strength: EvidenceStrength = if (outcome == DetectionOutcome.OBSERVED) EvidenceStrength.MODERATE else EvidenceStrength.NONE,
        customAttributes: Map<String, String> = emptyMap(),
        error: CollectionError? = null,
    ): DetectorResult {
        if (outcome == DetectionOutcome.FAILED) {
            val err = error ?: CollectionError("COLLECTION_FAILED", "Native collector error", recoverable = true)
            return DetectorResult(
                descriptor = descriptor,
                outcome = DetectionOutcome.FAILED,
                strength = EvidenceStrength.NONE,
                unitResults = emptyList(),
                collectionError = err,
            )
        }

        val units = descriptor.evidenceUnits.mapIndexed { index, unit ->
            val isPrimary = index == 0
            val unitOutcome = if (isPrimary) outcome else DetectionOutcome.NOT_OBSERVED
            val unitStrength = if (isPrimary && outcome == DetectionOutcome.OBSERVED) strength else EvidenceStrength.NONE
            createUnitResult(unit, unitOutcome, unitStrength, descriptor.id, customAttributes)
        }

        return DetectorResult(
            descriptor = descriptor,
            outcome = outcome,
            strength = strength,
            unitResults = units,
            collectionError = null,
        )
    }

    fun buildReport(
        results: List<DetectorResult>,
        completion: ScanCompletion = ScanCompletion.COMPLETE,
        durationMillis: Long = 15,
    ): TamperProbeReport = TamperProbeReport(
        wireSchemaVersion = 1,
        engineVersion = "1.0.0-E2E",
        catalogVersion = "1.0",
        completion = completion,
        durationMillis = durationMillis,
        results = results,
    )

    fun buildWireEnvelopeJson(
        results: List<WireDetectorResult>,
        completion: String = "COMPLETE",
        schemaVersion: Int = 1,
    ): String {
        val resultsJson = results.joinToString(",") { r ->
            val errorStr = if (r.collectionError != null) "\"${r.collectionError}\"" else "null"
            """
            {
              "detectorId": "${r.detectorId}",
              "outcome": "${r.outcome.name}",
              "evidenceStrength": "${r.evidenceStrength.name}",
              "payload": ${r.payload},
              "collectionError": $errorStr
            }
            """.trimIndent()
        }
        return """
        {
          "schemaVersion": $schemaVersion,
          "engineVersion": "1.0.0-E2E",
          "catalogVersion": "1.0",
          "completion": "$completion",
          "results": [$resultsJson],
          "engineError": null
        }
        """.trimIndent()
    }

    private fun loadCatalogJson(): String {
        val candidates = listOf(
            File("scripts/generated/detections_manifest.json"),
            File("tamperprobe/scripts/generated/detections_manifest.json"),
        )
        return requireNotNull(candidates.firstOrNull(File::isFile)) {
            "Manifest file not found"
        }.readText()
    }

    private fun loadFixturesJson(): String {
        val candidates = listOf(
            File("src/test/resources/payload-fixtures.json"),
            File("tamperprobe/src/test/resources/payload-fixtures.json"),
        )
        return requireNotNull(candidates.firstOrNull(File::isFile)) {
            "Payload fixtures file not found"
        }.readText()
    }
}
