package io.leemikepop.tamperprobe.lab.internal

import android.content.Context
import io.leemikepop.tamperprobe.lab.api.DetectorDescriptor
import io.leemikepop.tamperprobe.lab.api.EvidenceDomainDescriptor
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitDescriptor
import io.leemikepop.tamperprobe.lab.api.TamperProbeException
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
internal data class CatalogFile(
    val schemaVersion: Int = 0,
    val catalogVersion: String = "",
    val evidenceContractVersion: Int = 0,
    val evidenceDomains: List<CatalogEvidenceDomain> = emptyList(),
    val detections: List<CatalogDetection> = emptyList(),
)

@Serializable
internal data class CatalogEvidenceDomain(
    val id: String,
    val title: String,
    val shortTitle: String,
    val description: String,
)

@Serializable
internal data class CatalogEvidenceUnit(
    val id: String,
    val title: String,
    val domainId: String,
    val observedObject: String,
    val proposition: String,
    val observationChannel: String,
    val availability: String,
    val trustBoundary: String,
    val inferenceLimit: String,
)

@Serializable
internal data class CatalogDetection(
    val id: String,
    val name: String,
    val description: String,
    val payloadSchemaVersion: Int,
    val primaryEvidenceDomainId: String,
    val evidenceUnits: List<CatalogEvidenceUnit>,
)

internal data class ParsedCatalog(
    val schemaVersion: Int,
    val catalogVersion: String,
    val evidenceContractVersion: Int,
    val evidenceDomains: List<EvidenceDomainDescriptor>,
    val descriptors: List<DetectorDescriptor>,
)

internal object CatalogParser {
    private val json = Json { ignoreUnknownKeys = false }

    fun parse(content: String): ParsedCatalog {
        val file = try {
            json.decodeFromString<CatalogFile>(content)
        } catch (error: Exception) {
            throw TamperProbeException("CATALOG_DECODE_FAILED", "Unable to decode detector catalog", error)
        }
        if (file.schemaVersion != 1 || file.catalogVersion != "1.0" || file.evidenceContractVersion != 1) {
            throw TamperProbeException("UNSUPPORTED_CATALOG", "Only the v1 detector catalog is supported")
        }

        val domains = file.evidenceDomains.map { domain ->
            val fields = listOf(domain.id, domain.title, domain.shortTitle, domain.description)
            if (fields.any { it.isBlank() }) {
                throw TamperProbeException("INVALID_CATALOG", "Evidence domain fields must be non-empty")
            }
            EvidenceDomainDescriptor(domain.id, domain.title, domain.shortTitle, domain.description)
        }
        val domainIds = domains.map { it.id }
        if (domains.isEmpty() || domainIds.toSet().size != domains.size) {
            throw TamperProbeException("INVALID_CATALOG", "Catalog must declare unique evidence domains")
        }

        val descriptors = file.detections.map { item ->
            if (item.primaryEvidenceDomainId !in domainIds || item.payloadSchemaVersion != 1) {
                throw TamperProbeException("INVALID_CATALOG", "Detector domain or payload schema is invalid")
            }
            val units = item.evidenceUnits.map { unit ->
                val fields = listOf(
                    unit.id,
                    unit.title,
                    unit.domainId,
                    unit.observedObject,
                    unit.proposition,
                    unit.observationChannel,
                    unit.availability,
                    unit.trustBoundary,
                    unit.inferenceLimit,
                )
                if (fields.any { it.isBlank() } || unit.domainId !in domainIds) {
                    throw TamperProbeException("INVALID_CATALOG", "Evidence unit fields are invalid")
                }
                EvidenceUnitDescriptor(
                    id = unit.id,
                    title = unit.title,
                    domainId = unit.domainId,
                    observedObject = unit.observedObject,
                    proposition = unit.proposition,
                    observationChannel = unit.observationChannel,
                    availability = unit.availability,
                    trustBoundary = unit.trustBoundary,
                    inferenceLimit = unit.inferenceLimit,
                )
            }
            if (units.isEmpty() || units.map { it.id }.toSet().size != units.size ||
                units.none { it.domainId == item.primaryEvidenceDomainId }
            ) {
                throw TamperProbeException("INVALID_CATALOG", "Detector evidence units are invalid")
            }
            DetectorDescriptor(
                id = item.id,
                name = item.name,
                description = item.description,
                primaryEvidenceDomainId = item.primaryEvidenceDomainId,
                payloadSchemaVersion = item.payloadSchemaVersion,
                evidenceUnits = units,
            )
        }.sortedBy { it.id }

        val detectorIds = descriptors.map { it.id }
        val unitIds = descriptors.flatMap { descriptor -> descriptor.evidenceUnits.map { it.id } }
        // Counts are not pinned: the catalog is bundled in the same AAR it was generated for, and
        // the research catalog is expected to change. Structure is still checked.
        if (descriptors.isEmpty() || detectorIds.toSet().size != descriptors.size ||
            unitIds.toSet().size != unitIds.size
        ) {
            throw TamperProbeException("INVALID_CATALOG", "Catalog must contain unique detectors and units")
        }

        return ParsedCatalog(
            schemaVersion = file.schemaVersion,
            catalogVersion = file.catalogVersion,
            evidenceContractVersion = file.evidenceContractVersion,
            evidenceDomains = domains,
            descriptors = descriptors,
        )
    }
}

internal object CatalogLoader {
    fun load(context: Context): ParsedCatalog {
        val content = try {
            context.assets.open("tamperprobe/detections_manifest.json").bufferedReader().use { it.readText() }
        } catch (error: Exception) {
            throw TamperProbeException("CATALOG_NOT_FOUND", "Bundled detector catalog is unavailable", error)
        }
        return CatalogParser.parse(content)
    }
}
