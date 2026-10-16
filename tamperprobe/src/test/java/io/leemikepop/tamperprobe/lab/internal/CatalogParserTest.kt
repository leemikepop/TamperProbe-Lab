package io.leemikepop.tamperprobe.lab.internal

import io.leemikepop.tamperprobe.lab.api.TamperProbeException
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class CatalogParserTest {
    @Test
    fun v1CatalogPublishesEightDomainsThirtyFiveDetectorsAndFiftyUnits() {
        val catalog = CatalogParser.parse(catalogText())

        assertEquals(1, catalog.schemaVersion)
        assertEquals("1.0", catalog.catalogVersion)
        assertEquals(1, catalog.evidenceContractVersion)
        assertEquals(8, catalog.evidenceDomains.size)
        assertEquals(38, catalog.descriptors.size)
        assertEquals(54, catalog.descriptors.sumOf { it.evidenceUnits.size })
        assertTrue(catalog.descriptors.all { it.payloadSchemaVersion == 1 })
        assertTrue(catalog.descriptors.all { descriptor ->
            descriptor.evidenceUnits.any { it.domainId == descriptor.primaryEvidenceDomainId }
        })
    }

    @Test
    fun legacySchemaIsRejected() {
        val legacy = catalogText().replaceFirst("\"schemaVersion\": 1", "\"schemaVersion\": 3")
        assertThrows(TamperProbeException::class.java) { CatalogParser.parse(legacy) }
    }

    @Test
    fun unknownLegacyFieldsAreRejected() {
        val legacy = catalogText().replaceFirst(
            "\"catalogVersion\": \"1.0\"",
            "\"catalogVersion\": \"1.0\", \"publicationContract\": {}",
        )
        assertThrows(TamperProbeException::class.java) { CatalogParser.parse(legacy) }
    }

    @Test
    fun unknownPrimaryDomainIsRejected() {
        val invalid = catalogText().replaceFirst(
            Regex("\"primaryEvidenceDomainId\": \"[^\"]+\""),
            "\"primaryEvidenceDomainId\": \"unknown-domain\"",
        )
        assertThrows(TamperProbeException::class.java) { CatalogParser.parse(invalid) }
    }

    private fun catalogText(): String {
        val candidates = listOf(
            File("scripts/generated/detections_manifest.json"),
            File("tamperprobe/scripts/generated/detections_manifest.json"),
        )
        return requireNotNull(candidates.firstOrNull(File::isFile)) {
            "Generated detector catalog is unavailable"
        }.readText()
    }
}
