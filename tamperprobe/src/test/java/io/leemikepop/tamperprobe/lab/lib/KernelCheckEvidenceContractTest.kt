package io.leemikepop.tamperprobe.lab.lib

import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.DetectorResult
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitResult
import io.leemikepop.tamperprobe.lab.internal.CatalogParser
import io.leemikepop.tamperprobe.lab.internal.EvidenceAdapterInput
import io.leemikepop.tamperprobe.lab.internal.EvidenceAdapterRegistry
import java.io.File
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * KERNEL_CHECK's two units, driven by payloads shaped as kernel_check.cpp emits them: the
 * identity coherence unit signals on a release disagreement, publishes agreement only as a
 * concealable negative, and is UNAVAILABLE with fewer than two readable sources; a banner scan
 * that saw only uname publishes its not-found as a concealable negative.
 */
class KernelCheckEvidenceContractTest {
    private val descriptor by lazy {
        val candidates = listOf(
            File("scripts/generated/detections_manifest.json"),
            File("tamperprobe/scripts/generated/detections_manifest.json"),
        )
        CatalogParser.parse(requireNotNull(candidates.firstOrNull(File::isFile)).readText())
            .descriptors.single { it.id == "KERNEL_CHECK" }
    }

    @Test
    fun theCatalogDeclaresBothUnits() {
        assertEquals(listOf(POSTURE, COHERENCE), descriptor.evidenceUnits.map { it.id })
    }

    @Test
    fun disagreeingSourcesSignalTheCoherenceUnitOnly() {
        val units = map(
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            payload(
                state = "disagree",
                sources = listOf(
                    Triple("zygote_os_version", true, "6.1.162+blu-spark"),
                    Triple("uname_release", true, "6.1.162-android14-11-g2ec90535fa34-ab15810641"),
                    Triple("proc_sys_kernel_osrelease", false, ""),
                    Triple("proc_version_release", false, ""),
                ),
                findings = listOf(mismatchFinding()),
                errors = listOf("kallsyms", "modules", "cmdline", "proc_version", "proc_sys_kernel_osrelease"),
            ),
        )
        val result = DetectorResult(descriptor, DetectionOutcome.OBSERVED, EvidenceStrength.MODERATE, units)
        val coherence = result.unitResults.single { it.descriptor.id == COHERENCE }
        val posture = result.unitResults.single { it.descriptor.id == POSTURE }

        val signal = coherence.records.single { it.kind == EvidenceRecordKind.SIGNAL }
        assertEquals("KERNEL_CHECK.identity-coherence.assessment-signal", signal.code)
        assertEquals(EvidenceStrength.MODERATE, signal.signalStrength)
        assertEquals("disagree", signal.attributes["identityCoherence.state"])
        assertEquals("6.1.162+blu-spark", signal.attributes["identityCoherence.sources.0.value"])
        assertEquals(
            "6.1.162-android14-11-g2ec90535fa34-ab15810641",
            signal.attributes["identityCoherence.sources.1.value"],
        )
        assertTrue(posture.records.none { it.kind == EvidenceRecordKind.SIGNAL })
        assertTrue(result.unitResults.flatMap { it.records }.none { it.code.endsWith(".concealable-negative") })
    }

    @Test
    fun agreeingSourcesAreANotObservedConcealableNegative() {
        val units = map(
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            payload(
                state = "agree",
                sources = listOf(
                    Triple("zygote_os_version", true, STOCK),
                    Triple("uname_release", true, STOCK),
                    Triple("proc_sys_kernel_osrelease", false, ""),
                    Triple("proc_version_release", false, ""),
                ),
                identityNegatives = true,
                bannerNegatives = true,
                errors = listOf("kallsyms", "modules", "cmdline", "proc_version", "proc_sys_kernel_osrelease"),
            ),
        )
        val result = DetectorResult(descriptor, DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE, units)
        val coherence = result.unitResults.single { it.descriptor.id == COHERENCE }
        val posture = result.unitResults.single { it.descriptor.id == POSTURE }

        assertFalse(result.unitResults.flatMap { it.records }.any { it.kind == EvidenceRecordKind.SIGNAL })
        val identityNegative = coherence.records.single {
            it.code == "KERNEL_CHECK.identity-coherence.concealable-negative"
        }
        assertEquals(EvidenceRecordKind.OBSERVATION, identityNegative.kind)
        assertEquals("true", identityNegative.attributes["concealable"])
        assertEquals("kernel_identity_coherence", identityNegative.attributes["check"])
        assertEquals(
            listOf("custom_kernel_signature", "kernel_symbol_token"),
            posture.records.filter { it.code == "KERNEL_CHECK.integrity-posture.concealable-negative" }
                .map { it.attributes.getValue("check") },
        )
        // Unreadable procfs sources keep the coherence unit PARTIAL, attributed to it alone.
        assertEquals(EvidenceUnitCollectionStatus.PARTIAL, coherence.collectionStatus)
        assertEquals(
            setOf("proc_version", "proc_sys_kernel_osrelease"),
            issueSources(coherence),
        )
        assertEquals(setOf("kallsyms", "modules", "cmdline", "proc_version"), issueSources(posture))
    }

    @Test
    fun aSingleReadableSourceLeavesTheUnitUnavailableNeverNegative() {
        val units = map(
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            payload(
                state = "unavailable",
                sources = listOf(
                    Triple("zygote_os_version", false, ""),
                    Triple("uname_release", true, STOCK),
                    Triple("proc_sys_kernel_osrelease", false, ""),
                    Triple("proc_version_release", false, ""),
                ),
                errors = listOf("proc_version", "proc_sys_kernel_osrelease", "zygote_os_version", "kernel_identity"),
            ),
        )
        val result = DetectorResult(descriptor, DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE, units)
        val coherence = result.unitResults.single { it.descriptor.id == COHERENCE }

        assertEquals(EvidenceUnitCollectionStatus.UNAVAILABLE, coherence.collectionStatus)
        assertTrue(coherence.records.isEmpty())
        assertTrue("kernel_identity" in issueSources(coherence))
        assertTrue(issueSources(coherence).containsAll(setOf("zygote_os_version", "proc_sys_kernel_osrelease")))
        val posture = result.unitResults.single { it.descriptor.id == POSTURE }
        assertTrue(posture.records.isNotEmpty())
        assertFalse(issueSources(posture).contains("kernel_identity"))
    }

    @Test
    fun aMissingCoherenceSnapshotIsUnavailableRatherThanClean() {
        val units = map(
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            buildJsonObject {
                put("kernelRelease", STOCK)
                put("hitCount", 0)
                put("findings", buildJsonArray {})
            },
        )
        val coherence = units.single { it.descriptor.id == COHERENCE }

        assertEquals(EvidenceUnitCollectionStatus.UNAVAILABLE, coherence.collectionStatus)
        assertEquals(listOf("KERNEL_CHECK.identity-coherence.unavailable"), coherence.issues.map { it.code })
    }

    @Test
    fun aPostureFindingSignalsThePostureUnitWhileCoherenceAgrees() {
        val units = map(
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            payload(
                state = "agree",
                sources = listOf(
                    Triple("zygote_os_version", true, "6.1.162+blu_spark"),
                    Triple("uname_release", true, "6.1.162+blu_spark"),
                ),
                findings = listOf(
                    buildJsonObject {
                        put("check", "custom_kernel_signature")
                        put("marker", "custom_kernel_keyword")
                        put("value", "blu_spark")
                    },
                ),
                identityNegatives = true,
            ),
        )
        val result = DetectorResult(descriptor, DetectionOutcome.OBSERVED, EvidenceStrength.MODERATE, units)

        assertEquals(
            listOf("KERNEL_CHECK.integrity-posture.assessment-signal"),
            result.unitResults.flatMap { it.records }.filter { it.kind == EvidenceRecordKind.SIGNAL }.map { it.code },
        )
        val coherence = result.unitResults.single { it.descriptor.id == COHERENCE }
        assertEquals(EvidenceUnitCollectionStatus.COMPLETE, coherence.collectionStatus)
        assertEquals("agree", coherence.records.single().attributes["identityCoherence.state"])
    }

    private fun map(outcome: DetectionOutcome, strength: EvidenceStrength, payload: JsonObject): List<EvidenceUnitResult> =
        EvidenceAdapterRegistry.map(EvidenceAdapterInput(descriptor, outcome, strength, payload))

    private fun issueSources(unit: EvidenceUnitResult): Set<String> =
        unit.issues.flatMap { issue ->
            issue.attributes.filterKeys { it.endsWith(".source") }.values
        }.toSet()

    private fun mismatchFinding() = buildJsonObject {
        put("check", "kernel_identity_mismatch")
        put("unitId", COHERENCE)
        put("marker", "release_disagreement")
        put("value", "zygote_os_version=6.1.162+blu-spark, uname_release=$STOCK")
    }

    private fun payload(
        state: String,
        sources: List<Triple<String, Boolean, String>>,
        findings: List<JsonObject> = emptyList(),
        identityNegatives: Boolean = false,
        bannerNegatives: Boolean = false,
        errors: List<String> = emptyList(),
    ) = buildJsonObject {
        put("kernelRelease", sources.firstOrNull { it.first == "uname_release" }?.third.orEmpty())
        put("kernelVersion", "#1 SMP PREEMPT")
        put("procVersion", "")
        put("procCmdline", "")
        put("kallsymsReadable", false)
        put("modulesReadable", false)
        put("bannerSources", buildJsonArray { add(JsonPrimitive("uname")) })
        put("bannerConcealableNegatives", buildJsonArray {
            if (bannerNegatives) {
                listOf("custom_kernel_signature", "kernel_symbol_token").forEach { check ->
                    add(buildJsonObject {
                        put("check", check)
                        put("source", "uname")
                        put("concealable", true)
                        put("reason", "fixture")
                    })
                }
            }
        })
        put("identityCoherence", buildJsonObject {
            put("state", state)
            put("readableSourceCount", sources.count { it.second })
            put("distinctReleaseCount", sources.filter { it.second }.map { it.third }.distinct().size)
            put("sources", buildJsonArray {
                sources.forEach { (id, readable, value) ->
                    add(buildJsonObject {
                        put("source", id)
                        put("readable", readable)
                        put("value", value)
                    })
                }
            })
            put("unreadableSources", buildJsonArray {
                sources.filterNot { it.second }.forEach { add(JsonPrimitive(it.first)) }
            })
        })
        put("identityConcealableNegatives", buildJsonArray {
            if (identityNegatives) {
                add(buildJsonObject {
                    put("check", "kernel_identity_coherence")
                    put("concealable", true)
                    put("reason", "fixture")
                })
            }
        })
        put("hitCount", findings.count { it["check"].toString() != "\"kernel_identity_mismatch\"" })
        put("findings", buildJsonArray { findings.forEach { add(it) } })
        put("collectionErrors", buildJsonArray {
            errors.forEach { source ->
                add(buildJsonObject {
                    put("source", source)
                    put("errno", 0)
                    put("message", "fixture collection error")
                })
            }
        })
    }

    private companion object {
        const val POSTURE = "kernel-check.integrity-posture"
        const val COHERENCE = "kernel-check.identity-coherence"
        const val STOCK = "6.1.162-android14-11-g2ec90535fa34-ab15810641"
    }
}
