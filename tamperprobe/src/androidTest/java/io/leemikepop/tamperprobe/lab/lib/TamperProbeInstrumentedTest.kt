package io.leemikepop.tamperprobe.lab.lib

import android.os.SystemClock
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.leemikepop.tamperprobe.lab.TamperProbe
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.ScanRequest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

@RunWith(AndroidJUnit4::class)
class TamperProbeInstrumentedTest {
    private external fun runNativeMemoryHookFixtures(cacheDirectory: String): String
    private external fun runNativePropertyFixtures(): String
    private external fun runNativeLsposedSepolicyFixtures(): String
    private external fun runNativeRootSepolicyFixtures(): String
    private external fun runNativeDangerousPackagesFixtures(): String
    private external fun runNativeBinaryArtifactFixtures(cacheDirectory: String): String
    private external fun runNativePackageStorageVisibilityFixtures(): String
    private external fun runNativeTeeAssessmentFixtures(): String

    @Test
    fun nativeMemoryHookFixturesExerciseCppSeams() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val result = Json.parseToJsonElement(
            runNativeMemoryHookFixtures(context.cacheDir.absolutePath),
        ).jsonObject
        val failures = result.getValue("failures").jsonArray
        assertEquals(14, result.getValue("caseCount").jsonPrimitive.content.toInt())
        assertTrue("Native fixture failures: $failures", failures.isEmpty())
    }

    @Test
    fun nativePropertyFixturesExerciseCppSeams() {
        val result = Json.parseToJsonElement(runNativePropertyFixtures()).jsonObject
        val failures = result.getValue("failures").jsonArray
        assertEquals(45, result.getValue("caseCount").jsonPrimitive.content.toInt())
        assertTrue("Native property fixture failures: $failures", failures.isEmpty())
    }

    @Test
    fun nativeLsposedSepolicyFixturesExerciseStrictGates() {
        val result = Json.parseToJsonElement(runNativeLsposedSepolicyFixtures()).jsonObject
        val failures = result.getValue("failures").jsonArray
        assertEquals(26, result.getValue("caseCount").jsonPrimitive.content.toInt())
        assertTrue("Native LSPosed policy fixture failures: $failures", failures.isEmpty())
    }

    @Test
    fun nativeRootSepolicyFixturesExerciseSharedOracle() {
        val result = Json.parseToJsonElement(runNativeRootSepolicyFixtures()).jsonObject
        val failures = result.getValue("failures").jsonArray
        assertEquals(17, result.getValue("caseCount").jsonPrimitive.content.toInt())
        assertTrue("Native-root policy fixture failures: $failures", failures.isEmpty())
    }

    @Test
    fun nativeDangerousPackagesFixturesKeepPermissionDenialsDiagnostic() {
        val result = Json.parseToJsonElement(runNativeDangerousPackagesFixtures()).jsonObject
        val failures = result.getValue("failures").jsonArray
        assertEquals(8, result.getValue("caseCount").jsonPrimitive.content.toInt())
        assertTrue("Native dangerous-package fixture failures: $failures", failures.isEmpty())
    }

    @Test
    fun nativeBinaryArtifactFixturesExerciseObjectAndFormatModel() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val result = Json.parseToJsonElement(
            runNativeBinaryArtifactFixtures(context.cacheDir.absolutePath),
        ).jsonObject
        val failures = result.getValue("failures").jsonArray
        assertEquals(12, result.getValue("caseCount").jsonPrimitive.content.toInt())
        assertTrue("Native binary-artifact fixture failures: $failures", failures.isEmpty())
    }

    @Test
    fun nativePackageStorageVisibilityFixturesExerciseReadOnlyPolicy() {
        val result = Json.parseToJsonElement(
            runNativePackageStorageVisibilityFixtures(),
        ).jsonObject
        val failures = result.getValue("failures").jsonArray
        assertEquals(12, result.getValue("caseCount").jsonPrimitive.content.toInt())
        assertTrue("Native package-storage fixture failures: $failures", failures.isEmpty())
    }

    @Test
    fun nativeTeeFixturesExerciseConservativeAssessmentPolicy() {
        val result = Json.parseToJsonElement(runNativeTeeAssessmentFixtures()).jsonObject
        val failures = result.getValue("failures").jsonArray
        assertEquals(24, result.getValue("caseCount").jsonPrimitive.content.toInt())
        assertTrue("Native TEE fixture failures: $failures", failures.isEmpty())
    }

    @Test
    fun teeDetectorsExecuteThroughPublicContractWithoutResidualAliases() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        val ids = setOf(
            "TEE_ATTESTATION",
            "TEE_OVERSIZED_CHALLENGE",
            "TEE_KEYSTORE_CONSISTENCY",
        )
        val aliasesBefore = tamperProbeAliases()
        val warmup = client.scanBlocking(ScanRequest(ids))
        assertTrue(warmup.results.none { it.outcome == DetectionOutcome.FAILED })
        val measurements = (1..5).map { repetition ->
            val startedAt = SystemClock.elapsedRealtime()
            val report = client.scanBlocking(ScanRequest(ids))
            Triple(repetition, SystemClock.elapsedRealtime() - startedAt, report)
        }
        val report = measurements.last().third
        val aliasesAfter = tamperProbeAliases()

        measurements.forEach { (_, _, measuredReport) ->
            assertEquals(ids, measuredReport.results.map { it.descriptor.id }.toSet())
            assertTrue(measuredReport.results.none { it.outcome == DetectionOutcome.FAILED })
        }
        assertEquals(
            mapOf(
                "TEE_ATTESTATION" to 1,
                "TEE_OVERSIZED_CHALLENGE" to 1,
                "TEE_KEYSTORE_CONSISTENCY" to 1,
            ),
            report.results.associate { it.descriptor.id to it.descriptor.payloadSchemaVersion },
        )
        assertEquals(aliasesBefore, aliasesAfter)
        measurements.forEach { (repetition, elapsedMs, measuredReport) ->
            measuredReport.results.forEach { result ->
                Log.i(
                    "TamperProbeTeeDeviceTest",
                    buildString {
                        append("repetition=$repetition")
                        append(" id=${result.descriptor.id}")
                        append(" outcome=${result.outcome}")
                        append(" strength=${result.strength}")
                        append(" schema=${result.descriptor.payloadSchemaVersion}")
                        append(" records=${result.unitResults.flatMap { it.records }.map { it.code }}")
                        append(" safeAttributes=${result.unitResults.flatMap { it.records }.associate { evidence ->
                            evidence.code to evidence.attributes.filterKeys(::isSafeTeeAttribute)
                        }}")
                        append(" collectionError=${result.collectionError?.code}")
                    },
                )
            }
            Log.i(
                "TamperProbeTeeDeviceTest",
                "repetition=$repetition fullScanElapsedMs=$elapsedMs",
            )
        }
    }

    @Test
    fun lsposedSepolicyRunsOnlyThroughExplicitSelection() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        val report = client.scanBlocking(ScanRequest(setOf("LSPOSED_SEPOLICY")))
        val result = report.results.single()
        assertEquals("LSPOSED_SEPOLICY", result.descriptor.id)
        assertEquals(1, result.descriptor.payloadSchemaVersion)
        assertTrue(result.outcome != DetectionOutcome.FAILED)
    }

    @Test
    fun packageStorageVisibilityRunsOnlyThroughExplicitSelection() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        val result = client.scanBlocking(
            ScanRequest(setOf("PACKAGE_STORAGE_VISIBILITY")),
        ).results.single()

        assertEquals("PACKAGE_STORAGE_VISIBILITY", result.descriptor.id)
        assertEquals("app-visibility", result.descriptor.primaryEvidenceDomainId)
        assertEquals(1, result.descriptor.payloadSchemaVersion)
        assertTrue(result.outcome != DetectionOutcome.FAILED)
        val telemetryOnly = result.unitResults
            .flatMap { it.records }
            .filter { it.attributes["assessmentImpact"] == "telemetry_only" }
        assertTrue(telemetryOnly.all { it.kind == EvidenceRecordKind.RESEARCH })
        assertTrue(telemetryOnly.none { it.kind == EvidenceRecordKind.SIGNAL })
    }

    @Test
    fun propertyAreaResidueRunsOnlyThroughExplicitSelection() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        val report = client.scanBlocking(ScanRequest(setOf("PROPERTY_AREA_RESIDUE")))
        val result = report.results.single()

        assertEquals("PROPERTY_AREA_RESIDUE", result.descriptor.id)
        assertEquals("system-state", result.descriptor.primaryEvidenceDomainId)
        assertEquals(1, result.descriptor.payloadSchemaVersion)
        assertTrue(result.outcome != DetectionOutcome.FAILED)
        Log.i(
            "PropertyAreaResidueDeviceTest",
            "outcome=${result.outcome} strength=${result.strength} records=${result.unitResults.flatMap { it.records }.map { it.code }}",
        )
    }

    @Test
    fun buildPatchCoherenceRunsOnlyThroughExplicitSelection() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        val report = client.scanBlocking(ScanRequest(setOf("BUILD_PATCH_COHERENCE")))
        val result = report.results.single()

        assertEquals("BUILD_PATCH_COHERENCE", result.descriptor.id)
        assertEquals("system-state", result.descriptor.primaryEvidenceDomainId)
        assertEquals(1, result.descriptor.payloadSchemaVersion)
        assertTrue(result.outcome != DetectionOutcome.FAILED)
        Log.i(
            "BuildPatchCoherenceDeviceTest",
            "outcome=${result.outcome} strength=${result.strength} records=${result.unitResults.flatMap { it.records }.map { it.code }}",
        )
    }

    @Test
    fun drmCredentialCoherenceRunsOnlyThroughExplicitSelection() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        val report = client.scanBlocking(ScanRequest(setOf("DRM_CREDENTIAL_COHERENCE")))
        val result = report.results.single()

        assertEquals("DRM_CREDENTIAL_COHERENCE", result.descriptor.id)
        assertEquals("hardware-attestation", result.descriptor.primaryEvidenceDomainId)
        assertEquals(1, result.descriptor.payloadSchemaVersion)
        assertTrue(result.outcome != DetectionOutcome.FAILED)
        Log.i(
            "DrmCredentialDeviceTest",
            "outcome=${result.outcome} strength=${result.strength} records=${result.unitResults.flatMap { it.records }.map { it.code }}",
        )
    }

    @Test
    fun keystoreGrantSplitRunsOnlyThroughExplicitSelection() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        val report = client.scanBlocking(ScanRequest(setOf("KEYSTORE_GRANT_SPLIT")))
        val result = report.results.single()

        assertEquals("KEYSTORE_GRANT_SPLIT", result.descriptor.id)
        assertEquals("hardware-attestation", result.descriptor.primaryEvidenceDomainId)
        assertEquals(1, result.descriptor.payloadSchemaVersion)
        assertTrue(result.outcome != DetectionOutcome.FAILED)
        Log.i(
            "KeystoreGrantSplitDeviceTest",
            "outcome=${result.outcome} strength=${result.strength} records=${result.unitResults.flatMap { it.records }.map { it.code }}",
        )
    }

    @Test
    fun bothPolicyBackedDetectorsShareOneExplicitScan() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        val ids = setOf("LSPOSED_SEPOLICY", "NATIVE_ROOT_SEPOLICY")
        val report = client.scanBlocking(ScanRequest(ids))

        assertEquals(ids, report.results.map { it.descriptor.id }.toSet())
        assertTrue(report.results.none { it.outcome == DetectionOutcome.FAILED })
        assertEquals(
            mapOf("LSPOSED_SEPOLICY" to 1, "NATIVE_ROOT_SEPOLICY" to 1),
            report.results.associate { it.descriptor.id to it.descriptor.payloadSchemaVersion },
        )
        val cjk = Regex("[\\u3400-\\u9FFF]")
        report.results.forEach { result ->
            assertTrue(!cjk.containsMatchIn(result.descriptor.name))
            assertTrue(!cjk.containsMatchIn(result.descriptor.description))
            assertTrue(result.unitResults.flatMap { it.records }.none { cjk.containsMatchIn(it.summary) })
            Log.i(
                "TamperProbePolicyOracleTest",
                buildString {
                    append("id=${result.descriptor.id}")
                    append(" outcome=${result.outcome}")
                    append(" strength=${result.strength}")
                    append(" schema=${result.descriptor.payloadSchemaVersion}")
                    append(" records=${result.unitResults.flatMap { it.records }.map { it.code }}")
                    append(" collectionError=${result.collectionError?.code}")
                },
            )
        }
    }

    @Test
    fun catalogAndRepeatedSelectionsUseIndependentScanState() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        assertTrue(client.availableDetectors().isNotEmpty())

        val busyBox = client.scanBlocking(ScanRequest(setOf("BUSYBOX")))
        assertEquals(listOf("BUSYBOX"), busyBox.results.map { it.descriptor.id })

        val suBinary = client.scanBlocking(ScanRequest(setOf("SU_BINARY")))
        assertEquals(listOf("SU_BINARY"), suBinary.results.map { it.descriptor.id })
    }

    @Test
    fun memoryAndHookDetectorsExecuteThroughPublicContract() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        val ids = setOf(
            "MEMORY_FD_ANOMALY",
            "MEMORY_MAPS_ANOMALY",
            "MEMORY_LINKER_VISIBILITY",
            "PROLOGUE_SCANNER",
            "RUNTIME_INSTRUMENTATION",
            "ELF_TEXT_INTEGRITY",
            "VDSO_INTEGRITY",
        )

        val report = client.scanBlocking(ScanRequest(ids))
        assertEquals(ids, report.results.map { it.descriptor.id }.toSet())
        assertTrue(report.results.none { it.outcome == DetectionOutcome.FAILED })
        val entryPatterns = report.results
            .single { it.descriptor.id == "PROLOGUE_SCANNER" }
            .unitResults
            .flatMap { it.records }
            .filter { it.kind.name == "RESEARCH" }
        assertEquals(1, entryPatterns.size)
        val patternAttributes = entryPatterns.single().attributes
        // An empty record here is the failure this test exists to catch: the unit was
        // published with no attributes at all until 2026-09-07, because its plan named
        // payload keys the detector never emitted.
        assertTrue(patternAttributes.isNotEmpty())
        assertEquals("diagnostic_only", patternAttributes["entryPatternPolicy"])
        val patternIndices = patternAttributes.keys
            .mapNotNull { key -> key.removePrefix("patterns.").substringBefore('.').toIntOrNull() }
            .distinct()
        assertTrue(patternIndices.isNotEmpty())
        patternIndices.forEach { index ->
            assertEquals(
                "diagnostic_only",
                patternAttributes["patterns.$index.patternAssessmentImpact"],
            )
            val entryBytesHex = patternAttributes["patterns.$index.entryBytesHex"]
            // Unreadable entries legitimately report no bytes; a readable one is 16 bytes.
            assertTrue(entryBytesHex == null || entryBytesHex.isEmpty() || entryBytesHex.length == 32)
        }
        Log.i(
            "TamperProbeDeviceTest",
            "prologueEntryPatterns=${patternIndices.map { index ->
                mapOf(
                    "library" to patternAttributes["patterns.$index.targetLibrary"],
                    "function" to patternAttributes["patterns.$index.function"],
                    "entryPattern" to patternAttributes["patterns.$index.entryPattern"],
                    "impact" to patternAttributes["patterns.$index.patternAssessmentImpact"],
                )
            }}",
        )
        report.results.forEach { result ->
            Log.i(
                "TamperProbeDeviceTest",
                buildString {
                    append("id=${result.descriptor.id}")
                    append(" outcome=${result.outcome}")
                    append(" strength=${result.strength}")
                    append(" schema=${result.descriptor.payloadSchemaVersion}")
                    append(" records=${result.unitResults.flatMap { it.records }.map { it.code }}")
                    append(" collectionError=${result.collectionError?.code}")
                },
            )
        }
    }

    @Test
    fun propertyAndSelinuxDetectorsPublishSchemaV2EnglishEvidence() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        val ids = setOf("DANGEROUS_PROPS", "SYSTEM_PROPERTIES_TAMPER", "SELINUX_CHECK")
        val report = client.scanBlocking(ScanRequest(ids))
        val cjk = Regex("[\\u3400-\\u9fff]")

        assertEquals(ids, report.results.map { it.descriptor.id }.toSet())
        assertTrue(report.results.none { it.outcome == DetectionOutcome.FAILED })
        report.results.forEach { result ->
            assertEquals(1, result.descriptor.payloadSchemaVersion)
            assertTrue(!cjk.containsMatchIn(result.descriptor.name))
            assertTrue(!cjk.containsMatchIn(result.descriptor.description))
            assertTrue(result.unitResults.flatMap { it.records }.none { cjk.containsMatchIn(it.summary) })
            Log.i(
                "TamperProbeDeviceTest",
                buildString {
                    append("id=${result.descriptor.id}")
                    append(" outcome=${result.outcome}")
                    append(" strength=${result.strength}")
                    append(" schema=${result.descriptor.payloadSchemaVersion}")
                    append(" records=${result.unitResults.flatMap { it.records }.map { it.code }}")
                    append(" collectionError=${result.collectionError?.code}")
                },
            )
        }
    }

    companion object {
        private fun tamperProbeAliases(): Set<String> {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            return keyStore.aliases().toList()
                .filter { it.startsWith("tamperprobe_") }
                .toSet()
        }

        private fun isSafeTeeAttribute(path: String): Boolean {
            val field = path.substringAfterLast('.')
            return field in setOf(
                "id",
                "required",
                "state",
                "source",
                "errorCategory",
                "numericErrorCode",
                "aliasCleanupSucceeded",
                "challengeSize",
                "keySecurityLevel",
                "requiredCheckCount",
                "completedRequiredCheckCount",
                "requiredContradictionCount",
                "signaturesChecked",
                "signaturesValid",
                "trustedRootState",
                "rkpProvisioningExtensionPresent",
                "provisioningExpiryState",
                "present",
                "matches",
                "attestationSecurityLevel",
                "keymasterSecurityLevel",
                "deviceLocked",
                "verifiedBootState",
                "runtimeDigestAvailable",
                "comparable",
                "zeroBootKey",
                "zeroBootHash",
                "validationState",
                "revoked",
                "suspended",
                "expiredEntryCount",
            )
        }

        init {
            System.loadLibrary("tamperprobe_native")
        }
    }
}
