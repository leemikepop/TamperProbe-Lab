package io.leemikepop.tamperprobe.lab.e2e

import io.leemikepop.tamperprobe.lab.api.CollectionError
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.ReferenceTamperScorer
import io.leemikepop.tamperprobe.lab.api.ReferenceTamperScoringPolicy
import io.leemikepop.tamperprobe.lab.api.ScanCompletion
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tier 4: Real-World Application Workload Scenarios E2E Tests.
 * Evaluates realistic device, emulator, root hiding, injection, and tampering workloads.
 */
class Tier4RealWorldWorkloadsE2ETest {

    // =========================================================================
    // Scenario 1: Standard Android Physical Device (Clean, Stock Unrooted)
    // =========================================================================
    @Test
    fun scenario_01_cleanPhysicalStockDevice_allDetectorsClean_scoreZeroThresholdNotReached() {
        val descriptors = E2ETestHelper.catalog.descriptors
        val results = descriptors.map { desc ->
            E2ETestHelper.createDetectorResult(
                desc,
                DetectionOutcome.NOT_OBSERVED,
                EvidenceStrength.NONE,
                mapOf("verified" to "clean"),
            )
        }
        val report = E2ETestHelper.buildReport(results, ScanCompletion.COMPLETE, durationMillis = 24)
        val score = ReferenceTamperScorer.score(report)

        assertEquals(0, score.score)
        assertEquals(4, score.threshold)
        assertFalse(score.thresholdReached)
        assertTrue(score.observedDetectorIds.isEmpty())
        assertTrue(score.inconclusiveDetectorIds.isEmpty())
        assertTrue(score.failedDetectorIds.isEmpty())
        assertEquals(descriptors.size, report.results.size)
    }

    // =========================================================================
    // Scenario 2: Standard Android Studio AVD (x86_64, API 34+)
    // =========================================================================
    @Test
    fun scenario_02_androidStudioAvd_emulatorDetectorsTrigger_scoreReached() {
        val emuHwDesc = E2ETestHelper.descriptorFor("EMULATOR_HARDWARE_INDICATORS")
        val emuProfileDesc = E2ETestHelper.descriptorFor("EMULATOR_SYSTEM_PROFILE")

        val rEmuHw = E2ETestHelper.createDetectorResult(
            emuHwDesc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("glRenderer" to "Android Emulator OpenGL ES Translator"),
        )
        val rEmuProf = E2ETestHelper.createDetectorResult(
            emuProfileDesc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("ro.kernel.qemu" to "1", "ro.hardware" to "ranchu", "ro.product.model" to "sdk_gphone64_x86_64"),
        )
        val standardCleanResults = E2ETestHelper.catalog.descriptors.take(10).map { desc ->
            E2ETestHelper.createDetectorResult(desc, DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE)
        }

        val report = E2ETestHelper.buildReport(listOf(rEmuHw, rEmuProf) + standardCleanResults)
        val score = ReferenceTamperScorer.score(report)

        // STRONG(4) + STRONG(4) = 8 >= 4
        assertEquals(8, score.score)
        assertTrue(score.thresholdReached)
        assertTrue(score.observedDetectorIds.contains("EMULATOR_HARDWARE_INDICATORS"))
        assertTrue(score.observedDetectorIds.contains("EMULATOR_SYSTEM_PROFILE"))
    }

    // =========================================================================
    // Scenario 3: Device with SUSFS Root Hiding Active
    // =========================================================================
    @Test
    fun scenario_03_susfsRootHiding_statxOrGapScanTriggers_tamperDetected() {
        val rMount = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("MOUNT_INTEGRITY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("statxMismatch" to "true", "gapSize" to "14", "anomaly" to "susfs_hidden_mount_layer"),
        )
        val rSusfs = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("NATIVE_ROOT_SUSFS"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("susfsProbe" to "detected"),
        )
        val otherResults = E2ETestHelper.catalog.descriptors
            .filter { it.id != "MOUNT_INTEGRITY" && it.id != "NATIVE_ROOT_SUSFS" }
            .map { E2ETestHelper.createDetectorResult(it, DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE) }

        val report = E2ETestHelper.buildReport(listOf(rMount, rSusfs) + otherResults)
        val score = ReferenceTamperScorer.score(report)

        // 4 + 4 = 8 >= 4
        assertEquals(8, score.score)
        assertTrue(score.thresholdReached)
        assertTrue(score.observedDetectorIds.contains("MOUNT_INTEGRITY"))
        assertTrue(score.observedDetectorIds.contains("NATIVE_ROOT_SUSFS"))
    }

    // =========================================================================
    // Scenario 4: Device with Frida Dynamic Instrumentation Hook Active
    // =========================================================================
    @Test
    fun scenario_04_fridaDynamicInstrumentation_memoryAndRuntimeDetectorsTrigger() {
        val rGot = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("gotHook" to "dlsym_escape"),
        )
        val rSmaps = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("ZYGISK_SMAPS"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("dirtyExecPagesKB" to "32"),
        )
        val rSig = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("sigaction" to "frida-gadget-handler"),
        )
        val rComm = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("comm" to "gmain_frida"),
        )

        val report = E2ETestHelper.buildReport(listOf(rGot, rSmaps, rSig, rComm))
        val score = ReferenceTamperScorer.score(report)

        // 4 * 4 = 16 >= 4
        assertEquals(16, score.score)
        assertTrue(score.thresholdReached)
        assertEquals(4, score.observedDetectorIds.size)
    }

    // =========================================================================
    // Scenario 5: Device with resetprop Altered Properties & Spoofed State
    // =========================================================================
    @Test
    fun scenario_05_resetpropTamperedProperties_holeScanAndCmdlineMismatchTrigger() {
        val rPropTamper = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("unreferencedBytes" to "512", "cmdlineMismatch" to "androidboot.verifiedbootstate"),
        )
        val rProps = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("DANGEROUS_PROPS"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("ro.debuggable" to "1"),
        )

        val report = E2ETestHelper.buildReport(listOf(rPropTamper, rProps))
        val score = ReferenceTamperScorer.score(report)

        // 4 + 2 = 6 >= 4
        assertEquals(6, score.score)
        assertTrue(score.thresholdReached)
        assertTrue(score.observedDetectorIds.contains("SYSTEM_PROPERTIES_TAMPER"))
    }

    // =========================================================================
    // Scenario 6: APatch / KernelPatch Root Environment
    // =========================================================================
    @Test
    fun scenario_06_apatchKernelPatch_supercallAndKernelBannerTrigger() {
        val rPrctl = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("supercallLatencyDeviation" to "5.4x"),
        )
        val rKernel = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("KERNEL_CHECK"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("versionSignature" to "t.me/KernelPatch"),
        )

        val report = E2ETestHelper.buildReport(listOf(rPrctl, rKernel))
        val score = ReferenceTamperScorer.score(report)

        // 2 + 2 = 4 >= 4
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    // =========================================================================
    // Scenario 7: KernelSU Root Environment with Driver FD
    // =========================================================================
    @Test
    fun scenario_07_kernelsuEnvironment_rootDriverAndMountTrigger() {
        val rDriver = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("NATIVE_ROOT_DEVPTS"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("fdTarget" to "[ksu_driver]"),
        )
        val rMount = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("MOUNT_INTEGRITY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("overlay" to "/data/adb/ksu/modules"),
        )

        val report = E2ETestHelper.buildReport(listOf(rDriver, rMount))
        val score = ReferenceTamperScorer.score(report)

        // 4 + 2 = 6 >= 4
        assertEquals(6, score.score)
        assertTrue(score.thresholdReached)
    }

    // =========================================================================
    // Scenario 8: LSposed Framework Active Hook Environment
    // =========================================================================
    @Test
    fun scenario_08_lsposedActiveFramework_mapsSepolicyAndPrologueTrigger() {
        val rMaps = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("LSPOSED_MAPS"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("lsposedLibrary" to "liblspd.so"),
        )
        val rSepolicy = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("LSPOSED_SEPOLICY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("rule" to "magisk_client_allow"),
        )
        val rPrologue = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("PROLOGUE_SCANNER"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("prologueHook" to "trampoline_detected"),
        )

        val report = E2ETestHelper.buildReport(listOf(rMaps, rSepolicy, rPrologue))
        val score = ReferenceTamperScorer.score(report)

        // 4 + 4 + 4 = 12 >= 4
        assertEquals(12, score.score)
        assertTrue(score.thresholdReached)
    }

    // =========================================================================
    // Scenario 9: Hardened Enterprise Restricted Device (MDM Sandbox)
    // =========================================================================
    @Test
    fun scenario_09_hardenedEnterpriseMdmDevice_inconclusiveProcfs_scoreDoesNotExceedThreshold() {
        val rInconclusive1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("MEMORY_FD_ANOMALY"),
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("reason" to "mdm_proc_restricted"),
        )
        val rInconclusive2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("KERNEL_CHECK"),
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("reason" to "mdm_kallsyms_restricted"),
        )
        val cleanResults = E2ETestHelper.catalog.descriptors.take(5).map {
            E2ETestHelper.createDetectorResult(it, DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE)
        }

        val report = E2ETestHelper.buildReport(listOf(rInconclusive1, rInconclusive2) + cleanResults)
        val score = ReferenceTamperScorer.score(report)

        // 1 + 1 = 2 < 4 -> Not Reached (No false positive lockouts)
        assertEquals(2, score.score)
        assertFalse(score.thresholdReached)
        assertEquals(2, score.inconclusiveDetectorIds.size)
    }

    // =========================================================================
    // Scenario 10: Banking Application Pre-Transaction Integrity Inspection
    // =========================================================================
    @Test
    fun scenario_10_bankingHighSensitivityPolicy_strictEvaluation() {
        val bankingPolicy = ReferenceTamperScoringPolicy(
            weakWeight = 2,
            moderateWeight = 4,
            strongWeight = 8,
            inconclusiveWeight = 2,
            threshold = 4,
        )

        // Single weak signal from custom ROM on a banking app reaches threshold under high-sensitivity policy
        val rCustomRom = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("CUSTOM_ROM"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.WEAK,
            mapOf("tag" to "test-keys"),
        )
        val report = E2ETestHelper.buildReport(listOf(rCustomRom))
        val score = ReferenceTamperScorer.score(report, bankingPolicy)

        assertEquals(2, score.score)
        assertFalse(score.thresholdReached)

        // Two weak signals or one moderate signal triggers threshold
        val rPkg = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("DANGEROUS_PACKAGES"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.WEAK,
            mapOf("pkg" to "com.chelpus.lackypatch"),
        )
        val report2 = E2ETestHelper.buildReport(listOf(rCustomRom, rPkg))
        val score2 = ReferenceTamperScorer.score(report2, bankingPolicy)

        assertEquals(4, score2.score)
        assertTrue(score2.thresholdReached)
    }

    // =========================================================================
    // Scenario 11: Multi-Tenant Virtual App Container / Parallel Space
    // =========================================================================
    @Test
    fun scenario_11_virtualAppContainer_storageAndNamespaceAnomalies() {
        val rStorage = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("PACKAGE_STORAGE_VISIBILITY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.WEAK,
            mapOf("virtualizedPath" to "/data/data/com.lbe.parallel/parallel/0/"),
        )
        val rNs = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("containerMntNs" to "divergent"),
        )

        val report = E2ETestHelper.buildReport(listOf(rStorage, rNs))
        val score = ReferenceTamperScorer.score(report)

        // 1 + 2 = 3 < 4 (Sub-threshold sandboxing anomaly without root)
        assertEquals(3, score.score)
        assertFalse(score.thresholdReached)
        assertEquals(listOf("PACKAGE_STORAGE_VISIBILITY", "ZYGISK_NAMESPACE"), score.observedDetectorIds)
    }
}
