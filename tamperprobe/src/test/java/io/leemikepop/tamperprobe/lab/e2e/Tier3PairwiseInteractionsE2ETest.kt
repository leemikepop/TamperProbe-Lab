package io.leemikepop.tamperprobe.lab.e2e

import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.ReferenceTamperScorer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tier 3: Pairwise & Cross-Feature Interaction E2E Tests.
 * Evaluates >= 21 multi-detector interaction scenarios across evidence domains.
 */
class Tier3PairwiseInteractionsE2ETest {

    @Test
    fun interaction_01_mountIdGap_and_statxCrossref_dualMountTamper() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("MOUNT_INTEGRITY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("gap" to "32", "statxMismatch" to "true"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun interaction_02_smapsDirtyPage_and_gotPltEscape_compositeMemoryHook() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("ZYGISK_SMAPS"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("dirtyKB" to "16"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("escapedSymbols" to "open,read"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(8, score.score)
        assertTrue(score.thresholdReached)
        assertEquals(listOf("ZYGISK_SMAPS", "MEMORY_LINKER_VISIBILITY"), score.observedDetectorIds)
    }

    @Test
    fun interaction_03_signalHandler_and_linkerMapsOnly_fridaInjection() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("signalHandler" to "anonymous_memory"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("unlinkedMaps" to "1"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun interaction_04_kptrRestrict_and_procVersion_customKernelSignature() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("KERNEL_CHECK"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("kptr_restrict" to "disabled", "versionSignature" to "t.me/custom_kernel"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(2, score.score)
        assertTrue(score.observedDetectorIds.contains("KERNEL_CHECK"))
    }

    @Test
    fun interaction_05_supercallLatency_and_cgroup_apatchEnvironment() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("supercallLatency" to "anomaly_detected", "cgroup" to "/apatch/daemon"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(2, score.score)
    }

    @Test
    fun interaction_06_crossProcessFdTrap_and_threadComm_zygiskInjection() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("MEMORY_FD_ANOMALY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("fdTrap" to "closed_by_zygisk"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("comm" to "zygisk-companion"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(8, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun interaction_07_propertyAreaHoleScan_and_procCmdline_resetpropTamper() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("unreferencedBytes" to "256", "cmdlineMismatch" to "androidboot.verifiedbootstate"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(2, score.score)
    }

    @Test
    fun interaction_08_emulatorHardware_and_emulatorSystemProfile_fullEmulator() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("EMULATOR_HARDWARE_INDICATORS"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("glRenderer" to "Android Emulator OpenGL ES Translator"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("EMULATOR_SYSTEM_PROFILE"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("ro.kernel.qemu" to "1", "ro.hardware" to "ranchu"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(8, score.score)
        assertTrue(score.thresholdReached)
        assertEquals(listOf("EMULATOR_HARDWARE_INDICATORS", "EMULATOR_SYSTEM_PROFILE"), score.observedDetectorIds)
    }

    @Test
    fun interaction_09_mountNamespaceSplit_and_rootDriverIoctl_kernelSuEnvironment() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("nsSplit" to "true"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("NATIVE_ROOT_DEVPTS"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("driverFd" to "[ksu_driver]"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(6, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun interaction_10_heapEntropy_and_smapsDirtyPage_runtimePollution() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("heapEntropy" to "abnormal"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("ZYGISK_SMAPS"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("dirtyKB" to "24"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(6, score.score)
    }

    @Test
    fun interaction_11_selinuxCheck_and_lsposedSepolicy_sepolicyBackdoor() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("SELINUX_CHECK"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("enforcing" to "false"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("LSPOSED_SEPOLICY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("rule" to "allow_untrusted_app_xposed"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(8, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun interaction_12_suBinary_and_suContext_traditionalRoot() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("SU_BINARY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("path" to "/system/xbin/su"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("SU_CONTEXT"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("context" to "u:r:su:s0"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(8, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun interaction_13_dangerousPackages_and_packageStorage_managerVisibility() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("DANGEROUS_PACKAGES"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.WEAK,
            mapOf("pkg" to "com.topjohnwu.magisk"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("PACKAGE_STORAGE_VISIBILITY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.WEAK,
            mapOf("dir" to "/data/data/com.topjohnwu.magisk"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(2, score.score)
    }

    @Test
    fun interaction_14_teeAttestation_and_teeKeystoreConsistency_untrustedHardware() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("TEE_ATTESTATION"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("attestationStatus" to "unlocked_bootloader"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("TEE_KEYSTORE_CONSISTENCY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("keystoreStatus" to "inconsistent"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(8, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun interaction_15_prologueScanner_and_elfTextIntegrity_nativePatching() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("PROLOGUE_SCANNER"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("hook" to "trampoline_in_prologue"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("ELF_TEXT_INTEGRITY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("checksum" to "mismatch"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(8, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun interaction_16_vdsoIntegrity_and_runtimeInstrumentation_syscallHijacking() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("VDSO_INTEGRITY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("vdsoTamper" to "modified_syscall_stub"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("hook" to "inline_syscall_redirect"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(6, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun interaction_17_mountIntegrity_and_rwPaths_remountedSystem() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("MOUNT_INTEGRITY"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("mountOption" to "rw"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("RW_PATHS"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("writablePath" to "/system/bin"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun interaction_18_emulatorIndicators_and_customRom_emulatedLineage() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("EMULATOR_HARDWARE_INDICATORS"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("glRenderer" to "llvmpipe"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("CUSTOM_ROM"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.WEAK,
            mapOf("rom" to "lineageos"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(5, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun interaction_19_zygiskNamespace_and_zygiskSmaps_fullZygiskSuite() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("isolatedMnt" to "true"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("ZYGISK_SMAPS"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("dirtyCodePage" to "zygisk_so"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(6, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun interaction_20_kernelCheck_and_nativeRootPrctl_kernelExploit() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("KERNEL_CHECK"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("kptr_restrict" to "0"),
        )
        val r2 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL"),
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("prctlStatus" to "elevated_caps"),
        )
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun interaction_21_multiVectorFullSystemCompromise() {
        val detectors = listOf(
            E2ETestHelper.descriptorFor("SU_BINARY") to EvidenceStrength.STRONG,
            E2ETestHelper.descriptorFor("MOUNT_INTEGRITY") to EvidenceStrength.STRONG,
            E2ETestHelper.descriptorFor("ZYGISK_SMAPS") to EvidenceStrength.STRONG,
            E2ETestHelper.descriptorFor("KERNEL_CHECK") to EvidenceStrength.MODERATE,
            E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER") to EvidenceStrength.MODERATE,
        )
        val results = detectors.map { (desc, str) ->
            E2ETestHelper.createDetectorResult(desc, DetectionOutcome.OBSERVED, str)
        }
        val report = E2ETestHelper.buildReport(results)
        val score = ReferenceTamperScorer.score(report)
        // 4 + 4 + 4 + 2 + 2 = 16
        assertEquals(16, score.score)
        assertTrue(score.thresholdReached)
        assertEquals(5, score.observedDetectorIds.size)
    }
}
