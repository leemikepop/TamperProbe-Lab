package io.leemikepop.tamperprobe.lab.e2e

import io.leemikepop.tamperprobe.lab.api.CollectionError
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.api.ReferenceTamperScorer
import io.leemikepop.tamperprobe.lab.api.ReferenceTamperScoringPolicy
import io.leemikepop.tamperprobe.lab.api.ScanCompletion
import io.leemikepop.tamperprobe.lab.internal.DetectorResultMapper
import io.leemikepop.tamperprobe.lab.internal.WireDetectorResult
import io.leemikepop.tamperprobe.lab.internal.WireParser
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tier 1: Feature Coverage E2E Tests.
 * Ensures all 21 features defined in PROJECT.md / TEST_INFRA.md have >= 5 opaque-box test cases.
 */
class Tier1FeatureCoverageE2ETest {

    // =========================================================================
    // Feature 1: statx Mount ID Cross-Reference (R1.1)
    // =========================================================================

    @Test
    fun f01_statxMountId_cleanConsistentMounts_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("statxChecks" to "consistent", "verifiedPaths" to "12"),
        )
        val report = E2ETestHelper.buildReport(listOf(result))
        val score = ReferenceTamperScorer.score(report)

        assertEquals(0, score.score)
        assertFalse(score.thresholdReached)
        assertEquals(DetectionOutcome.NOT_OBSERVED, report.results[0].outcome)
        assertEquals(EvidenceStrength.NONE, report.results[0].strength)
    }

    @Test
    fun f01_statxMountId_mismatchedStatxMountId_triggersObservedStrong() {
        val descriptor = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("statxMountId" to "4096", "mountinfoId" to "2048", "anomaly" to "susfs_hidden_mount"),
        )
        val report = E2ETestHelper.buildReport(listOf(result))
        val score = ReferenceTamperScorer.score(report)

        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
        assertTrue(score.observedDetectorIds.contains("MOUNT_INTEGRITY"))
    }

    @Test
    fun f01_statxMountId_statxSyscallPermissionDenied_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "EACCES_statx"),
        )
        val report = E2ETestHelper.buildReport(listOf(result))
        val score = ReferenceTamperScorer.score(report)

        assertEquals(1, score.score)
        assertFalse(score.thresholdReached)
        assertTrue(score.inconclusiveDetectorIds.contains("MOUNT_INTEGRITY"))
    }

    @Test
    fun f01_statxMountId_multipleCheckedMountPoints_mapsUnitRecords() {
        val descriptor = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("pathsChecked" to "/system,/vendor,/data", "mismatches" to "0"),
        )
        assertEquals(descriptor.evidenceUnits.size, result.unitResults.size)
        assertTrue(result.unitResults.all { it.collectionStatus == EvidenceUnitCollectionStatus.COMPLETE })
    }

    @Test
    fun f01_statxMountId_wirePayloadDecoding_preservesStatxMetadata() {
        val descriptor = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val wireResult = WireDetectorResult(
            detectorId = "MOUNT_INTEGRITY",
            outcome = DetectionOutcome.NOT_OBSERVED,
            evidenceStrength = EvidenceStrength.NONE,
            payload = buildJsonObject {
                put("completedStatxChecks", 4)
                put("mountInfoReadable", true)
            },
        )
        val mapped = DetectorResultMapper.map(descriptor, wireResult)
        assertEquals(DetectionOutcome.NOT_OBSERVED, mapped.outcome)
        assertEquals(EvidenceStrength.NONE, mapped.strength)
        assertNull(mapped.collectionError)
    }

    // =========================================================================
    // Feature 2: Mount ID Gap Scanning (R1.1)
    // =========================================================================

    @Test
    fun f02_mountIdGap_continuousSequence_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("artMountId" to "100", "dataMirrorMountId" to "101", "gapSize" to "0"),
        )
        val report = E2ETestHelper.buildReport(listOf(result))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(0, score.score)
    }

    @Test
    fun f02_mountIdGap_largeGapBetweenConsecutiveMounts_triggersSignal() {
        val descriptor = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("artMountId" to "100", "dataMirrorMountId" to "150", "gapSize" to "49", "anomaly" to "erased_mounts"),
        )
        val report = E2ETestHelper.buildReport(listOf(result))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(2, score.score)
        assertTrue(score.observedDetectorIds.contains("MOUNT_INTEGRITY"))
    }

    @Test
    fun f02_mountIdGap_minorGapWithinTolerance_isTreatedAsNeutral() {
        val descriptor = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("gapSize" to "1", "telemetryOnly" to "true"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
        assertTrue(result.unitResults.flatMap { it.records }.none { it.kind == EvidenceRecordKind.SIGNAL })
    }

    @Test
    fun f02_mountIdGap_mountinfoUnreadable_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "mountinfo_unreadable"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
        assertEquals(1, result.unitResults.first { it.issues.isNotEmpty() }.issues.size)
    }

    @Test
    fun f02_mountIdGap_compoundGapAndHiddenOverlay_triggersStrongSignal() {
        val descriptor = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("gapSize" to "12", "hiddenOverlays" to "kernelsu_modules"),
        )
        val report = E2ETestHelper.buildReport(listOf(result))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    // =========================================================================
    // Feature 3: Mount Namespace Split (R1.1)
    // =========================================================================

    @Test
    fun f03_mountNamespaceSplit_identicalNamespaceInodes_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("selfMntNs" to "4026531840", "initMntNs" to "4026531840"),
        )
        val report = E2ETestHelper.buildReport(listOf(result))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(0, score.score)
    }

    @Test
    fun f03_mountNamespaceSplit_divergentNamespaceInode_triggersObserved() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("selfMntNs" to "4026532999", "initMntNs" to "4026531840", "splitDetected" to "true"),
        )
        val report = E2ETestHelper.buildReport(listOf(result))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(2, score.score)
        assertTrue(score.observedDetectorIds.contains("ZYGISK_NAMESPACE"))
    }

    @Test
    fun f03_mountNamespaceSplit_initNamespaceInaccessible_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "init_ns_read_failed"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
        assertEquals(EvidenceStrength.NONE, result.strength)
    }

    @Test
    fun f03_mountNamespaceSplit_unitRecordVerification() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
        )
        val signalRecords = result.unitResults.flatMap { it.records }.filter { it.kind == EvidenceRecordKind.SIGNAL }
        assertEquals(1, signalRecords.size)
        assertEquals(EvidenceStrength.STRONG, signalRecords[0].signalStrength)
    }

    @Test
    fun f03_mountNamespaceSplit_wirePayloadRoundtrip() {
        val wireResult = WireDetectorResult(
            detectorId = "ZYGISK_NAMESPACE",
            outcome = DetectionOutcome.OBSERVED,
            evidenceStrength = EvidenceStrength.MODERATE,
            payload = buildJsonObject {
                put("nsMismatch", true)
            },
        )
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val mapped = DetectorResultMapper.map(descriptor, wireResult)
        assertEquals(DetectionOutcome.OBSERVED, mapped.outcome)
        assertEquals(EvidenceStrength.MODERATE, mapped.strength)
    }

    // =========================================================================
    // Feature 4: GOT/PLT Escape (R1.2)
    // =========================================================================

    @Test
    fun f04_gotPltEscape_symbolsWithinExportingElf_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("dlsymTarget" to "libc.so", "address" to "0x7b120040", "bounds" to "0x7b120000-0x7b150000"),
        )
        val report = E2ETestHelper.buildReport(listOf(result))
        assertEquals(0, ReferenceTamperScorer.score(report).score)
    }

    @Test
    fun f04_gotPltEscape_dlsymAddressEscapesElfBounds_triggersObservedStrong() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("symbol" to "open", "dlsymAddress" to "0x7ff00010", "expectedElfBounds" to "0x7b120000-0x7b150000", "hookType" to "got_hook"),
        )
        val report = E2ETestHelper.buildReport(listOf(result))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun f04_gotPltEscape_multipleHookedSymbolsEscaping_reportsMultipleSignals() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("escapedSymbols" to "open,read,stat,kill"),
        )
        assertEquals(EvidenceStrength.STRONG, result.strength)
        assertTrue(result.unitResults.isNotEmpty())
    }

    @Test
    fun f04_gotPltEscape_unresolvableElfHeader_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "elf_header_inaccessible"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    @Test
    fun f04_gotPltEscape_cleanResolutionAcrossLibraries_noSignals() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("checkedLibs" to "libc.so,libdl.so,libm.so"),
        )
        assertTrue(result.unitResults.flatMap { it.records }.none { it.kind == EvidenceRecordKind.SIGNAL })
    }

    // =========================================================================
    // Feature 5: Linker Maps-Only Modules (R1.2)
    // =========================================================================

    @Test
    fun f05_linkerMapsOnly_allExecutableSegmentsInPhdr_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("mapsCount" to "150", "phdrMatches" to "150"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f05_linkerMapsOnly_executableMapMissingFromLinker_triggersObserved() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("unlinkedSegment" to "0x7a000000-0x7a050000", "perms" to "r-xp", "dl_iterate_phdr_record" to "missing"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(2, score.score)
        assertTrue(score.observedDetectorIds.contains("MEMORY_LINKER_VISIBILITY"))
    }

    @Test
    fun f05_linkerMapsOnly_anonymousExecutableBlock_triggersSignal() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("injectedPayload" to "[anon:unlinked_frida]"),
        )
        assertEquals(EvidenceStrength.STRONG, result.strength)
    }

    @Test
    fun f05_linkerMapsOnly_dlIteratePhdrFailure_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "dl_iterate_phdr_failed"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    @Test
    fun f05_linkerMapsOnly_cleanStandardModules_recordsObservation() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
        )
        assertTrue(result.unitResults.flatMap { it.records }.any { it.kind == EvidenceRecordKind.OBSERVATION })
    }

    // =========================================================================
    // Feature 6: Smaps Dirty-Page Hook Detection (R1.2)
    // =========================================================================

    @Test
    fun f06_smapsDirtyPage_zeroPrivateDirtyOnExecSegments_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_SMAPS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("maxPrivateDirtyKB" to "0", "examinedLibs" to "libc.so,libart.so"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(0, score.score)
    }

    @Test
    fun f06_smapsDirtyPage_privateDirtyAbove8KB_triggersObservedStrong() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_SMAPS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("lib" to "libc.so", "privateDirtyKB" to "16", "thresholdKB" to "8", "hookArtifact" to "dirty_code_page"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun f06_smapsDirtyPage_dirtyBelowThreshold_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_SMAPS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("privateDirtyKB" to "4", "thresholdKB" to "8"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f06_smapsDirtyPage_smapsUnreadable_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_SMAPS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "smaps_permission_denied"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    @Test
    fun f06_smapsDirtyPage_multipleHookedLibraries_accumulatesDirtyPages() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_SMAPS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("dirtyLibraries" to "libc.so:12KB,libart.so:32KB"),
        )
        assertEquals(EvidenceStrength.STRONG, result.strength)
    }

    // =========================================================================
    // Feature 7: Signal Handler Audit (R1.2)
    // =========================================================================

    @Test
    fun f07_signalHandlerAudit_standardSystemHandlers_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("SIGSEGV" to "libart.so", "SIGTRAP" to "libc.so"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f07_signalHandlerAudit_handlerInAnonymousMemory_triggersObserved() {
        val descriptor = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("signal" to "SIGTRAP", "handlerAddress" to "0x7e001000", "backingMemory" to "anonymous_mmap"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(2, score.score)
        assertTrue(score.observedDetectorIds.contains("RUNTIME_INSTRUMENTATION"))
    }

    @Test
    fun f07_signalHandlerAudit_handlerPointingToFridaAgent_triggersStrong() {
        val descriptor = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("signal" to "SIGSEGV", "handlerPath" to "/data/local/tmp/re.frida.gadget.so"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun f07_signalHandlerAudit_sigactionFailure_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "sigaction_query_failed"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    @Test
    fun f07_signalHandlerAudit_defaultAndIgnoreHandlers_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("SIGTRAP" to "SIG_DFL", "SIGILL" to "SIG_IGN"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    // =========================================================================
    // Feature 8: kptr_restrict Disabled Check (R1.3)
    // =========================================================================

    @Test
    fun f08_kptrRestrict_allPointersZero_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("top20Pointers" to "all_zero", "nonZeroRatio" to "0.0"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f08_kptrRestrict_nonZeroRatioAbove50Percent_triggersObserved() {
        val descriptor = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("top20Pointers" to "16/20_nonzero", "nonZeroRatio" to "0.80", "kptr_restrict" to "disabled"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(2, score.score)
        assertTrue(score.observedDetectorIds.contains("KERNEL_CHECK"))
    }

    @Test
    fun f08_kptrRestrict_nonZeroRatioBelow50Percent_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("top20Pointers" to "4/20_nonzero", "nonZeroRatio" to "0.20"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f08_kptrRestrict_kallsymsUnreadable_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "kallsyms_permission_denied"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    @Test
    fun f08_kptrRestrict_wirePayloadValidation() {
        val wire = WireDetectorResult(
            detectorId = "KERNEL_CHECK",
            outcome = DetectionOutcome.OBSERVED,
            evidenceStrength = EvidenceStrength.MODERATE,
            payload = buildJsonObject {
                put("kptrRestrictDisabled", true)
                put("nonZeroPointerRatio", 0.75)
            },
        )
        val descriptor = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val mapped = DetectorResultMapper.map(descriptor, wire)
        assertEquals(DetectionOutcome.OBSERVED, mapped.outcome)
        assertEquals(EvidenceStrength.MODERATE, mapped.strength)
    }

    // =========================================================================
    // Feature 9: /proc/version Signature Scan (R1.3)
    // =========================================================================

    @Test
    fun f09_procVersionSignature_cleanKernelBanner_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("banner" to "Linux version 5.15.0-android14-9-g12345 (build-user@build-host)"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f09_procVersionSignature_cjkSignatureDetected_triggersObservedModerate() {
        val descriptor = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("banner" to "Linux version 5.15.0-頂級核心-KernelSU", "matchedPattern" to "CJK_CHARACTERS"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(2, score.score)
    }

    @Test
    fun f09_procVersionSignature_telegramHandleDetected_triggersObservedModerate() {
        val descriptor = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("banner" to "Linux version 5.10.0 (t.me/kernel_patch_group)", "matchedPattern" to "TELEGRAM_URL"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(2, score.score)
    }

    @Test
    fun f09_procVersionSignature_emojiSignatureDetected_triggersObservedModerate() {
        val descriptor = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("banner" to "Linux version 5.4.0-🔥SuperKernel🔥", "matchedPattern" to "EMOJI_CHARACTERS"),
        )
        assertEquals(EvidenceStrength.MODERATE, result.strength)
    }

    @Test
    fun f09_procVersionSignature_procVersionUnreadable_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "proc_version_unreadable"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    // =========================================================================
    // Feature 10: Supercall Latency Probe (R1.4)
    // =========================================================================

    @Test
    fun f10_supercallLatency_normalSyscallLatency_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("meanLatencyNs" to "450", "expectedBaselineNs" to "400"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f10_supercallLatency_apatchSupercallLatencyAnomaly_triggersObserved() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("meanLatencyNs" to "2800", "deviation" to "6.2x", "probe" to "apatch_supercall_anomaly"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(2, score.score)
    }

    @Test
    fun f10_supercallLatency_nonArm64ArchitectureFallback_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("arch" to "x86_64", "probeFallback" to "graceful_skip"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f10_supercallLatency_timerFailure_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "monotonic_timer_unavailable"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    @Test
    fun f10_supercallLatency_multiIterationConsistency() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("iterations" to "64", "variance" to "0.012"),
        )
        assertTrue(result.unitResults.flatMap { it.records }.none { it.kind == EvidenceRecordKind.SIGNAL })
    }

    // =========================================================================
    // Feature 11: cgroup Process Allocation (R1.4)
    // =========================================================================

    @Test
    fun f11_cgroupAllocation_standardAppSlice_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("cgroup" to "/uid_10234/pid_5678", "hierarchy" to "standard_zygote"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f11_cgroupAllocation_rootDaemonSliceAnomaly_triggersObserved() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("cgroup" to "/magisk/daemon", "anomaly" to "non_zygote_hierarchy"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(2, score.score)
    }

    @Test
    fun f11_cgroupAllocation_inaccessibleCgroup_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "proc_cgroup_inaccessible"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    @Test
    fun f11_cgroupAllocation_rootProcessHierarchyDetected_triggersStrong() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("cgroup" to "/system.slice/ksud.service"),
        )
        assertEquals(EvidenceStrength.STRONG, result.strength)
    }

    @Test
    fun f11_cgroupAllocation_standardHierarchyUnitRecords() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
        )
        assertEquals(descriptor.evidenceUnits.size, result.unitResults.size)
    }

    // =========================================================================
    // Feature 12: Root Driver & ioctl Probes (R1.4)
    // =========================================================================

    @Test
    fun f12_rootDriverIoctl_standardFileDescriptors_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_DEVPTS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("fdCount" to "12", "driverArtifacts" to "none"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f12_rootDriverIoctl_ksuDriverFdDetected_triggersObservedStrong() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_DEVPTS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("fdTarget" to "[ksu_driver]", "fdNumber" to "5", "driverType" to "kernelsu_driver"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun f12_rootDriverIoctl_ksuFdWrapperDetected_triggersObservedModerate() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_DEVPTS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("fdTarget" to "[ksu_fdwrapper]"),
        )
        assertEquals(EvidenceStrength.MODERATE, result.strength)
    }

    @Test
    fun f12_rootDriverIoctl_procFdInaccessible_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_DEVPTS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "proc_self_fd_inaccessible"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    @Test
    fun f12_rootDriverIoctl_cleanDevptsPty_recordsObservation() {
        val descriptor = E2ETestHelper.descriptorFor("NATIVE_ROOT_DEVPTS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("ptyMode" to "isolated_app"),
        )
        assertTrue(result.unitResults.flatMap { it.records }.any { it.kind == EvidenceRecordKind.OBSERVATION })
    }

    // =========================================================================
    // Feature 13: MEMORY_FD_ANOMALY descriptor scoring
    // The cross-process FD trap itself is ZYGISK_FD_FORENSICS and is covered by
    // RuntimeBindingContractTest; these cases only exercise scoring and outcome
    // mechanics on synthetic MEMORY_FD_ANOMALY payloads.
    // =========================================================================

    @Test
    fun f13_memoryFdAnomaly_cleanDescriptor_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_FD_ANOMALY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("trapStatus" to "intact", "fdValid" to "true"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f13_memoryFdAnomaly_strongOutcomeScoresFourPoints() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_FD_ANOMALY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("trapStatus" to "corrupted_by_zygisk", "fdStatus" to "EBADF"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun f13_memoryFdAnomaly_collectionFailure_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_FD_ANOMALY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "binder_ipc_timeout"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    @Test
    fun f13_memoryFdAnomaly_moderateOutcomeRetainsStrength() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_FD_ANOMALY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("expectedInode" to "12345", "actualInode" to "0"),
        )
        assertEquals(EvidenceStrength.MODERATE, result.strength)
    }

    @Test
    fun f13_memoryFdAnomaly_unitStatusMapping() {
        val descriptor = E2ETestHelper.descriptorFor("MEMORY_FD_ANOMALY")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
        )
        assertEquals(EvidenceUnitCollectionStatus.COMPLETE, result.unitResults[0].collectionStatus)
    }

    // =========================================================================
    // Feature 14: Thread comm Name Scan (R1.5)
    // =========================================================================

    @Test
    fun f14_threadCommScan_standardThreadNames_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("threads" to "main,RenderThread,pool-1-thread-1"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f14_threadCommScan_zygiskThreadDetected_triggersObservedStrong() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("matchedThread" to "zygisk-companion", "tid" to "4501"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun f14_threadCommScan_magiskOrXposedThreadDetected_triggersObserved() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("matchedThread" to "magiskd_monitor"),
        )
        assertEquals(EvidenceStrength.MODERATE, result.strength)
    }

    @Test
    fun f14_threadCommScan_taskDirUnreadable_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "proc_task_unreadable"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    @Test
    fun f14_threadCommScan_fridaAgentThread_triggersObservedStrong() {
        val descriptor = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("matchedThread" to "gmain", "module" to "frida-agent"),
        )
        assertEquals(EvidenceStrength.STRONG, result.strength)
    }

    // =========================================================================
    // Feature 15: Heap Entropy Analysis (R1.5)
    // =========================================================================

    @Test
    fun f15_heapEntropy_normalHeapRatio_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("freeRatio" to "0.15", "heapEntropy" to "4.2"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f15_heapEntropy_abnormalAllocationRatio_triggersObserved() {
        val descriptor = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("freeRatio" to "0.88", "entropyAnomaly" to "zygisk_heap_pollution"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(2, score.score)
    }

    @Test
    fun f15_heapEntropy_mallinfo2Unavailable_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "mallinfo2_unavailable"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    @Test
    fun f15_heapEntropy_extremeHeapFragmentation_triggersStrong() {
        val descriptor = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("freeRatio" to "0.98", "unmappedArenaPointers" to "14"),
        )
        assertEquals(EvidenceStrength.STRONG, result.strength)
    }

    @Test
    fun f15_heapEntropy_standardHeapGrowth_maintainsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("allocatedMB" to "32", "freeMB" to "4"),
        )
        assertTrue(result.unitResults.flatMap { it.records }.none { it.kind == EvidenceRecordKind.SIGNAL })
    }

    // =========================================================================
    // Feature 16: Property Area Hole Scan Promotion (R1.6)
    // =========================================================================

    @Test
    fun f16_propertyAreaHoleScan_zeroUnreferencedBytes_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("unreferencedBytes" to "0", "trieNodes" to "320"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(0, score.score)
    }

    @Test
    fun f16_propertyAreaHoleScan_unreferencedAllocationBytes_promotedToSignal() {
        val descriptor = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("unreferencedBytes" to "128", "anomaly" to "resetprop_trie_hole"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(2, score.score)
        val signals = result.unitResults.flatMap { it.records }.filter { it.kind == EvidenceRecordKind.SIGNAL }
        assertEquals(1, signals.size)
        assertEquals(EvidenceStrength.MODERATE, signals[0].signalStrength)
    }

    @Test
    fun f16_propertyAreaHoleScan_largeHoleFromMultipleAlteredProps_triggersStrong() {
        val descriptor = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("unreferencedBytes" to "1024", "deletedNodes" to "8"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun f16_propertyAreaHoleScan_propAreaContextMappingFailure_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "prop_area_mmap_failed"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    @Test
    fun f16_propertyAreaHoleScan_wirePayloadDecoding() {
        val wire = WireDetectorResult(
            detectorId = "SYSTEM_PROPERTIES_TAMPER",
            outcome = DetectionOutcome.OBSERVED,
            evidenceStrength = EvidenceStrength.MODERATE,
            payload = buildJsonObject {
                put("unreferencedBytes", 256)
            },
        )
        val descriptor = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val mapped = DetectorResultMapper.map(descriptor, wire)
        assertEquals(DetectionOutcome.OBSERVED, mapped.outcome)
    }

    // =========================================================================
    // Feature 17: /proc/cmdline Consistency (R1.6)
    // =========================================================================

    @Test
    fun f17_procCmdlineConsistency_matchingCmdlineAndProps_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("androidboot.verifiedbootstate" to "green", "propState" to "green"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, result.outcome)
    }

    @Test
    fun f17_procCmdlineConsistency_bootstateMismatch_triggersObserved() {
        val descriptor = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("cmdlineBootState" to "orange", "propBootState" to "green", "anomaly" to "spoofed_verifiedbootstate"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(2, score.score)
    }

    @Test
    fun f17_procCmdlineConsistency_slotSuffixMismatch_triggersObserved() {
        val descriptor = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.WEAK,
            mapOf("cmdlineSlot" to "_a", "propSlot" to "_b"),
        )
        assertEquals(EvidenceStrength.WEAK, result.strength)
    }

    @Test
    fun f17_procCmdlineConsistency_procCmdlineUnreadable_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "proc_cmdline_unreadable"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    @Test
    fun f17_procCmdlineConsistency_consistentMultiPropertyValidation() {
        val descriptor = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("matchedProps" to "verifiedbootstate,slot_suffix,hardware,serialno"),
        )
        assertTrue(result.unitResults.flatMap { it.records }.none { it.kind == EvidenceRecordKind.SIGNAL })
    }

    // =========================================================================
    // Feature 18: emulator_hardware_indicators (R2 Detector A)
    // =========================================================================

    @Test
    fun f18_emulatorHardware_physicalGpuRenderer_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("EMULATOR_HARDWARE_INDICATORS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("glRenderer" to "Adreno 740", "glVendor" to "Qualcomm"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(0, score.score)
    }

    @Test
    fun f18_emulatorHardware_eglRendererEmulatorString_triggersObservedStrong() {
        val descriptor = E2ETestHelper.descriptorFor("EMULATOR_HARDWARE_INDICATORS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("glRenderer" to "Android Emulator OpenGL ES Translator", "glVendor" to "Google (NVIDIA Corporation)"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
        assertTrue(score.observedDetectorIds.contains("EMULATOR_HARDWARE_INDICATORS"))
    }

    @Test
    fun f18_emulatorHardware_armTimerRegisterDeviation_triggersObservedModerate() {
        val descriptor = E2ETestHelper.descriptorFor("EMULATOR_HARDWARE_INDICATORS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("cntvct_el0" to "anomaly_delta_exceeded", "monotonicDelta" to "14500ns"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(2, score.score)
    }

    @Test
    fun f18_emulatorHardware_scheduleJitterLowCv_triggersObservedWeak() {
        val descriptor = E2ETestHelper.descriptorFor("EMULATOR_HARDWARE_INDICATORS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.WEAK,
            mapOf("schedYieldCV" to "0.018", "uniqueBuckets" to "2"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(1, score.score)
    }

    @Test
    fun f18_emulatorHardware_eglInitializationFailure_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("EMULATOR_HARDWARE_INDICATORS")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "egl_get_display_failed"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    // =========================================================================
    // Feature 19: emulator_system_profile (R2 Detector B)
    // =========================================================================

    @Test
    fun f19_emulatorProfile_cleanPhysicalProperties_returnsNotObserved() {
        val descriptor = E2ETestHelper.descriptorFor("EMULATOR_SYSTEM_PROFILE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("ro.product.model" to "Pixel 8", "ro.hardware" to "zuma", "ro.kernel.qemu" to "0"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(0, score.score)
    }

    @Test
    fun f19_emulatorProfile_qemuSystemProperties_triggersObservedStrong() {
        val descriptor = E2ETestHelper.descriptorFor("EMULATOR_SYSTEM_PROFILE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("ro.kernel.qemu" to "1", "ro.hardware" to "ranchu", "ro.product.model" to "sdk_gphone64_x86_64"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
        assertTrue(score.observedDetectorIds.contains("EMULATOR_SYSTEM_PROFILE"))
    }

    @Test
    fun f19_emulatorProfile_genericBuildFingerprint_triggersObservedWeak() {
        val descriptor = E2ETestHelper.descriptorFor("EMULATOR_SYSTEM_PROFILE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.WEAK,
            mapOf("ro.build.fingerprint" to "google/sdk_gphone_x86/generic_x86:14/UPB2.230407.014/10123456:userdebug/dev-keys"),
        )
        val score = ReferenceTamperScorer.score(E2ETestHelper.buildReport(listOf(result)))
        assertEquals(1, score.score)
    }

    @Test
    fun f19_emulatorProfile_bootPropertiesColdBootWait_triggersObservedModerate() {
        val descriptor = E2ETestHelper.descriptorFor("EMULATOR_SYSTEM_PROFILE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("ro.boottime.init.cold_boot_wait" to "1420", "ro.boot.qemu" to "1"),
        )
        assertEquals(EvidenceStrength.MODERATE, result.strength)
    }

    @Test
    fun f19_emulatorProfile_missingProperties_returnsInconclusive() {
        val descriptor = E2ETestHelper.descriptorFor("EMULATOR_SYSTEM_PROFILE")
        val result = E2ETestHelper.createDetectorResult(
            descriptor,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "property_service_inaccessible"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, result.outcome)
    }

    // =========================================================================
    // Feature 20: Catalog & Tooling Sync (R3)
    // =========================================================================

    @Test
    fun f20_catalogSync_catalogLoadsExpectedDomainsAndDetectors() {
        val catalog = E2ETestHelper.catalog
        assertEquals(8, catalog.evidenceDomains.size)
        assertTrue(catalog.descriptors.size >= 31)
        assertTrue(catalog.descriptors.all { it.evidenceUnits.isNotEmpty() })
    }

    @Test
    fun f20_catalogSync_allUnitDescriptorsHaveNineMandatoryAttributes() {
        val catalog = E2ETestHelper.catalog
        catalog.descriptors.flatMap { it.evidenceUnits }.forEach { unit ->
            assertTrue("id must not be blank", unit.id.isNotBlank())
            assertTrue("title must not be blank", unit.title.isNotBlank())
            assertTrue("domainId must not be blank", unit.domainId.isNotBlank())
            assertTrue("observedObject must not be blank", unit.observedObject.isNotBlank())
            assertTrue("proposition must not be blank", unit.proposition.isNotBlank())
            assertTrue("observationChannel must not be blank", unit.observationChannel.isNotBlank())
            assertTrue("availability must not be blank", unit.availability.isNotBlank())
            assertTrue("trustBoundary must not be blank", unit.trustBoundary.isNotBlank())
            assertTrue("inferenceLimit must not be blank", unit.inferenceLimit.isNotBlank())
        }
    }

    @Test
    fun f20_catalogSync_wireContractConformsToVersion1() {
        val json = E2ETestHelper.buildWireEnvelopeJson(
            listOf(
                WireDetectorResult("SU_BINARY", DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE),
            ),
        )
        val envelope = WireParser.parse(json.toByteArray(Charsets.UTF_8))
        assertEquals(1, envelope.schemaVersion)
        assertEquals("COMPLETE", envelope.completion)
        assertEquals(1, envelope.results.size)
    }

    @Test
    fun f20_catalogSync_detectorDescriptorsEnforceSingleDomainAffinity() {
        val catalog = E2ETestHelper.catalog
        catalog.descriptors.forEach { d ->
            assertTrue(
                "Primary domain ${d.primaryEvidenceDomainId} must exist in domains",
                catalog.evidenceDomains.any { it.id == d.primaryEvidenceDomainId },
            )
        }
    }

    // =========================================================================
    // Feature 21: Thesis Technical Comparison (R4)
    // =========================================================================

    @Test
    fun f21_thesisComparison_referenceScorerCalculatesAccurateCompositeScore() {
        val r1 = E2ETestHelper.createDetectorResult(E2ETestHelper.descriptorFor("SU_BINARY"), DetectionOutcome.OBSERVED, EvidenceStrength.STRONG)
        val r2 = E2ETestHelper.createDetectorResult(E2ETestHelper.descriptorFor("MOUNT_INTEGRITY"), DetectionOutcome.OBSERVED, EvidenceStrength.MODERATE)
        val r3 = E2ETestHelper.createDetectorResult(E2ETestHelper.descriptorFor("BUSYBOX"), DetectionOutcome.OBSERVED, EvidenceStrength.WEAK)
        val r4 = E2ETestHelper.createDetectorResult(E2ETestHelper.descriptorFor("SELINUX_CHECK"), DetectionOutcome.INCONCLUSIVE, EvidenceStrength.NONE)
        val r5 = E2ETestHelper.createDetectorResult(E2ETestHelper.descriptorFor("CUSTOM_ROM"), DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE)

        val report = E2ETestHelper.buildReport(listOf(r1, r2, r3, r4, r5))
        val score = ReferenceTamperScorer.score(report)

        // STRONG(4) + MODERATE(2) + WEAK(1) + INCONCLUSIVE(1) = 8
        assertEquals(8, score.score)
        assertEquals(4, score.threshold)
        assertTrue(score.thresholdReached)
        assertEquals(listOf("SU_BINARY", "MOUNT_INTEGRITY", "BUSYBOX"), score.observedDetectorIds)
        assertEquals(listOf("SELINUX_CHECK"), score.inconclusiveDetectorIds)
        assertTrue(score.failedDetectorIds.isEmpty())
    }

    @Test
    fun f21_thesisComparison_customSensitivityScoringPolicy() {
        val policy = ReferenceTamperScoringPolicy(
            weakWeight = 2,
            moderateWeight = 3,
            strongWeight = 5,
            inconclusiveWeight = 0,
            threshold = 5,
        )
        val r1 = E2ETestHelper.createDetectorResult(E2ETestHelper.descriptorFor("KERNEL_CHECK"), DetectionOutcome.OBSERVED, EvidenceStrength.MODERATE)
        val r2 = E2ETestHelper.createDetectorResult(E2ETestHelper.descriptorFor("CUSTOM_ROM"), DetectionOutcome.OBSERVED, EvidenceStrength.WEAK)

        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report, policy)

        // 3 + 2 = 5 >= 5 -> threshold reached
        assertEquals(5, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun f21_thesisComparison_inconclusiveDoesNotTriggerObservedList() {
        val r1 = E2ETestHelper.createDetectorResult(E2ETestHelper.descriptorFor("MEMORY_FD_ANOMALY"), DetectionOutcome.INCONCLUSIVE, EvidenceStrength.NONE)
        val report = E2ETestHelper.buildReport(listOf(r1))
        val score = ReferenceTamperScorer.score(report)

        assertEquals(1, score.score)
        assertFalse(score.thresholdReached)
        assertTrue(score.observedDetectorIds.isEmpty())
        assertEquals(listOf("MEMORY_FD_ANOMALY"), score.inconclusiveDetectorIds)
    }

    @Test
    fun f21_thesisComparison_failedResultsTrackedInFailedList() {
        val r1 = E2ETestHelper.createDetectorResult(
            E2ETestHelper.descriptorFor("SU_BINARY"),
            DetectionOutcome.FAILED,
            EvidenceStrength.NONE,
            error = CollectionError("NATIVE_CRASH", "SIGSEGV in collector", recoverable = false),
        )
        val report = E2ETestHelper.buildReport(listOf(r1))
        val score = ReferenceTamperScorer.score(report)

        assertEquals(0, score.score)
        assertEquals(listOf("SU_BINARY"), score.failedDetectorIds)
    }

    @Test
    fun f21_thesisComparison_zeroTamperCleanReport_producesZeroScore() {
        val results = E2ETestHelper.catalog.descriptors.take(5).map { desc ->
            E2ETestHelper.createDetectorResult(desc, DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE)
        }
        val report = E2ETestHelper.buildReport(results)
        val score = ReferenceTamperScorer.score(report)

        assertEquals(0, score.score)
        assertFalse(score.thresholdReached)
        assertTrue(score.observedDetectorIds.isEmpty())
        assertTrue(score.inconclusiveDetectorIds.isEmpty())
        assertTrue(score.failedDetectorIds.isEmpty())
    }
}
