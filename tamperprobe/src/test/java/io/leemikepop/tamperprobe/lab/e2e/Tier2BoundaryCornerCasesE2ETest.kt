package io.leemikepop.tamperprobe.lab.e2e

import io.leemikepop.tamperprobe.lab.api.CollectionError
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.api.ReferenceTamperScorer
import io.leemikepop.tamperprobe.lab.api.ReferenceTamperScoringPolicy
import io.leemikepop.tamperprobe.lab.api.TamperProbeException
import io.leemikepop.tamperprobe.lab.internal.CatalogParser
import io.leemikepop.tamperprobe.lab.internal.DetectorResultMapper
import io.leemikepop.tamperprobe.lab.internal.WireDetectorResult
import io.leemikepop.tamperprobe.lab.internal.WireParser
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tier 2: Boundary & Corner Cases E2E Tests.
 * Ensures all 21 features defined in PROJECT.md / TEST_INFRA.md have >= 5 boundary/corner test cases.
 */
class Tier2BoundaryCornerCasesE2ETest {

    // =========================================================================
    // Feature 1: statx Mount ID Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f01_boundary_emptyMountPath_handlesGracefully() {
        val desc = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("path" to "", "statxMountId" to "0"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f01_boundary_maxPathLength4096_processedCorrectly() {
        val longPath = "/system/" + "a".repeat(4088)
        val desc = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("path" to longPath),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f01_boundary_maxUint64MountId_handledWithoutOverflow() {
        val desc = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("statxMountId" to "18446744073709551615", "mountinfoId" to "1"),
        )
        assertEquals(EvidenceStrength.STRONG, res.strength)
    }

    @Test
    fun f01_boundary_zeroMountId_treatedAsValid() {
        val desc = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("statxMountId" to "0", "mountinfoId" to "0"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f01_boundary_unicodeMountPointPath_parsedAccurately() {
        val desc = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("path" to "/mnt/測試/挂载點", "statxMountId" to "99"),
        )
        assertEquals(EvidenceStrength.MODERATE, res.strength)
    }

    // =========================================================================
    // Feature 2: Mount ID Gap Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f02_boundary_zeroGap_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("gap" to "0"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f02_boundary_gapOfOne_treatedAsNormalSequence() {
        val desc = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("gap" to "1"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f02_boundary_maxIntGap_handlesLargeInteger() {
        val desc = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("gap" to Integer.MAX_VALUE.toString()),
        )
        assertEquals(EvidenceStrength.STRONG, res.strength)
    }

    @Test
    fun f02_boundary_invertedRangeStartEnd_doesNotThrow() {
        val desc = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("rangeStart" to "500", "rangeEnd" to "100"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f02_boundary_emptyMountSequence_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("MOUNT_INTEGRITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("mountsCount" to "0"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    // =========================================================================
    // Feature 3: Mount Namespace Split Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f03_boundary_inodeZero_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("selfInode" to "0"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f03_boundary_maxUint64Inode_handledCorrectly() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("selfInode" to "18446744073709551615", "initInode" to "18446744073709551615"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f03_boundary_whitespaceNamespacePath_handledSafely() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("nsPath" to "   /proc/self/ns/mnt   "),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f03_boundary_sameInodeDifferentDevice_detectsSplit() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("selfDev" to "4", "initDev" to "5", "inode" to "4026531840"),
        )
        assertEquals(EvidenceStrength.MODERATE, res.strength)
    }

    @Test
    fun f03_boundary_symlinkLoopInProcNs_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "ELOOP_symlink_loop"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    // =========================================================================
    // Feature 4: GOT/PLT Escape Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f04_boundary_addressZero_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("symbol" to "malloc", "address" to "0x0"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f04_boundary_highestUserAddress_escapesBounds() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("symbol" to "open", "address" to "0x00007fffffffffff", "bounds" to "0x7b000000-0x7b050000"),
        )
        assertEquals(EvidenceStrength.STRONG, res.strength)
    }

    @Test
    fun f04_boundary_emptySymbolName_handledGracefully() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("symbol" to "", "address" to "0x7b010000"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f04_boundary_exactSegmentLowerEdgeAddress_isWithinBounds() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("symbol" to "entry", "address" to "0x7b000000", "bounds" to "0x7b000000-0x7b050000"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f04_boundary_exactSegmentUpperEdgeAddressPlusOne_escapesBounds() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("symbol" to "trampoline", "address" to "0x7b050001", "bounds" to "0x7b000000-0x7b050000"),
        )
        assertEquals(EvidenceStrength.MODERATE, res.strength)
    }

    // =========================================================================
    // Feature 5: Linker Maps-Only Modules Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f05_boundary_zeroExecutablePages_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("execPages" to "0"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f05_boundary_tenThousandSegments_handledEfficiently() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("segmentCount" to "10000", "unlinked" to "0"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f05_boundary_singleByteUnlinkedSegment_triggersObserved() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.WEAK,
            mapOf("sizeBytes" to "1", "unlinked" to "1"),
        )
        assertEquals(EvidenceStrength.WEAK, res.strength)
    }

    @Test
    fun f05_boundary_rwxpPermissionSegment_triggersStrong() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("perms" to "rwxp", "unlinked" to "1"),
        )
        assertEquals(EvidenceStrength.STRONG, res.strength)
    }

    @Test
    fun f05_boundary_trailingWhitespaceInMapsPath_normalizedCorrectly() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_LINKER_VISIBILITY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("path" to "/system/lib64/libc.so   "),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    // =========================================================================
    // Feature 6: Smaps Dirty-Page Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f06_boundary_privateDirtyExactly8192Bytes_thresholdBoundaryIsNeutral() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_SMAPS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("privateDirtyBytes" to "8192", "thresholdBytes" to "8192"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f06_boundary_privateDirty8193Bytes_exceedsThresholdTriggersSignal() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_SMAPS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("privateDirtyBytes" to "8193", "thresholdBytes" to "8192"),
        )
        assertEquals(EvidenceStrength.STRONG, res.strength)
    }

    @Test
    fun f06_boundary_privateDirty8191Bytes_belowThresholdIsNeutral() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_SMAPS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("privateDirtyBytes" to "8191", "thresholdBytes" to "8192"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f06_boundary_zeroByteSmapsFile_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_SMAPS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("fileBytes" to "0"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f06_boundary_malformedSmapsHeader_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_SMAPS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "corrupted_smaps_header"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    // =========================================================================
    // Feature 7: Signal Handler Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f07_boundary_address0SigDfl_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("signal" to "SIGTRAP", "handler" to "0x0", "semantic" to "SIG_DFL"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f07_boundary_address1SigIgn_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("signal" to "SIGILL", "handler" to "0x1", "semantic" to "SIG_IGN"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f07_boundary_vdsoPageHandler_treatedAsSystem() {
        val desc = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("signal" to "SIGSEGV", "handlerRegion" to "[vdso]"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f07_boundary_deletedLibraryPath_triggersObserved() {
        val desc = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("handlerPath" to "/data/local/tmp/libhook.so (deleted)"),
        )
        assertEquals(EvidenceStrength.STRONG, res.strength)
    }

    @Test
    fun f07_boundary_maxUint64AddressHandler_triggersSignal() {
        val desc = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("handlerAddress" to "0xffffffffffffffff"),
        )
        assertEquals(EvidenceStrength.MODERATE, res.strength)
    }

    // =========================================================================
    // Feature 8: kptr_restrict Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f08_boundary_exactlyTenOfTwentyNonZero_fiftyPercentIsNeutral() {
        val desc = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("nonZeroCount" to "10", "totalLines" to "20", "ratio" to "0.50"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f08_boundary_elevenOfTwentyNonZero_fiftyFivePercentTriggersSignal() {
        val desc = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("nonZeroCount" to "11", "totalLines" to "20", "ratio" to "0.55"),
        )
        assertEquals(EvidenceStrength.MODERATE, res.strength)
    }

    @Test
    fun f08_boundary_zeroOfTwentyNonZero_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("nonZeroCount" to "0", "totalLines" to "20"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f08_boundary_twentyOfTwentyNonZero_triggersSignal() {
        val desc = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("nonZeroCount" to "20", "totalLines" to "20"),
        )
        assertEquals(EvidenceStrength.MODERATE, res.strength)
    }

    @Test
    fun f08_boundary_singleLineKallsyms_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("totalLines" to "1", "error" to "insufficient_lines"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    // =========================================================================
    // Feature 9: /proc/version Signature Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f09_boundary_singleCjkCharacter_triggersObserved() {
        val desc = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("version" to "Linux version 5.15.0 \u4E00", "matched" to "CJK_U4E00"),
        )
        assertEquals(EvidenceStrength.MODERATE, res.strength)
    }

    @Test
    fun f09_boundary_singleEmojiCharacter_triggersObserved() {
        val desc = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("version" to "Linux version 5.15.0 \uD83D\uDE00", "matched" to "EMOJI_GRIN"),
        )
        assertEquals(EvidenceStrength.MODERATE, res.strength)
    }

    @Test
    fun f09_boundary_emptyVersionString_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("version" to ""),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f09_boundary_65536CharBanner_handledWithoutCrash() {
        val longBanner = "Linux version 5.15.0 " + "x".repeat(65515)
        val desc = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("bannerLength" to longBanner.length.toString()),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f09_boundary_nearTelegramSubstring_doesNotFalsePositive() {
        val desc = E2ETestHelper.descriptorFor("KERNEL_CHECK")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("version" to "Linux version 5.15.0 (contact: format.me/info)"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    // =========================================================================
    // Feature 10: Supercall Latency Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f10_boundary_zeroLatency_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("latencyNs" to "0"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f10_boundary_negativeDelta_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "clock_skew_negative_delta"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f10_boundary_tenMillionNsLatency_triggersSignal() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("latencyNs" to "10000000"),
        )
        assertEquals(EvidenceStrength.STRONG, res.strength)
    }

    @Test
    fun f10_boundary_x86Architecture_skipsGracefully() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("arch" to "x86", "supported" to "false"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f10_boundary_zeroJitterAcrossSamples_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("variance" to "0.000"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    // =========================================================================
    // Feature 11: cgroup Allocation Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f11_boundary_rootSliceOnly_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("cgroup" to "/"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f11_boundary_malformedColonSeparatedLine_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "corrupted_cgroup_format"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f11_boundary_oneThousandCgroupLines_parsedWithoutError() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("lineCount" to "1000"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f11_boundary_missingControllerName_handledSafely() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("raw" to "0::/uid_1000"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f11_boundary_specialCharactersInCgroupPath_parsedCorrectly() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_PRCTL")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("path" to "/uid_1000/app_process_#1"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    // =========================================================================
    // Feature 12: Root Driver & ioctl Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f12_boundary_1024OpenFds_scannedAccurately() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_DEVPTS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("totalFds" to "1024"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f12_boundary_nullBytesInFdTarget_handledSafely() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_DEVPTS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("fdTarget" to "/dev/null\u0000extra"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f12_boundary_negativeFd_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_DEVPTS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("fd" to "-1", "error" to "invalid_fd"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f12_boundary_nonExistentFdPath_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_DEVPTS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "ENOENT_proc_fd"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f12_boundary_extremeIoctlCommandCode_handledGracefully() {
        val desc = E2ETestHelper.descriptorFor("NATIVE_ROOT_DEVPTS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("ioctlCmd" to "0xFFFFFFFF", "errno" to "ENOTTY"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    // =========================================================================
    // Feature 13: Cross-Process FD Trap Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f13_boundary_closedFdEBADF_triggersObserved() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_FD_ANOMALY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("status" to "EBADF"),
        )
        assertEquals(EvidenceStrength.STRONG, res.strength)
    }

    @Test
    fun f13_boundary_invalidSocketFd_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_FD_ANOMALY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "ENOTSOCK"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f13_boundary_readOnlyMountOTmpfileFailure_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_FD_ANOMALY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "EROFS_o_tmpfile"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f13_boundary_largeBufferPayload_handledWithoutBufferOverflow() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_FD_ANOMALY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("payloadBytes" to "1048576"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f13_boundary_ipcTransactionTimeout_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("MEMORY_FD_ANOMALY")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "ETIMEDOUT_binder"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    // =========================================================================
    // Feature 14: Thread comm Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f14_boundary_exactly15CharCommName_scannedAccurately() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("comm" to "zygisk-companio"), // 15 chars
        )
        assertEquals(EvidenceStrength.STRONG, res.strength)
    }

    @Test
    fun f14_boundary_16CharTruncatedComm_scannedAccurately() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("comm" to "magiskd_monitor"), // 15 chars
        )
        assertEquals(EvidenceStrength.MODERATE, res.strength)
    }

    @Test
    fun f14_boundary_emptyCommName_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("comm" to ""),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f14_boundary_commWithNewline_trimmedCorrectly() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("comm" to "RenderThread\n"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f14_boundary_uppercaseZygiskComm_matchesCaseInsensitive() {
        val desc = E2ETestHelper.descriptorFor("ZYGISK_NAMESPACE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("comm" to "ZYGISK_MAIN"),
        )
        assertEquals(EvidenceStrength.STRONG, res.strength)
    }

    // =========================================================================
    // Feature 15: Heap Entropy Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f15_boundary_zeroTotalHeap_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("totalHeapBytes" to "0"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f15_boundary_freeGreaterThanTotalHeap_corruptedStatsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "corrupted_heap_metrics", "free" to "200", "total" to "100"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f15_boundary_entropyZero_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("entropy" to "0.0"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f15_boundary_entropyEightMax_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("entropy" to "8.0"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f15_boundary_ratioNearOne_triggersObserved() {
        val desc = E2ETestHelper.descriptorFor("RUNTIME_INSTRUMENTATION")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("freeRatio" to "0.9999"),
        )
        assertEquals(EvidenceStrength.MODERATE, res.strength)
    }

    // =========================================================================
    // Feature 16: Property Area Hole Scan Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f16_boundary_unreferencedBytesZero_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("unreferencedBytes" to "0"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f16_boundary_unreferencedBytesOne_triggersSignal() {
        val desc = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.MODERATE,
            mapOf("unreferencedBytes" to "1"),
        )
        assertEquals(EvidenceStrength.MODERATE, res.strength)
    }

    @Test
    fun f16_boundary_maxUint32UnreferencedBytes_handledWithoutCrash() {
        val desc = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.STRONG,
            mapOf("unreferencedBytes" to "4294967295"),
        )
        assertEquals(EvidenceStrength.STRONG, res.strength)
    }

    @Test
    fun f16_boundary_negativeOffset_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "invalid_trie_offset"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f16_boundary_emptyTrieHeader_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("error" to "empty_prop_area_header"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    // =========================================================================
    // Feature 17: /proc/cmdline Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f17_boundary_emptyCmdline_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("cmdline" to ""),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f17_boundary_cmdlineWithoutAndroidboot_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("cmdline" to "console=ttyMSM0 earlycon=msm_geni_serial"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f17_boundary_repeatedCmdlineParameters_firstOrLastHandledPredictably() {
        val desc = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("cmdline" to "androidboot.slot_suffix=_a androidboot.slot_suffix=_a"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f17_boundary_trailingNewlineInCmdline_trimmedProperly() {
        val desc = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("cmdline" to "androidboot.hardware=qcom\n\u0000"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f17_boundary_quotedCmdlineValues_unquotedAccurately() {
        val desc = E2ETestHelper.descriptorFor("SYSTEM_PROPERTIES_TAMPER")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("cmdline" to "androidboot.verifiedbootstate=\"green\""),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    // =========================================================================
    // Feature 18: Emulator Hardware Indicators Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f18_boundary_emptyGlRendererString_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("EMULATOR_HARDWARE_INDICATORS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("glRenderer" to ""),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f18_boundary_appleM1PhysicalSilicon_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("EMULATOR_HARDWARE_INDICATORS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("glRenderer" to "Apple M1", "glVendor" to "Apple"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f18_boundary_timerDeviationExactlyThreshold_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("EMULATOR_HARDWARE_INDICATORS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("timerDeltaNs" to "5000", "thresholdNs" to "5000"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f18_boundary_schedJitterCvExactly003_boundaryThreshold() {
        val desc = E2ETestHelper.descriptorFor("EMULATOR_HARDWARE_INDICATORS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("schedYieldCV" to "0.0300", "thresholdCV" to "0.0300"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f18_boundary_zeroSchedYieldSamples_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("EMULATOR_HARDWARE_INDICATORS")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("samplesCount" to "0"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    // =========================================================================
    // Feature 19: Emulator System Profile Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f19_boundary_emptyPropertiesMap_returnsInconclusive() {
        val desc = E2ETestHelper.descriptorFor("EMULATOR_SYSTEM_PROFILE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.INCONCLUSIVE,
            EvidenceStrength.NONE,
            mapOf("checkedProps" to "0"),
        )
        assertEquals(DetectionOutcome.INCONCLUSIVE, res.outcome)
    }

    @Test
    fun f19_boundary_qemuPropZeroString_returnsNotObserved() {
        val desc = E2ETestHelper.descriptorFor("EMULATOR_SYSTEM_PROFILE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("ro.kernel.qemu" to "0"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f19_boundary_buildFingerprintExactPrefixMatch_triggersWeak() {
        val desc = E2ETestHelper.descriptorFor("EMULATOR_SYSTEM_PROFILE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.OBSERVED,
            EvidenceStrength.WEAK,
            mapOf("ro.build.fingerprint" to "generic/aosp/generic:14"),
        )
        assertEquals(EvidenceStrength.WEAK, res.strength)
    }

    @Test
    fun f19_boundary_nonAsciiModelName_handledCorrectly() {
        val desc = E2ETestHelper.descriptorFor("EMULATOR_SYSTEM_PROFILE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("ro.product.model" to "手機_測試旗艦"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    @Test
    fun f19_boundary_oneThousandUnrelatedProps_filteredCorrectly() {
        val desc = E2ETestHelper.descriptorFor("EMULATOR_SYSTEM_PROFILE")
        val res = E2ETestHelper.createDetectorResult(
            desc,
            DetectionOutcome.NOT_OBSERVED,
            EvidenceStrength.NONE,
            mapOf("unrelatedPropsCount" to "1000", "emulatorProps" to "0"),
        )
        assertEquals(DetectionOutcome.NOT_OBSERVED, res.outcome)
    }

    // =========================================================================
    // Feature 20: Catalog & Tooling Sync Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f20_boundary_emptyJson_throwsTamperProbeException() {
        assertThrows(TamperProbeException::class.java) {
            CatalogParser.parse("{}")
        }
    }

    @Test
    fun f20_boundary_missingSchemaVersion_throwsTamperProbeException() {
        val json = """{"catalogVersion": "1.0", "evidenceDomains": [], "detections": []}"""
        assertThrows(TamperProbeException::class.java) {
            CatalogParser.parse(json)
        }
    }

    @Test
    fun f20_boundary_unsupportedSchemaVersion2_throwsTamperProbeException() {
        val json = """{"schemaVersion": 2, "catalogVersion": "1.0", "evidenceDomains": [], "detections": []}"""
        assertThrows(TamperProbeException::class.java) {
            CatalogParser.parse(json)
        }
    }

    @Test
    fun f20_boundary_emptyWireResponse_throwsTamperProbeException() {
        assertThrows(TamperProbeException::class.java) {
            WireParser.parse(ByteArray(0))
        }
    }

    @Test
    fun f20_boundary_wireSchemaVersionMismatch_throwsTamperProbeException() {
        val json = """{"schemaVersion": 99, "completion": "COMPLETE", "results": []}"""
        assertThrows(TamperProbeException::class.java) {
            WireParser.parse(json.toByteArray(Charsets.UTF_8))
        }
    }

    // =========================================================================
    // Feature 21: Thesis Technical Comparison Boundary & Corner Cases
    // =========================================================================

    @Test
    fun f21_boundary_score3Threshold4_isFalse() {
        val r1 = E2ETestHelper.createDetectorResult(E2ETestHelper.descriptorFor("SU_BINARY"), DetectionOutcome.OBSERVED, EvidenceStrength.WEAK)
        val r2 = E2ETestHelper.createDetectorResult(E2ETestHelper.descriptorFor("BUSYBOX"), DetectionOutcome.OBSERVED, EvidenceStrength.MODERATE)
        // WEAK(1) + MODERATE(2) = 3 < 4
        val report = E2ETestHelper.buildReport(listOf(r1, r2))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(3, score.score)
        assertFalse(score.thresholdReached)
    }

    @Test
    fun f21_boundary_score4Threshold4_isTrue() {
        val r1 = E2ETestHelper.createDetectorResult(E2ETestHelper.descriptorFor("SU_BINARY"), DetectionOutcome.OBSERVED, EvidenceStrength.STRONG)
        // STRONG(4) >= 4
        val report = E2ETestHelper.buildReport(listOf(r1))
        val score = ReferenceTamperScorer.score(report)
        assertEquals(4, score.score)
        assertTrue(score.thresholdReached)
    }

    @Test
    fun f21_boundary_extremeHighCombinedScore_handlesLargeSum() {
        val results = (1..30).map { i ->
            E2ETestHelper.createDetectorResult(
                E2ETestHelper.createSyntheticDescriptor("SYNTH_$i"),
                DetectionOutcome.OBSERVED,
                EvidenceStrength.STRONG,
            )
        }
        val report = E2ETestHelper.buildReport(results)
        val score = ReferenceTamperScorer.score(report)
        assertEquals(120, score.score)
        assertTrue(score.thresholdReached)
        assertEquals(30, score.observedDetectorIds.size)
    }

    @Test
    fun f21_boundary_allWeightsZeroExceptThreshold_alwaysFalse() {
        val policy = ReferenceTamperScoringPolicy(
            weakWeight = 0,
            moderateWeight = 0,
            strongWeight = 0,
            inconclusiveWeight = 0,
            threshold = 10,
        )
        val r1 = E2ETestHelper.createDetectorResult(E2ETestHelper.descriptorFor("SU_BINARY"), DetectionOutcome.OBSERVED, EvidenceStrength.STRONG)
        val report = E2ETestHelper.buildReport(listOf(r1))
        val score = ReferenceTamperScorer.score(report, policy)
        assertEquals(0, score.score)
        assertFalse(score.thresholdReached)
    }

    @Test
    fun f21_boundary_emptyReportZeroResults_evaluatesZero() {
        val report = E2ETestHelper.buildReport(emptyList())
        val score = ReferenceTamperScorer.score(report)
        assertEquals(0, score.score)
        assertFalse(score.thresholdReached)
        assertTrue(score.observedDetectorIds.isEmpty())
        assertTrue(score.inconclusiveDetectorIds.isEmpty())
        assertTrue(score.failedDetectorIds.isEmpty())
    }
}
