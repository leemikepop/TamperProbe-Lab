#include <elf.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "../common/proc_maps.h"
#include "../detections/binary-artifact/binary_artifact_probe.h"
#include "../detections/kernel-interface/kernel_identity_coherence.h"
#include "../detections/kernel-interface/lsposed_sepolicy.h"
#include "../detections/kernel-interface/native_root_sepolicy.h"
#include "../detections/app-visibility/dangerous_packages_logic.h"
#include "../detections/app-visibility/package_storage_visibility_logic.h"
#include "../detections/process-memory/memory_linker_visibility.h"
#include "../detections/system-state/property_area_parser.h"
#include "../detections/system-state/property_detector_logic.h"
#include "../detections/runtime-integrity/elf_integrity.h"
#include "../detections/runtime-integrity/entry_pattern.h"
#include "../detections/runtime-integrity/smaps_dirt.h"
#include "../detections/hardware-attestation/tee_assessment.h"
#include "../nlohmann/json.hpp"

namespace tamperprobe {
namespace {

#if defined(__LP64__)
using FixtureElfHeader = Elf64_Ehdr;
using FixtureProgramHeader = Elf64_Phdr;
constexpr unsigned char kFixtureElfClass = ELFCLASS64;
#else
using FixtureElfHeader = Elf32_Ehdr;
using FixtureProgramHeader = Elf32_Phdr;
constexpr unsigned char kFixtureElfClass = ELFCLASS32;
#endif

constexpr std::uint64_t kSegmentOffset = 4096;
constexpr std::uintptr_t kSegmentVirtualAddress = 4096;

void expect(bool condition, const char* name, nlohmann::json& failures) {
    if (!condition) failures.push_back(name);
}

bool writeFixtureElf(const std::string& path, const unsigned char* bytes, size_t byteCount) {
    const int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) return false;

    FixtureElfHeader header{};
    std::memcpy(header.e_ident, ELFMAG, SELFMAG);
    header.e_ident[EI_CLASS] = kFixtureElfClass;
    header.e_ident[EI_DATA] = ELFDATA2LSB;
    header.e_ident[EI_VERSION] = EV_CURRENT;
    header.e_version = EV_CURRENT;
    header.e_ehsize = sizeof(FixtureElfHeader);
    header.e_phoff = sizeof(FixtureElfHeader);
    header.e_phentsize = sizeof(FixtureProgramHeader);
    header.e_phnum = 1;

    FixtureProgramHeader programHeader{};
    programHeader.p_type = PT_LOAD;
    programHeader.p_flags = PF_R | PF_X;
    programHeader.p_offset = kSegmentOffset;
    programHeader.p_vaddr = kSegmentVirtualAddress;
    programHeader.p_filesz = byteCount;
    programHeader.p_memsz = byteCount;
    programHeader.p_align = kSegmentOffset;

    const bool written = pwrite(fd, &header, sizeof(header), 0) == sizeof(header) &&
                         pwrite(fd, &programHeader, sizeof(programHeader), header.e_phoff) == sizeof(programHeader) &&
                         pwrite(fd, bytes, byteCount, kSegmentOffset) == static_cast<ssize_t>(byteCount);
    close(fd);
    return written;
}

ProcMapEntry mapEntry(std::uintptr_t start, std::uintptr_t end) {
    ProcMapEntry entry;
    entry.start = start;
    entry.end = end;
    entry.permissions = "r-xp";
    entry.readable = true;
    entry.executable = true;
    entry.privateMapping = true;
    return entry;
}

nlohmann::json runFixtures(const std::string& cacheDirectory) {
    nlohmann::json failures = nlohmann::json::array();
    int caseCount = 0;

    ProcMapEntry structured;
    ++caseCount;
    expect(parseProcMapLine("1000-2000 r-xp 00000100 08:01 42 /system/lib64/libc.so", structured) &&
               structured.start == 0x1000 && structured.end == 0x2000 && structured.fileOffset == 0x100 &&
               structured.inode == 42 && structured.readable && structured.executable && !structured.writable &&
               structured.privateMapping && structured.device == "08:01" && structured.path == "/system/lib64/libc.so",
           "structured_map_line", failures);

    ProcMapEntry malformed;
    ++caseCount;
    expect(!parseProcMapLine("not-a-proc-map-row", malformed), "malformed_map_line", failures);

    ProcMapEntry deletedMemfd;
    ++caseCount;
    expect(parseProcMapLine("3000-4000 r-xp 00000000 00:00 0 /memfd:frida-agent (deleted)", deletedMemfd) &&
               deletedMemfd.deleted && deletedMemfd.executable &&
               normalizeDeletedMapPath(deletedMemfd.path) == "/memfd:frida-agent",
           "deleted_executable_memfd", failures);

    ++caseCount;
    const std::vector<ProcMapEntry> contiguousMaps = {mapEntry(0x5000, 0x5800), mapEntry(0x5800, 0x6000)};
    expect(linkerRangeCoveredByMaps(0x5100, 0x5f00, contiguousMaps), "linker_range_covered", failures);

    ++caseCount;
    const std::vector<ProcMapEntry> mapsWithGap = {mapEntry(0x5000, 0x5700), mapEntry(0x5800, 0x6000)};
    expect(!linkerRangeCoveredByMaps(0x5100, 0x5f00, mapsWithGap), "linker_visibility_mismatch", failures);

    std::array<unsigned char, 16> memoryBytes = {
        0x00, 0x00, 0x00, 0x14,  // AArch64 branch-shaped veneer; bytes are not executed.
        0x1f, 0x20, 0x03, 0xd5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const std::string fixturePath = cacheDirectory + "/tamperprobe-native-integrity.elf";
    const bool fixtureWritten = writeFixtureElf(fixturePath, memoryBytes.data(), memoryBytes.size());
    const auto memoryStart = reinterpret_cast<std::uintptr_t>(memoryBytes.data());
    ProcMapsSnapshot readableMaps;
    readableMaps.readable = true;
    readableMaps.entries.push_back(mapEntry(memoryStart, memoryStart + memoryBytes.size()));

    ++caseCount;
    ByteComparisonResult comparison;
    if (fixtureWritten && memoryStart > kSegmentVirtualAddress) {
        comparison = compareLoadedAddressWithBackingElf(fixturePath, memoryStart - kSegmentVirtualAddress, memoryStart,
                                                        memoryBytes.size(), readableMaps);
    }
    expect(fixtureWritten && comparison.status == ByteComparisonStatus::MATCH &&
               comparison.backingFileOffset == kSegmentOffset,
           "legal_veneer_matches_backing_elf", failures);

    ++caseCount;
    const EntryPatternObservation aarch64Veneer =
        classifyEntryPattern(memoryBytes.data(), memoryBytes.size(), EntryPatternArchitecture::AARCH64);
    expect(aarch64Veneer.supported && aarch64Veneer.branchLike && !aarch64Veneer.expectedPrologue &&
               aarch64Veneer.trampolineLike && !aarch64Veneer.suspiciousJump,
           "aarch64_branch_veneer_is_diagnostic", failures);

    ++caseCount;
    const std::array<std::uint8_t, 16> x86IndirectJump = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90,
                                                          0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    const EntryPatternObservation x86Trampoline =
        classifyEntryPattern(x86IndirectJump.data(), x86IndirectJump.size(), EntryPatternArchitecture::X86_64);
    expect(x86Trampoline.supported && x86Trampoline.branchLike && !x86Trampoline.expectedPrologue &&
               x86Trampoline.trampolineLike && x86Trampoline.suspiciousJump,
           "x86_64_indirect_jump_is_diagnostic", failures);

    ++caseCount;
    memoryBytes[4] ^= 0xff;
    const ByteComparisonResult modified = compareLoadedAddressWithBackingElf(
        fixturePath, memoryStart - kSegmentVirtualAddress, memoryStart, memoryBytes.size(), readableMaps);
    expect(modified.status == ByteComparisonStatus::DIFFERENT && modified.firstMismatchOffset == 4,
           "modified_elf_bytes", failures);

    ++caseCount;
    ProcMapsSnapshot unavailableMaps;
    const ByteComparisonResult unavailable = compareLoadedAddressWithBackingElf(
        fixturePath, memoryStart - kSegmentVirtualAddress, memoryStart, memoryBytes.size(), unavailableMaps);
    expect(unavailable.status == ByteComparisonStatus::UNAVAILABLE, "unavailable_memory_source", failures);

    ++caseCount;
    expect(pathHasBasename("/apex/com.android.runtime/lib64/bionic/libc.so", "libc.so") &&
               pathHasBasename("/apex/com.android.art/lib64/libart.so", "libart.so") &&
               pathHasBasename("/system/lib64/libinput.so", "libinput.so") &&
               pathHasBasename("/apex/com.android.runtime/lib64/bionic/libdl.so", "libdl.so") &&
               !pathHasBasename("/data/local/tmp/libhook.so", "libc.so"),
           "module_provenance", failures);

    // smaps region layouts taken from the Redmi 13C (Linux 4.19, 4096-byte pages). Addresses are
    // synthetic; the region boundaries, file offsets and dirty sizes are the measured ones.
    const auto feedSmaps = [](SmapsDirtAccumulator& accumulator, const char* text) {
        std::istringstream stream(text);
        std::string row;
        while (std::getline(stream, row)) {
            row.push_back('\n');
            accumulator.feedLine(row.c_str());
        }
        accumulator.finish();
    };
    const auto region = [](const char* header, int privateDirtyKB, int sharedDirtyKB) {
        return std::string(header) + "\nRss: 4 kB\nShared_Dirty: " + std::to_string(sharedDirtyKB) +
               " kB\nPrivate_Dirty: " + std::to_string(privateDirtyKB) + " kB\nVmFlags: rd ex mr mw me\n";
    };

    // Inline hooks (lsposed_control_2026, L2): patching splits libart.so's text into one-page
    // regions of 4 kB each. The legacy per-region threshold sees nothing; the per-library summary
    // sees all nine pages and their shape.
    ++caseCount;
    {
        const char* libart = "/apex/com.android.art/lib64/libart.so";
        const unsigned long offsets[] = {0x24a000, 0x3d7000, 0x467000, 0x497000, 0x5a5000,
                                         0x65c000, 0x671000, 0x679000, 0x88c000};
        std::string text;
        unsigned long cleanStart = 0x200000;
        for (unsigned long patched : offsets) {
            char header[256];
            std::snprintf(header, sizeof(header), "7000%06lx-7000%06lx r-xp %08lx fd:07 42 %s",
                          cleanStart, patched, cleanStart, libart);
            text += region(header, 0, 0);
            std::snprintf(header, sizeof(header), "7000%06lx-7000%06lx r-xp %08lx fd:07 42 %s",
                          patched, patched + 0x1000, patched, libart);
            text += region(header, 4, 0);
            cleanStart = patched + 0x1000;
        }
        SmapsDirtAccumulator accumulator(4096);
        feedSmaps(accumulator, text.c_str());
        const auto libraries = accumulator.dirtyLibraries();
        expect(accumulator.legacyRegionHits().empty() && libraries.size() == 1 &&
                   libraries[0].path == libart && libraries[0].dirtyRegionCount == 9 &&
                   libraries[0].singlePageDirtyRegionCount == 9 && libraries[0].privateDirtyKB == 36 &&
                   libraries[0].largestDirtyRegionKB == 4 && libraries[0].executableRegionCount == 18,
               "smaps_inline_hook_split_shape", failures);
    }

    // Self-read contamination (before SelfMemoryReader): one large region dirtied in place, with
    // no split. The legacy threshold fires; the shape is not one-page regions.
    ++caseCount;
    {
        SmapsDirtAccumulator accumulator(4096);
        feedSmaps(accumulator,
                  region("70000000-70837000 r-xp 00200000 fd:07 42 /apex/com.android.art/lib64/libart.so", 8416, 0)
                          .c_str());
        const auto libraries = accumulator.dirtyLibraries();
        expect(accumulator.legacyRegionHits().size() == 1 && libraries.size() == 1 &&
                   libraries[0].dirtyRegionCount == 1 && libraries[0].singlePageDirtyRegionCount == 0 &&
                   libraries[0].privateDirtyKB == 8416,
               "smaps_unsplit_region_dirt", failures);
    }

    // Clean text, a dirty anonymous executable page and a dirty non-executable system mapping are
    // all outside this channel.
    ++caseCount;
    {
        SmapsDirtAccumulator accumulator(4096);
        const std::string text =
                region("70000000-70100000 r-xp 00200000 fd:07 42 /apex/com.android.art/lib64/libart.so", 0, 0) +
                region("71000000-71001000 r-xp 00000000 00:00 0 ", 4, 0) +
                region("72000000-72032000 r--p 00c00000 fd:07 42 /apex/com.android.art/lib64/libart.so", 0, 136);
        feedSmaps(accumulator, text.c_str());
        expect(accumulator.legacyRegionHits().empty() && accumulator.dirtyLibraries().empty(),
               "smaps_clean_and_out_of_scope", failures);
    }

    unlink(fixturePath.c_str());
    return {{"caseCount", caseCount}, {"failures", failures}};
}

constexpr std::uint32_t kFixturePropertyMagic = 0x504f5250U;
constexpr std::uint32_t kFixturePropertyVersion = 0xfc6ed0abU;
constexpr std::uint32_t kFixtureLongPropertyFlag = 1U << 16;
constexpr std::size_t kFixturePropertyHeaderSize = 128;
constexpr std::size_t kFixturePropertyValueMax = 92;

struct FixturePropertyAreaHeader {
    std::uint32_t bytesUsed;
    std::uint32_t serial;
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t reserved[28];
};

struct FixturePropertyTrieNode {
    std::uint32_t nameLength;
    std::uint32_t propertyOffset;
    std::uint32_t leftOffset;
    std::uint32_t rightOffset;
    std::uint32_t childrenOffset;
};

struct FixtureLongPropertyReference {
    char legacyError[56];
    std::uint32_t offset;
};

struct FixturePropertyInfo {
    std::uint32_t serial;
    union {
        char value[kFixturePropertyValueMax];
        FixtureLongPropertyReference longProperty;
    };
};

std::size_t alignFixture(std::size_t value) {
    return (value + 3U) & ~3U;
}

std::vector<std::string> splitPropertyName(const std::string& property) {
    std::vector<std::string> segments;
    std::istringstream stream(property);
    std::string segment;
    while (std::getline(stream, segment, '.')) segments.push_back(segment);
    return segments;
}

std::vector<std::uint8_t> buildPropertyAreaFixture(const std::string& property, const std::string& value,
                                                   bool longValue, std::size_t trailingHole = 0) {
    const auto segments = splitPropertyName(property);
    std::size_t cursor = sizeof(FixturePropertyTrieNode) + kFixturePropertyValueMax;
    std::vector<std::uint32_t> nodeOffsets;
    for (const auto& segment : segments) {
        nodeOffsets.push_back(static_cast<std::uint32_t>(cursor));
        cursor += alignFixture(sizeof(FixturePropertyTrieNode) + segment.size() + 1);
    }
    const std::uint32_t propertyOffset = static_cast<std::uint32_t>(cursor);
    const std::size_t propertyAllocation = alignFixture(sizeof(FixturePropertyInfo) + property.size() + 1);
    cursor += propertyAllocation;
    if (longValue) cursor += alignFixture(value.size() + 1);
    cursor += trailingHole;

    std::vector<std::uint8_t> fixture(kFixturePropertyHeaderSize + cursor, 0);
    auto* header = reinterpret_cast<FixturePropertyAreaHeader*>(fixture.data());
    header->bytesUsed = static_cast<std::uint32_t>(cursor);
    header->magic = kFixturePropertyMagic;
    header->version = kFixturePropertyVersion;
    std::uint8_t* data = fixture.data() + kFixturePropertyHeaderSize;

    auto* root = reinterpret_cast<FixturePropertyTrieNode*>(data);
    root->childrenOffset = nodeOffsets.front();
    for (std::size_t index = 0; index < segments.size(); ++index) {
        auto* node = reinterpret_cast<FixturePropertyTrieNode*>(data + nodeOffsets[index]);
        node->nameLength = static_cast<std::uint32_t>(segments[index].size());
        memcpy(data + nodeOffsets[index] + sizeof(FixturePropertyTrieNode), segments[index].c_str(),
               segments[index].size() + 1);
        if (index + 1 < segments.size()) {
            node->childrenOffset = nodeOffsets[index + 1];
        } else {
            node->propertyOffset = propertyOffset;
        }
    }

    auto* propertyInfo = reinterpret_cast<FixturePropertyInfo*>(data + propertyOffset);
    memcpy(data + propertyOffset + sizeof(FixturePropertyInfo), property.c_str(), property.size() + 1);
    if (longValue) {
        propertyInfo->serial = kFixtureLongPropertyFlag | (static_cast<std::uint32_t>(value.size()) << 24U);
        propertyInfo->longProperty.offset = static_cast<std::uint32_t>(propertyAllocation);
        memcpy(data + propertyOffset + propertyAllocation, value.c_str(), value.size() + 1);
    } else {
        propertyInfo->serial = static_cast<std::uint32_t>(value.size()) << 24U;
        memcpy(propertyInfo->value, value.c_str(), value.size() + 1);
    }
    return fixture;
}

PropertyObservation propertyObservation(const char* property, const char* source, PropertyObservationState state,
                                        const char* value = "") {
    return {property, source, state, value, {}, 0};
}

// Mirrors aggregateAssessment in selinux_check.cpp.
const char* selinuxOutcome(const SelinuxAssessment& assessment) {
    if (assessment.strongestFinding == EvidenceStrength::STRONG) return "strong";
    if (assessment.strongestFinding == EvidenceStrength::MODERATE) return "moderate";
    return assessment.hasReliableObservation ? "not_observed" : "inconclusive";
}

bool hasSelinuxFinding(const SelinuxAssessment& assessment, const char* id) {
    for (const auto& finding : assessment.findings) {
        if (finding.id == id) return true;
    }
    return false;
}

constexpr unsigned int kFixtureAppUid = 10234;

struct SelinuxScenario {
    // The selinuxfs_enforce read: readErrno != 0 means the open/read failed; otherwise
    // readValue is what the node returned.
    int readErrno = 0;
    const char* readValue = "1";
    bool selinuxfsVerified = true;
    int statErrno = 0;
    unsigned int statMode = 0100644;
    unsigned int statUid = 0;
    unsigned int statGid = 0;
    bool libselinuxAvailable = false;
    SelinuxMode libselinuxMode = SelinuxMode::UNKNOWN;
    bool writable = false;
};

struct SelinuxScenarioResult {
    SelinuxReadDenialInference inference;
    SelinuxAssessment assessment;
};

// Builds the assessment input the way SELinuxDetection::execute does.
SelinuxScenarioResult runSelinuxScenario(const SelinuxScenario& scenario) {
    SelinuxReadDenialInput denial;
    denial.readErrno = scenario.readErrno;
    denial.selinuxfsVerified = scenario.selinuxfsVerified;
    denial.callerUid = kFixtureAppUid;
    denial.callerGroups = {kFixtureAppUid, 3003, 9997};
    if (scenario.readErrno == EACCES) {
        denial.statAttempted = true;
        denial.statErrno = scenario.statErrno;
        if (scenario.statErrno == 0) {
            denial.statMode = scenario.statMode;
            denial.statUid = scenario.statUid;
            denial.statGid = scenario.statGid;
        }
    }
    SelinuxScenarioResult result;
    result.inference = inferSelinuxReadDenial(denial);

    SelinuxAssessmentInput input;
    SelinuxEnforcementObservation file{"selinuxfs_enforce", false, SelinuxMode::UNKNOWN, false};
    if (scenario.readErrno == 0) {
        if (std::string(scenario.readValue) == "1") {
            file = {"selinuxfs_enforce", true, SelinuxMode::ENFORCING, false};
        } else if (std::string(scenario.readValue) == "0") {
            file = {"selinuxfs_enforce", true, SelinuxMode::PERMISSIVE, false};
        }
    }
    input.enforcementSources.push_back(file);
    input.enforcementSources.push_back({"selinuxfs_read_denial", result.inference.state == "inferred",
                                        result.inference.mode, true});
    input.enforcementSources.push_back(
        {"libselinux", scenario.libselinuxAvailable, scenario.libselinuxMode, false});
    input.writeProbeAvailable = true;
    input.enforceNodeWritable = scenario.writable;
    result.assessment = assessSelinux(input);
    return result;
}

void runSelinuxReadDenialFixtures(int& caseCount, nlohmann::json& failures) {
    // EACCES on a node stat() shows as the kernel's 0644: SELinux refused a DAC-readable read.
    ++caseCount;
    SelinuxScenario measured;
    measured.readErrno = EACCES;
    const auto measuredResult = runSelinuxScenario(measured);
    expect(measuredResult.inference.state == "inferred" &&
               measuredResult.inference.mode == SelinuxMode::ENFORCING &&
               measuredResult.inference.dacBasis == "measured_mode" &&
               measuredResult.inference.anomaly.empty() &&
               std::string(selinuxOutcome(measuredResult.assessment)) == "not_observed" &&
               measuredResult.assessment.findings.empty(),
           "selinux_read_denial_stat_0644_not_observed", failures);

    // stat() refused as well: the DAC basis falls back to the kernel constant and says so.
    ++caseCount;
    SelinuxScenario statDenied;
    statDenied.readErrno = EACCES;
    statDenied.statErrno = EACCES;
    const auto statDeniedResult = runSelinuxScenario(statDenied);
    expect(statDeniedResult.inference.state == "inferred" &&
               statDeniedResult.inference.dacBasis == "kernel_constant" &&
               statDeniedResult.inference.dacPermitsRead &&
               std::string(selinuxOutcome(statDeniedResult.assessment)) == "not_observed",
           "selinux_read_denial_stat_denied_kernel_constant", failures);

    // stat() shows no other-read: DAC alone explains the refusal, so nothing is inferred.
    ++caseCount;
    SelinuxScenario noOtherRead;
    noOtherRead.readErrno = EACCES;
    noOtherRead.statMode = 0100640;
    const auto noOtherReadResult = runSelinuxScenario(noOtherRead);
    expect(noOtherReadResult.inference.state == "not_inferred" &&
               noOtherReadResult.inference.reason == "dac_denies_read" &&
               noOtherReadResult.inference.anomaly == "enforce_node_dac_not_kernel_default" &&
               std::string(selinuxOutcome(noOtherReadResult.assessment)) == "inconclusive" &&
               noOtherReadResult.assessment.findings.empty(),
           "selinux_read_denial_no_other_read_not_inferred", failures);

    // A readable node answers directly: "0" stays MODERATE, "1" is NOT_OBSERVED.
    ++caseCount;
    SelinuxScenario readZero;
    readZero.readValue = "0";
    const auto readZeroResult = runSelinuxScenario(readZero);
    expect(readZeroResult.inference.state == "not_applicable" &&
               std::string(selinuxOutcome(readZeroResult.assessment)) == "moderate" &&
               hasSelinuxFinding(readZeroResult.assessment, "selinux_permissive"),
           "selinux_read_zero_moderate", failures);

    ++caseCount;
    const auto readOneResult = runSelinuxScenario({});
    expect(readOneResult.inference.state == "not_applicable" &&
               std::string(selinuxOutcome(readOneResult.assessment)) == "not_observed" &&
               readOneResult.assessment.findings.empty(),
           "selinux_read_one_not_observed", failures);

    // Only EACCES is inferred; ENOENT and EPERM stay unanswered.
    ++caseCount;
    bool otherErrnosInconclusive = true;
    for (const int errorNumber : {ENOENT, EPERM, EIO}) {
        SelinuxScenario other;
        other.readErrno = errorNumber;
        const auto otherResult = runSelinuxScenario(other);
        otherErrnosInconclusive = otherErrnosInconclusive &&
                                  otherResult.inference.state == "not_inferred" &&
                                  otherResult.inference.reason == "read_errno_not_eacces" &&
                                  std::string(selinuxOutcome(otherResult.assessment)) == "inconclusive";
    }
    expect(otherErrnosInconclusive, "selinux_read_enoent_eperm_inconclusive", failures);

    // Without the SELINUX_MAGIC check the kernel-mode argument does not apply.
    ++caseCount;
    SelinuxScenario unverified;
    unverified.readErrno = EACCES;
    unverified.selinuxfsVerified = false;
    const auto unverifiedResult = runSelinuxScenario(unverified);
    expect(unverifiedResult.inference.reason == "selinuxfs_not_verified" &&
               std::string(selinuxOutcome(unverifiedResult.assessment)) == "inconclusive",
           "selinux_read_denial_requires_selinuxfs", failures);

    // stat() failing with anything but EACCES gives no DAC basis at all.
    ++caseCount;
    SelinuxScenario statMissing;
    statMissing.readErrno = EACCES;
    statMissing.statErrno = ENOENT;
    const auto statMissingResult = runSelinuxScenario(statMissing);
    expect(statMissingResult.inference.reason == "stat_failed" &&
               std::string(selinuxOutcome(statMissingResult.assessment)) == "inconclusive",
           "selinux_read_denial_stat_enoent_not_inferred", failures);

    // A writable enforce node is STRONG whatever the inference says.
    ++caseCount;
    SelinuxScenario writable;
    writable.readErrno = EACCES;
    writable.writable = true;
    const auto writableResult = runSelinuxScenario(writable);
    expect(std::string(selinuxOutcome(writableResult.assessment)) == "strong" &&
               hasSelinuxFinding(writableResult.assessment, "enforce_node_writable"),
           "selinux_read_denial_writable_node_strong", failures);

    // Inferred ENFORCING against libselinux PERMISSIVE: MODERATE, never STRONG.
    ++caseCount;
    SelinuxScenario inferredVsPermissive;
    inferredVsPermissive.readErrno = EACCES;
    inferredVsPermissive.libselinuxAvailable = true;
    inferredVsPermissive.libselinuxMode = SelinuxMode::PERMISSIVE;
    const auto inferredVsPermissiveResult = runSelinuxScenario(inferredVsPermissive);
    expect(std::string(selinuxOutcome(inferredVsPermissiveResult.assessment)) == "moderate" &&
               hasSelinuxFinding(inferredVsPermissiveResult.assessment, "inferred_enforcement_contradiction") &&
               hasSelinuxFinding(inferredVsPermissiveResult.assessment, "selinux_permissive") &&
               !hasSelinuxFinding(inferredVsPermissiveResult.assessment, "enforcement_source_contradiction"),
           "selinux_inferred_vs_libselinux_permissive_moderate", failures);

    // Inferred ENFORCING agreeing with libselinux ENFORCING: NOT_OBSERVED.
    ++caseCount;
    SelinuxScenario inferredAgrees;
    inferredAgrees.readErrno = EACCES;
    inferredAgrees.libselinuxAvailable = true;
    inferredAgrees.libselinuxMode = SelinuxMode::ENFORCING;
    const auto inferredAgreesResult = runSelinuxScenario(inferredAgrees);
    expect(std::string(selinuxOutcome(inferredAgreesResult.assessment)) == "not_observed" &&
               inferredAgreesResult.assessment.findings.empty(),
           "selinux_inferred_agrees_with_libselinux", failures);

    // Two read sources disagreeing stays STRONG, unchanged by the inferred source.
    ++caseCount;
    SelinuxScenario readContradiction;
    readContradiction.libselinuxAvailable = true;
    readContradiction.libselinuxMode = SelinuxMode::PERMISSIVE;
    const auto readContradictionResult = runSelinuxScenario(readContradiction);
    expect(std::string(selinuxOutcome(readContradictionResult.assessment)) == "strong" &&
               hasSelinuxFinding(readContradictionResult.assessment, "enforcement_source_contradiction") &&
               !hasSelinuxFinding(readContradictionResult.assessment, "inferred_enforcement_contradiction"),
           "selinux_read_source_contradiction_strong", failures);

    // DAC is evaluated per permission class, as generic_permission() does.
    ++caseCount;
    expect(selinuxDacPermitsRead(0100644, 0, 0, kFixtureAppUid, {kFixtureAppUid}) &&
               !selinuxDacPermitsRead(0100640, 0, 0, kFixtureAppUid, {kFixtureAppUid}) &&
               selinuxDacPermitsRead(0100640, 0, 3003, kFixtureAppUid, {kFixtureAppUid, 3003}) &&
               !selinuxDacPermitsRead(0100204, kFixtureAppUid, 0, kFixtureAppUid, {kFixtureAppUid}) &&
               selinuxDacPermitsRead(kSelinuxEnforceKernelMode, kSelinuxEnforceKernelUid,
                                     kSelinuxEnforceKernelGid, kFixtureAppUid, {kFixtureAppUid}),
           "selinux_dac_permission_classes", failures);
}

nlohmann::json runPropertyFixtures() {
    nlohmann::json failures = nlohmann::json::array();
    int caseCount = 0;

    ++caseCount;
    const auto missing =
        assessDangerousProperties({propertyObservation("ro.secure", "fixture", PropertyObservationState::MISSING)});
    expect(missing.findings.empty() && missing.availableRuleCount == 0, "missing_property_is_diagnostic", failures);

    ++caseCount;
    const auto dangerous = assessDangerousProperties(
        {propertyObservation("ro.secure", "fixture", PropertyObservationState::PRESENT, "0")});
    expect(dangerous.findings.size() == 1 && dangerous.strongestFinding == EvidenceStrength::MODERATE,
           "dangerous_property_is_moderate", failures);

    ++caseCount;
    const auto environmentTelemetry = assessPropertyPostureTelemetry(
        {}, {propertyObservation("ro.boot.qemu", "fixture", PropertyObservationState::PRESENT, "1"),
             propertyObservation("sys.usb.config", "fixture", PropertyObservationState::PRESENT, "mtp, adb")});
    expect(environmentTelemetry.size() == 2 && environmentTelemetry[0].id == "emulator_environment" &&
               environmentTelemetry[1].id == "adb_transport_enabled",
           "emulator_and_adb_transport_are_telemetry", failures);

    ++caseCount;
    const auto adbRootTelemetry = assessPropertyPostureTelemetry(
        {propertyObservation("service.adb.root", "fixture", PropertyObservationState::PRESENT, "1")}, {});
    expect(adbRootTelemetry.size() == 1 && adbRootTelemetry[0].id == "adb_root_requested",
           "standalone_adb_root_request_is_telemetry", failures);

    ++caseCount;
    const std::vector<PropertyObservation> adbRootDebuggable = {
        propertyObservation("service.adb.root", "fixture", PropertyObservationState::PRESENT, "1"),
        propertyObservation("ro.debuggable", "fixture", PropertyObservationState::PRESENT, "1")};
    const auto combinedAdbFinding = assessDangerousProperties(adbRootDebuggable);
    const auto combinedAdbTelemetry = assessPropertyPostureTelemetry(adbRootDebuggable, {});
    expect(combinedAdbFinding.strongestFinding == EvidenceStrength::MODERATE && combinedAdbTelemetry.empty(),
           "adb_root_debuggable_is_finding_without_duplicate_telemetry", failures);

    // Settings.Global adb_enabled: AdbService enables adbd for any value > 0, the Settings UI
    // writes only 0 or 1, and getInt(..., 0) reads an unparsable value as 0.
    const std::vector<PropertyObservation> usbWithAdb = {
        propertyObservation("sys.usb.config", "fixture", PropertyObservationState::PRESENT, "mtp,adb")};
    const auto adbSettingAssessment = [](const PropertyObservation& setting,
                                         const std::vector<PropertyObservation>& posture) {
        DangerousPropertiesAssessment assessment;
        assessAdbEnabledSetting(assessment, setting, posture);
        return assessment;
    };
    const auto adbSetting = [](PropertyObservationState state, const char* value = "") {
        return propertyObservation("adb_enabled", "settings_global", state, value);
    };

    ++caseCount;
    const auto adbStandard = adbSettingAssessment(adbSetting(PropertyObservationState::PRESENT, "1"), usbWithAdb);
    const auto adbOff = adbSettingAssessment(adbSetting(PropertyObservationState::PRESENT, "0"), {});
    expect(adbStandard.findings.empty() && adbStandard.availableRuleCount == 1 && adbStandard.checkedRuleCount == 1 &&
               adbOff.findings.empty(),
           "adb_enabled_standard_values_are_not_findings", failures);

    ++caseCount;
    const auto adbEvasion = adbSettingAssessment(adbSetting(PropertyObservationState::PRESENT, "3"), usbWithAdb);
    expect(adbEvasion.findings.size() == 1 && adbEvasion.findings[0].id == "adb_enabled_nonstandard" &&
               adbEvasion.findings[0].actual == "3" && adbEvasion.strongestFinding == EvidenceStrength::MODERATE,
           "adb_enabled_nonstandard_with_live_usb_adb_is_moderate", failures);

    ++caseCount;
    const auto adbUncorroborated = adbSettingAssessment(adbSetting(PropertyObservationState::PRESENT, "3"), {});
    const auto adbNegative = adbSettingAssessment(adbSetting(PropertyObservationState::PRESENT, "-1"), usbWithAdb);
    const auto adbGarbage = adbSettingAssessment(adbSetting(PropertyObservationState::PRESENT, "on"), usbWithAdb);
    const auto adbOverflow =
        adbSettingAssessment(adbSetting(PropertyObservationState::PRESENT, "2147483648"), usbWithAdb);
    expect(adbUncorroborated.strongestFinding == EvidenceStrength::WEAK &&
               adbNegative.strongestFinding == EvidenceStrength::WEAK &&
               adbGarbage.strongestFinding == EvidenceStrength::WEAK &&
               adbOverflow.strongestFinding == EvidenceStrength::WEAK,
           "adb_enabled_nonstandard_without_live_enable_is_weak", failures);

    ++caseCount;
    expect(classifyAdbEnabledSetting("+1") == AdbEnabledSettingClass::STANDARD &&
               classifyAdbEnabledSetting("2147483647") == AdbEnabledSettingClass::NONSTANDARD_ENABLED &&
               classifyAdbEnabledSetting("-2147483648") == AdbEnabledSettingClass::NONSTANDARD_DISABLED &&
               classifyAdbEnabledSetting(" 1") == AdbEnabledSettingClass::UNPARSABLE &&
               classifyAdbEnabledSetting("") == AdbEnabledSettingClass::UNPARSABLE &&
               classifyAdbEnabledSetting("-") == AdbEnabledSettingClass::UNPARSABLE,
           "adb_enabled_classification_mirrors_integer_parse_int", failures);

    ++caseCount;
    const auto adbUnreadable = adbSettingAssessment(adbSetting(PropertyObservationState::UNAVAILABLE), usbWithAdb);
    const auto adbMissing = adbSettingAssessment(adbSetting(PropertyObservationState::MISSING), usbWithAdb);
    expect(adbUnreadable.findings.empty() && adbUnreadable.availableRuleCount == 0 &&
               adbUnreadable.checkedRuleCount == 1 && adbMissing.findings.empty() &&
               adbMissing.availableRuleCount == 1,
           "adb_enabled_unreadable_is_not_an_answered_rule", failures);

    // Android 17 QPR1 (API 37) returns adb_enabled = 0 to every third-party app, so on API 37+
    // a 0 is the platform's value, not the device's. The redaction only yields 0: any other
    // value is still the device's real setting and is graded as below API 37.
    const auto redactedRead = [&](const char* value, int apiLevel) {
        return applyAdbEnabledPlatformRedaction(adbSetting(PropertyObservationState::PRESENT, value), apiLevel);
    };
    const auto isIssueKey = [](PropertyObservationState state, const char* expected) {
        const char* key = propertyObservationIssueKey(state);
        return expected == nullptr ? key == nullptr : key != nullptr && std::string(key) == expected;
    };

    ++caseCount;
    const auto api37Zero = redactedRead("0", 37);
    const auto api37ZeroAssessment = adbSettingAssessment(api37Zero, usbWithAdb);
    expect(api37Zero.state == PropertyObservationState::REDACTED_BY_PLATFORM && api37Zero.value.empty() &&
               std::string(propertyObservationStateName(api37Zero.state)) == "redacted_by_platform" &&
               isIssueKey(api37Zero.state, "collectionWarnings") && api37ZeroAssessment.findings.empty() &&
               api37ZeroAssessment.checkedRuleCount == 1 && api37ZeroAssessment.availableRuleCount == 0,
           "adb_enabled_api37_zero_is_redacted_issue_not_answer", failures);

    ++caseCount;
    const auto api37Three = redactedRead("3", 37);
    const auto api37ThreeAssessment = adbSettingAssessment(api37Three, usbWithAdb);
    const auto api37One = redactedRead("1", 37);
    const auto api37OneAssessment = adbSettingAssessment(api37One, usbWithAdb);
    expect(api37Three.state == PropertyObservationState::PRESENT && api37Three.value == "3" &&
               api37ThreeAssessment.findings.size() == 1 &&
               api37ThreeAssessment.findings[0].id == "adb_enabled_nonstandard" &&
               api37ThreeAssessment.strongestFinding == EvidenceStrength::MODERATE &&
               api37ThreeAssessment.availableRuleCount == 1 && api37One.state == PropertyObservationState::PRESENT &&
               isIssueKey(api37One.state, nullptr) && api37OneAssessment.findings.empty() &&
               api37OneAssessment.availableRuleCount == 1,
           "adb_enabled_api37_nonzero_is_still_an_answer", failures);

    ++caseCount;
    const auto api37Negative = adbSettingAssessment(redactedRead("-1", 37), usbWithAdb);
    const auto api37Garbage = adbSettingAssessment(redactedRead("on", 37), usbWithAdb);
    const auto api37Uncorroborated = adbSettingAssessment(redactedRead("3", 37), {});
    expect(api37Negative.strongestFinding == EvidenceStrength::WEAK &&
               api37Garbage.strongestFinding == EvidenceStrength::WEAK &&
               api37Uncorroborated.strongestFinding == EvidenceStrength::WEAK,
           "adb_enabled_api37_negative_unparsable_uncorroborated_stay_weak", failures);

    ++caseCount;
    const auto api33Zero = redactedRead("0", 33);
    const auto api33ZeroAssessment = adbSettingAssessment(api33Zero, usbWithAdb);
    const auto api33ThreeAssessment = adbSettingAssessment(redactedRead("3", 33), usbWithAdb);
    const auto api36Zero = redactedRead("0", 36);
    expect(api33Zero.state == PropertyObservationState::PRESENT && api33Zero.value == "0" &&
               isIssueKey(api33Zero.state, nullptr) && api33ZeroAssessment.findings.empty() &&
               api33ZeroAssessment.availableRuleCount == 1 &&
               api33ThreeAssessment.strongestFinding == EvidenceStrength::MODERATE &&
               api33ThreeAssessment.findings.size() == 1 && api36Zero.state == PropertyObservationState::PRESENT,
           "adb_enabled_below_api37_is_unchanged", failures);

    ++caseCount;
    // Every spelling Integer.parseInt reads as 0 is the redaction's value; an unreadable API
    // level cannot rule the redaction out. A missing row and a failed read keep their state.
    const auto api37Missing =
        applyAdbEnabledPlatformRedaction(adbSetting(PropertyObservationState::MISSING), 37);
    const auto api37Unreadable =
        applyAdbEnabledPlatformRedaction(adbSetting(PropertyObservationState::UNAVAILABLE), 37);
    expect(redactedRead("00", 37).state == PropertyObservationState::REDACTED_BY_PLATFORM &&
               redactedRead("+0", 40).state == PropertyObservationState::REDACTED_BY_PLATFORM &&
               redactedRead("-0", 37).state == PropertyObservationState::REDACTED_BY_PLATFORM &&
               redactedRead("0", -1).state == PropertyObservationState::REDACTED_BY_PLATFORM &&
               redactedRead(" 0", 37).state == PropertyObservationState::PRESENT &&
               api37Missing.state == PropertyObservationState::MISSING &&
               adbSettingAssessment(api37Missing, usbWithAdb).availableRuleCount == 1 &&
               api37Unreadable.state == PropertyObservationState::UNAVAILABLE &&
               isIssueKey(api37Unreadable.state, "collectionErrors"),
           "adb_enabled_redaction_covers_zero_spellings_and_unknown_api", failures);

    ++caseCount;
    // A redacted adb_enabled must not turn the detector INCONCLUSIVE while the property rules
    // answered; alone, it leaves no answered rule. Mirrors aggregateAssessment in
    // dangerous_props.cpp.
    auto answeredWithRedaction = assessDangerousProperties(
        {propertyObservation("ro.secure", "bionic", PropertyObservationState::PRESENT, "1")});
    assessAdbEnabledSetting(answeredWithRedaction, api37Zero, usbWithAdb);
    const auto redactionAlone = adbSettingAssessment(api37Zero, usbWithAdb);
    expect(answeredWithRedaction.findings.empty() && answeredWithRedaction.availableRuleCount > 0 &&
               answeredWithRedaction.strongestFinding == EvidenceStrength::NONE &&
               redactionAlone.availableRuleCount == 0,
           "adb_enabled_redaction_keeps_detector_not_observed_when_properties_answer", failures);

    ++caseCount;
    const auto consistent = compareEquivalentPropertySources(
        {"ro.secure"}, {propertyObservation("ro.secure", "bionic", PropertyObservationState::PRESENT, "1"),
                        propertyObservation("ro.secure", "getprop", PropertyObservationState::PRESENT, "1")});
    expect(consistent.size() == 1 && consistent[0].comparable && !consistent[0].mismatch, "consistent_property_sources",
           failures);

    ++caseCount;
    const auto mismatched = compareEquivalentPropertySources(
        {"ro.secure"}, {propertyObservation("ro.secure", "bionic", PropertyObservationState::PRESENT, "1"),
                        propertyObservation("ro.secure", "getprop", PropertyObservationState::PRESENT, "0")});
    expect(mismatched.size() == 1 && mismatched[0].mismatch, "mismatched_property_sources", failures);

    ++caseCount;
    const auto unavailable = compareEquivalentPropertySources(
        {"ro.secure"}, {propertyObservation("ro.secure", "bionic", PropertyObservationState::PRESENT, "1"),
                        propertyObservation("ro.secure", "getprop", PropertyObservationState::UNAVAILABLE)});
    expect(unavailable.size() == 1 && !unavailable[0].comparable && !unavailable[0].mismatch,
           "unavailable_property_source", failures);

    ++caseCount;
    const auto cleanFixture = buildPropertyAreaFixture("ro.secure", "1", false);
    const auto cleanArea = parsePropertyAreaBuffer(cleanFixture.data(), cleanFixture.size(), "fixture", "clean");
    expect(cleanArea.status == PropertyAreaStatus::PARSED && cleanArea.unreferencedBytes == 0 &&
               cleanArea.properties.at("ro.secure") == "1",
           "clean_property_area", failures);

    ++caseCount;
    const auto holeFixture = buildPropertyAreaFixture("ro.secure", "1", false, 8);
    const auto holeArea = parsePropertyAreaBuffer(holeFixture.data(), holeFixture.size(), "fixture", "holey");
    expect(holeArea.status == PropertyAreaStatus::PARSED && holeArea.unreferencedBytes == 8 &&
               holeArea.unreferencedRanges.size() == 1,
           "holey_property_area", failures);

    ++caseCount;
    auto invalidFixture = cleanFixture;
    reinterpret_cast<FixturePropertyAreaHeader*>(invalidFixture.data())->magic = 0;
    const auto invalidArea =
        parsePropertyAreaBuffer(invalidFixture.data(), invalidFixture.size(), "fixture", "invalid");
    expect(invalidArea.status == PropertyAreaStatus::INVALID, "invalid_property_area", failures);

    ++caseCount;
    auto cyclicFixture = cleanFixture;
    std::uint8_t* cyclicData = cyclicFixture.data() + kFixturePropertyHeaderSize;
    constexpr std::uint32_t firstNodeOffset = sizeof(FixturePropertyTrieNode) + kFixturePropertyValueMax;
    reinterpret_cast<FixturePropertyTrieNode*>(cyclicData + firstNodeOffset)->leftOffset = firstNodeOffset;
    const auto cyclicArea = parsePropertyAreaBuffer(cyclicFixture.data(), cyclicFixture.size(), "fixture", "cyclic");
    expect(cyclicArea.status == PropertyAreaStatus::INVALID && cyclicArea.error.find("cycle") != std::string::npos,
           "cyclic_property_area", failures);

    ++caseCount;
    const std::string longValue(160, 'x');
    const auto longFixture = buildPropertyAreaFixture("ro.long_property", longValue, true);
    const auto longArea = parsePropertyAreaBuffer(longFixture.data(), longFixture.size(), "fixture", "long");
    expect(longArea.status == PropertyAreaStatus::PARSED && longArea.properties.at("ro.long_property") == longValue,
           "long_value_property_area", failures);

    ++caseCount;
    SelinuxAssessmentInput writableInput;
    writableInput.writeProbeAvailable = true;
    writableInput.enforceNodeWritable = true;
    expect(assessSelinux(writableInput).strongestFinding == EvidenceStrength::STRONG, "selinux_writable_enforce_node",
           failures);

    ++caseCount;
    SelinuxAssessmentInput contradictionInput;
    contradictionInput.enforcementSources = {{"file", true, SelinuxMode::ENFORCING},
                                             {"libselinux", true, SelinuxMode::PERMISSIVE}};
    expect(assessSelinux(contradictionInput).strongestFinding == EvidenceStrength::STRONG,
           "selinux_source_contradiction", failures);

    ++caseCount;
    SelinuxAssessmentInput permissiveInput;
    permissiveInput.enforcementSources = {{"file", true, SelinuxMode::PERMISSIVE}};
    expect(assessSelinux(permissiveInput).strongestFinding == EvidenceStrength::MODERATE, "selinux_permissive",
           failures);

    ++caseCount;
    SelinuxAssessmentInput disabledInput;
    disabledInput.enforcementSources = {{"libselinux", true, SelinuxMode::DISABLED}};
    expect(assessSelinux(disabledInput).strongestFinding == EvidenceStrength::MODERATE, "selinux_disabled", failures);

    ++caseCount;
    SelinuxAssessmentInput enforcingInput;
    enforcingInput.enforcementSources = {{"file", true, SelinuxMode::ENFORCING}};
    const auto enforcing = assessSelinux(enforcingInput);
    expect(enforcing.strongestFinding == EvidenceStrength::NONE && enforcing.hasReliableObservation &&
               enforcing.findings.empty(),
           "selinux_enforcing", failures);

    ++caseCount;
    const auto unavailableSelinux = assessSelinux({});
    expect(unavailableSelinux.strongestFinding == EvidenceStrength::NONE &&
               !unavailableSelinux.hasReliableObservation && unavailableSelinux.findings.empty(),
           "selinux_unavailable", failures);

    // A denied write probe is the expected result on every device and answers nothing about
    // the global enforcement mode, so on its own it must leave the detector INCONCLUSIVE.
    // This is the fleet's actual shape: both enforcement sources unreadable, enforce node
    // denied.
    ++caseCount;
    SelinuxAssessmentInput deniedWriteProbeOnly;
    deniedWriteProbeOnly.writeProbeAvailable = true;
    deniedWriteProbeOnly.enforceNodeWritable = false;
    const auto deniedOnly = assessSelinux(deniedWriteProbeOnly);
    expect(deniedOnly.strongestFinding == EvidenceStrength::NONE &&
               !deniedOnly.hasReliableObservation && deniedOnly.findings.empty(),
           "selinux_denied_write_probe_alone_is_not_an_answer", failures);

    // A writable enforce node is STRONG and must still reach OBSERVED even though no
    // enforcement source reported a mode.
    ++caseCount;
    SelinuxAssessmentInput writableNode;
    writableNode.writeProbeAvailable = true;
    writableNode.enforceNodeWritable = true;
    const auto writable = assessSelinux(writableNode);
    expect(writable.strongestFinding == EvidenceStrength::STRONG && writable.findings.size() == 1,
           "selinux_writable_enforce_node_still_observed", failures);

    runSelinuxReadDenialFixtures(caseCount, failures);

    return {{"caseCount", caseCount}, {"failures", failures}};
}

nlohmann::json validLsposedPolicySnapshot(const char* lsposedDecision = "allowed") {
    const auto control = [](const char* id, const char* expected) {
        return nlohmann::json{{"id", id},
                              {"contextsValid", true},
                              {"nativeAvailable", true},
                              {"javaAvailable", true},
                              {"nativeStable", true},
                              {"javaStable", true},
                              {"stable", true},
                              {"sourcesAgree", true},
                              {"observationAvailable", true},
                              {"decision", expected},
                              {"trusted", true},
                              {"observationPassed", true},
                              {"passed", true}};
    };
    return {{"schemaVersion", 1},
            {"carrier",
             {{"state", "present"},
              {"context", "u:r:app_zygote:s0"},
              {"domain", "app_zygote"},
              {"uid", 10234},
              {"applicationUid", 10234},
              {"uidMatches", true}}},
            {"enforcementSources",
             {{{"source", "libselinux"}, {"state", "present"}, {"enabled", true}, {"mode", "enforcing"}},
              {{"source", "hidden_android_selinux"}, {"state", "present"}, {"mode", "enforcing"}}}},
            {"querySources", {{{"source", "native_libselinux"}, {"state", "available"}, {"required", true}}}},
            {"controls",
             {control("positive_app_zygote_dyntransition", "allowed"),
              control("negative_untrusted_app_ptrace_init", "denied")}},
            {"rules",
             {{{"id", "lsposed_file_read"},
               {"targetContextState", "valid"},
               {"nativeAvailable", true},
               {"javaAvailable", true},
               {"nativeStable", true},
               {"javaStable", true},
               {"stable", true},
               {"sourcesAgree", true},
               {"observationAvailable", true},
               {"decision", lsposedDecision},
               {"trusted", true},
               {"assessmentImpact", "moderate_finding"}},
              {{"id", "system_server_execmem"},
               {"targetContextState", "valid"},
               {"nativeAvailable", true},
               {"javaAvailable", true},
               {"nativeStable", true},
               {"javaStable", true},
               {"stable", true},
               {"sourcesAgree", true},
               {"observationAvailable", true},
               {"decision", "allowed"},
               {"trusted", true},
               {"assessmentImpact", "telemetry_only"}},
              {{"id", "magisk_binder_call"},
               {"targetContextState", "valid"},
               {"nativeAvailable", true},
               {"javaAvailable", true},
               {"nativeStable", true},
               {"javaStable", true},
               {"stable", true},
               {"sourcesAgree", true},
               {"observationAvailable", true},
               {"decision", "allowed"},
               {"trusted", true},
               {"assessmentImpact", "telemetry_only"}}}},
            {"collectionErrors", nlohmann::json::array()}};
}

nlohmann::json runLsposedSepolicyFixtures() {
    nlohmann::json failures = nlohmann::json::array();
    int caseCount = 0;

    ++caseCount;
    const auto allowed = assessLsposedPolicySnapshot(validLsposedPolicySnapshot("allowed"));
    expect(allowed.assessment == DetectionAssessment::moderateObserved() && allowed.payload["findings"].size() == 1,
           "validated_lsposed_rule_allowed", failures);

    ++caseCount;
    const auto denied = assessLsposedPolicySnapshot(validLsposedPolicySnapshot("denied"));
    expect(denied.assessment == DetectionAssessment::notObserved() && denied.payload["findings"].empty(),
           "validated_lsposed_rule_denied", failures);

    ++caseCount;
    auto absentSnapshot = validLsposedPolicySnapshot();
    absentSnapshot["rules"][0]["targetContextState"] = "absent";
    absentSnapshot["rules"][0]["trusted"] = false;
    const auto absent = assessLsposedPolicySnapshot(absentSnapshot);
    expect(absent.assessment == DetectionAssessment::notObserved(), "lsposed_context_absent", failures);

    ++caseCount;
    auto permissiveSnapshot = validLsposedPolicySnapshot();
    permissiveSnapshot["enforcementSources"][0]["mode"] = "permissive";
    expect(assessLsposedPolicySnapshot(permissiveSnapshot).assessment == DetectionAssessment::inconclusive(),
           "permissive_is_inconclusive", failures);

    ++caseCount;
    auto disabledSnapshot = validLsposedPolicySnapshot();
    disabledSnapshot["enforcementSources"][0]["enabled"] = false;
    disabledSnapshot["enforcementSources"][0]["mode"] = "disabled";
    expect(assessLsposedPolicySnapshot(disabledSnapshot).assessment == DetectionAssessment::inconclusive(),
           "disabled_is_inconclusive", failures);

    ++caseCount;
    auto wrongDomain = validLsposedPolicySnapshot();
    wrongDomain["carrier"]["domain"] = "isolated_app";
    expect(assessLsposedPolicySnapshot(wrongDomain).assessment == DetectionAssessment::inconclusive(),
           "wrong_carrier_domain", failures);

    ++caseCount;
    auto uidMismatch = validLsposedPolicySnapshot();
    uidMismatch["carrier"]["uidMatches"] = false;
    expect(assessLsposedPolicySnapshot(uidMismatch).assessment == DetectionAssessment::inconclusive(),
           "carrier_uid_mismatch", failures);

    ++caseCount;
    auto unstable = validLsposedPolicySnapshot();
    unstable["controls"][0]["stable"] = false;
    unstable["controls"][0]["passed"] = false;
    expect(assessLsposedPolicySnapshot(unstable).assessment == DetectionAssessment::inconclusive(), "unstable_control",
           failures);

    ++caseCount;
    auto enforcementContradiction = validLsposedPolicySnapshot();
    enforcementContradiction["enforcementSources"][1]["mode"] = "permissive";
    expect(assessLsposedPolicySnapshot(enforcementContradiction).assessment == DetectionAssessment::inconclusive(),
           "native_java_enforcement_contradiction", failures);

    ++caseCount;
    auto queryContradiction = validLsposedPolicySnapshot();
    queryContradiction["rules"][0]["sourcesAgree"] = false;
    queryContradiction["rules"][0]["trusted"] = false;
    expect(assessLsposedPolicySnapshot(queryContradiction).assessment == DetectionAssessment::inconclusive(),
           "native_java_rule_contradiction", failures);

    ++caseCount;
    auto missingSymbols = validLsposedPolicySnapshot();
    missingSymbols["querySources"][0]["state"] = "unavailable";
    expect(assessLsposedPolicySnapshot(missingSymbols).assessment == DetectionAssessment::inconclusive(),
           "missing_native_symbols", failures);

    ++caseCount;
    auto javaOnly = validLsposedPolicySnapshot();
    javaOnly["enforcementSources"][0] = {
        {"source", "libselinux"}, {"state", "unavailable"}, {"enabled", false}, {"mode", "unknown"}};
    javaOnly["querySources"][0]["state"] = "unavailable";
    for (auto& control : javaOnly["controls"]) {
        control["contextsValid"] = false;
        control["nativeAvailable"] = false;
        control["nativeStable"] = false;
        control["trusted"] = false;
        control["passed"] = false;
    }
    for (auto& rule : javaOnly["rules"]) {
        rule["targetContextState"] = "unavailable";
        rule["nativeAvailable"] = false;
        rule["nativeStable"] = false;
        rule["trusted"] = false;
    }
    const auto javaOnlyEvaluation = assessLsposedPolicySnapshot(javaOnly);
    expect(javaOnlyEvaluation.assessment == DetectionAssessment::inconclusive() &&
               javaOnlyEvaluation.payload["rules"].size() == 3 && javaOnlyEvaluation.payload["findings"].empty() &&
               javaOnlyEvaluation.payload["rules"][0].value("decision", std::string()) == "allowed" &&
               !javaOnlyEvaluation.payload["rules"][0].value("trusted", true),
           "java_only_rules_remain_visible_without_finding", failures);

    ++caseCount;
    expect(assessLsposedPolicySnapshot(nlohmann::json::array()).assessment == DetectionAssessment::inconclusive(),
           "malformed_snapshot", failures);

    ++caseCount;
    expect(assessLsposedPolicySnapshotBytes("not-json").assessment == DetectionAssessment::inconclusive(),
           "malformed_snapshot_bytes", failures);

    ++caseCount;
    expect(assessLsposedPolicySnapshotBytes(std::string(64U * 1024U + 1U, 'x')).assessment ==
               DetectionAssessment::inconclusive(),
           "oversized_snapshot_bytes", failures);

    ++caseCount;
    const nlohmann::json bindFailure = {{"schemaVersion", 1},
                                        {"collectionFailure", {{"source", "carrier"}, {"message", "bind failed"}}}};
    expect(assessLsposedPolicySnapshot(bindFailure).assessment == DetectionAssessment::inconclusive(),
           "carrier_bind_failure", failures);

    ++caseCount;
    const nlohmann::json timeout = {{"schemaVersion", 1},
                                    {"collectionFailure", {{"source", "carrier"}, {"message", "timeout"}}}};
    expect(assessLsposedPolicySnapshot(timeout).assessment == DetectionAssessment::inconclusive(), "carrier_timeout",
           failures);

    ++caseCount;
    auto genericAllowed = validLsposedPolicySnapshot("denied");
    genericAllowed["rules"][1]["decision"] = "allowed";
    genericAllowed["rules"][2]["decision"] = "allowed";
    const auto generic = assessLsposedPolicySnapshot(genericAllowed);
    expect(generic.assessment == DetectionAssessment::notObserved() && generic.payload["findings"].empty(),
           "generic_rules_are_telemetry_only", failures);

    ++caseCount;
    auto unavailableRule = validLsposedPolicySnapshot();
    unavailableRule["rules"][0]["targetContextState"] = "unavailable";
    unavailableRule["rules"][0]["trusted"] = false;
    expect(assessLsposedPolicySnapshot(unavailableRule).assessment == DetectionAssessment::inconclusive(),
           "unavailable_lsposed_rule", failures);

    return {{"caseCount", caseCount}, {"failures", failures}};
}

nlohmann::json policyOracleFixtureSnapshot() {
    const auto control = [](const char* id, const char* expected) {
        return nlohmann::json{
            {"id", id},
            {"contextsValid", true},
            {"nativeAvailable", true},
            {"nativeDecisions", {expected, expected}},
            {"javaAvailable", true},
            {"javaDecisions", {expected, expected}},
            {"nativeStable", true},
            {"javaStable", true},
            {"stable", true},
            {"sourcesAgree", true},
            {"contradiction", false},
            {"observationAvailable", true},
            {"decision", expected},
            {"trustedTier", "native_trusted"},
            {"nativePassed", true},
            {"javaPassed", true},
        };
    };
    const auto rule = [](const char* id, const char* decision, const char* impact) {
        return nlohmann::json{
            {"id", id},
            {"sourceContextState", "valid"},
            {"targetContextState", "valid"},
            {"nativeAvailable", true},
            {"nativeDecisions", {decision, decision}},
            {"javaAvailable", true},
            {"javaDecisions", {decision, decision}},
            {"nativeStable", true},
            {"javaStable", true},
            {"stable", true},
            {"sourcesAgree", true},
            {"contradiction", false},
            {"observationAvailable", true},
            {"decision", decision},
            {"trustedTier", "native_trusted"},
            {"assessmentImpact", impact},
        };
    };
    return {
        {"schemaVersion", 2},
        {"carrier",
         {{"state", "present"},
          {"context", "u:r:app_zygote:s0"},
          {"domain", "app_zygote"},
          {"uid", 10234},
          {"applicationUid", 10234},
          {"uidMatches", true}}},
        {"device", {{"buildType", "user"}}},
        {"enforcementSources",
         {{{"source", "libselinux"}, {"state", "present"}, {"enabled", true}, {"mode", "enforcing"}},
          {{"source", "hidden_android_selinux"}, {"state", "present"}, {"enabled", true}, {"mode", "enforcing"}}}},
        {"querySources",
         {{{"source", "native_libselinux"}, {"state", "available"}, {"required", false}},
          {{"source", "hidden_android_selinux"}, {"state", "available"}, {"required", false}}}},
        {"controls",
         {control("positive_app_zygote_dyntransition", "allowed"),
          control("negative_untrusted_app_ptrace_init", "denied")}},
        {"rules",
         {rule("lsposed_file_read", "denied", "moderate_or_weak_finding"),
          rule("xposed_data_read", "denied", "weak_finding"),
          rule("system_server_execmem", "allowed", "telemetry_only"),
          rule("magisk_binder_call", "denied", "weak_finding"), rule("ksu_file_read", "denied", "weak_finding"),
          rule("adbd_adbroot_binder_call", "denied", "weak_finding"),
          rule("shell_su_transition", "denied", "user_build_weak_finding")}},
        {"collectionErrors", nlohmann::json::array()},
    };
}

nlohmann::json* fixtureRule(nlohmann::json& snapshot, const char* id) {
    for (auto& row : snapshot["rules"]) {
        if (row.value("id", std::string()) == id) return &row;
    }
    return nullptr;
}

void setFixtureRuleDecision(nlohmann::json& snapshot, const char* id, const char* nativeDecision,
                            const char* javaDecision) {
    auto* row = fixtureRule(snapshot, id);
    if (row == nullptr) return;
    (*row)["nativeAvailable"] = true;
    (*row)["nativeDecisions"] = {nativeDecision, nativeDecision};
    (*row)["javaAvailable"] = true;
    (*row)["javaDecisions"] = {javaDecision, javaDecision};
    (*row)["nativeStable"] = true;
    (*row)["javaStable"] = true;
    (*row)["stable"] = true;
    (*row)["sourcesAgree"] = std::string(nativeDecision) == javaDecision;
    (*row)["contradiction"] = std::string(nativeDecision) != javaDecision;
    (*row)["observationAvailable"] = (*row)["sourcesAgree"];
    (*row)["decision"] = (*row)["sourcesAgree"] ? nativeDecision : "unavailable";
}

void makeFixtureJavaOnly(nlohmann::json& snapshot) {
    snapshot["enforcementSources"][0] = {
        {"source", "libselinux"},
        {"state", "unavailable"},
        {"enabled", false},
        {"mode", "unknown"},
    };
    snapshot["querySources"][0]["state"] = "unavailable";
    for (auto& control : snapshot["controls"]) {
        control["contextsValid"] = false;
        control["nativeAvailable"] = false;
        control["nativeDecisions"] = nlohmann::json::array();
        control["nativeStable"] = false;
        control["nativePassed"] = false;
        control["trustedTier"] = "java_controlled";
    }
    for (auto& rule : snapshot["rules"]) {
        rule["sourceContextState"] = "unavailable";
        rule["targetContextState"] = "unavailable";
        rule["nativeAvailable"] = false;
        rule["nativeDecisions"] = nlohmann::json::array();
        rule["nativeStable"] = false;
        rule["trustedTier"] = "java_controlled";
        rule["decision"] = rule["javaDecisions"][0];
    }
}

// The shape a clean phone produces (Xiaomi 12, E1 C-xiaomi12-8c664b4): libselinux is outside
// the app's linker namespace, so only the Java tier answers; every root and hook framework type
// is absent from the loaded policy, while AOSP's own su and system_server types exist and the
// Java query denies them.
nlohmann::json cleanJavaOnlyFixtureSnapshot() {
    auto snapshot = policyOracleFixtureSnapshot();
    makeFixtureJavaOnly(snapshot);
    for (auto& rule : snapshot["rules"]) {
        rule["sourceContextState"] = "valid";
        rule["targetContextState"] = "valid";
        rule["javaDecisions"] = {"denied", "denied"};
        rule["decision"] = "denied";
    }
    for (const char* id : {"lsposed_file_read", "xposed_data_read", "magisk_binder_call",
                           "ksu_file_read", "adbd_adbroot_binder_call"}) {
        (*fixtureRule(snapshot, id))["targetContextState"] = "absent";
    }
    return snapshot;
}

bool hasPolicyWarning(const nlohmann::json& payload, const char* source) {
    for (const auto& error : payload["collectionErrors"]) {
        if (error.value("source", std::string()) == source) return true;
    }
    return false;
}

bool concealableNegativesAre(const nlohmann::json& payload, const std::vector<std::string>& ruleIds) {
    const auto& negatives = payload["concealableNegatives"];
    if (!negatives.is_array() || negatives.size() != ruleIds.size()) return false;
    for (size_t index = 0; index < ruleIds.size(); ++index) {
        const auto& negative = negatives[index];
        if (negative.value("ruleId", std::string()) != ruleIds[index] ||
            negative.value("targetContextState", std::string()) != "absent" ||
            !negative.value("concealable", false)) {
            return false;
        }
    }
    return payload["overview"].value("concealableNegativeCount", -1) ==
           static_cast<int>(ruleIds.size());
}

nlohmann::json runSharedLsposedSepolicyFixtures() {
    nlohmann::json failures = nlohmann::json::array();
    int caseCount = 0;

    ++caseCount;
    auto nativeAllowed = policyOracleFixtureSnapshot();
    setFixtureRuleDecision(nativeAllowed, "lsposed_file_read", "allowed", "allowed");
    expect(assessLsposedPolicySnapshot(nativeAllowed).assessment == DetectionAssessment::moderateObserved(),
           "native_lsposed_allowed_is_moderate", failures);

    ++caseCount;
    auto javaAllowed = policyOracleFixtureSnapshot();
    makeFixtureJavaOnly(javaAllowed);
    auto* javaLsposed = fixtureRule(javaAllowed, "lsposed_file_read");
    (*javaLsposed)["javaDecisions"] = {"allowed", "allowed"};
    (*javaLsposed)["decision"] = "allowed";
    const auto javaAllowedResult = assessLsposedPolicySnapshot(javaAllowed);
    expect(javaAllowedResult.assessment == DetectionAssessment::weakObserved() &&
               javaAllowedResult.payload["findings"][0].value("trustTier", std::string()) == "java_controlled",
           "java_only_lsposed_allowed_is_weak", failures);

    ++caseCount;
    auto javaDenied = policyOracleFixtureSnapshot();
    makeFixtureJavaOnly(javaDenied);
    expect(assessLsposedPolicySnapshot(javaDenied).assessment == DetectionAssessment::inconclusive(),
           "java_only_denied_is_inconclusive", failures);

    ++caseCount;
    expect(assessLsposedPolicySnapshot(policyOracleFixtureSnapshot()).assessment == DetectionAssessment::notObserved(),
           "native_denied_is_not_observed", failures);

    ++caseCount;
    auto absent = policyOracleFixtureSnapshot();
    auto* absentRule = fixtureRule(absent, "lsposed_file_read");
    (*absentRule)["targetContextState"] = "absent";
    (*absentRule)["nativeAvailable"] = false;
    (*absentRule)["nativeDecisions"] = nlohmann::json::array();
    (*absentRule)["nativeStable"] = false;
    const auto absentResult = assessLsposedPolicySnapshot(absent);
    expect(absentResult.assessment == DetectionAssessment::notObserved() &&
               concealableNegativesAre(absentResult.payload, {"lsposed_file_read"}) &&
               absentResult.payload["overview"].value("trustedNegativeCount", -1) == 1,
           "native_absent_is_a_concealable_not_observed", failures);

    ++caseCount;
    auto xposedAllowed = policyOracleFixtureSnapshot();
    setFixtureRuleDecision(xposedAllowed, "xposed_data_read", "allowed", "allowed");
    expect(assessLsposedPolicySnapshot(xposedAllowed).assessment == DetectionAssessment::weakObserved(),
           "xposed_data_allowed_is_weak", failures);

    ++caseCount;
    expect(assessLsposedPolicySnapshot(policyOracleFixtureSnapshot()).payload["findings"].empty(),
           "generic_rule_does_not_create_finding", failures);

    ++caseCount;
    auto permissive = policyOracleFixtureSnapshot();
    permissive["enforcementSources"][0]["mode"] = "permissive";
    expect(assessLsposedPolicySnapshot(permissive).assessment == DetectionAssessment::inconclusive(),
           "permissive_is_inconclusive", failures);

    ++caseCount;
    auto disabled = policyOracleFixtureSnapshot();
    disabled["enforcementSources"][0]["enabled"] = false;
    disabled["enforcementSources"][0]["mode"] = "disabled";
    expect(assessLsposedPolicySnapshot(disabled).assessment == DetectionAssessment::inconclusive(),
           "disabled_is_inconclusive", failures);

    ++caseCount;
    auto wrongDomain = policyOracleFixtureSnapshot();
    wrongDomain["carrier"]["domain"] = "isolated_app";
    expect(assessLsposedPolicySnapshot(wrongDomain).assessment == DetectionAssessment::inconclusive(),
           "wrong_carrier_domain", failures);

    ++caseCount;
    auto uidMismatch = policyOracleFixtureSnapshot();
    uidMismatch["carrier"]["uidMatches"] = false;
    expect(assessLsposedPolicySnapshot(uidMismatch).assessment == DetectionAssessment::inconclusive(),
           "carrier_uid_mismatch", failures);

    ++caseCount;
    auto unstable = policyOracleFixtureSnapshot();
    unstable["controls"][0]["nativePassed"] = false;
    unstable["controls"][0]["javaPassed"] = false;
    unstable["controls"][0]["stable"] = false;
    expect(assessLsposedPolicySnapshot(unstable).assessment == DetectionAssessment::inconclusive(), "unstable_control",
           failures);

    ++caseCount;
    auto enforcementContradiction = policyOracleFixtureSnapshot();
    enforcementContradiction["enforcementSources"][1]["mode"] = "permissive";
    expect(assessLsposedPolicySnapshot(enforcementContradiction).assessment == DetectionAssessment::inconclusive(),
           "enforcement_contradiction", failures);

    ++caseCount;
    auto ruleContradiction = policyOracleFixtureSnapshot();
    setFixtureRuleDecision(ruleContradiction, "lsposed_file_read", "allowed", "denied");
    expect(assessLsposedPolicySnapshot(ruleContradiction).assessment == DetectionAssessment::inconclusive(),
           "rule_contradiction", failures);

    ++caseCount;
    auto absentJavaAllowed = policyOracleFixtureSnapshot();
    auto* absentJavaRule = fixtureRule(absentJavaAllowed, "lsposed_file_read");
    (*absentJavaRule)["targetContextState"] = "absent";
    (*absentJavaRule)["nativeAvailable"] = false;
    (*absentJavaRule)["nativeDecisions"] = nlohmann::json::array();
    (*absentJavaRule)["nativeStable"] = false;
    (*absentJavaRule)["javaDecisions"] = {"allowed", "allowed"};
    expect(assessLsposedPolicySnapshot(absentJavaAllowed).assessment == DetectionAssessment::inconclusive(),
           "absent_context_java_allowed_is_contradiction", failures);

    ++caseCount;
    auto missingNativeSymbols = nativeAllowed;
    missingNativeSymbols["querySources"][0]["state"] = "unavailable";
    expect(assessLsposedPolicySnapshot(missingNativeSymbols).assessment == DetectionAssessment::weakObserved(),
           "missing_native_symbols_uses_java_controlled", failures);

    ++caseCount;
    auto missingAllSymbols = policyOracleFixtureSnapshot();
    missingAllSymbols["querySources"][0]["state"] = "unavailable";
    missingAllSymbols["querySources"][1]["state"] = "unavailable";
    expect(assessLsposedPolicySnapshot(missingAllSymbols).assessment == DetectionAssessment::inconclusive(),
           "missing_all_query_sources", failures);

    ++caseCount;
    expect(assessLsposedPolicySnapshot(nlohmann::json::array()).assessment == DetectionAssessment::inconclusive(),
           "malformed_snapshot", failures);

    ++caseCount;
    expect(assessLsposedPolicySnapshotBytes(std::string(64U * 1024U + 1U, 'x')).assessment ==
               DetectionAssessment::inconclusive(),
           "oversized_snapshot", failures);

    ++caseCount;
    expect(assessLsposedPolicySnapshot(
               {{"schemaVersion", 2}, {"collectionFailure", {{"source", "carrier"}, {"message", "bind failed"}}}})
                   .assessment == DetectionAssessment::inconclusive(),
           "bind_failure", failures);

    ++caseCount;
    expect(assessLsposedPolicySnapshot(
               {{"schemaVersion", 2}, {"collectionFailure", {{"source", "carrier"}, {"message", "timeout"}}}})
                   .assessment == DetectionAssessment::inconclusive(),
           "carrier_timeout", failures);

    ++caseCount;
    const auto clean = assessLsposedPolicySnapshot(cleanJavaOnlyFixtureSnapshot());
    expect(clean.assessment == DetectionAssessment::notObserved() &&
               concealableNegativesAre(clean.payload, {"lsposed_file_read", "xposed_data_read"}) &&
               clean.payload["overview"].value("trustedNegativeCount", -1) == 0 &&
               clean.payload["findings"].empty() && !hasPolicyWarning(clean.payload, "policy_rules"),
           "clean_java_only_absent_types_are_concealable_not_observed", failures);

    ++caseCount;
    auto cleanCarrierFailure = cleanJavaOnlyFixtureSnapshot();
    cleanCarrierFailure["carrier"]["domain"] = "isolated_app";
    const auto carrierFailure = assessLsposedPolicySnapshot(cleanCarrierFailure);
    expect(carrierFailure.assessment == DetectionAssessment::inconclusive() &&
               carrierFailure.payload["concealableNegatives"].empty(),
           "clean_java_only_carrier_failure_stays_inconclusive", failures);

    ++caseCount;
    auto cleanPresentAllowed = cleanJavaOnlyFixtureSnapshot();
    auto* presentLsposed = fixtureRule(cleanPresentAllowed, "lsposed_file_read");
    (*presentLsposed)["targetContextState"] = "valid";
    (*presentLsposed)["javaDecisions"] = {"allowed", "allowed"};
    (*presentLsposed)["decision"] = "allowed";
    expect(assessLsposedPolicySnapshot(cleanPresentAllowed).assessment == DetectionAssessment::weakObserved(),
           "clean_java_only_present_allowed_type_is_observed", failures);

    ++caseCount;
    auto cleanPresentDenied = cleanJavaOnlyFixtureSnapshot();
    (*fixtureRule(cleanPresentDenied, "xposed_data_read"))["targetContextState"] = "valid";
    const auto presentDenied = assessLsposedPolicySnapshot(cleanPresentDenied);
    expect(presentDenied.assessment == DetectionAssessment::inconclusive() &&
               hasPolicyWarning(presentDenied.payload, "policy_rules"),
           "clean_java_only_present_denied_type_stays_inconclusive", failures);

    ++caseCount;
    auto cleanAbsentAllowed = cleanJavaOnlyFixtureSnapshot();
    (*fixtureRule(cleanAbsentAllowed, "lsposed_file_read"))["javaDecisions"] = {"allowed", "allowed"};
    expect(assessLsposedPolicySnapshot(cleanAbsentAllowed).assessment == DetectionAssessment::inconclusive(),
           "clean_java_only_absent_type_java_allowed_is_contradiction", failures);

    return {{"caseCount", caseCount}, {"failures", failures}};
}

nlohmann::json runNativeRootSepolicyFixtures() {
    nlohmann::json failures = nlohmann::json::array();
    int caseCount = 0;
    const std::array<const char*, 4> ruleIds = {
        "magisk_binder_call",
        "ksu_file_read",
        "adbd_adbroot_binder_call",
        "shell_su_transition",
    };
    for (const char* ruleId : ruleIds) {
        ++caseCount;
        auto snapshot = policyOracleFixtureSnapshot();
        setFixtureRuleDecision(snapshot, ruleId, "allowed", "allowed");
        const std::string caseName = std::string("native_root_rule_allowed_") + ruleId;
        expect(assessNativeRootPolicySnapshot(snapshot).assessment == DetectionAssessment::weakObserved(),
               caseName.c_str(), failures);
    }

    ++caseCount;
    auto multiple = policyOracleFixtureSnapshot();
    setFixtureRuleDecision(multiple, "magisk_binder_call", "allowed", "allowed");
    setFixtureRuleDecision(multiple, "ksu_file_read", "allowed", "allowed");
    expect(assessNativeRootPolicySnapshot(multiple).assessment == DetectionAssessment::weakObserved() &&
               assessNativeRootPolicySnapshot(multiple).payload["findings"].size() == 2,
           "multiple_hits_remain_weak", failures);

    ++caseCount;
    auto nonUserShell = policyOracleFixtureSnapshot();
    nonUserShell["device"]["buildType"] = "userdebug";
    setFixtureRuleDecision(nonUserShell, "shell_su_transition", "allowed", "allowed");
    const auto nonUserResult = assessNativeRootPolicySnapshot(nonUserShell);
    expect(nonUserResult.assessment == DetectionAssessment::notObserved() && nonUserResult.payload["findings"].empty(),
           "non_user_shell_transition_is_telemetry", failures);

    ++caseCount;
    auto javaAllowed = policyOracleFixtureSnapshot();
    makeFixtureJavaOnly(javaAllowed);
    auto* javaMagisk = fixtureRule(javaAllowed, "magisk_binder_call");
    (*javaMagisk)["javaDecisions"] = {"allowed", "allowed"};
    (*javaMagisk)["decision"] = "allowed";
    expect(assessNativeRootPolicySnapshot(javaAllowed).assessment == DetectionAssessment::weakObserved(),
           "java_only_native_root_allowed_is_weak", failures);

    ++caseCount;
    auto javaDenied = policyOracleFixtureSnapshot();
    makeFixtureJavaOnly(javaDenied);
    expect(assessNativeRootPolicySnapshot(javaDenied).assessment == DetectionAssessment::inconclusive(),
           "java_only_native_root_denied_is_inconclusive", failures);

    ++caseCount;
    expect(
        assessNativeRootPolicySnapshot(policyOracleFixtureSnapshot()).assessment == DetectionAssessment::notObserved(),
        "native_root_all_denied_is_not_observed", failures);

    ++caseCount;
    auto contradiction = policyOracleFixtureSnapshot();
    setFixtureRuleDecision(contradiction, "magisk_binder_call", "allowed", "denied");
    expect(assessNativeRootPolicySnapshot(contradiction).assessment == DetectionAssessment::inconclusive(),
           "native_root_contradiction", failures);

    ++caseCount;
    auto categoryIsolation = policyOracleFixtureSnapshot();
    setFixtureRuleDecision(categoryIsolation, "lsposed_file_read", "allowed", "allowed");
    setFixtureRuleDecision(categoryIsolation, "xposed_data_read", "allowed", "allowed");
    const auto isolated = assessNativeRootPolicySnapshot(categoryIsolation);
    expect(isolated.assessment == DetectionAssessment::notObserved() && isolated.payload["rules"].size() == 4,
           "native_root_category_isolation", failures);

    ++caseCount;
    auto missingNative = javaAllowed;
    expect(assessNativeRootPolicySnapshot(missingNative).assessment == DetectionAssessment::weakObserved(),
           "native_root_missing_symbols_java_fallback", failures);

    ++caseCount;
    const auto cleanUser = assessNativeRootPolicySnapshot(cleanJavaOnlyFixtureSnapshot());
    expect(cleanUser.assessment == DetectionAssessment::inconclusive() &&
               cleanUser.payload["concealableNegatives"].empty() &&
               hasPolicyWarning(cleanUser.payload, "policy_rules"),
           "clean_java_only_user_build_shell_su_denial_stays_inconclusive", failures);

    ++caseCount;
    auto cleanUserdebug = cleanJavaOnlyFixtureSnapshot();
    cleanUserdebug["device"]["buildType"] = "userdebug";
    const auto userdebug = assessNativeRootPolicySnapshot(cleanUserdebug);
    expect(userdebug.assessment == DetectionAssessment::notObserved() &&
               concealableNegativesAre(userdebug.payload, {"magisk_binder_call", "ksu_file_read",
                                                           "adbd_adbroot_binder_call"}) &&
               userdebug.payload["overview"].value("trustedNegativeCount", -1) == 0 &&
               !hasPolicyWarning(userdebug.payload, "policy_rules"),
           "clean_java_only_absent_types_are_concealable_not_observed", failures);

    ++caseCount;
    auto cleanUidMismatch = cleanUserdebug;
    cleanUidMismatch["carrier"]["uidMatches"] = false;
    const auto uidMismatch = assessNativeRootPolicySnapshot(cleanUidMismatch);
    expect(uidMismatch.assessment == DetectionAssessment::inconclusive() &&
               uidMismatch.payload["concealableNegatives"].empty(),
           "clean_java_only_carrier_uid_mismatch_stays_inconclusive", failures);

    ++caseCount;
    auto cleanKsuAllowed = cleanUserdebug;
    auto* presentKsu = fixtureRule(cleanKsuAllowed, "ksu_file_read");
    (*presentKsu)["targetContextState"] = "valid";
    (*presentKsu)["javaDecisions"] = {"allowed", "allowed"};
    (*presentKsu)["decision"] = "allowed";
    expect(assessNativeRootPolicySnapshot(cleanKsuAllowed).assessment == DetectionAssessment::weakObserved(),
           "clean_java_only_present_allowed_type_is_observed", failures);

    ++caseCount;
    auto nativeMixed = policyOracleFixtureSnapshot();
    for (const char* id : {"magisk_binder_call", "ksu_file_read", "adbd_adbroot_binder_call"}) {
        auto* row = fixtureRule(nativeMixed, id);
        (*row)["targetContextState"] = "absent";
        (*row)["nativeAvailable"] = false;
        (*row)["nativeDecisions"] = nlohmann::json::array();
        (*row)["nativeStable"] = false;
    }
    const auto mixed = assessNativeRootPolicySnapshot(nativeMixed);
    expect(mixed.assessment == DetectionAssessment::notObserved() &&
               concealableNegativesAre(mixed.payload, {"magisk_binder_call", "ksu_file_read",
                                                       "adbd_adbroot_binder_call"}) &&
               mixed.payload["overview"].value("trustedNegativeCount", -1) == 1,
           "native_trusted_absent_types_are_still_concealable", failures);

    return {{"caseCount", caseCount}, {"failures", failures}};
}

nlohmann::json runDangerousPackagesFixtures() {
    nlohmann::json failures = nlohmann::json::array();
    int caseCount = 0;

    ++caseCount;
    expect(classifyPathProbeResult(0, 0).state == PathProbeState::Exists, "visible_path_is_present", failures);

    ++caseCount;
    expect(classifyPathProbeResult(-1, ENOENT).state == PathProbeState::NotFound, "enoent_path_is_absent",
           failures);

    ++caseCount;
    expect(classifyPathProbeResult(-1, EACCES).state == PathProbeState::Inaccessible,
           "eacces_path_is_diagnostic", failures);

    ++caseCount;
    expect(classifyPathProbeResult(-1, EPERM).state == PathProbeState::Inaccessible,
           "eperm_path_is_diagnostic", failures);

    ++caseCount;
    expect(aggregateDangerousPackageAssessment(false, false, true, false) ==
               DetectionAssessment::inconclusive(),
           "inaccessible_only_is_inconclusive", failures);

    ++caseCount;
    expect(aggregateDangerousPackageAssessment(true, false, true, true) ==
               DetectionAssessment::weakObserved(),
           "visible_package_is_a_finding", failures);

    ++caseCount;
    expect(aggregateDangerousPackageAssessment(false, true, true, true) ==
               DetectionAssessment::weakObserved(),
           "visible_path_is_a_finding", failures);

    ++caseCount;
    expect(aggregateDangerousPackageAssessment(false, false, true, true) ==
               DetectionAssessment::notObserved(),
           "complete_neutral_collection_is_not_observed", failures);

    return {{"caseCount", caseCount}, {"failures", failures}};
}

nlohmann::json runBinaryArtifactFixtures(const std::string& cacheDirectory) {
    nlohmann::json failures = nlohmann::json::array();
    int caseCount = 0;

    const std::string elfPath = cacheDirectory + "/tamperprobe-binary-artifact.elf";
    const std::string symlinkPath = cacheDirectory + "/tamperprobe-binary-artifact-link";
    const std::string textPath = cacheDirectory + "/tamperprobe-binary-artifact.txt";
    const std::string directoryPath = cacheDirectory + "/tamperprobe-binary-artifact-dir";
    const std::string missingPath = cacheDirectory + "/tamperprobe-binary-artifact-missing";

    unlink(symlinkPath.c_str());
    unlink(elfPath.c_str());
    unlink(textPath.c_str());
    unlink(missingPath.c_str());
    rmdir(directoryPath.c_str());

    const std::array<unsigned char, 4> fixtureBytes = {0x00, 0x01, 0x02, 0x03};
    const bool elfWritten =
        writeFixtureElf(elfPath, fixtureBytes.data(), fixtureBytes.size()) &&
        chmod(elfPath.c_str(), 0700) == 0;
    const auto elfProbe =
        probeBinaryArtifact({elfPath, "fixed_path"});

    ++caseCount;
    expect(elfWritten && elfProbe["lstat"].value("fileType", "") == "regular" &&
               elfProbe["fstat"].value("fileType", "") == "regular" &&
               elfProbe["header"].value("format", "") == "elf_magic" &&
               elfProbe["header"].value("sameResolvedObject", false),
           "binary_regular_elf_metadata", failures);

    ++caseCount;
    const auto strongSu =
        evaluateBinaryArtifactProbes({elfProbe}, BinaryArtifactProfile::Su);
    expect(strongSu.assessment == DetectionAssessment::strongObserved() &&
               strongSu.payload["overview"].value("strongFindingCount", 0) == 1,
           "binary_executable_elf_su_is_strong", failures);

    ++caseCount;
    const auto weakBusyBox =
        evaluateBinaryArtifactProbes({elfProbe}, BinaryArtifactProfile::BusyBox);
    expect(weakBusyBox.assessment == DetectionAssessment::weakObserved() &&
               weakBusyBox.payload["overview"].value("weakFindingCount", 0) == 1,
           "binary_busybox_remains_weak", failures);

    const bool symlinkCreated = symlink(elfPath.c_str(), symlinkPath.c_str()) == 0;
    const auto symlinkProbe =
        probeBinaryArtifact({symlinkPath, "fixed_path"});
    ++caseCount;
    expect(symlinkCreated && symlinkProbe["lstat"].value("fileType", "") == "symlink" &&
               symlinkProbe["fstat"].value("fileType", "") == "regular" &&
               evaluateBinaryArtifactProbes({symlinkProbe}, BinaryArtifactProfile::Su).assessment ==
                   DetectionAssessment::strongObserved(),
           "binary_lstat_and_fstat_preserve_symlink_semantics", failures);

    const int textDescriptor =
        open(textPath.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0700);
    const char textBytes[] = "#!/system/bin/sh\n";
    const bool textWritten =
        textDescriptor >= 0 &&
        write(textDescriptor, textBytes, sizeof(textBytes) - 1) ==
            static_cast<ssize_t>(sizeof(textBytes) - 1);
    if (textDescriptor >= 0) close(textDescriptor);
    const auto textProbe =
        probeBinaryArtifact({textPath, "fixed_path"});
    ++caseCount;
    expect(textWritten && textProbe["header"].value("format", "") == "other" &&
               evaluateBinaryArtifactProbes({textProbe}, BinaryArtifactProfile::Su).assessment ==
                   DetectionAssessment::weakObserved(),
           "binary_non_elf_su_path_is_weak", failures);

    const bool directoryCreated = mkdir(directoryPath.c_str(), 0700) == 0;
    const auto directoryProbe =
        probeBinaryArtifact({directoryPath, "fixed_path"});
    ++caseCount;
    expect(directoryCreated && directoryProbe["fstat"].value("fileType", "") == "directory" &&
               directoryProbe["header"].value("state", "") == "not_attempted" &&
               evaluateBinaryArtifactProbes({directoryProbe}, BinaryArtifactProfile::Su).assessment ==
                   DetectionAssessment::weakObserved(),
           "binary_directory_path_is_visible_but_weak", failures);

    const auto missingProbe =
        probeBinaryArtifact({missingPath, "fixed_path"});
    ++caseCount;
    expect(missingProbe["lstat"].value("state", "") == "not_found" &&
               evaluateBinaryArtifactProbes({missingProbe}, BinaryArtifactProfile::Su).assessment ==
                   DetectionAssessment::notObserved(),
           "binary_missing_path_is_not_observed", failures);

    const nlohmann::json deniedProbe = {
        {"path", "/data/local/inaccessible-su"},
        {"candidateSource", "fixed_path"},
        {"access", {{"state", "denied"}, {"errno", EACCES}}},
        {"lstat", {{"state", "denied"}, {"errno", EACCES}}},
        {"openPath", {{"state", "denied"}, {"errno", EACCES}}},
        {"fstat", {{"state", "not_attempted"}, {"errno", 0}}},
        {"header",
         {{"state", "not_attempted"},
          {"errno", 0},
          {"format", "not_applicable"},
          {"bytesRead", 0}}},
    };
    const auto denied =
        evaluateBinaryArtifactProbes({deniedProbe}, BinaryArtifactProfile::Su);
    ++caseCount;
    expect(denied.assessment == DetectionAssessment::inconclusive() &&
               denied.payload["findings"].empty() &&
               denied.payload["overview"].value("deniedOperationCount", 0) == 3 &&
               denied.payload["overview"].value("unavailableCandidateCount", 0) == 1,
           "binary_permission_denials_are_diagnostic_only", failures);

    chmod(elfPath.c_str(), 0600);
    const auto nonExecutableElfProbe =
        probeBinaryArtifact({elfPath, "fixed_path"});
    ++caseCount;
    expect(nonExecutableElfProbe["header"].value("format", "") == "elf_magic" &&
               evaluateBinaryArtifactProbes({nonExecutableElfProbe}, BinaryArtifactProfile::Su)
                       .assessment == DetectionAssessment::weakObserved(),
           "binary_non_executable_elf_su_path_is_weak", failures);

    auto changedTargetProbe = elfProbe;
    changedTargetProbe["header"]["sameResolvedObject"] = false;
    ++caseCount;
    expect(evaluateBinaryArtifactProbes({changedTargetProbe}, BinaryArtifactProfile::Su).assessment ==
               DetectionAssessment::weakObserved(),
           "binary_changed_target_cannot_be_strong", failures);

    std::vector<BinaryArtifactCandidate> pathCandidates = {
        {"/system/bin/su", "fixed_path"},
    };
    appendPathCandidates(pathCandidates, "su",
                         "/system/bin:/vendor/bin:relative::/vendor/bin:/", 2);
    ++caseCount;
    expect(pathCandidates.size() == 3 &&
               pathCandidates[1].path == "/vendor/bin/su" &&
               pathCandidates[1].source == "environment_path" &&
               pathCandidates[2].path == "/su",
           "binary_path_candidates_are_absolute_deduplicated_and_bounded", failures);

    auto environmentElfProbe = elfProbe;
    environmentElfProbe["candidateSource"] = "environment_path";
    ++caseCount;
    expect(evaluateBinaryArtifactProbes({environmentElfProbe}, BinaryArtifactProfile::Su)
                       .assessment == DetectionAssessment::weakObserved(),
           "binary_environment_path_candidate_cannot_be_strong", failures);

    unlink(symlinkPath.c_str());
    unlink(elfPath.c_str());
    unlink(textPath.c_str());
    rmdir(directoryPath.c_str());

    return {{"caseCount", caseCount}, {"failures", failures}};
}

nlohmann::json runPackageStorageVisibilityFixtures() {
    nlohmann::json failures = nlohmann::json::array();
    int caseCount = 0;
    const StorageProbeOutcome present{StorageProbeState::PRESENT, 0, 7, 8};
    const StorageProbeOutcome missing{StorageProbeState::NOT_FOUND, ENOENT, 0, 0};
    const StorageProbeOutcome denied{StorageProbeState::DENIED, EACCES, 0, 0};
    const StorageProbeOutcome error{StorageProbeState::ERROR, EIO, 0, 0};

    ++caseCount;
    const auto canonical = assessStorageCandidate(true, present, present, present, missing, missing, missing);
    expect(canonical.finding && canonical.telemetry && canonical.ruleId == "canonical_package_data",
           "canonical_success_with_alias_difference_is_finding_and_telemetry", failures);

    ++caseCount;
    const auto unicodeSuccess = assessStorageCandidate(true, missing, missing, missing, present, present, present);
    expect(unicodeSuccess.finding && unicodeSuccess.telemetry && unicodeSuccess.ruleId == "unicode_alias",
           "unicode_success_is_corroborated_finding", failures);

    ++caseCount;
    const auto unicodeDenied = assessStorageCandidate(true, missing, missing, missing, denied, denied, denied);
    expect(unicodeDenied.finding && unicodeDenied.telemetry && unicodeDenied.ruleId == "unicode_alias",
           "repeated_permission_boundary_is_corroborated_finding", failures);

    ++caseCount;
    const auto singleDifference = assessStorageCandidate(true, missing, missing, missing, present, missing, missing);
    expect(!singleDifference.finding && singleDifference.telemetry, "single_syscall_difference_is_telemetry", failures);

    ++caseCount;
    const auto mixedBoundary = assessStorageCandidate(true, missing, missing, missing, present, denied, missing);
    expect(!mixedBoundary.finding && mixedBoundary.telemetry, "mixed_success_and_permission_boundary_is_not_consistent",
           failures);

    ++caseCount;
    const auto caseOnly = assessStorageCandidate(false, missing, missing, missing, present, present, present);
    expect(!caseOnly.finding && caseOnly.telemetry, "casefold_difference_is_telemetry", failures);

    ++caseCount;
    const auto allMissing = assessStorageCandidate(true, missing, missing, missing, missing, missing, missing);
    expect(
        !allMissing.finding && !allMissing.telemetry &&
            assessPackageStorageOverall(StorageProbeState::PRESENT, 2, 0) == PackageStorageOverallState::NOT_OBSERVED,
        "all_enoent_is_not_observed", failures);

    ++caseCount;
    const auto partialFailure = assessStorageCandidate(true, missing, error, missing, present, error, missing);
    expect(!partialFailure.finding && partialFailure.telemetry, "partial_source_failure_does_not_create_finding",
           failures);

    ++caseCount;
    expect(
        assessPackageStorageOverall(StorageProbeState::NOT_FOUND, 0, 0) == PackageStorageOverallState::INCONCLUSIVE &&
            assessPackageStorageOverall(StorageProbeState::DENIED, 0, 0) == PackageStorageOverallState::INCONCLUSIVE,
        "storage_unavailable_is_inconclusive", failures);

    ++caseCount;
    expect(androidUserIdForUid(212345U) == 2 && packageStoragePathForUid(212345U, "obb", "com.example.owner") ==
                                                    "/storage/emulated/2/Android/obb/com.example.owner",
           "uid_derived_user_storage_path", failures);

    ++caseCount;
    std::unordered_set<std::string> findingKeys;
    expect(reservePackageStorageFinding(findingKeys, "com.example.owner", "data", "unicode_alias") &&
               !reservePackageStorageFinding(findingKeys, "com.example.owner", "data", "unicode_alias") &&
               reservePackageStorageFinding(findingKeys, "com.example.owner", "obb", "unicode_alias"),
           "finding_keys_are_deduplicated_per_package_root_rule", failures);

    ++caseCount;
    expect(canRetainPackageStorageObservation(kMaximumPackageStorageObservationRecords - 1) &&
               !canRetainPackageStorageObservation(kMaximumPackageStorageObservationRecords),
           "candidate_observation_cap_is_enforced", failures);

    return {{"caseCount", caseCount}, {"failures", failures}};
}

nlohmann::json runTeeAssessmentFixtures() {
    nlohmann::json failures = nlohmann::json::array();
    int caseCount = 0;

    ++caseCount;
    expect(tee_common::assessAttestation(
                   {.strongFindingCount = 1,
                    .moderateFindingCount = 1,
                    .weakFindingCount = 1,
                    .requiredValidationComplete = false}) ==
                   DetectionAssessment::strongObserved(),
           "tee_attestation_strong_finding", failures);

    ++caseCount;
    expect(tee_common::assessAttestation(
                   {.moderateFindingCount = 1,
                    .weakFindingCount = 2,
                    .requiredValidationComplete = true}) ==
                   DetectionAssessment::moderateObserved(),
           "tee_attestation_moderate_finding", failures);

    ++caseCount;
    expect(tee_common::assessAttestation(
                   {.weakFindingCount = 3,
                    .requiredValidationComplete = true}) ==
                   DetectionAssessment::weakObserved(),
           "tee_attestation_weak_findings_do_not_promote", failures);

    ++caseCount;
    expect(tee_common::assessAttestation({}) ==
                   DetectionAssessment::inconclusive(),
           "tee_attestation_missing_validation_is_inconclusive", failures);

    ++caseCount;
    expect(tee_common::assessAttestation(
                   {.requiredValidationComplete = true}) ==
                   DetectionAssessment::notObserved(),
           "tee_attestation_complete_clean_validation", failures);

    ++caseCount;
    expect(tee_common::assessAttestation(
                   {.strongFindingCount = 1}) ==
                   DetectionAssessment::strongObserved(),
           "tee_attestation_challenge_mismatch", failures);

    ++caseCount;
    expect(tee_common::assessAttestation(
                   {.strongFindingCount = 1}) ==
                   DetectionAssessment::strongObserved(),
           "tee_attestation_chain_signature_invalid", failures);

    ++caseCount;
    expect(tee_common::assessAttestation(
                   {.requiredValidationComplete = true}) ==
                   DetectionAssessment::notObserved(),
           "tee_attestation_official_root_complete", failures);

    ++caseCount;
    expect(tee_common::assessAttestation({}) ==
                   DetectionAssessment::inconclusive(),
           "tee_attestation_unknown_root_inconclusive", failures);

    ++caseCount;
    expect(tee_common::assessAttestation(
                   {.requiredValidationComplete = true}) ==
                   DetectionAssessment::notObserved(),
           "tee_attestation_boot_hash_match", failures);

    ++caseCount;
    expect(tee_common::assessAttestation(
                   {.moderateFindingCount = 1}) ==
                   DetectionAssessment::moderateObserved(),
           "tee_attestation_boot_hash_mismatch", failures);

    ++caseCount;
    expect(tee_common::assessAttestation(
                   {.moderateFindingCount = 1}) ==
                   DetectionAssessment::moderateObserved(),
           "tee_attestation_zero_boot_material", failures);

    ++caseCount;
    expect(!tee_common::isHardwareBackedAttestation(0),
           "tee_attestation_software_security_level", failures);

    ++caseCount;
    expect(tee_common::isHardwareBackedAttestation(1),
           "tee_attestation_tee_security_level", failures);

    ++caseCount;
    expect(tee_common::isHardwareBackedAttestation(2),
           "tee_attestation_strongbox_security_level", failures);

    ++caseCount;
    expect(tee_common::assessOversizedChallenge("accepted") ==
                   DetectionAssessment::strongObserved(),
           "tee_oversized_accepted", failures);

    ++caseCount;
    expect(tee_common::assessOversizedChallenge("rejected") ==
                   DetectionAssessment::notObserved(),
           "tee_oversized_rejected", failures);

    ++caseCount;
    expect(tee_common::assessOversizedChallenge("provider_error") ==
                   DetectionAssessment::inconclusive(),
           "tee_oversized_provider_error", failures);

    ++caseCount;
    expect(tee_common::classifyRevocationStatus("REVOKED") ==
                   tee_common::RevocationStatus::REVOKED,
           "tee_revocation_revoked", failures);

    ++caseCount;
    expect(tee_common::classifyRevocationStatus("SUSPENDED") ==
                   tee_common::RevocationStatus::SUSPENDED,
           "tee_revocation_suspended", failures);

    ++caseCount;
    expect(tee_common::classifyRevocationStatus("NORMAL") ==
                   tee_common::RevocationStatus::NORMAL,
           "tee_revocation_normal", failures);

    ++caseCount;
    expect(tee_common::assessKeystoreConsistency(
                   {.requiredCheckCount = 3,
                    .completedRequiredCheckCount = 3,
                    .requiredContradictionCount = 1}) ==
                   DetectionAssessment::moderateObserved(),
           "tee_consistency_contradiction", failures);

    ++caseCount;
    expect(tee_common::assessKeystoreConsistency(
                   {.requiredCheckCount = 3,
                    .completedRequiredCheckCount = 2,
                    .requiredContradictionCount = 0}) ==
                   DetectionAssessment::inconclusive(),
           "tee_consistency_unavailable", failures);

    ++caseCount;
    expect(tee_common::assessKeystoreConsistency(
                   {.requiredCheckCount = 3,
                    .completedRequiredCheckCount = 3,
                    .requiredContradictionCount = 0}) ==
                   DetectionAssessment::notObserved(),
           "tee_consistency_clean", failures);

    // Attested versus property-claimed boot state.
    const tee_common::BootStateClaim lockedGreen{"green", "1", "locked"};
    const tee_common::BootStateClaim unlockedOrange{"orange", "0", "unlocked"};

    ++caseCount;
    const auto honestLocked =
            tee_common::compareAttestedBootState(true, true, 0, lockedGreen);
    expect(honestLocked.comparable && honestLocked.comparedProperties.size() == 3 &&
                   honestLocked.contradictedProperties.empty(),
           "boot_state_locked_verified_agrees", failures);

    ++caseCount;
    const auto honestUnlocked =
            tee_common::compareAttestedBootState(true, false, 2, unlockedOrange);
    expect(honestUnlocked.comparable && honestUnlocked.contradictedProperties.empty(),
           "boot_state_unlocked_unverified_agrees", failures);

    ++caseCount;
    const auto spoofedProperties =
            tee_common::compareAttestedBootState(true, false, 2, lockedGreen);
    expect(spoofedProperties.comparable &&
                   spoofedProperties.contradictedProperties ==
                           std::vector<std::string>{"ro.boot.verifiedbootstate",
                                                    "ro.boot.flash.locked",
                                                    "ro.boot.vbmeta.device_state"},
           "boot_state_spoofed_properties_contradict_attestation", failures);

    ++caseCount;
    const auto forgedAttestation =
            tee_common::compareAttestedBootState(true, true, 0, unlockedOrange);
    expect(forgedAttestation.contradictedProperties.size() == 3,
           "boot_state_forged_attestation_contradicts_honest_properties", failures);

    ++caseCount;
    const auto untrusted =
            tee_common::compareAttestedBootState(false, false, 2, lockedGreen);
    expect(!untrusted.comparable && untrusted.comparedProperties.empty() &&
                   untrusted.notComparableReason == "attestation_not_trusted",
           "boot_state_untrusted_attestation_is_not_compared", failures);

    ++caseCount;
    const auto missingProperties =
            tee_common::compareAttestedBootState(true, true, 0, {"", "", "vendor-value"});
    expect(!missingProperties.comparable &&
                   missingProperties.notComparableReason == "no_boot_state_property",
           "boot_state_missing_or_unknown_properties_are_not_compared", failures);

    ++caseCount;
    const auto partialClaim =
            tee_common::compareAttestedBootState(true, true, 1, {"YELLOW", "", "locked"});
    expect(partialClaim.comparable && partialClaim.comparedProperties.size() == 2 &&
                   partialClaim.contradictedProperties.empty(),
           "boot_state_self_signed_yellow_agrees_case_insensitively", failures);

    ++caseCount;
    const auto colourOnly =
            tee_common::compareAttestedBootState(true, true, 0, {"yellow", "1", "locked"});
    expect(colourOnly.contradictedProperties ==
                   std::vector<std::string>{"ro.boot.verifiedbootstate"},
           "boot_state_colour_mismatch_alone_contradicts", failures);

    return {{"caseCount", caseCount}, {"failures", failures}};
}

nlohmann::json runKernelIdentityFixtures() {
    using kernel_identity::CoherenceState;
    using kernel_identity::compareReleases;
    nlohmann::json failures = nlohmann::json::array();
    int caseCount = 0;

    // The Pixel 7 shape: SUSFS rewrote newuname after Zygote cached os.version.
    ++caseCount;
    const auto lateSpoof = compareReleases({{"zygote_os_version", "6.1.162+blu-spark"},
                                            {"uname_release",
                                             "6.1.162-android14-11-g2ec90535fa34-ab15810641"},
                                            {"proc_sys_kernel_osrelease", ""},
                                            {"proc_version_release", ""}});
    expect(lateSpoof.state == CoherenceState::DISAGREE &&
                   lateSpoof.distinctReleases.size() == 2 &&
                   lateSpoof.readableSourceIds.size() == 2 &&
                   lateSpoof.unreadableSourceIds.size() == 2,
           "kernel_identity_disagree", failures);

    // A spoof applied before Zygote: every readable source carries the same string.
    ++caseCount;
    const auto earlySpoof = compareReleases({{"zygote_os_version", "6.1.162-stock"},
                                             {"uname_release", "6.1.162-stock\n"},
                                             {"proc_sys_kernel_osrelease", ""},
                                             {"proc_version_release", ""}});
    expect(earlySpoof.state == CoherenceState::AGREE && earlySpoof.distinctReleases.size() == 1,
           "kernel_identity_agree_after_trim", failures);

    ++caseCount;
    const auto single = compareReleases({{"zygote_os_version", ""},
                                         {"uname_release", "6.1.162-stock"},
                                         {"proc_sys_kernel_osrelease", "  "},
                                         {"proc_version_release", ""}});
    expect(single.state == CoherenceState::UNAVAILABLE && single.readableSourceIds.size() == 1,
           "kernel_identity_single_source_unavailable", failures);

    // procfs disagreeing with both Java and syscall views is still a disagreement.
    ++caseCount;
    const auto procfs = compareReleases({{"zygote_os_version", "6.1.162-stock"},
                                         {"uname_release", "6.1.162-stock"},
                                         {"proc_sys_kernel_osrelease", "6.1.162+custom"},
                                         {"proc_version_release", ""}});
    expect(procfs.state == CoherenceState::DISAGREE, "kernel_identity_procfs_disagree", failures);

    ++caseCount;
    expect(kernel_identity::parseProcVersionRelease(
                   "Linux version 6.1.162-android14-11 (build-user@build-host) (clang) #1 SMP") ==
                   "6.1.162-android14-11",
           "kernel_identity_proc_version_parse", failures);

    ++caseCount;
    expect(kernel_identity::parseProcVersionRelease("6.1.162 something else").empty() &&
                   kernel_identity::parseProcVersionRelease("Linux version").empty(),
           "kernel_identity_proc_version_reject", failures);

    ++caseCount;
    expect(kernel_identity::assessKernelCheck({.postureHitCount = 0,
                                               .coherence = CoherenceState::DISAGREE,
                                               .anyPostureSourceReadable = true}) ==
                   DetectionAssessment::moderateObserved(),
           "kernel_check_disagree_observed", failures);

    ++caseCount;
    expect(kernel_identity::assessKernelCheck({.postureHitCount = 0,
                                               .coherence = CoherenceState::AGREE,
                                               .anyPostureSourceReadable = true}) ==
                   DetectionAssessment::notObserved(),
           "kernel_check_agree_not_observed", failures);

    ++caseCount;
    expect(kernel_identity::assessKernelCheck({.postureHitCount = 0,
                                               .coherence = CoherenceState::UNAVAILABLE,
                                               .anyPostureSourceReadable = false}) ==
                   DetectionAssessment::inconclusive(),
           "kernel_check_nothing_read_inconclusive", failures);

    ++caseCount;
    expect(kernel_identity::assessKernelCheck({.postureHitCount = 2,
                                               .coherence = CoherenceState::DISAGREE,
                                               .anyPostureSourceReadable = true}) ==
                   DetectionAssessment::strongObserved(),
           "kernel_check_posture_strong_kept", failures);

    ++caseCount;
    expect(kernel_identity::assessKernelCheck({.postureHitCount = 1,
                                               .coherence = CoherenceState::DISAGREE,
                                               .anyPostureSourceReadable = true}) ==
                   DetectionAssessment::moderateObserved(),
           "kernel_check_mismatch_never_strong_alone", failures);

    return {{"caseCount", caseCount}, {"failures", failures}};
}

}  // namespace
}  // namespace tamperprobe

extern "C" JNIEXPORT jstring JNICALL
Java_io_leemikepop_tamperprobe_lab_lib_TamperProbeInstrumentedTest_runNativeKernelIdentityFixtures(JNIEnv* env,
                                                                                               jobject) {
    const std::string result = tamperprobe::runKernelIdentityFixtures().dump();
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_leemikepop_tamperprobe_lab_lib_TamperProbeInstrumentedTest_runNativeMemoryHookFixtures(JNIEnv* env, jobject,
                                                                                           jstring cacheDirectory) {
    const char* value = env->GetStringUTFChars(cacheDirectory, nullptr);
    const std::string directory = value == nullptr ? std::string() : std::string(value);
    if (value != nullptr) env->ReleaseStringUTFChars(cacheDirectory, value);
    const std::string result = tamperprobe::runFixtures(directory).dump();
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_leemikepop_tamperprobe_lab_lib_TamperProbeInstrumentedTest_runNativePropertyFixtures(JNIEnv* env, jobject) {
    const std::string result = tamperprobe::runPropertyFixtures().dump();
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_leemikepop_tamperprobe_lab_lib_TamperProbeInstrumentedTest_runNativeLsposedSepolicyFixtures(JNIEnv* env, jobject) {
    const std::string result = tamperprobe::runSharedLsposedSepolicyFixtures().dump();
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_leemikepop_tamperprobe_lab_lib_TamperProbeInstrumentedTest_runNativeRootSepolicyFixtures(JNIEnv* env, jobject) {
    const std::string result = tamperprobe::runNativeRootSepolicyFixtures().dump();
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_leemikepop_tamperprobe_lab_lib_TamperProbeInstrumentedTest_runNativeDangerousPackagesFixtures(JNIEnv* env,
                                                                                                  jobject) {
    const std::string result = tamperprobe::runDangerousPackagesFixtures().dump();
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_leemikepop_tamperprobe_lab_lib_TamperProbeInstrumentedTest_runNativeBinaryArtifactFixtures(
    JNIEnv* env, jobject, jstring cacheDirectory) {
    const char* value = env->GetStringUTFChars(cacheDirectory, nullptr);
    const std::string directory = value == nullptr ? std::string() : std::string(value);
    if (value != nullptr) env->ReleaseStringUTFChars(cacheDirectory, value);
    const std::string result = tamperprobe::runBinaryArtifactFixtures(directory).dump();
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_leemikepop_tamperprobe_lab_lib_TamperProbeInstrumentedTest_runNativePackageStorageVisibilityFixtures(JNIEnv* env,
                                                                                                         jobject) {
    const std::string result = tamperprobe::runPackageStorageVisibilityFixtures().dump();
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_leemikepop_tamperprobe_lab_lib_TamperProbeInstrumentedTest_runNativeTeeAssessmentFixtures(
        JNIEnv* env, jobject) {
    const std::string result = tamperprobe::runTeeAssessmentFixtures().dump();
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_io_leemikepop_tamperprobe_lab_lib_PackageStorageVisibilityStatefulInstrumentedTest_runNativeStorageOperation(
    JNIEnv* env, jobject, jstring operationValue, jstring pathValue, jstring sourceValue) {
    const char* operationChars = env->GetStringUTFChars(operationValue, nullptr);
    const char* pathChars = env->GetStringUTFChars(pathValue, nullptr);
    const char* sourceChars = env->GetStringUTFChars(sourceValue, nullptr);
    if (operationChars == nullptr || pathChars == nullptr || sourceChars == nullptr) {
        if (operationChars != nullptr) {
            env->ReleaseStringUTFChars(operationValue, operationChars);
        }
        if (pathChars != nullptr) {
            env->ReleaseStringUTFChars(pathValue, pathChars);
        }
        if (sourceChars != nullptr) {
            env->ReleaseStringUTFChars(sourceValue, sourceChars);
        }
        return EINVAL;
    }

    const std::string operation(operationChars);
    const std::string path(pathChars);
    const std::string source(sourceChars);
    env->ReleaseStringUTFChars(operationValue, operationChars);
    env->ReleaseStringUTFChars(pathValue, pathChars);
    env->ReleaseStringUTFChars(sourceValue, sourceChars);

    errno = 0;
    int result = -1;
    if (operation == "mkdir") {
        result = mkdir(path.c_str(), 0700);
    } else if (operation == "create") {
        const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd >= 0) {
            close(fd);
            result = 0;
        }
    } else if (operation == "rename") {
        result = rename(source.c_str(), path.c_str());
    } else if (operation == "rmdir") {
        result = rmdir(path.c_str());
    } else if (operation == "unlink") {
        result = unlink(path.c_str());
    } else {
        return EINVAL;
    }
    return result == 0 ? 0 : errno;
}
