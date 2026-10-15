#include <dlfcn.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "../../common/log.h"
#include "../../common/proc_maps.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"
#include "elf_integrity.h"
#include "entry_pattern.h"

namespace tamperprobe {
namespace {

constexpr size_t kPrologueBytes = 16;

struct LibraryTarget {
    const char* library;
    std::vector<const char*> expectedBasenames;
    std::vector<const char*> functions;
};

const std::array<LibraryTarget, 2> kLibraryTargets = {{
        {.library = "libc.so",
         .expectedBasenames = {"libc.so"},
         .functions = {"open", "openat", "read", "write", "access", "readlink",
                       "readlinkat", "stat", "mmap", "mprotect", "ioctl"}},
        {.library = "libdl.so",
         .expectedBasenames = {"libdl.so", "linker", "linker64"},
         .functions = {"dlopen", "dlsym", "dlclose"}},
}};

enum class ProbeStatus {
    CLEAN,
    MODIFIED,
    UNAVAILABLE,
};

struct ProbeResult {
    ProbeStatus status = ProbeStatus::UNAVAILABLE;
    std::string reason;
    std::string resolvedPath;
    std::uint64_t backingFileOffset = 0;
    std::string patternArchitecture;
    bool patternSupported = false;
    bool patternAvailable = false;
    bool branchLike = false;
    bool expectedPrologue = false;
    bool trampolineLike = false;
    bool suspiciousJump = false;
    std::string entryBytesHex;
};

const char* statusName(ProbeStatus status) {
    switch (status) {
        case ProbeStatus::CLEAN:
            return "clean";
        case ProbeStatus::MODIFIED:
            return "modified";
        case ProbeStatus::UNAVAILABLE:
            return "unavailable";
    }
    return "unknown";
}

bool pathHasExpectedBasename(const char* path, const std::vector<const char*>& expectedBasenames) {
    for (const char* expectedBasename : expectedBasenames) {
        if (pathHasBasename(path, expectedBasename)) return true;
    }
    return false;
}

ProbeResult makeProbeResult() {
    ProbeResult result;
    const EntryPatternArchitecture architecture = currentEntryPatternArchitecture();
    result.patternArchitecture = entryPatternArchitectureName(architecture);
    result.patternSupported = architecture != EntryPatternArchitecture::UNSUPPORTED;
    return result;
}

std::string hexBytes(const std::array<std::uint8_t, kPrologueBytes>& bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string output;
    output.reserve(bytes.size() * 2);
    for (std::uint8_t value : bytes) {
        output.push_back(kHex[value >> 4]);
        output.push_back(kHex[value & 0x0f]);
    }
    return output;
}

void collectEntryPattern(void* functionAddress, ProbeResult& result) {
    if (!result.patternSupported) return;

    std::array<std::uint8_t, kPrologueBytes> entryBytes{};
    if (!readSelfMemoryRange(reinterpret_cast<std::uintptr_t>(functionAddress), entryBytes.data(),
                             entryBytes.size())) {
        return;
    }
    result.patternAvailable = true;
    result.entryBytesHex = hexBytes(entryBytes);
    const EntryPatternObservation observation = classifyEntryPattern(
            entryBytes.data(), entryBytes.size(), currentEntryPatternArchitecture());
    result.patternSupported = observation.supported;
    result.branchLike = observation.branchLike;
    result.expectedPrologue = observation.expectedPrologue;
    result.trampolineLike = observation.trampolineLike;
    result.suspiciousJump = observation.suspiciousJump;
}

const char* entryPatternName(const ProbeResult& result) {
    if (!result.patternSupported) return "unsupported";
    if (!result.patternAvailable) return "unavailable";
    if (result.trampolineLike) return "trampoline_like";
    if (result.branchLike && !result.expectedPrologue) return "branch_like";
    if (result.expectedPrologue) return "expected_prologue";
    return "ordinary";
}

ProbeResult inspectFunction(void* libraryHandle, const LibraryTarget& target,
                            const char* functionName,
                            const ProcMapsSnapshot& maps) {
    ProbeResult result = makeProbeResult();
    dlerror();
    void* functionAddress = dlsym(libraryHandle, functionName);
    const char* symbolError = dlerror();
    if (symbolError != nullptr || functionAddress == nullptr) {
        result.reason = "symbol_not_resolved";
        return result;
    }
    collectEntryPattern(functionAddress, result);

    Dl_info libraryInfo{};
    if (dladdr(functionAddress, &libraryInfo) == 0 || libraryInfo.dli_fname == nullptr ||
        libraryInfo.dli_fbase == nullptr) {
        result.reason = "backing_library_not_resolved";
        return result;
    }
    result.resolvedPath = libraryInfo.dli_fname;
    if (!pathHasExpectedBasename(libraryInfo.dli_fname, target.expectedBasenames)) {
        result.status = ProbeStatus::MODIFIED;
        result.reason = "resolved_outside_expected_library";
        return result;
    }

    const ByteComparisonResult comparison = compareLoadedAddressWithBackingElf(
            libraryInfo.dli_fname, reinterpret_cast<std::uintptr_t>(libraryInfo.dli_fbase),
            reinterpret_cast<std::uintptr_t>(functionAddress), kPrologueBytes, maps);
    if (comparison.status == ByteComparisonStatus::MATCH) result.status = ProbeStatus::CLEAN;
    if (comparison.status == ByteComparisonStatus::DIFFERENT) result.status = ProbeStatus::MODIFIED;
    result.reason = comparison.reason;
    result.backingFileOffset = comparison.backingFileOffset;
    return result;
}

nlohmann::json checkPayload(const LibraryTarget& target, const char* functionName,
                            const ProbeResult& result) {
    return {{"targetLibrary", target.library},
            {"expectedLibraries", target.expectedBasenames},
            {"function", functionName},
            {"status", statusName(result.status)},
            {"reason", result.reason},
            {"resolvedPath", result.resolvedPath},
            {"backingFileOffset", result.backingFileOffset},
            {"patternArchitecture", result.patternArchitecture},
            {"patternSupported", result.patternSupported},
            {"patternAvailable", result.patternAvailable},
            {"branchLike", result.branchLike},
            {"expectedPrologue", result.expectedPrologue},
            {"trampolineLike", result.trampolineLike},
            {"suspiciousJump", result.suspiciousJump},
            {"entryPattern", entryPatternName(result)},
            {"entryBytesHex", result.entryBytesHex},
            {"patternAssessmentImpact", "diagnostic_only"}};
}

// The entry-pattern unit's own view. Its descriptor names per-function pattern bytes as
// the observed object, so it needs the rows rather than the aggregate counts. The
// integrity view keeps its own copy of these fields because the two units are read
// independently and neither should have to reach into the other's rows.
nlohmann::json patternPayload(const LibraryTarget& target, const char* functionName,
                              const ProbeResult& result) {
    return {{"targetLibrary", target.library},
            {"function", functionName},
            {"patternArchitecture", result.patternArchitecture},
            {"patternSupported", result.patternSupported},
            {"patternAvailable", result.patternAvailable},
            {"branchLike", result.branchLike},
            {"expectedPrologue", result.expectedPrologue},
            {"trampolineLike", result.trampolineLike},
            {"suspiciousJump", result.suspiciousJump},
            {"entryPattern", entryPatternName(result)},
            {"entryBytesHex", result.entryBytesHex},
            {"patternAssessmentImpact", "diagnostic_only"}};
}

DetectionAssessment aggregateAssessment(size_t modifiedEntryCount,
                                        size_t unavailableEntryCount) {
    if (modifiedEntryCount > 0) return DetectionAssessment::moderateObserved();
    if (unavailableEntryCount > 0) return DetectionAssessment::inconclusive();
    return DetectionAssessment::notObserved();
}

}  // namespace

class PrologueScannerDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        (void)scanContext;
        nlohmann::json payload;
        payload["targetLibraries"] = nlohmann::json::array();
        payload["checkedLibraries"] = nlohmann::json::array();
        payload["unavailableLibraries"] = nlohmann::json::array();
        payload["comparisonMethod"] = "resolved_module_and_backing_elf";
        payload["entryPatternPolicy"] = "diagnostic_only";
        payload["entryPatternArchitecture"] =
                entryPatternArchitectureName(currentEntryPatternArchitecture());
        payload["patternObservationCount"] = 0;
        payload["branchLikeFunctionCount"] = 0;
        payload["trampolineFunctionCount"] = 0;
        payload["checks"] = nlohmann::json::array();
        payload["patterns"] = nlohmann::json::array();
        payload["checkedFunctions"] = nlohmann::json::array();
        payload["triggeredFunctions"] = nlohmann::json::array();
        payload["unavailableFunctions"] = nlohmann::json::array();

        const ProcMapsSnapshot maps = readProcMaps();
        for (const LibraryTarget& target : kLibraryTargets) {
            payload["targetLibraries"].push_back(target.library);
        }
        if (!maps.readable || maps.entries.empty()) {
            for (const LibraryTarget& target : kLibraryTargets) {
                payload["unavailableLibraries"].push_back(target.library);
                for (const char* functionName : target.functions) {
                    ProbeResult unavailable = makeProbeResult();
                    unavailable.reason = "process_maps_unavailable";
                    payload["checks"].push_back(
                            checkPayload(target, functionName, unavailable));
                    payload["patterns"].push_back(
                            patternPayload(target, functionName, unavailable));
                    payload["unavailableFunctions"].push_back(functionName);
                }
            }
            LOGW("event=prologue_scan_complete status=unavailable");
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        for (const LibraryTarget& target : kLibraryTargets) {
            void* libraryHandle = dlopen(target.library, RTLD_NOW | RTLD_LOCAL);
            if (libraryHandle == nullptr) {
                payload["unavailableLibraries"].push_back(target.library);
                for (const char* functionName : target.functions) {
                    ProbeResult unavailable = makeProbeResult();
                    unavailable.reason = "library_not_loaded";
                    payload["checks"].push_back(
                            checkPayload(target, functionName, unavailable));
                    payload["patterns"].push_back(
                            patternPayload(target, functionName, unavailable));
                    payload["unavailableFunctions"].push_back(functionName);
                }
                continue;
            }
            payload["checkedLibraries"].push_back(target.library);

            for (const char* functionName : target.functions) {
                const ProbeResult probe = inspectFunction(libraryHandle, target, functionName, maps);
                payload["checks"].push_back(checkPayload(target, functionName, probe));
                payload["patterns"].push_back(patternPayload(target, functionName, probe));
                if (probe.patternAvailable) {
                    payload["patternObservationCount"] =
                            payload["patternObservationCount"].get<size_t>() + 1;
                }
                if (probe.branchLike && !probe.expectedPrologue) {
                    payload["branchLikeFunctionCount"] =
                            payload["branchLikeFunctionCount"].get<size_t>() + 1;
                }
                if (probe.trampolineLike) {
                    payload["trampolineFunctionCount"] =
                            payload["trampolineFunctionCount"].get<size_t>() + 1;
                }
                if (probe.patternAvailable && (probe.branchLike || probe.trampolineLike)) {
                    LOGI("event=prologue_entry_pattern library=%s function=%s pattern=%s impact=diagnostic_only",
                         target.library, functionName, entryPatternName(probe));
                }
                if (probe.status == ProbeStatus::UNAVAILABLE) {
                    payload["unavailableFunctions"].push_back(functionName);
                    LOGW("event=prologue_check library=%s function=%s status=unavailable reason=%s",
                         target.library, functionName, probe.reason.c_str());
                    continue;
                }

                payload["checkedFunctions"].push_back(functionName);
                if (probe.status == ProbeStatus::MODIFIED) {
                    payload["triggeredFunctions"].push_back(functionName);
                    LOGW("event=prologue_check library=%s function=%s status=modified reason=%s path=%s",
                         target.library, functionName, probe.reason.c_str(),
                         probe.resolvedPath.c_str());
                } else {
                    LOGD("event=prologue_check library=%s function=%s status=clean",
                         target.library, functionName);
                }
            }
            dlclose(libraryHandle);
        }

        const size_t checkedCount = payload["checkedFunctions"].size();
        const size_t triggeredCount = payload["triggeredFunctions"].size();
        const size_t unavailableCount = payload["unavailableFunctions"].size();
        LOGI("event=prologue_scan_complete checked=%zu triggered=%zu unavailable=%zu",
             checkedCount, triggeredCount, unavailableCount);

        // entry-pattern observations are research-only and are intentionally excluded here.
        const DetectionAssessment assessment =
                aggregateAssessment(triggeredCount, unavailableCount);
        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "PROLOGUE_SCANNER"; }
};

REGISTER_DETECTION(PrologueScannerDetection);

}  // namespace tamperprobe
