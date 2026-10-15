#include <dlfcn.h>
#include <link.h>

#include <cstdint>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "../../common/io_utils.h"
#include "../../common/proc_maps.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"
#include "memory_linker_visibility.h"

namespace tamperprobe {
bool linkerRangeCoveredByMaps(std::uintptr_t start, std::uintptr_t end,
                              const std::vector<ProcMapEntry>& maps) {
    if (start >= end) return false;
    std::uintptr_t cursor = start;
    for (const ProcMapEntry& entry : maps) {
        if (entry.end <= cursor) continue;
        if (entry.start > cursor) return false;
        if (entry.end > cursor) cursor = entry.end;
        if (cursor >= end) return true;
    }
    return false;
}

namespace {

struct LinkerObject {
    std::string path;
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> loadRanges;
};

struct GotPltTarget {
    const char* symbol;
    std::vector<const char*> expectedLibraries;
};

int collectLinkerObject(dl_phdr_info* info, size_t, void* data) {
    auto* objects = static_cast<std::vector<LinkerObject>*>(data);
    if (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0') return 0;

    LinkerObject object;
    object.path = info->dlpi_name;
    for (ElfW(Half) index = 0; index < info->dlpi_phnum; ++index) {
        const ElfW(Phdr)& header = info->dlpi_phdr[index];
        if (header.p_type != PT_LOAD || header.p_memsz == 0) continue;
        const auto start = static_cast<std::uintptr_t>(info->dlpi_addr + header.p_vaddr);
        const auto end = start + static_cast<std::uintptr_t>(header.p_memsz);
        if (end > start) object.loadRanges.emplace_back(start, end);
    }
    if (!object.loadRanges.empty()) objects->push_back(std::move(object));
    return 0;
}

bool overlapsAnyObject(const ProcMapEntry& entry, const std::vector<LinkerObject>& objects) {
    for (const LinkerObject& object : objects) {
        for (const auto& range : object.loadRanges) {
            if (rangesOverlap(entry.start, entry.end, range.first, range.second)) return true;
        }
    }
    return false;
}

bool isBenignRuntimeExecutable(const std::string& lowered) {
    return lowered.find("jit-cache") != std::string::npos ||
           lowered.find("jit-code-cache") != std::string::npos ||
           lowered.find("jit-zygote") != std::string::npos ||
           lowered.find("dalvik-") != std::string::npos ||
           lowered.find("webview") != std::string::npos ||
           lowered.find("chromium") != std::string::npos ||
           lowered.find("v8-code") != std::string::npos ||
           lowered.find("wasm-code") != std::string::npos;
}

bool isSharedObjectCandidate(const ProcMapEntry& entry) {
    if (!entry.executable || entry.path.empty() || entry.path.front() == '[') return false;
    const std::string lowered = lowercase_copy(entry.path);
    if (isBenignRuntimeExecutable(lowered)) return false;
    const std::string normalized = normalizeDeletedMapPath(entry.path);
    return normalized.find(".so") != std::string::npos ||
           normalized.find(".apk!/lib/") != std::string::npos;
}

std::vector<std::pair<std::uintptr_t, std::uintptr_t>> findExpectedRanges(
        const std::vector<LinkerObject>& objects,
        const std::vector<const char*>& expectedLibraries) {
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> ranges;
    for (const LinkerObject& object : objects) {
        for (const char* expected : expectedLibraries) {
            if (object.path.find(expected) != std::string::npos) {
                for (const auto& range : object.loadRanges) {
                    ranges.push_back(range);
                }
                break;
            }
        }
    }
    return ranges;
}

}  // namespace

class MemoryLinkerVisibilityDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        (void)scanContext;
        nlohmann::json payload;
        payload["linkerOnlyModules"] = nlohmann::json::array();
        payload["mapsOnlyModules"] = nlohmann::json::array();
        payload["gotPltEscapes"] = nlohmann::json::array();
        payload["collectionErrors"] = nlohmann::json::array();

        const ProcMapsSnapshot maps = readProcMaps();
        payload["mapsReadable"] = maps.readable;
        payload["scannedMappings"] = maps.entries.size();
        payload["malformedMapLines"] = maps.malformedLineCount;
        if (!maps.readable || maps.entries.empty()) {
            payload["collectionErrors"].push_back(
                    {{"source", "/proc/self/maps"},
                     {"errno", maps.error},
                     {"message", maps.readable ? "No valid map entries"
                                                : "Unable to read process maps"}});
            payload["linkerObjectCount"] = 0;
            payload["findingCount"] = 0;
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        std::vector<LinkerObject> objects;
        dl_iterate_phdr(collectLinkerObject, &objects);
        payload["linkerObjectCount"] = objects.size();

        for (const LinkerObject& object : objects) {
            bool fullyCovered = true;
            for (const auto& range : object.loadRanges) {
                if (!linkerRangeCoveredByMaps(range.first, range.second, maps.entries)) {
                    fullyCovered = false;
                    break;
                }
            }
            if (!fullyCovered) {
                payload["linkerOnlyModules"].push_back(
                        {{"path", object.path},
                         {"loadRangeCount", object.loadRanges.size()},
                         {"assessmentImpact", "moderate"}});
            }
        }

        std::set<std::string> mapsOnlyPaths;
        for (const ProcMapEntry& entry : maps.entries) {
            if (!isSharedObjectCandidate(entry) || overlapsAnyObject(entry, objects)) continue;
            const std::string path = normalizeDeletedMapPath(entry.path);
            if (mapsOnlyPaths.insert(path).second) {
                payload["mapsOnlyModules"].push_back(
                        {{"path", path}, {"assessmentImpact", "moderate"}});
            }
        }

        const std::vector<GotPltTarget> gotPltTargets = {
                {"open", {"libc.so"}},
                {"openat", {"libc.so"}},
                {"read", {"libc.so"}},
                {"write", {"libc.so"}},
                {"stat", {"libc.so"}},
                {"mprotect", {"libc.so"}},
                {"kill", {"libc.so"}},
                {"dlsym", {"libdl.so", "linker64", "linker"}},
        };

        for (const auto& target : gotPltTargets) {
            void* symPtr = dlsym(RTLD_DEFAULT, target.symbol);
            if (symPtr == nullptr) continue;

            const auto addr = reinterpret_cast<std::uintptr_t>(symPtr);
            const auto expectedRanges = findExpectedRanges(objects, target.expectedLibraries);
            if (expectedRanges.empty()) continue;

            bool inRange = false;
            for (const auto& range : expectedRanges) {
                if (addr >= range.first && addr < range.second) {
                    inRange = true;
                    break;
                }
            }

            if (!inRange) {
                std::string resolvedPath = "[unmapped]";
                for (const ProcMapEntry& entry : maps.entries) {
                    if (addr >= entry.start && addr < entry.end) {
                        resolvedPath = entry.path.empty() ? "[anonymous]" : entry.path;
                        break;
                    }
                }

                payload["gotPltEscapes"].push_back({
                        {"symbol", target.symbol},
                        {"address", addr},
                        {"resolvedPath", resolvedPath},
                        {"expectedLibrary", target.expectedLibraries[0]},
                        {"assessmentImpact", "strong"},
                });
            }
        }

        const size_t gotPltCount = payload["gotPltEscapes"].size();
        const size_t linkerOnlyCount = payload["linkerOnlyModules"].size();
        const size_t mapsOnlyCount = payload["mapsOnlyModules"].size();
        payload["findingCount"] = gotPltCount + linkerOnlyCount + mapsOnlyCount;

        if (objects.empty()) {
            payload["collectionErrors"].push_back(
                    {{"source", "dl_iterate_phdr"},
                     {"errno", 0},
                     {"message", "No public linker objects were enumerated"}});
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        DetectionAssessment assessment = DetectionAssessment::notObserved();
        if (gotPltCount > 0) {
            assessment = DetectionAssessment::strongObserved();
        } else if (linkerOnlyCount > 0 || mapsOnlyCount > 0) {
            assessment = DetectionAssessment::moderateObserved();
        }

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "MEMORY_LINKER_VISIBILITY"; }
};

REGISTER_DETECTION(MemoryLinkerVisibilityDetection);

}  // namespace tamperprobe
