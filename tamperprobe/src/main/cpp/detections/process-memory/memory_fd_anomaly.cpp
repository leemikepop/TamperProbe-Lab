#include <dirent.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <initializer_list>
#include <set>
#include <string>

#include "../../common/io_utils.h"
#include "../../common/proc_maps.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {
namespace {

bool containsAny(const std::string& value, std::initializer_list<const char*> markers) {
    for (const char* marker : markers) {
        if (value.find(marker) != std::string::npos) return true;
    }
    return false;
}

bool isMemfd(const std::string& lowered) {
    return lowered.find("memfd:") != std::string::npos;
}

bool isAshmem(const std::string& lowered) {
    return lowered.rfind("/dev/ashmem", 0) == 0;
}

bool isBenignRuntimeArtifact(const std::string& lowered) {
    return containsAny(lowered,
                       {"jit-cache", "jit-code-cache", "jit-zygote", "dalvik-", "webview",
                        "chromium", "v8-code", "wasm-code", "gralloc", "hwui", "skia",
                        "fontmap", "gfxstats", "fresco"});
}

bool hasInstrumentationMarker(const std::string& lowered) {
    return containsAny(lowered,
                       {"frida", "gum-js", "gadget", "linjector", "zygisk", "riru", "lspd",
                        "lsposed", "xposed"});
}

bool hasSuspiciousExecutableSource(const std::string& lowered) {
    return lowered.rfind("/data/adb/", 0) == 0 || lowered.rfind("/data/local/tmp/", 0) == 0;
}

nlohmann::json mapObservation(const ProcMapEntry& entry, const char* type,
                              const char* classification) {
    return {{"type", type},
            {"source", "maps"},
            {"classification", classification},
            {"path", entry.path},
            {"permissions", entry.permissions},
            {"start", entry.start},
            {"end", entry.end}};
}

nlohmann::json fdObservation(const char* fd, const std::string& target,
                             const char* classification) {
    return {{"type", "memfd_handle"},
            {"source", "fd"},
            {"classification", classification},
            {"fd", fd},
            {"target", target}};
}

void addCollectionError(nlohmann::json& payload, const char* source, int error) {
    payload["collectionErrors"].push_back(
            {{"source", source}, {"errno", error}, {"message", std::strerror(error)}});
}

DetectionAssessment aggregateAssessment(bool hasSignal, bool mapsUsable,
                                        bool fdDirectoryReadable) {
    if (hasSignal) return DetectionAssessment::moderateObserved();
    if (!mapsUsable || !fdDirectoryReadable) return DetectionAssessment::inconclusive();
    return DetectionAssessment::notObserved();
}

}  // namespace

class MemoryFdDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        (void)scanContext;
        nlohmann::json payload;
        payload["findings"] = nlohmann::json::array();
        payload["candidates"] = nlohmann::json::array();
        payload["collectionErrors"] = nlohmann::json::array();

        std::set<std::string> findingKeys;
        std::set<std::string> candidateKeys;
        const ProcMapsSnapshot maps = readProcMaps();
        payload["mapsReadable"] = maps.readable;
        payload["scannedMappings"] = maps.entries.size();
        payload["malformedMapLines"] = maps.malformedLineCount;
        if (!maps.readable) {
            addCollectionError(payload, "/proc/self/maps", maps.error == 0 ? EIO : maps.error);
        } else if (maps.entries.empty()) {
            addCollectionError(payload, "/proc/self/maps", EIO);
        }

        for (const ProcMapEntry& entry : maps.entries) {
            if (!entry.executable) continue;
            const std::string lowered = lowercase_copy(entry.path);
            if (isBenignRuntimeArtifact(lowered)) continue;

            if (isMemfd(lowered) || isAshmem(lowered)) {
                const bool marked = hasInstrumentationMarker(lowered);
                const std::string key = std::string("map:") + entry.path;
                auto observation = mapObservation(entry, isMemfd(lowered) ? "executable_memfd"
                                                                          : "executable_ashmem",
                                                  marked ? "direct_marker" : "generic_candidate");
                if (marked && findingKeys.insert(key).second) {
                    payload["findings"].push_back(std::move(observation));
                } else if (!marked && candidateKeys.insert(key).second) {
                    payload["candidates"].push_back(std::move(observation));
                }
            }

            if (entry.deleted) {
                const bool marked = hasInstrumentationMarker(lowered);
                const bool suspiciousSource = hasSuspiciousExecutableSource(lowered);
                const std::string key = std::string("deleted:") + normalizeDeletedMapPath(entry.path);
                auto observation = mapObservation(entry, "deleted_executable",
                                                  marked ? "direct_marker"
                                                         : suspiciousSource ? "suspicious_source"
                                                                            : "generic_candidate");
                if ((marked || suspiciousSource) && findingKeys.insert(key).second) {
                    payload["findings"].push_back(std::move(observation));
                } else if (!marked && !suspiciousSource && candidateKeys.insert(key).second) {
                    payload["candidates"].push_back(std::move(observation));
                }
            }
        }

        int scannedFds = 0;
        DIR* directory = opendir("/proc/self/fd");
        const bool fdDirectoryReadable = directory != nullptr;
        payload["fdDirectoryReadable"] = fdDirectoryReadable;
        if (directory == nullptr) {
            addCollectionError(payload, "/proc/self/fd", errno == 0 ? EIO : errno);
        } else {
            while (dirent* entry = readdir(directory)) {
                if (entry->d_name[0] == '.') continue;
                ++scannedFds;
                const std::string fdPath = std::string("/proc/self/fd/") + entry->d_name;
                const std::string target = read_link_target(fdPath.c_str());
                if (target.empty()) continue;
                const std::string lowered = lowercase_copy(target);
                if (!isMemfd(lowered) || isBenignRuntimeArtifact(lowered)) continue;

                const bool marked = hasInstrumentationMarker(lowered);
                const std::string key = std::string("fd:") + target;
                auto observation = fdObservation(entry->d_name, target,
                                                 marked ? "direct_marker" : "generic_candidate");
                if (marked && findingKeys.insert(key).second) {
                    payload["findings"].push_back(std::move(observation));
                } else if (!marked && candidateKeys.insert(key).second) {
                    payload["candidates"].push_back(std::move(observation));
                }
            }
            closedir(directory);
        }

        payload["scannedFds"] = scannedFds;
        payload["findingCount"] = payload["findings"].size();
        payload["candidateCount"] = payload["candidates"].size();

        // candidates are research records and are intentionally excluded here.
        const DetectionAssessment assessment = aggregateAssessment(
            !payload["findings"].empty(), maps.readable && !maps.entries.empty(),
            fdDirectoryReadable);
        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "MEMORY_FD_ANOMALY"; }
};

REGISTER_DETECTION(MemoryFdDetection);

}  // namespace tamperprobe
