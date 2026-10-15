#include <dirent.h>
#include <link.h>

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

struct MarkerMatch {
    const char* marker = nullptr;
    const char* attribution = nullptr;
};

MarkerMatch directMarker(const std::string& lowered) {
    const std::initializer_list<MarkerMatch> markers = {
            {"playcurl", "Play Integrity Fix"},
            {"playintegrityfix", "Play Integrity Fix"},
            {"libpif", "Play Integrity Fix"},
            {"trickystore", "TrickyStore"},
            {"shamiko", "Shamiko"},
            {"zygisk_lsposed", "LSPosed"},
            {"magiskhide", "MagiskHide"},
            {"frida", "Frida"},       {"gum-js", "Frida"},
            {"frida-gadget", "Frida"}, {"linjector", "linjector"},
            {"zygisk", "Zygisk"},     {"riru", "Riru"},
            {"lsposed", "LSPosed"},   {"lspd", "LSPosed"},
            {"xposed", "Xposed"},     {"edxp", "EdXposed"},
            {"sandhook", "SandHook"}, {"yahfa", "YAHFA"},
            {"pif", "Play Integrity Fix"},
    };
    for (const MarkerMatch& candidate : markers) {
        if (lowered.find(candidate.marker) != std::string::npos) return candidate;
    }
    return {};
}

bool isGenericRuntimeThread(const std::string& lowered) {
    return lowered == "gmain" || lowered == "gdbus" || lowered == "pool-spawner";
}

bool isExecutableMemfd(const ProcMapEntry& entry) {
    const std::string lowered = lowercase_copy(entry.path);
    return entry.executable && lowered.find("memfd:") != std::string::npos &&
           lowered.find("jit-cache") == std::string::npos &&
           lowered.find("jit-code-cache") == std::string::npos;
}

nlohmann::json observation(const char* channel, const std::string& value,
                           const MarkerMatch& match, const char* classification) {
    nlohmann::json result = {{"channel", channel},
                             {"value", value},
                             {"classification", classification},
                             {"assessmentImpact", std::strcmp(classification, "direct_marker") == 0
                                                          ? "moderate"
                                                          : "telemetry_only"}};
    if (match.marker != nullptr) result["marker"] = match.marker;
    if (match.attribution != nullptr) result["attribution"] = match.attribution;
    return result;
}

void addCollectionError(nlohmann::json& payload, const char* source, int error) {
    payload["collectionErrors"].push_back(
            {{"source", source}, {"errno", error}, {"message", std::strerror(error)}});
}

struct LinkerCollector {
    nlohmann::json* directMarkers;
    std::set<std::string>* dedupe;
    size_t objectCount = 0;
};

int collectLinkerMarkers(dl_phdr_info* info, size_t, void* data) {
    auto* collector = static_cast<LinkerCollector*>(data);
    ++collector->objectCount;
    if (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0') return 0;
    const std::string path = info->dlpi_name;
    const MarkerMatch match = directMarker(lowercase_copy(path));
    if (match.marker != nullptr && collector->dedupe->insert("linker:" + path).second) {
        collector->directMarkers->push_back(
                observation("linker", path, match, "direct_marker"));
    }
    return 0;
}

DetectionAssessment aggregateAssessment(bool hasDirectMarkerSignal,
                                        bool allRequiredChannelsAvailable) {
    if (hasDirectMarkerSignal) return DetectionAssessment::moderateObserved();
    if (!allRequiredChannelsAvailable) return DetectionAssessment::inconclusive();
    return DetectionAssessment::notObserved();
}

}  // namespace

class RuntimeInstrumentationDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        (void)scanContext;
        nlohmann::json payload;
        payload["directMarkers"] = nlohmann::json::array();
        payload["genericAnomalies"] = nlohmann::json::array();
        payload["collectionErrors"] = nlohmann::json::array();
        std::set<std::string> directDedupe;
        std::set<std::string> genericDedupe;

        const ProcMapsSnapshot maps = readProcMaps();
        const bool mapsUsable = maps.readable && !maps.entries.empty();
        payload["mapsReadable"] = mapsUsable;
        payload["scannedMappings"] = maps.entries.size();
        payload["malformedMapLines"] = maps.malformedLineCount;
        if (!mapsUsable) {
            addCollectionError(payload, "/proc/self/maps", maps.error == 0 ? EIO : maps.error);
        }
        for (const ProcMapEntry& entry : maps.entries) {
            const std::string lowered = lowercase_copy(entry.path);
            const MarkerMatch match = directMarker(lowered);
            if (match.marker != nullptr && directDedupe.insert("maps:" + entry.path).second) {
                payload["directMarkers"].push_back(
                        observation("maps", entry.path, match, "direct_marker"));
            } else if (match.marker == nullptr && isExecutableMemfd(entry) &&
                       genericDedupe.insert("maps:" + entry.path).second) {
                payload["genericAnomalies"].push_back(
                        observation("maps", entry.path, {}, "generic_anomaly"));
            }
        }

        int scannedFds = 0;
        DIR* fdDirectory = opendir("/proc/self/fd");
        const bool fdDirectoryReadable = fdDirectory != nullptr;
        payload["fdDirectoryReadable"] = fdDirectoryReadable;
        if (!fdDirectoryReadable) {
            addCollectionError(payload, "/proc/self/fd", errno == 0 ? EIO : errno);
        } else {
            while (dirent* entry = readdir(fdDirectory)) {
                if (entry->d_name[0] == '.') continue;
                ++scannedFds;
                const std::string target =
                        read_link_target((std::string("/proc/self/fd/") + entry->d_name).c_str());
                if (target.empty()) continue;
                const MarkerMatch match = directMarker(lowercase_copy(target));
                if (match.marker != nullptr && directDedupe.insert("fd:" + target).second) {
                    payload["directMarkers"].push_back(
                            observation("fd", target, match, "direct_marker"));
                }
            }
            closedir(fdDirectory);
        }
        payload["scannedFds"] = scannedFds;

        int scannedThreads = 0;
        DIR* taskDirectory = opendir("/proc/self/task");
        const bool taskDirectoryReadable = taskDirectory != nullptr;
        payload["taskDirectoryReadable"] = taskDirectoryReadable;
        if (!taskDirectoryReadable) {
            addCollectionError(payload, "/proc/self/task", errno == 0 ? EIO : errno);
        } else {
            while (dirent* entry = readdir(taskDirectory)) {
                if (!is_numeric_name(entry->d_name, 20)) continue;
                ++scannedThreads;
                const std::string name = trim_copy(read_text_file(
                        (std::string("/proc/self/task/") + entry->d_name + "/comm").c_str(), 256));
                if (name.empty()) continue;
                const std::string lowered = lowercase_copy(name);
                const MarkerMatch match = directMarker(lowered);
                if (match.marker != nullptr && directDedupe.insert("thread:" + name).second) {
                    payload["directMarkers"].push_back(
                            observation("thread", name, match, "direct_marker"));
                } else if (isGenericRuntimeThread(lowered) &&
                           genericDedupe.insert("thread:" + name).second) {
                    payload["genericAnomalies"].push_back(
                            observation("thread", name, {}, "generic_anomaly"));
                }
            }
            closedir(taskDirectory);
        }
        payload["scannedThreads"] = scannedThreads;

        LinkerCollector linker{.directMarkers = &payload["directMarkers"],
                               .dedupe = &directDedupe};
        dl_iterate_phdr(collectLinkerMarkers, &linker);
        payload["linkerObjectCount"] = linker.objectCount;
        if (linker.objectCount == 0) {
            payload["collectionErrors"].push_back(
                    {{"source", "dl_iterate_phdr"},
                     {"errno", 0},
                     {"message", "No public linker objects were enumerated"}});
        }

        payload["directMarkerCount"] = payload["directMarkers"].size();
        payload["genericAnomalyCount"] = payload["genericAnomalies"].size();
        // generic anomalies are research-only and are intentionally excluded here.
        const DetectionAssessment assessment = aggregateAssessment(
            !payload["directMarkers"].empty(),
            mapsUsable && fdDirectoryReadable && taskDirectoryReadable && linker.objectCount > 0);
        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "RUNTIME_INSTRUMENTATION"; }
};

REGISTER_DETECTION(RuntimeInstrumentationDetection);

}  // namespace tamperprobe
