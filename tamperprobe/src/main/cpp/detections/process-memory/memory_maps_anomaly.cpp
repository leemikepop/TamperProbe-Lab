#include <signal.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
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

bool isBenignRuntimeExecutable(const std::string& lowered) {
    return containsAny(lowered,
                       {"jit-cache", "jit-code-cache", "jit-zygote", "dalvik-", "webview",
                        "chromium", "v8-code", "wasm-code"});
}

bool isAnonymousPath(const std::string& path) {
    return path.empty() || path == "[anon]" || path == "[anonymous]" ||
           path.rfind("[anon:", 0) == 0 || path.rfind("[anon_shmem:", 0) == 0 ||
           path.rfind("/dev/zero", 0) == 0 || path.rfind("/memfd:", 0) == 0;
}

const char* getSignalName(int signum) {
    switch (signum) {
        case SIGTRAP: return "SIGTRAP";
        case SIGSEGV: return "SIGSEGV";
        case SIGILL: return "SIGILL";
        case SIGBUS: return "SIGBUS";
        default: return "UNKNOWN";
    }
}

nlohmann::json finding(const ProcMapEntry& entry, const char* type,
                       const char* assessmentImpact) {
    return {{"type", type},
            {"path", entry.path.empty() ? "[anonymous]" : entry.path},
            {"permissions", entry.permissions},
            {"start", entry.start},
            {"end", entry.end},
            {"assessmentImpact", assessmentImpact}};
}

}  // namespace

class MemoryMapsAnomalyDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        (void)scanContext;
        nlohmann::json payload;
        payload["findings"] = nlohmann::json::array();
        payload["collectionErrors"] = nlohmann::json::array();

        const ProcMapsSnapshot maps = readProcMaps();
        payload["mapsReadable"] = maps.readable;
        payload["scannedMappings"] = maps.entries.size();
        payload["malformedMapLines"] = maps.malformedLineCount;
        if (!maps.readable || maps.entries.empty()) {
            const int error = maps.error == 0 ? EIO : maps.error;
            payload["collectionErrors"].push_back(
                    {{"source", "/proc/self/maps"},
                     {"errno", error},
                     {"message", std::strerror(error)}});
            payload["findingCount"] = 0;
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        std::set<std::string> dedupe;
        bool strongFinding = false;
        bool moderateFinding = false;

        for (const ProcMapEntry& entry : maps.entries) {
            if (!entry.executable) continue;
            const std::string lowered = lowercase_copy(entry.path);
            if (isBenignRuntimeExecutable(lowered)) continue;

            if (entry.writable) {
                const std::string key = std::string("wx:") + std::to_string(entry.start);
                if (dedupe.insert(key).second) {
                    payload["findings"].push_back(finding(entry, "writable_executable", "moderate"));
                    moderateFinding = true;
                }
            }
            if (isAnonymousPath(entry.path)) {
                const std::string key = std::string("anon:") + std::to_string(entry.start);
                if (dedupe.insert(key).second) {
                    payload["findings"].push_back(finding(entry, "anonymous_executable", "weak"));
                }
            }
            if (entry.deleted) {
                const std::string key = std::string("deleted:") + normalizeDeletedMapPath(entry.path);
                if (dedupe.insert(key).second) {
                    payload["findings"].push_back(finding(entry, "deleted_executable", "moderate"));
                    moderateFinding = true;
                }
            }
        }

        // Smaps dirty-page hook detection
        FILE* smapsFile = fopen("/proc/self/smaps", "r");
        const bool smapsReadable = (smapsFile != nullptr);
        if (smapsFile != nullptr) {
            char line[1024];
            std::string currentPath;
            std::string currentPerms;
            std::uintptr_t currentStart = 0;
            std::uintptr_t currentEnd = 0;
            bool currentExec = false;
            bool currentSystem = false;
            size_t privateDirty = 0;
            size_t sharedDirty = 0;

            auto finalizeRegion = [&]() {
                if (currentExec && currentSystem && (privateDirty > 8 || (privateDirty + sharedDirty) > 8)) {
                    const std::string key = std::string("smaps_dirty:") + currentPath + ":" + std::to_string(currentStart);
                    if (dedupe.insert(key).second) {
                        // Collected as context only. The 8 KB / 32 KB thresholds are
                        // uncalibrated constants adapted from Duck-Detector, and
                        // relocation plus copy-on-write on prelinked system libraries
                        // dirties executable pages on ordinary devices. Promote this to
                        // an assessment-bearing signal only after a clean-device
                        // baseline establishes a defensible threshold.
                        payload["findings"].push_back({
                                {"type", "smaps_dirty_page"},
                                {"path", currentPath},
                                {"permissions", currentPerms},
                                {"start", currentStart},
                                {"end", currentEnd},
                                {"privateDirtyKB", privateDirty},
                                {"sharedDirtyKB", sharedDirty},
                                {"assessmentImpact", "telemetry_only"},
                        });
                    }
                }
                privateDirty = 0;
                sharedDirty = 0;
            };

            while (fgets(line, sizeof(line), smapsFile)) {
                if (strchr(line, '-') && !strchr(line, ':') && strstr(line, " ")) {
                    finalizeRegion();
                    currentPath.clear();
                    currentPerms.clear();
                    currentStart = 0;
                    currentEnd = 0;
                    currentExec = false;
                    currentSystem = false;

                    unsigned long long startVal = 0, endVal = 0, offsetVal = 0, inodeVal = 0;
                    char permsVal[8] = {};
                    char devVal[32] = {};
                    int pathOffset = 0;
                    int matched = sscanf(line, "%llx-%llx %7s %llx %31s %llu %n",
                                         &startVal, &endVal, permsVal, &offsetVal, devVal, &inodeVal, &pathOffset);
                    if (matched >= 6) {
                        currentStart = static_cast<std::uintptr_t>(startVal);
                        currentEnd = static_cast<std::uintptr_t>(endVal);
                        currentPerms = permsVal;
                        currentExec = (strchr(permsVal, 'x') != nullptr);

                        if (pathOffset > 0 && pathOffset < static_cast<int>(strlen(line))) {
                            char* pathPtr = line + pathOffset;
                            size_t len = strlen(pathPtr);
                            while (len > 0 && (pathPtr[len - 1] == '\n' || pathPtr[len - 1] == '\r' || pathPtr[len - 1] == ' ')) {
                                pathPtr[--len] = '\0';
                            }
                            currentPath = pathPtr;
                            currentSystem = (currentPath.rfind("/system/", 0) == 0 ||
                                             currentPath.rfind("/vendor/", 0) == 0 ||
                                             currentPath.rfind("/apex/", 0) == 0 ||
                                             currentPath.rfind("/product/", 0) == 0);
                        }
                    }
                    continue;
                }

                if (strncmp(line, "Private_Dirty:", 14) == 0) {
                    privateDirty = strtoul(line + 14, nullptr, 10);
                } else if (strncmp(line, "Shared_Dirty:", 13) == 0) {
                    sharedDirty = strtoul(line + 13, nullptr, 10);
                }
            }
            finalizeRegion();
            fclose(smapsFile);
        }

        // Signal handler audit
        const int watchedSignals[] = {SIGTRAP, SIGSEGV, SIGILL, SIGBUS};
        for (int signum : watchedSignals) {
            struct sigaction act{};
            if (sigaction(signum, nullptr, &act) != 0) continue;

            uintptr_t handler = 0;
            if ((act.sa_flags & SA_SIGINFO) != 0) {
                handler = reinterpret_cast<uintptr_t>(act.sa_sigaction);
            } else {
                handler = reinterpret_cast<uintptr_t>(act.sa_handler);
            }

            if (handler == 0 ||
                handler == reinterpret_cast<uintptr_t>(SIG_DFL) ||
                handler == reinterpret_cast<uintptr_t>(SIG_IGN)) {
                continue;
            }

            std::string handlerPath = "[unmapped]";
            std::string handlerPerms = "";
            std::uintptr_t segStart = 0;
            std::uintptr_t segEnd = 0;
            bool foundMap = false;

            for (const ProcMapEntry& entry : maps.entries) {
                if (handler >= entry.start && handler < entry.end) {
                    handlerPath = entry.path.empty() ? "[anonymous]" : entry.path;
                    handlerPerms = entry.permissions;
                    segStart = entry.start;
                    segEnd = entry.end;
                    foundMap = true;
                    break;
                }
            }

            const std::string loweredPath = lowercase_copy(handlerPath);
            bool isAnon = !foundMap || isAnonymousPath(handlerPath);
            bool isSuspiciousPath = (loweredPath.find("frida") != std::string::npos ||
                                     loweredPath.find("gum-js") != std::string::npos ||
                                     loweredPath.find("gadget") != std::string::npos ||
                                     loweredPath.find("linjector") != std::string::npos ||
                                     loweredPath.find("sandhook") != std::string::npos ||
                                     loweredPath.find("xposed") != std::string::npos);

            if (isAnon || isSuspiciousPath) {
                const std::string key = std::string("sig:") + std::to_string(signum) + ":" + std::to_string(handler);
                if (dedupe.insert(key).second) {
                    const char* impact = isSuspiciousPath ? "strong" : "moderate";
                    if (isSuspiciousPath) {
                        strongFinding = true;
                    } else {
                        moderateFinding = true;
                    }
                    payload["findings"].push_back({
                            {"type", "suspicious_signal_handler"},
                            {"path", handlerPath},
                            {"permissions", handlerPerms},
                            {"start", segStart},
                            {"end", segEnd},
                            {"signum", signum},
                            {"signalName", getSignalName(signum)},
                            {"handlerAddress", handler},
                            {"assessmentImpact", impact},
                    });
                }
            }
        }

        if (!smapsReadable) {
            payload["collectionErrors"].push_back(
                    {{"source", "smaps"},
                     {"message", "/proc/self/smaps could not be opened; the dirty-page "
                                 "telemetry for this scan is absent, not empty."}});
        }
        payload["smapsReadable"] = smapsReadable;

        payload["findingCount"] = payload["findings"].size();

        // Entries marked telemetry_only are context, not evidence, and must not reach the
        // verdict. The smaps dirty-page entries share this findings array with real signals,
        // and the WEAK fallback below used to test the whole array for emptiness -- so an
        // ordinary device whose prelinked system libraries had been dirtied by relocation or
        // copy-on-write, which the comment beside that block says is normal, produced
        // WEAK OBSERVED. That contradicted this detector's own documentation, its
        // evidence.json inferenceLimit and the domain README, all of which state that the
        // dirty-page block is telemetry and does not affect the assessment.
        int assessmentBearingFindingCount = 0;
        for (const auto& entry : payload["findings"]) {
            if (entry.value("assessmentImpact", std::string()) != "telemetry_only") {
                ++assessmentBearingFindingCount;
            }
        }
        payload["assessmentBearingFindingCount"] = assessmentBearingFindingCount;

        DetectionAssessment assessment = DetectionAssessment::notObserved();
        if (strongFinding) {
            assessment = DetectionAssessment::strongObserved();
        } else if (moderateFinding) {
            assessment = DetectionAssessment::moderateObserved();
        } else if (assessmentBearingFindingCount > 0) {
            assessment = DetectionAssessment::weakObserved();
        }

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "MEMORY_MAPS_ANOMALY"; }
};

REGISTER_DETECTION(MemoryMapsAnomalyDetection);

}  // namespace tamperprobe
