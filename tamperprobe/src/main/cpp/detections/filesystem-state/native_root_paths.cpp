#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sstream>
#include <string>
#include <vector>

#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {

/**
 * Detects native-level root management artifacts by probing filesystem paths
 * associated with KernelSU, APatch, Magisk, and other root tools.
 *
 * Uses multi-confirmation approach: stat, lstat and open(O_PATH).
 * A path is only flagged when confirmed by at least 2 independent methods.
 *
 * References: Duck-Detector nativeroot/probes/path_probe.cpp
 */
class NativeRootPathsDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        struct PathRule {
            const char* path;
            const char* label;
            const char* rootTool;  // "ksu", "apatch", "magisk", "other"
        };

        static const PathRule rules[] = {
            // KernelSU
            {"/data/adb/ksud", "KernelSU daemon", "ksu"},
            {"/data/adb/ksu", "KernelSU directory", "ksu"},
            {"/data/adb/ksu/bin", "KernelSU binaries", "ksu"},
            {"/data/adb/ksu/modules", "KernelSU modules", "ksu"},
            // APatch
            {"/data/adb/apd", "APatch daemon", "apatch"},
            {"/data/adb/ap", "APatch directory", "apatch"},
            {"/data/adb/ap/bin", "APatch binaries", "apatch"},
            {"/data/adb/ap/modules", "APatch modules", "apatch"},
            {"/data/adb/apatch", "APatch residue", "apatch"},
            // Magisk
            {"/data/adb", "Shared root-framework data directory", "other"},
            {"/data/adb/modules", "Shared root-framework modules directory", "other"},
            {"/data/adb/magisk", "Magisk directory", "magisk"},
            {"/data/adb/magisk/magiskd", "Magisk daemon", "magisk"},
            {"/sbin/.magisk", "Magisk hidden dir", "magisk"},
            {"/system/bin/magisk", "Magisk system binary", "magisk"},
            {"/system/xbin/magisk", "Magisk xbin binary", "magisk"},
            // Other artifacts
            {"/data/local/stryker", "Stryker residue", "other"},
            {"/data/local/tmp/luckys", "Luckys tmp residue", "other"},
            {"/data/local/tmp/resetprop", "resetprop residue", "other"},
            {"/data/local/tmp/mount_mask", "Mount mask residue", "other"},
            {"/data/local/tmp/mount_mark", "Mount mark residue", "other"},
        };

        nlohmann::json payload;
        payload["findings"] = nlohmann::json::array();
        payload["inaccessiblePaths"] = nlohmann::json::array();
        payload["concealableNotFoundPaths"] = nlohmann::json::array();
        int hitCount = 0;
        int checkedCount = sizeof(rules) / sizeof(rules[0]);
        int completedPathCount = 0;
        int notFoundPathCount = 0;
        int errorPathCount = 0;
        bool ksuFound = false, apatchFound = false, magiskFound = false;

        for (const auto& rule : rules) {
            int confirmations = 0;
            std::string evidence;

            // 1. stat. Its errno is kept because it is the only thing that separates a path
            // that does not exist from a path this process may not look at. Under /data/adb,
            // whose directory an app uid cannot search, the lookup fails before the final
            // component is consulted: EACCES comes back whether or not the artifact exists,
            // so that probe carries no information about it.
            struct stat st{};
            errno = 0;
            const bool statSucceeded = stat(rule.path, &st) == 0;
            const int statErrno = statSucceeded ? 0 : errno;
            if (statSucceeded) {
                confirmations++;
                evidence += "stat";
            }

            // 2. lstat (symlink-aware)
            struct stat lst{};
            if (lstat(rule.path, &lst) == 0) {
                confirmations++;
                if (!evidence.empty()) evidence += ", ";
                evidence += "lstat";
            }

            // 3. open
            int fd = open(rule.path, O_RDONLY | O_PATH);
            if (fd >= 0) {
                close(fd);
                confirmations++;
                if (!evidence.empty()) evidence += ", ";
                evidence += "open";
            }

            // A rule answered the question if the path was seen, or was reachable and
            // absent. A denied lookup did not answer it.
            //
            // Under /data/adb a "not found" is not an answer either. An app uid cannot search
            // /data/adb where it exists, so the genuine reply there is EACCES; an app sees
            // ENOENT only if the directory is absent or hidden. Path-hiding in the kernel
            // (SUSFS sus_path, measured in follow-up experiment E2) returns exactly that
            // ENOENT, and no syscall an app can make tells it apart from a real absence:
            // stat, lstat, access, mkdir, open(O_CREAT | O_EXCL) and symlink all answer as for
            // a name that does not exist. Counting it as completed would let concealment raise
            // the coverage this report claims, so it is recorded separately instead.
            const bool absent = !statSucceeded && (statErrno == ENOENT || statErrno == ENOTDIR);
            if (absent && isUnderDataAdb(rule.path)) {
                payload["concealableNotFoundPaths"].push_back(rule.path);
            } else if (statSucceeded || absent) {
                completedPathCount++;
                if (!statSucceeded) notFoundPathCount++;
            } else if (statErrno == EACCES || statErrno == EPERM) {
                payload["inaccessiblePaths"].push_back(rule.path);
            } else {
                errorPathCount++;
            }

            // Require at least 2 confirmations
            if (confirmations < 2) continue;

            hitCount++;
            if (std::string(rule.rootTool) == "ksu") ksuFound = true;
            else if (std::string(rule.rootTool) == "apatch") apatchFound = true;
            else if (std::string(rule.rootTool) == "magisk") magiskFound = true;

            nlohmann::json finding;
            finding["path"] = rule.path;
            finding["label"] = rule.label;
            finding["rootTool"] = rule.rootTool;
            finding["confirmations"] = confirmations;
            finding["evidence"] = evidence;
            payload["findings"].push_back(finding);
        }

        payload["hitCount"] = hitCount;
        // checkedCount is the number of rules defined and is kept for compatibility. The
        // counts after it are what a consumer needs to weigh a NOT_OBSERVED: how many rules
        // could actually be answered from this process. The key names match the path probe
        // in DANGEROUS_PACKAGES so one reading applies to both.
        payload["checkedCount"] = checkedCount;
        payload["attemptedPathCount"] = checkedCount;
        payload["completedPathCount"] = completedPathCount;
        payload["notFoundPathCount"] = notFoundPathCount;
        payload["errorPathCount"] = errorPathCount;
        payload["concealableNotFoundPathCount"] =
            static_cast<int>(payload["concealableNotFoundPaths"].size());
        payload["ksuFound"] = ksuFound;
        payload["apatchFound"] = apatchFound;
        payload["magiskFound"] = magiskFound;

        // With no rule answerable there is no basis for NOT_OBSERVED.
        const bool nothingEvaluable = completedPathCount == 0 && hitCount == 0;
        DetectionAssessment assessment = nothingEvaluable
                                             ? DetectionAssessment::inconclusive()
                                             : DetectionAssessment::notObserved();
        if (nothingEvaluable) {
            const bool allDenied =
                static_cast<int>(payload["inaccessiblePaths"].size()) == checkedCount;
            payload["collectionErrors"] = nlohmann::json::array();
            payload["collectionErrors"].push_back(
                {{"source", "path_probe"},
                 {"errno", allDenied ? EACCES : 0},
                 {"message", "No probed path could be evaluated from this process."}});
        }
        if (ksuFound || apatchFound || magiskFound) {
            assessment = DetectionAssessment::strongObserved();
        } else if (hitCount > 0) {
            assessment = DetectionAssessment::weakObserved();
        }

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "NATIVE_ROOT_PATHS"; }

   private:
    /** True for /data/adb itself and anything below it, not for names that merely start with it. */
    static bool isUnderDataAdb(const char* path) {
        static const std::string prefix = "/data/adb";
        const std::string candidate(path);
        return candidate.compare(0, prefix.size(), prefix) == 0 &&
               (candidate.size() == prefix.size() || candidate[prefix.size()] == '/');
    }
};

REGISTER_DETECTION(NativeRootPathsDetection);

}  // namespace tamperprobe
