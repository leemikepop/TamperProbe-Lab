#include <unistd.h>

#include <cerrno>
#include <sstream>
#include <vector>

#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {

class RWPathsDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        const char* paths[] = {"/system",     "/system/bin", "/system/sbin", "/system/xbin",
                               "/vendor/bin", "/sbin",       "/etc",         nullptr};

        nlohmann::json payload;
        payload["writablePaths"] = nlohmann::json::array();
        DetectionAssessment assessment = DetectionAssessment::notObserved();
        int attemptedPathCount = 0;
        int completedPathCount = 0;
        int notFoundPathCount = 0;
        int errorPathCount = 0;

        for (const char** path = paths; *path; ++path) {
            ++attemptedPathCount;
            // access(W_OK) answers in two ways: 0 (writable), or EROFS / EACCES / EPERM (the
            // kernel evaluated the path and refused the write). ENOENT means the path is
            // absent and nothing was evaluated; /system/sbin and /sbin do not exist on
            // current Android, so they never answer.
            errno = 0;
            if (access(*path, W_OK) == 0) {
                ++completedPathCount;
                payload["writablePaths"].push_back(*path);
            } else if (errno == EROFS || errno == EACCES || errno == EPERM) {
                ++completedPathCount;
            } else if (errno == ENOENT || errno == ENOTDIR) {
                ++notFoundPathCount;
            } else {
                ++errorPathCount;
            }
        }
        payload["attemptedPathCount"] = attemptedPathCount;
        payload["completedPathCount"] = completedPathCount;
        payload["notFoundPathCount"] = notFoundPathCount;
        payload["errorPathCount"] = errorPathCount;

        if (!payload["writablePaths"].empty()) {
            assessment = DetectionAssessment::strongObserved();
        } else if (completedPathCount == 0) {
            // With no path evaluated there is no basis for NOT_OBSERVED.
            assessment = DetectionAssessment::inconclusive();
            payload["collectionErrors"] = nlohmann::json::array();
            payload["collectionErrors"].push_back(
                {{"source", "access"},
                 {"errno", 0},
                 {"message", "No probed system path could be evaluated from this process."}});
        }

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "RW_PATHS"; }
};

// 自動註冊
REGISTER_DETECTION(RWPathsDetection);

}  // namespace tamperprobe
