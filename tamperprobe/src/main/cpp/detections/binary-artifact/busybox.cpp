#include <vector>

#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "binary_artifact_probe.h"

namespace tamperprobe {

class BusyBoxDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        const std::vector<BinaryArtifactCandidate> candidates = {
            {"/system/bin/busybox", "fixed_path"},
            {"/system/xbin/busybox", "fixed_path"},
            {"/sbin/busybox", "fixed_path"},
            {"/data/local/busybox", "fixed_path"},
            {"/data/local/bin/busybox", "fixed_path"},
            {"/data/local/xbin/busybox", "fixed_path"},
        };

        std::vector<nlohmann::json> probes;
        probes.reserve(candidates.size());
        for (const auto& candidate : candidates) {
            probes.push_back(probeBinaryArtifact(candidate));
        }

        BinaryArtifactEvaluation evaluation =
            evaluateBinaryArtifactProbes(probes, BinaryArtifactProfile::BusyBox);
        return {evaluation.assessment, evaluation.payload.dump()};
    }

    const char* getId() const override { return "BUSYBOX"; }
};

REGISTER_DETECTION(BusyBoxDetection);

}  // namespace tamperprobe
