#include <vector>

#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "binary_artifact_probe.h"

namespace tamperprobe {

class SuBinaryDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        std::vector<BinaryArtifactCandidate> candidates = {
            {"/system/app/Superuser.apk", "fixed_path"},
            {"/sbin/su", "fixed_path"},
            {"/system/bin/su", "fixed_path"},
            {"/system/xbin/su", "fixed_path"},
            {"/data/local/xbin/su", "fixed_path"},
            {"/data/local/bin/su", "fixed_path"},
            {"/system/sd/xbin/su", "fixed_path"},
            {"/system/bin/failsafe/su", "fixed_path"},
            {"/data/local/su", "fixed_path"},
            {"/su/bin/su", "fixed_path"},
            // System-partition bin directories on the zygote PATH. Current Magisk exposes su
            // in /product/bin: at ablation cell R0 it was a symlink on Magisk's tmpfs over
            // that directory, resolving to a root-owned 0755 ELF, and graded only WEAK
            // because PATH-derived candidates cannot reach STRONG. Listing these as fixed
            // lets an executable ELF here grade STRONG. appendEnvironmentPathCandidates
            // skips paths already listed, so none of them is probed twice.
            {"/product/bin/su", "fixed_path"},
            {"/system_ext/bin/su", "fixed_path"},
            {"/vendor/bin/su", "fixed_path"},
            {"/odm/bin/su", "fixed_path"},
        };
        appendEnvironmentPathCandidates(candidates, "su");

        std::vector<nlohmann::json> probes;
        probes.reserve(candidates.size());
        for (const auto& candidate : candidates) {
            probes.push_back(probeBinaryArtifact(candidate));
        }

        BinaryArtifactEvaluation evaluation =
            evaluateBinaryArtifactProbes(probes, BinaryArtifactProfile::Su);
        return {evaluation.assessment, evaluation.payload.dump()};
    }

    const char* getId() const override { return "SU_BINARY"; }
};

REGISTER_DETECTION(SuBinaryDetection);

}  // namespace tamperprobe
