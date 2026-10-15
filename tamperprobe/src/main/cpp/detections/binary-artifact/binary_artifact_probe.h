#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "../../core/detection_result.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {

enum class BinaryArtifactProfile {
    Su,
    BusyBox,
};

struct BinaryArtifactCandidate {
    std::string path;
    std::string source;
};

struct BinaryArtifactEvaluation {
    DetectionAssessment assessment;
    nlohmann::json payload;
};

nlohmann::json probeBinaryArtifact(const BinaryArtifactCandidate& candidate);

BinaryArtifactEvaluation evaluateBinaryArtifactProbes(
    const std::vector<nlohmann::json>& probes, BinaryArtifactProfile profile);

void appendPathCandidates(std::vector<BinaryArtifactCandidate>& candidates,
                          const std::string& executableName, const std::string& pathValue,
                          std::size_t maxAdditionalCandidates);

void appendEnvironmentPathCandidates(std::vector<BinaryArtifactCandidate>& candidates,
                                     const std::string& executableName,
                                     std::size_t maxAdditionalCandidates = 32);

}  // namespace tamperprobe
