#ifndef TAMPERPROBE_LSPOSED_SEPOLICY_H
#define TAMPERPROBE_LSPOSED_SEPOLICY_H

#include <string>

#include "../../core/detection_result.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {

struct LsposedSepolicyEvaluation {
    DetectionAssessment assessment = DetectionAssessment::inconclusive();
    nlohmann::json payload = nlohmann::json::object();
};

LsposedSepolicyEvaluation assessLsposedPolicySnapshot(const nlohmann::json& snapshot);
LsposedSepolicyEvaluation assessLsposedPolicySnapshotBytes(const std::string& snapshotBytes);

}  // namespace tamperprobe

#endif  // TAMPERPROBE_LSPOSED_SEPOLICY_H
