#ifndef TAMPERPROBE_NATIVE_ROOT_SEPOLICY_H
#define TAMPERPROBE_NATIVE_ROOT_SEPOLICY_H

#include <string>

#include "../../core/detection_result.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {

struct NativeRootSepolicyEvaluation {
    DetectionAssessment assessment = DetectionAssessment::inconclusive();
    nlohmann::json payload = nlohmann::json::object();
};

NativeRootSepolicyEvaluation assessNativeRootPolicySnapshot(
    const nlohmann::json& snapshot);
NativeRootSepolicyEvaluation assessNativeRootPolicySnapshotBytes(
    const std::string& snapshotBytes);

}  // namespace tamperprobe

#endif  // TAMPERPROBE_NATIVE_ROOT_SEPOLICY_H
