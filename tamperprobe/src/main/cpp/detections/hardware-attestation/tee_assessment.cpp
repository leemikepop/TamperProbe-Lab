#include "tee_assessment.h"

namespace tamperprobe {
namespace tee_common {

DetectionAssessment assessAttestation(const AttestationAssessmentInput& input) {
    if (input.strongFindingCount > 0) {
        return DetectionAssessment::strongObserved();
    }
    if (input.moderateFindingCount > 0) {
        return DetectionAssessment::moderateObserved();
    }
    if (input.weakFindingCount > 0) {
        return DetectionAssessment::weakObserved();
    }
    return input.requiredValidationComplete
            ? DetectionAssessment::notObserved()
            : DetectionAssessment::inconclusive();
}

DetectionAssessment assessOversizedChallenge(const std::string& state) {
    if (state == "accepted") {
        return DetectionAssessment::strongObserved();
    }
    if (state == "rejected") {
        return DetectionAssessment::notObserved();
    }
    return DetectionAssessment::inconclusive();
}

RevocationStatus classifyRevocationStatus(const std::string& status) {
    if (status == "REVOKED") return RevocationStatus::REVOKED;
    if (status == "SUSPENDED") return RevocationStatus::SUSPENDED;
    return RevocationStatus::NORMAL;
}

bool isHardwareBackedAttestation(int securityLevel) {
    return securityLevel == 1 || securityLevel == 2;
}

DetectionAssessment assessKeystoreConsistency(
        const KeystoreConsistencyAssessmentInput& input) {
    if (input.requiredContradictionCount > 0) {
        return DetectionAssessment::moderateObserved();
    }
    if (input.requiredCheckCount <= 0 ||
        input.completedRequiredCheckCount != input.requiredCheckCount) {
        return DetectionAssessment::inconclusive();
    }
    return DetectionAssessment::notObserved();
}

}  // namespace tee_common
}  // namespace tamperprobe
