#ifndef TAMPERPROBE_TEE_ASSESSMENT_H
#define TAMPERPROBE_TEE_ASSESSMENT_H

#include <string>

#include "../../core/detection_result.h"

namespace tamperprobe {
namespace tee_common {

struct AttestationAssessmentInput {
    int strongFindingCount = 0;
    int moderateFindingCount = 0;
    int weakFindingCount = 0;
    bool requiredValidationComplete = false;
};

DetectionAssessment assessAttestation(const AttestationAssessmentInput& input);
DetectionAssessment assessOversizedChallenge(const std::string& state);

enum class RevocationStatus {
    NORMAL,
    REVOKED,
    SUSPENDED,
};

RevocationStatus classifyRevocationStatus(const std::string& status);
bool isHardwareBackedAttestation(int securityLevel);

struct KeystoreConsistencyAssessmentInput {
    int requiredCheckCount = 0;
    int completedRequiredCheckCount = 0;
    int requiredContradictionCount = 0;
};

DetectionAssessment assessKeystoreConsistency(
        const KeystoreConsistencyAssessmentInput& input);

}  // namespace tee_common
}  // namespace tamperprobe

#endif  // TAMPERPROBE_TEE_ASSESSMENT_H
