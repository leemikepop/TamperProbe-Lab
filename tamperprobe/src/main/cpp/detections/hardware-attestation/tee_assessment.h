#ifndef TAMPERPROBE_TEE_ASSESSMENT_H
#define TAMPERPROBE_TEE_ASSESSMENT_H

#include <string>
#include <vector>

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

// The boot state the system properties claim, as read in this process.
struct BootStateClaim {
    std::string verifiedBootState;  // ro.boot.verifiedbootstate
    std::string flashLocked;        // ro.boot.flash.locked
    std::string vbmetaDeviceState;  // ro.boot.vbmeta.device_state
};

struct BootStateCoherence {
    bool comparable = false;
    std::string notComparableReason;
    std::vector<std::string> comparedProperties;
    std::vector<std::string> contradictedProperties;
};

// Compares the hardware-attested RootOfTrust with the boot-state properties. Properties are
// spoofed globally, an attestation per app, so an app the attestation layer does not target
// sees the two disagree. Only a trusted attestation is compared; a property whose value is
// missing or outside its documented set is left out rather than counted as agreeing.
BootStateCoherence compareAttestedBootState(bool attestationTrusted, bool attestedLocked,
                                            int attestedVerifiedBootState,
                                            const BootStateClaim& claim);

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
