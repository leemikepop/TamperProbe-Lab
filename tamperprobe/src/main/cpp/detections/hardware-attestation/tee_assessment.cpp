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

namespace {

std::string lowercaseAscii(std::string value) {
    for (char& current : value) {
        if (current >= 'A' && current <= 'Z') current = static_cast<char>(current - 'A' + 'a');
    }
    return value;
}

// RootOfTrust VerifiedBootState (KeyMint) to the colour bootloaders publish.
const char* verifiedBootColour(int state) {
    switch (state) {
        case 0: return "green";
        case 1: return "yellow";
        case 2: return "orange";
        case 3: return "red";
        default: return nullptr;
    }
}

}  // namespace

BootStateCoherence compareAttestedBootState(bool attestationTrusted, bool attestedLocked,
                                            int attestedVerifiedBootState,
                                            const BootStateClaim& claim) {
    BootStateCoherence result;
    if (!attestationTrusted) {
        result.notComparableReason = "attestation_not_trusted";
        return result;
    }
    auto compare = [&result](const char* property, bool agrees) {
        result.comparedProperties.emplace_back(property);
        if (!agrees) result.contradictedProperties.emplace_back(property);
    };
    const char* attestedColour = verifiedBootColour(attestedVerifiedBootState);
    const std::string colour = lowercaseAscii(claim.verifiedBootState);
    if (attestedColour != nullptr &&
        (colour == "green" || colour == "yellow" || colour == "orange" || colour == "red")) {
        compare("ro.boot.verifiedbootstate", colour == attestedColour);
    }
    if (claim.flashLocked == "1" || claim.flashLocked == "0") {
        compare("ro.boot.flash.locked", (claim.flashLocked == "1") == attestedLocked);
    }
    const std::string deviceState = lowercaseAscii(claim.vbmetaDeviceState);
    if (deviceState == "locked" || deviceState == "unlocked") {
        compare("ro.boot.vbmeta.device_state", (deviceState == "locked") == attestedLocked);
    }
    if (result.comparedProperties.empty()) {
        result.notComparableReason = "no_boot_state_property";
        return result;
    }
    result.comparable = true;
    return result;
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
