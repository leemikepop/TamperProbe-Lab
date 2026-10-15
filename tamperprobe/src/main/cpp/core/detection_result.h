#ifndef DETECTION_RESULT_H
#define DETECTION_RESULT_H

#include <string>
#include <stdexcept>
#include <utility>

namespace tamperprobe {

enum class DetectionOutcome {
    OBSERVED,
    NOT_OBSERVED,
    INCONCLUSIVE,
    FAILED,
};

enum class EvidenceStrength {
    NONE,
    WEAK,
    MODERATE,
    STRONG,
};

inline const char* detectionOutcomeName(DetectionOutcome outcome) {
    switch (outcome) {
        case DetectionOutcome::OBSERVED: return "OBSERVED";
        case DetectionOutcome::NOT_OBSERVED: return "NOT_OBSERVED";
        case DetectionOutcome::INCONCLUSIVE: return "INCONCLUSIVE";
        case DetectionOutcome::FAILED: return "FAILED";
        default: return "INCONCLUSIVE";
    }
}

inline const char* evidenceStrengthName(EvidenceStrength strength) {
    switch (strength) {
        case EvidenceStrength::NONE: return "NONE";
        case EvidenceStrength::WEAK: return "WEAK";
        case EvidenceStrength::MODERATE: return "MODERATE";
        case EvidenceStrength::STRONG: return "STRONG";
        default: return "NONE";
    }
}

struct DetectionAssessment {
    DetectionOutcome outcome;
    EvidenceStrength strength;

    static DetectionAssessment strongObserved() {
        return {DetectionOutcome::OBSERVED, EvidenceStrength::STRONG};
    }
    static DetectionAssessment weakObserved() {
        return {DetectionOutcome::OBSERVED, EvidenceStrength::WEAK};
    }
    static DetectionAssessment moderateObserved() {
        return {DetectionOutcome::OBSERVED, EvidenceStrength::MODERATE};
    }
    static DetectionAssessment notObserved() {
        return {DetectionOutcome::NOT_OBSERVED, EvidenceStrength::NONE};
    }
    static DetectionAssessment inconclusive() {
        return {DetectionOutcome::INCONCLUSIVE, EvidenceStrength::NONE};
    }
};

inline bool operator==(const DetectionAssessment& left, const DetectionAssessment& right) {
    return left.outcome == right.outcome && left.strength == right.strength;
}

struct DetectionResult {
    DetectionOutcome outcome = DetectionOutcome::INCONCLUSIVE;
    EvidenceStrength evidenceStrength = EvidenceStrength::NONE;
    std::string payload{};

    DetectionResult() = default;
    DetectionResult(DetectionAssessment assessment, std::string payloadValue)
        : outcome(assessment.outcome),
          evidenceStrength(assessment.strength),
          payload(std::move(payloadValue)) {
        const bool valid = outcome == DetectionOutcome::OBSERVED
                               ? evidenceStrength != EvidenceStrength::NONE
                               : (outcome == DetectionOutcome::NOT_OBSERVED ||
                                  outcome == DetectionOutcome::INCONCLUSIVE) &&
                                     evidenceStrength == EvidenceStrength::NONE;
        if (!valid) {
            throw std::invalid_argument("Invalid native detection assessment");
        }
    }
};

}  // namespace tamperprobe

#endif  // DETECTION_RESULT_H
