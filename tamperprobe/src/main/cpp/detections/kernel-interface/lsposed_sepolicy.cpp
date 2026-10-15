#include "lsposed_sepolicy.h"

#include <string>
#include <vector>

#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "policy_oracle.h"

namespace tamperprobe {
namespace {

const std::vector<std::string> kLsposedRuleIds = {
    "lsposed_file_read",
    "xposed_data_read",
    "system_server_execmem",
};

// The negative counts describe what a NOT_OBSERVED rests on and stay zero otherwise.
// Concealable negatives are counted apart and never as trusted answers.
void finishOverview(LsposedSepolicyEvaluation& evaluation, const char* state,
                    int passedGateCount, int trustedNegativeCount = 0,
                    int concealableNegativeCount = 0) {
    evaluation.payload["overview"] =
        {{"oracleState", state},
         {"gateCount", 6},
         {"passedGateCount", passedGateCount},
         {"ruleCount", evaluation.payload["rules"].size()},
         {"findingCount", evaluation.payload["findings"].size()},
         {"trustedNegativeCount", trustedNegativeCount},
         {"concealableNegativeCount", concealableNegativeCount}};
}

void addFinding(nlohmann::json& payload, const char* id, const char* ruleId,
                const char* strength, const char* trustTier, const char* summary,
                const char* detail) {
    payload["findings"].push_back(
        {{"id", id},
         {"ruleId", ruleId},
         {"strength", strength},
         {"trustTier", trustTier},
         {"summary", summary},
         {"detail", detail}});
}

bool isAllowedAtTier(const nlohmann::json& rule, const char* tier) {
    if (rule.value("trustedTier", std::string()) != tier) return false;
    return std::string(tier) == "native_trusted"
               ? policyOracleNativeDecision(rule) == "allowed"
               : policyOracleJavaDecision(rule) == "allowed";
}

}  // namespace

LsposedSepolicyEvaluation assessLsposedPolicySnapshot(const nlohmann::json& snapshot) {
    LsposedSepolicyEvaluation evaluation;
    auto view = evaluatePolicyOracleSnapshot(snapshot, kLsposedRuleIds);
    evaluation.payload = std::move(view.payload);
    if (!view.structurallyValid) return evaluation;

    if (view.contradiction) {
        addPolicyOracleWarning(
            evaluation.payload, "policy_contradiction",
            "Available SELinux policy observations contradict one another.");
        finishOverview(evaluation, "inconclusive", view.passedGateCount);
        return evaluation;
    }
    if (!view.nativeTrusted && !view.javaControlled) {
        addPolicyOracleWarning(
            evaluation.payload, "policy_trust",
            "Neither the native-trusted nor Java-controlled policy tier passed.");
        finishOverview(evaluation, "inconclusive", view.passedGateCount);
        return evaluation;
    }

    const auto* lsposed = findPolicyOracleRow(evaluation.payload["rules"],
                                               "lsposed_file_read");
    const auto* xposed = findPolicyOracleRow(evaluation.payload["rules"],
                                              "xposed_data_read");
    if (lsposed == nullptr || xposed == nullptr) {
        addPolicyOracleWarning(evaluation.payload, "rules",
                               "A required LSPosed/Xposed policy rule is missing.");
        finishOverview(evaluation, "inconclusive", view.passedGateCount);
        return evaluation;
    }

    bool moderate = false;
    if (isAllowedAtTier(*lsposed, "native_trusted")) {
        addFinding(
            evaluation.payload, "lsposed_file_read_allowed", "lsposed_file_read",
            "moderate", "native_trusted",
            "LSPosed file read is allowed by SELinux policy",
            "Native validation and controls confirm that untrusted_app can read lsposed_file.");
        moderate = true;
    } else if (isAllowedAtTier(*lsposed, "java_controlled")) {
        addFinding(
            evaluation.payload, "lsposed_file_read_allowed", "lsposed_file_read",
            "weak", "java_controlled",
            "LSPosed file read is allowed by the Java policy oracle",
            "Stable controlled Java queries allow untrusted_app to read lsposed_file; native context validation is unavailable.");
    }

    if (isAllowedAtTier(*xposed, "native_trusted") ||
        isAllowedAtTier(*xposed, "java_controlled")) {
        const std::string tier = xposed->value("trustedTier", std::string("untrusted"));
        addFinding(
            evaluation.payload, "xposed_data_read_allowed", "xposed_data_read", "weak",
            tier.c_str(), "Xposed data read is allowed by SELinux policy",
            "A controlled policy query allows untrusted_app to read xposed_data.");
    }

    if (!evaluation.payload["findings"].empty()) {
        evaluation.assessment = moderate ? DetectionAssessment::moderateObserved()
                                         : DetectionAssessment::weakObserved();
        finishOverview(evaluation, "observed", view.passedGateCount);
        return evaluation;
    }

    const std::vector<const nlohmann::json*> required = {lsposed, xposed};
    // Every required rule must be answered. A Java denial cannot be told from an API failure,
    // so it answers nothing; an absent target type answers only as a concealable negative.
    const auto negatives = collectPolicyOracleNegatives(required);
    if (negatives.complete) {
        evaluation.payload["concealableNegatives"] = negatives.concealable;
        evaluation.assessment = DetectionAssessment::notObserved();
        finishOverview(evaluation, "not_observed", view.passedGateCount,
                       negatives.trustedCount,
                       static_cast<int>(negatives.concealable.size()));
        return evaluation;
    }

    addPolicyOracleWarning(
        evaluation.payload, "policy_rules",
        "A required rule has no answer that supports NOT_OBSERVED: only a native-trusted denial or an absent target type answers one, and a Java denial cannot be told from API failure.");
    finishOverview(evaluation, "inconclusive", view.passedGateCount);
    return evaluation;
}

LsposedSepolicyEvaluation assessLsposedPolicySnapshotBytes(const std::string& snapshotBytes) {
    LsposedSepolicyEvaluation evaluation;
    auto view = evaluatePolicyOracleSnapshotBytes(snapshotBytes, kLsposedRuleIds);
    if (!view.structurallyValid) {
        evaluation.payload = std::move(view.payload);
        return evaluation;
    }
    return assessLsposedPolicySnapshot(nlohmann::json::parse(snapshotBytes));
}

class LSPosedSepolicyDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& context) override {
        const auto evaluation =
            assessLsposedPolicySnapshotBytes(context.policyOracleSnapshot);
        return {evaluation.assessment, evaluation.payload.dump()};
    }

    const char* getId() const override { return "LSPOSED_SEPOLICY"; }
};

REGISTER_DETECTION(LSPosedSepolicyDetection);

}  // namespace tamperprobe
