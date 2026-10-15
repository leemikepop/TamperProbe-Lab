#include "native_root_sepolicy.h"

#include <string>
#include <vector>

#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "policy_oracle.h"

namespace tamperprobe {
namespace {

const std::vector<std::string> kNativeRootRuleIds = {
    "magisk_binder_call",
    "ksu_file_read",
    "adbd_adbroot_binder_call",
    "shell_su_transition",
};

// The negative counts describe what a NOT_OBSERVED rests on and stay zero otherwise.
// Concealable negatives are counted apart and never as trusted answers.
void finishOverview(NativeRootSepolicyEvaluation& evaluation, const char* state,
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

bool isAllowed(const nlohmann::json& rule) {
    const std::string tier = rule.value("trustedTier", std::string());
    if (tier == "native_trusted") return policyOracleNativeDecision(rule) == "allowed";
    if (tier == "java_controlled") return policyOracleJavaDecision(rule) == "allowed";
    return false;
}

void addFinding(nlohmann::json& payload, const nlohmann::json& rule,
                const char* id, const char* summary, const char* detail) {
    payload["findings"].push_back(
        {{"id", id},
         {"ruleId", rule.value("id", std::string())},
         {"strength", "weak"},
         {"trustTier", rule.value("trustedTier", std::string("untrusted"))},
         {"summary", summary},
         {"detail", detail}});
}

nlohmann::json* findMutableRule(nlohmann::json& rows, const char* id) {
    if (!rows.is_array()) return nullptr;
    for (auto& row : rows) {
        if (row.is_object() && row.value("id", std::string()) == id) return &row;
    }
    return nullptr;
}

}  // namespace

NativeRootSepolicyEvaluation assessNativeRootPolicySnapshot(
    const nlohmann::json& snapshot) {
    NativeRootSepolicyEvaluation evaluation;
    auto view = evaluatePolicyOracleSnapshot(snapshot, kNativeRootRuleIds);
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

    auto* magisk = findMutableRule(evaluation.payload["rules"], "magisk_binder_call");
    auto* ksu = findMutableRule(evaluation.payload["rules"], "ksu_file_read");
    auto* adbroot = findMutableRule(
        evaluation.payload["rules"], "adbd_adbroot_binder_call");
    auto* shellSu = findMutableRule(evaluation.payload["rules"], "shell_su_transition");
    if (magisk == nullptr || ksu == nullptr || adbroot == nullptr || shellSu == nullptr) {
        addPolicyOracleWarning(evaluation.payload, "rules",
                               "A required native-root policy rule is missing.");
        finishOverview(evaluation, "inconclusive", view.passedGateCount);
        return evaluation;
    }

    const bool userBuild = evaluation.payload["device"].value(
        "buildType", std::string()) == "user";
    if (!userBuild) (*shellSu)["assessmentImpact"] = "telemetry_only";

    if (isAllowed(*magisk)) {
        addFinding(evaluation.payload, *magisk, "magisk_binder_allowed",
                   "Magisk binder call is allowed by SELinux policy",
                   "A controlled policy query allows untrusted_app to call the magisk binder domain.");
    }
    if (isAllowed(*ksu)) {
        addFinding(evaluation.payload, *ksu, "ksu_file_read_allowed",
                   "KernelSU file read is allowed by SELinux policy",
                   "A controlled policy query allows untrusted_app to read ksu_file.");
    }
    if (isAllowed(*adbroot)) {
        addFinding(evaluation.payload, *adbroot, "adbd_adbroot_binder_allowed",
                   "ADB-root binder call is allowed by SELinux policy",
                   "A controlled policy query allows adbd to call the adbroot binder domain.");
    }
    if (userBuild && isAllowed(*shellSu)) {
        addFinding(evaluation.payload, *shellSu, "shell_su_transition_allowed",
                   "Shell-to-su transition is allowed on a user build",
                   "A controlled policy query allows shell to transition to su on ro.build.type=user.");
    }

    if (!evaluation.payload["findings"].empty()) {
        evaluation.assessment = DetectionAssessment::weakObserved();
        finishOverview(evaluation, "observed", view.passedGateCount);
        return evaluation;
    }

    std::vector<const nlohmann::json*> required = {magisk, ksu, adbroot};
    if (userBuild) required.push_back(shellSu);
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

NativeRootSepolicyEvaluation assessNativeRootPolicySnapshotBytes(
    const std::string& snapshotBytes) {
    auto view = evaluatePolicyOracleSnapshotBytes(snapshotBytes, kNativeRootRuleIds);
    if (!view.structurallyValid) {
        NativeRootSepolicyEvaluation evaluation;
        evaluation.payload = std::move(view.payload);
        return evaluation;
    }
    return assessNativeRootPolicySnapshot(nlohmann::json::parse(snapshotBytes));
}

class NativeRootSepolicyDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& context) override {
        const auto evaluation =
            assessNativeRootPolicySnapshotBytes(context.policyOracleSnapshot);
        return {evaluation.assessment, evaluation.payload.dump()};
    }

    const char* getId() const override { return "NATIVE_ROOT_SEPOLICY"; }
};

REGISTER_DETECTION(NativeRootSepolicyDetection);

}  // namespace tamperprobe
