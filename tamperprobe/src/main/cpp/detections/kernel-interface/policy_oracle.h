#ifndef TAMPERPROBE_POLICY_ORACLE_H
#define TAMPERPROBE_POLICY_ORACLE_H

#include <jni.h>

#include <cstddef>
#include <string>
#include <vector>

#include "../../nlohmann/json.hpp"

namespace tamperprobe {

constexpr std::size_t kMaximumPolicyOracleSnapshotBytes = 64U * 1024U;

struct PolicyOracleView {
    nlohmann::json payload = nlohmann::json::object();
    bool structurallyValid = false;
    bool nativeTrusted = false;
    bool javaControlled = false;
    bool contradiction = false;
    int passedGateCount = 0;
};

nlohmann::json collectPolicyOracleSnapshot(JNIEnv* env, jint applicationUid);

PolicyOracleView evaluatePolicyOracleSnapshot(
    const nlohmann::json& snapshot,
    const std::vector<std::string>& consumerRuleIds);

PolicyOracleView evaluatePolicyOracleSnapshotBytes(
    const std::string& snapshotBytes,
    const std::vector<std::string>& consumerRuleIds);

const nlohmann::json* findPolicyOracleRow(
    const nlohmann::json& rows,
    const std::string& id);

std::string policyOracleNativeDecision(const nlohmann::json& row);
std::string policyOracleJavaDecision(const nlohmann::json& row);

// How the required rules of one consumer answer "not allowed". A trusted negative is a
// stable native-trusted denial of a rule whose target type exists. A concealable negative
// is a rule whose target type the loaded policy does not define: it cannot be allowed, but
// hiding tools manufacture that absence (KernelSU "Hide SELinux modification" turns
// ksu_file absent), so it is published apart and never counted as an answer.
struct PolicyOracleNegatives {
    bool complete = false;  // every required rule is a trusted or a concealable negative
    int trustedCount = 0;
    nlohmann::json concealable = nlohmann::json::array();
};

// Callers must already have required a passing trust tier and no contradiction.
PolicyOracleNegatives collectPolicyOracleNegatives(
    const std::vector<const nlohmann::json*>& requiredRules);
void addPolicyOracleWarning(
    nlohmann::json& payload,
    const std::string& source,
    const std::string& message);

}  // namespace tamperprobe

#endif  // TAMPERPROBE_POLICY_ORACLE_H
