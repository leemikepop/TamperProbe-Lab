#include "../../common/log.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"
#include "tee_assessment.h"
#include "tee_common.h"

namespace tamperprobe {
namespace {

constexpr int kOversizedChallengeBytes = 256;
constexpr const char* kTag = "TEE_OVERSIZED_CHALLENGE";

class TeeOversizedChallengeDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        nlohmann::json payload = {
                {"checked", false},
                {"accepted", false},
                {"state", "not_checked"},
                {"stage", "setup"},
                {"errorCategory", "none"},
                {"numericErrorCode", -1},
                {"aliasCleanupSucceeded", false},
                {"challengeSize", kOversizedChallengeBytes},
                {"findings", nlohmann::json::array()},
                {"collectionWarnings", nlohmann::json::array()}};

        if (scanContext.env == nullptr || scanContext.androidContext == nullptr) {
            payload["collectionError"] = "JNI/Context not initialized";
            return {DetectionAssessment::inconclusive(),
                    payload.dump()};
        }

        const tee_common::CollectorResult collected =
                tee_common::checkOversizedChallenge(
                        scanContext.env, scanContext.androidContext,
                        kOversizedChallengeBytes, kTag);
        if (!collected.invoked) {
            payload["collectionError"] = collected.error;
            return {DetectionAssessment::inconclusive(),
                    payload.dump()};
        }
        const nlohmann::json observation =
                nlohmann::json::parse(collected.json, nullptr, false);
        if (observation.is_discarded() || !observation.is_object()) {
            payload["collectionError"] =
                    "Keystore collector returned malformed JSON";
            return {DetectionAssessment::inconclusive(),
                    payload.dump()};
        }

        const std::string state =
                observation.value("state", std::string("collection_failed"));
        payload["state"] = state;
        payload["stage"] =
                observation.value("stage", std::string("generate"));
        payload["errorCategory"] =
                observation.value("errorCategory", std::string("none"));
        payload["numericErrorCode"] =
                observation.value("numericErrorCode", -1);
        payload["aliasCleanupSucceeded"] =
                observation.value("aliasCleanupSucceeded", false);
        payload["checked"] = state == "accepted" || state == "rejected";
        payload["accepted"] = state == "accepted";

        if (state == "collection_failed") {
            payload["collectionError"] =
                    observation.value("errorCategory",
                                      std::string("collection_failed"));
            return {DetectionAssessment::inconclusive(),
                    payload.dump()};
        }
        if (state == "accepted") {
            payload["findings"].push_back(
                    {{"id", "oversized_challenge_accepted"},
                     {"summary",
                      "Android Keystore accepted an oversized attestation challenge"},
                     {"detail",
                      "A 256-byte challenge exceeded the documented 128-byte limit "
                      "but key generation completed."},
                     {"strength", "STRONG"}});
        } else if (state != "rejected") {
            payload["collectionWarnings"].push_back(
                    {{"source", "android_keystore"},
                     {"state", state},
                     {"detail", payload["errorCategory"]}});
        }
        if (!payload["aliasCleanupSucceeded"].get<bool>()) {
            payload["collectionWarnings"].push_back(
                    {{"source", "keystore_alias"},
                     {"state", "cleanup_failed"},
                     {"detail",
                      "The temporary oversized-challenge alias could not be confirmed absent."}});
        }

        return {tee_common::assessOversizedChallenge(state),
                payload.dump()};
    }

    const char* getId() const override { return "TEE_OVERSIZED_CHALLENGE"; }
};

REGISTER_DETECTION(TeeOversizedChallengeDetection);

}  // namespace
}  // namespace tamperprobe
