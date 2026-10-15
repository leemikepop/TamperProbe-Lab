#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"
#include "tee_assessment.h"
#include "tee_common.h"

namespace tamperprobe {
namespace {

constexpr const char* kTag = "TEE_KEYSTORE_CONSISTENCY";

class TeeKeystoreConsistencyDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        nlohmann::json payload = {
                {"checks", nlohmann::json::array()},
                {"findings", nlohmann::json::array()},
                {"collectionWarnings", nlohmann::json::array()},
                {"requiredCheckCount", 0},
                {"completedRequiredCheckCount", 0},
                {"requiredContradictionCount", 0}};

        if (scanContext.env == nullptr || scanContext.androidContext == nullptr) {
            payload["collectionError"] = "JNI/Context not initialized";
            return {DetectionAssessment::inconclusive(),
                    payload.dump()};
        }

        const tee_common::CollectorResult collected =
                tee_common::collectKeystoreConsistency(
                        scanContext.env, scanContext.androidContext, kTag);
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

        const std::string collectionState =
                observation.value("collectionState",
                                  std::string("collection_failed"));
        if (collectionState == "collection_failed") {
            payload["collectionError"] =
                    observation.value("errorCategory",
                                      std::string("collection_failed"));
            return {DetectionAssessment::inconclusive(),
                    payload.dump()};
        }
        if (collectionState != "ok") {
            payload["collectionWarnings"].push_back(
                    {{"source", "android_keystore"},
                     {"state", collectionState},
                     {"detail",
                      observation.value("errorCategory",
                                        std::string("provider_error"))}});
            return {DetectionAssessment::inconclusive(),
                    payload.dump()};
        }

        tee_common::KeystoreConsistencyAssessmentInput assessmentInput;
        if (observation.contains("checks") &&
            observation["checks"].is_array()) {
            for (const auto& check : observation["checks"]) {
                if (!check.is_object()) continue;
                payload["checks"].push_back(check);
                const bool required = check.value("required", false);
                const std::string state =
                        check.value("state", std::string("unavailable"));
                const std::string id =
                        check.value("id", std::string("unknown"));
                if (!required) {
                    if (state == "unavailable") {
                        payload["collectionWarnings"].push_back(
                                {{"source", id},
                                 {"state", state},
                                 {"detail", "Optional diagnostic unavailable"}});
                    }
                    continue;
                }
                ++assessmentInput.requiredCheckCount;
                if (state == "passed" || state == "contradiction") {
                    ++assessmentInput.completedRequiredCheckCount;
                }
                if (state == "contradiction") {
                    ++assessmentInput.requiredContradictionCount;
                    payload["findings"].push_back(
                            {{"id", id},
                             {"summary",
                              "Android Keystore required consistency check contradicted"},
                             {"detail",
                              "A public Keystore operation completed with internally "
                              "inconsistent behavior."},
                             {"strength", "MODERATE"}});
                } else if (state == "unavailable") {
                    payload["collectionWarnings"].push_back(
                            {{"source", id},
                             {"state", state},
                             {"detail", "Required consistency check unavailable"}});
                }
            }
        }

        payload["requiredCheckCount"] =
                assessmentInput.requiredCheckCount;
        payload["completedRequiredCheckCount"] =
                assessmentInput.completedRequiredCheckCount;
        payload["requiredContradictionCount"] =
                assessmentInput.requiredContradictionCount;
        return {tee_common::assessKeystoreConsistency(assessmentInput),
                payload.dump()};
    }

    const char* getId() const override { return "TEE_KEYSTORE_CONSISTENCY"; }
};

REGISTER_DETECTION(TeeKeystoreConsistencyDetection);

}  // namespace
}  // namespace tamperprobe
