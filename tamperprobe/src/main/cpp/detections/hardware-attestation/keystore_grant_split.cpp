#include <string>

#include "../../common/jni_call.hpp"
#include "../../common/log.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {
namespace {

constexpr char kTag[] = "KeystoreGrantSplit";
constexpr const char* kCollectorClass =
        "io/leemikepop/tamperprobe/lab/internal/tee/KeystoreGrantSplitCollector";

nlohmann::json collectorPayload(const DetectionContext& scanContext, std::string& error) {
    try {
        jni::ScopedLocalRef<jstring> encoded(
                scanContext.env,
                jni::CallStaticMethod<jstring>(scanContext.env, kCollectorClass,
                                               "collectGrantSplit",
                                               "(Landroid/content/Context;)Ljava/lang/String;",
                                               scanContext.androidContext));
        if (!encoded.get()) {
            error = "Keystore grant collector returned no data";
            return nlohmann::json();
        }
        nlohmann::json parsed = nlohmann::json::parse(
                jni::JStringToString(scanContext.env, encoded.get()), nullptr, false);
        if (parsed.is_discarded() || !parsed.is_object()) {
            error = "Keystore grant collector returned malformed JSON";
            return nlohmann::json();
        }
        return parsed;
    } catch (const jni::JNIException& failure) {
        LOGE_TAG(kTag, "event=collector_failed error=%s", failure.what());
        error = "Keystore grant collector invocation failed";
        return nlohmann::json();
    }
}

}  // namespace

/**
 * Reads one Keystore key's certificate chain through two lookup paths and compares them.
 *
 * A stored certificate chain is the same bytes to every reader, so a difference between
 * two readings of the same key proves the chain is being produced per lookup rather than
 * returned from storage. The check carries no reference data and no allowlist, which is
 * why it still works against a keybox spoofer serving a chain that verifies to a genuine
 * root: the forgery has to be consistent across every path an application can ask
 * through, and the grant path is one an interception layer has to handle separately.
 *
 * Two disagreements are graded. A length or digest difference is STRONG. A grant path that
 * denies the key exists, after the alias path returned its chain and a non-attested control
 * key's grant read back fine, is MODERATE: it is what TrickyStore produced on a Pixel 7, and
 * it has fewer clean-device measurements behind it than the digest comparison.
 *
 * Deliberately narrower than Duck-Detector's equivalent. Duck also grants to an isolated
 * process, which cannot reach the Keystore service on any device, and falls back to
 * hand-marshalled IKeystoreService parcels, which an SDK linked into a host application
 * must not ship. Only the documented KeyStoreManager path is used here, so the check is
 * unavailable below API 36 and says so rather than reporting a clean device.
 */
class KeystoreGrantSplitDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        nlohmann::json payload = {
                {"available", false},
                {"apiLevel", 0},
                {"grantIssued", false},
                {"grantReadback", "not_run"},
                {"controlReadback", "not_run"},
                {"split", false},
                {"splitKind", "none"},
                {"mismatchIndex", -1},
                {"ownerChain", nlohmann::json::array()},
                {"granteeChain", nlohmann::json::array()},
                {"findings", nlohmann::json::array()},
                {"collectionErrors", nlohmann::json::array()},
        };

        if (scanContext.env == nullptr || scanContext.androidContext == nullptr) {
            payload["collectionErrors"].push_back(
                    {{"source", "jni"}, {"message", "JNI/Context not initialized"}});
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        std::string collectorError;
        const nlohmann::json observation = collectorPayload(scanContext, collectorError);
        if (!collectorError.empty()) {
            payload["collectionErrors"].push_back(
                    {{"source", "keystore"}, {"message", collectorError}});
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        payload["apiLevel"] = observation.value("apiLevel", 0);
        payload["grantIssued"] = observation.value("grantIssued", false);
        payload["grantReadback"] = observation.value("grantReadback", std::string("not_run"));
        payload["controlReadback"] =
                observation.value("controlReadback", std::string("not_run"));
        const bool available = observation.value("available", false);
        payload["available"] = available;

        if (!available) {
            const std::string reason =
                    observation.value("unavailableReason", std::string("unspecified"));
            payload["collectionErrors"].push_back(
                    {{"source", "keystore"}, {"message", reason}});
            LOGI_TAG(kTag, "event=grant_split available=0 reason=%s", reason.c_str());
            // A check that could not run has observed nothing. Reporting NOT_OBSERVED
            // here would turn an absent API into a statement about the device.
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        if (observation.contains("ownerChain")) payload["ownerChain"] = observation["ownerChain"];
        if (observation.contains("granteeChain")) {
            payload["granteeChain"] = observation["granteeChain"];
        }

        const bool split = observation.value("split", false);
        const std::string splitKind =
                observation.value("splitKind", std::string("none"));
        const int mismatchIndex = observation.value("mismatchIndex", -1);
        payload["split"] = split;
        payload["splitKind"] = splitKind;
        payload["mismatchIndex"] = mismatchIndex;

        LOGI_TAG(kTag,
                 "event=grant_split available=1 split=%d kind=%s index=%d ownerLen=%d "
                 "granteeLen=%d control=%s",
                 split ? 1 : 0, splitKind.c_str(), mismatchIndex,
                 static_cast<int>(payload["ownerChain"].size()),
                 static_cast<int>(payload["granteeChain"].size()),
                 payload["controlReadback"].get<std::string>().c_str());

        if (!split) {
            return {DetectionAssessment::notObserved(), payload.dump()};
        }

        if (splitKind == "grant_key_missing") {
            // Graded apart from a digest split, and below it. The collector only reports
            // this state after a non-attested key's grant read back fine in the same uid,
            // which rules out a broken grant channel; what it has not been measured against
            // is more than one clean, locked API 36+ device, so it stays MODERATE.
            payload["findings"].push_back({
                    {"id", "keystore_grant_key_missing"},
                    {"unitId", "keystore-grant.chain-consistency"},
                    {"strength", evidenceStrengthName(EvidenceStrength::MODERATE)},
                    {"splitKind", splitKind},
                    {"mismatchIndex", -1},
                    {"summary",
                     "The alias path returned an attested key's certificate chain, but the "
                     "grant path for the same key reported that no key exists"},
                    {"detail",
                     "A freshly generated attested key returned a certificate chain by alias "
                     "and a grant for it was issued, yet reading the grant back reported no "
                     "key behind it. A key generated without attestation was granted and "
                     "read back normally in the same process, so the grant path works and "
                     "only the attested key is missing from it: its chain was served without "
                     "a stored key behind it."},
            });
            return {DetectionAssessment::moderateObserved(), payload.dump()};
        }

        payload["findings"].push_back({
                {"id", "keystore_grant_chain_split"},
                {"unitId", "keystore-grant.chain-consistency"},
                {"strength", evidenceStrengthName(EvidenceStrength::STRONG)},
                {"splitKind", splitKind},
                {"mismatchIndex", mismatchIndex},
                {"summary",
                 "One Keystore key returned different certificate chains through the alias "
                 "path and the grant path"},
                {"detail",
                 std::string("The same key was read twice, by alias and through a grant "
                             "issued to this application's own uid, and the two chains "
                             "disagree at ") +
                         (mismatchIndex < 0 ? "their length"
                                            : "index " + std::to_string(mismatchIndex)) +
                         " (" + splitKind +
                         "). A stored chain is identical to every reader, so a difference "
                         "means the chain is being produced per lookup rather than returned "
                         "from storage."},
        });
        return {DetectionAssessment{DetectionOutcome::OBSERVED, EvidenceStrength::STRONG},
                payload.dump()};
    }

    const char* getId() const override { return "KEYSTORE_GRANT_SPLIT"; }
};

REGISTER_DETECTION(KeystoreGrantSplitDetection);

}  // namespace tamperprobe
