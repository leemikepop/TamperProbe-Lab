#include <string>

#include "../../common/jni_call.hpp"
#include "../../common/io_utils.h"
#include "../../common/log.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {
namespace {

constexpr char kTag[] = "DrmCredentialCoherence";
constexpr const char* kCollectorClass =
        "io/leemikepop/tamperprobe/lab/internal/drm/DrmCredentialCollector";

// Integer.MAX_VALUE. A Widevine plugin returns this in place of a system ID when it has
// no provisioned identity to report. Duck-Detector keys its own check on the same
// constant; it is a property of the Widevine plugin, not of either tool.
constexpr char kUnprovisionedSystemId[] = "2147483647";

struct PropertyReading {
    std::string status;
    std::string value;
};

PropertyReading readReading(const nlohmann::json& root, const char* field) {
    PropertyReading reading;
    const auto entry = root.find(field);
    if (entry == root.end() || !entry->is_object()) {
        reading.status = "absent";
        return reading;
    }
    reading.status = entry->value("status", std::string("absent"));
    reading.value = entry->value("value", std::string());
    return reading;
}

// What the device says about its own boot state. Every one of these is writable by a
// module, which is the point: they are the claim, not the evidence.
struct BootClaim {
    std::string verifiedBootState;
    std::string flashLocked;
    std::string vbmetaDeviceState;
    bool claimsLocked = false;
    bool claimsUnlocked = false;
};

BootClaim readBootClaim() {
    BootClaim claim;
    claim.verifiedBootState = trim_copy(read_property_value("ro.boot.verifiedbootstate"));
    claim.flashLocked = trim_copy(read_property_value("ro.boot.flash.locked"));
    claim.vbmetaDeviceState = trim_copy(read_property_value("ro.boot.vbmeta.device_state"));

    // "Claims locked" requires agreement, not a single property, so that a device which
    // is honest anywhere is never treated as claiming a locked state.
    claim.claimsLocked = claim.verifiedBootState == "green" && claim.flashLocked == "1" &&
                         (claim.vbmetaDeviceState.empty() || claim.vbmetaDeviceState == "locked");
    claim.claimsUnlocked = claim.verifiedBootState == "orange" || claim.flashLocked == "0" ||
                           claim.vbmetaDeviceState == "unlocked";
    return claim;
}

nlohmann::json collectorPayload(const DetectionContext& scanContext, std::string& error) {
    try {
        jni::ScopedLocalRef<jstring> encoded(
                scanContext.env,
                jni::CallStaticMethod<jstring>(scanContext.env, kCollectorClass,
                                               "collectDrmCredential",
                                               "(Landroid/content/Context;)Ljava/lang/String;",
                                               scanContext.androidContext));
        if (!encoded.get()) {
            error = "DRM collector returned no data";
            return nlohmann::json();
        }
        const std::string json = jni::JStringToString(scanContext.env, encoded.get());
        nlohmann::json parsed = nlohmann::json::parse(json, nullptr, false);
        if (parsed.is_discarded() || !parsed.is_object()) {
            error = "DRM collector returned malformed JSON";
            return nlohmann::json();
        }
        return parsed;
    } catch (const jni::JNIException& failure) {
        LOGE_TAG(kTag, "event=collector_failed error=%s", failure.what());
        error = "DRM collector invocation failed";
        return nlohmann::json();
    }
}

}  // namespace

/**
 * Compares the boot state the device claims against a credential the claim cannot forge.
 *
 * A device that reports a locked bootloader and a verified boot chain has, if it is
 * telling the truth, never had its Widevine L1 provisioning erased. Unlocking destroys
 * that key material, and no userspace module re-provisions it. So a device advertising
 * Widevine L1 while reporting the unprovisioned-system-ID placeholder, on a device
 * claiming to be locked, is stating two things that cannot both be true.
 *
 * The check is deliberately anchored on the contradiction rather than on the placeholder
 * alone. A device that honestly reports an unlocked bootloader is excluded, and so is a
 * device that only ever advertised L3 and therefore has no L1 credential to be missing.
 */
class DrmCredentialCoherenceDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        nlohmann::json payload = {
                {"schemeSupported", false},
                {"securityLevel", "unavailable"},
                {"systemIdState", "unavailable"},
                {"sessionStatus", "not_probed"},
                {"bootClaim", nlohmann::json::object()},
                {"comparable", false},
                {"findings", nlohmann::json::array()},
                {"collectionErrors", nlohmann::json::array()},
        };

        const BootClaim claim = readBootClaim();
        payload["bootClaim"] = {
                {"verifiedBootState", claim.verifiedBootState},
                {"flashLocked", claim.flashLocked},
                {"vbmetaDeviceState", claim.vbmetaDeviceState},
                {"claimsLocked", claim.claimsLocked},
                {"claimsUnlocked", claim.claimsUnlocked},
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
                    {{"source", "media_drm"}, {"message", collectorError}});
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        const bool schemeSupported = observation.value("schemeSupported", false);
        payload["schemeSupported"] = schemeSupported;
        payload["hardwareSecureAllSupported"] =
                observation.value("hardwareSecureAllSupported", false);
        payload["sessionStatus"] =
                observation.value("sessionStatus", std::string("not_probed"));
        bool collectStageFailed = false;
        if (observation.contains("errors") && observation["errors"].is_array()) {
            for (const auto& entry : observation["errors"]) {
                const std::string stage = entry.value("stage", std::string("unknown"));
                if (stage == "collect") collectStageFailed = true;
                payload["collectionErrors"].push_back(
                        {{"source", "media_drm"},
                         {"message",
                          std::string("stage=") + stage +
                                  " type=" + entry.value("type", std::string("unknown"))}});
            }
        }

        // A throw inside the collector's outer try abandons the whole collection: the fields
        // it had not reached yet are simply absent, and the reader below would then default
        // them to false. That produced a clean NOT_OBSERVED carrying an assertion the check
        // never established -- "Widevine is not supported on this device" when the support
        // query itself had thrown, or "device does not advertise Widevine L1" when
        // constructing MediaDrm had thrown. The collector's own comment says an unavailable
        // DRM stack must not be read as a missing credential; this is what enforces it.
        // Errors from readProperty and probeSession carry their own stage names, stay
        // localised to one field, and deliberately do not reach here.
        if (collectStageFailed) {
            payload["comparable"] = false;
            payload["notComparableReason"] =
                    "the DRM collector aborted before it could answer; see collectionErrors";
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        const PropertyReading securityLevel = readReading(observation, "securityLevel");
        const PropertyReading systemId = readReading(observation, "systemId");
        payload["securityLevel"] =
                securityLevel.status == "available" ? securityLevel.value : securityLevel.status;
        payload["drmVersion"] = readReading(observation, "version").value;

        const bool systemIdAvailable = systemId.status == "available";
        const bool systemIdUnprovisioned =
                systemIdAvailable && systemId.value == kUnprovisionedSystemId;
        payload["systemIdState"] = !systemIdAvailable ? systemId.status
                                   : systemIdUnprovisioned ? "unprovisioned_placeholder"
                                                           : "provisioned";
        payload["systemId"] = systemIdAvailable ? systemId.value : std::string();

        const bool advertisesL1 =
                securityLevel.status == "available" && securityLevel.value == "L1";
        // Comparable only when the device both claims to be locked and has an L1
        // credential to be missing. Everything else contributes telemetry and nothing
        // else - an L3 device never had the credential, and an honestly unlocked device
        // is not contradicting itself.
        const bool comparable = schemeSupported && advertisesL1 && claim.claimsLocked &&
                                !claim.claimsUnlocked;
        payload["comparable"] = comparable;
        if (!comparable) {
            payload["notComparableReason"] =
                    !schemeSupported          ? "Widevine is not supported on this device"
                    : !advertisesL1           ? "device does not advertise Widevine L1"
                    : claim.claimsUnlocked    ? "device reports an unlocked bootloader"
                                              : "device does not claim a locked, verified boot state";
        }

        const std::string sessionStatus =
                observation.value("sessionStatus", std::string("not_probed"));
        const bool sessionUnprovisioned = sessionStatus == "not_provisioned";

        LOGI_TAG(kTag,
                 "event=drm_credential comparable=%d level=%s systemId=%s session=%s "
                 "claimsLocked=%d",
                 comparable ? 1 : 0, payload["securityLevel"].get<std::string>().c_str(),
                 payload["systemIdState"].get<std::string>().c_str(), sessionStatus.c_str(),
                 claim.claimsLocked ? 1 : 0);

        if (comparable && systemIdUnprovisioned) {
            // MODERATE and never STRONG. The contradiction is sound as an argument, but
            // no locked, unmodified device has been measured yet, so the rate at which
            // legitimate devices present this way is unknown. Raise the grade only once
            // a clean control exists.
            payload["findings"].push_back({
                    {"id", "locked_claim_without_drm_credential"},
                    {"unitId", "drm-credential.boot-state-coherence"},
                    {"strength", evidenceStrengthName(EvidenceStrength::MODERATE)},
                    {"sessionStatus", sessionStatus},
                    {"corroboratedBySession", sessionUnprovisioned},
                    {"summary",
                     "Device claims a locked, verified boot state while advertising Widevine "
                     "L1 with no provisioned credential"},
                    {"detail",
                     std::string("The device reports verifiedbootstate=") +
                             claim.verifiedBootState + " and flash.locked=" + claim.flashLocked +
                             ", and its Widevine plugin advertises L1, but the plugin reports the "
                             "unprovisioned-system-ID placeholder" +
                             (sessionUnprovisioned ? " and could not open a provisioned session"
                                                   : "") +
                             ". L1 key material is erased when the bootloader is unlocked and "
                             "cannot be restored from userspace, so these two statements cannot "
                             "both be true."},
            });
            return {DetectionAssessment{DetectionOutcome::OBSERVED, EvidenceStrength::MODERATE},
                    payload.dump()};
        }

        return {DetectionAssessment::notObserved(), payload.dump()};
    }

    const char* getId() const override { return "DRM_CREDENTIAL_COHERENCE"; }
};

REGISTER_DETECTION(DrmCredentialCoherenceDetection);

}  // namespace tamperprobe
