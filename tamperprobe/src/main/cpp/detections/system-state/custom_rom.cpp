#include <cstring>
#include <string>

#include "../../common/io_utils.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {

/**
 * Detects custom ROM indicators:
 * - build.tags containing "test-keys" (unsigned builds)
 * - ro.debuggable = 1 (debug mode enabled)
 * - ro.secure = 0 (insecure build)
 * - Custom ROM fingerprints (LineageOS, PixelExperience, etc.)
 *
 * References: customrom skill
 */
class CustomRomDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        nlohmann::json payload;
        payload["findings"] = nlohmann::json::array();
        payload["collectionErrors"] = nlohmann::json::array();
        int hitCount = 0;

        // 1. Check build tags
        std::string buildTags = read_property_value("ro.build.tags");
        payload["buildTags"] = buildTags;
        if (buildTags.find("test-keys") != std::string::npos) {
            hitCount++;
            nlohmann::json f;
            f["check"] = "build.tags";
            f["value"] = buildTags;
            f["detail"] = "Build signed with test-keys (not release-keys)";
            payload["findings"].push_back(f);
        }

        // 2. Check ro.debuggable
        std::string debuggable = read_property_value("ro.debuggable");
        payload["roDebuggable"] = debuggable;
        if (debuggable == "1") {
            hitCount++;
            nlohmann::json f;
            f["check"] = "ro.debuggable";
            f["value"] = debuggable;
            f["detail"] = "Debug mode is enabled";
            payload["findings"].push_back(f);
        }

        // 3. Check ro.secure
        std::string secure = read_property_value("ro.secure");
        payload["roSecure"] = secure;
        if (secure == "0") {
            hitCount++;
            nlohmann::json f;
            f["check"] = "ro.secure";
            f["value"] = secure;
            f["detail"] = "Build is not marked as secure";
            payload["findings"].push_back(f);
        }

        // 4. Check for known custom ROM properties
        static const struct { const char* prop; const char* romName; } romProps[] = {
            {"ro.lineage.build.version", "LineageOS"},
            {"ro.cm.version", "CyanogenMod"},
            {"ro.modversion", "Custom ROM (modversion)"},
            {"ro.pixelexperience.version", "PixelExperience"},
            {"ro.carbon.version", "CarbonROM"},
            {"ro.crdroid.version", "crDroid"},
            {"ro.potato.version", "PotatoProject"},
            {"ro.evolution.version", "Evolution X"},
            {"ro.corvus.version", "Corvus OS"},
        };

        for (const auto& rp : romProps) {
            std::string val = read_property_value(rp.prop);
            if (!val.empty()) {
                hitCount++;
                nlohmann::json f;
                f["check"] = rp.prop;
                f["value"] = val;
                f["detail"] = std::string("Detected ") + rp.romName;
                payload["findings"].push_back(f);
            }
        }

        payload["hitCount"] = hitCount;

        // read_property_value returns an empty string both for a property that is absent and
        // for one this process cannot read, so absence alone proves nothing. These three
        // anchors are present on every Android build, stock or custom; if none of them can be
        // read, the property channel itself is unavailable and a not-found is not an answer.
        const int readableAnchorCount = static_cast<int>(!buildTags.empty()) +
                                        static_cast<int>(!debuggable.empty()) +
                                        static_cast<int>(!secure.empty());
        payload["readableAnchorCount"] = readableAnchorCount;

        DetectionAssessment assessment = DetectionAssessment::notObserved();
        if (hitCount >= 3) assessment = DetectionAssessment::strongObserved();
        else if (hitCount > 0) assessment = DetectionAssessment::weakObserved();
        else if (readableAnchorCount == 0) {
            assessment = DetectionAssessment::inconclusive();
            payload["collectionErrors"].push_back(
                {{"source", "system_properties"},
                 {"message", "None of ro.build.tags, ro.debuggable or ro.secure could be read, "
                             "so no build property was available to evaluate."}});
        }

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "CUSTOM_ROM"; }
};

REGISTER_DETECTION(CustomRomDetection);

}  // namespace tamperprobe
