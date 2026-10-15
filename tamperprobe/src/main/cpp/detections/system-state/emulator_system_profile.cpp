#include <cstring>
#include <string>
#include <vector>

#include "../../common/io_utils.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {
namespace {

const char* strengthName(EvidenceStrength strength) {
    switch (strength) {
        case EvidenceStrength::WEAK: return "weak";
        case EvidenceStrength::MODERATE: return "moderate";
        case EvidenceStrength::STRONG: return "strong";
        case EvidenceStrength::NONE: return "none";
    }
    return "none";
}

struct PropertyRule {
    const char* property;
    enum class MatchType {
        EQUALS,
        CONTAINS,
        NON_EMPTY,
    } matchType;
    const char* expectedValue;
    EvidenceStrength strength;
    const char* summary;
};

// Describes how a rule actually matched. The finding detail said "equals" for every rule,
// including CONTAINS rules such as ro.hardware containing "goldfish" and NON_EMPTY rules
// such as qemu.hw.mainkeys, which misstated the evidence to anyone reading the report.
std::string matchTypeDescription(PropertyRule::MatchType matchType, const char* expectedValue) {
    switch (matchType) {
        case PropertyRule::MatchType::EQUALS:
            return " equals";
        case PropertyRule::MatchType::CONTAINS:
            return std::string(" contains '") + expectedValue + "' in";
        case PropertyRule::MatchType::NON_EMPTY:
            return " is present with value";
    }
    return " matched with value";
}

const PropertyRule kQemuPropertyRules[] = {
    {"ro.kernel.qemu", PropertyRule::MatchType::EQUALS, "1", EvidenceStrength::STRONG, "Kernel QEMU emulator flag is active"},
    {"ro.boot.qemu", PropertyRule::MatchType::EQUALS, "1", EvidenceStrength::STRONG, "Bootloader QEMU flag is active"},
    {"ro.hardware", PropertyRule::MatchType::CONTAINS, "goldfish", EvidenceStrength::STRONG, "Hardware identifies as Goldfish emulator platform"},
    {"ro.hardware", PropertyRule::MatchType::CONTAINS, "ranchu", EvidenceStrength::STRONG, "Hardware identifies as Ranchu emulator platform"},
    {"ro.hardware", PropertyRule::MatchType::CONTAINS, "vbox86", EvidenceStrength::STRONG, "Hardware identifies as VirtualBox emulator platform"},
    {"ro.hardware", PropertyRule::MatchType::CONTAINS, "cheets", EvidenceStrength::STRONG, "Hardware identifies as ChromeOS ARC container"},
    {"ro.product.board", PropertyRule::MatchType::CONTAINS, "goldfish", EvidenceStrength::STRONG, "Product board identifies as Goldfish emulator"},
    {"ro.product.board", PropertyRule::MatchType::CONTAINS, "ranchu", EvidenceStrength::STRONG, "Product board identifies as Ranchu emulator"},
    {"ro.boot.hardware", PropertyRule::MatchType::CONTAINS, "goldfish", EvidenceStrength::STRONG, "Boot hardware identifies as Goldfish emulator"},
    {"ro.boot.hardware", PropertyRule::MatchType::CONTAINS, "ranchu", EvidenceStrength::STRONG, "Boot hardware identifies as Ranchu emulator"},
    {"ro.product.model", PropertyRule::MatchType::CONTAINS, "sdk_gphone", EvidenceStrength::MODERATE, "Product model matches Android Studio Google Phone emulator"},
    {"ro.product.model", PropertyRule::MatchType::CONTAINS, "Android SDK built for x86", EvidenceStrength::MODERATE, "Product model matches Android SDK x86 emulator image"},
    {"ro.product.model", PropertyRule::MatchType::CONTAINS, "Emulator", EvidenceStrength::MODERATE, "Product model explicitly declares emulator"},
    {"ro.product.model", PropertyRule::MatchType::CONTAINS, "google_sdk", EvidenceStrength::MODERATE, "Product model matches Google SDK development image"},
    {"ro.product.device", PropertyRule::MatchType::CONTAINS, "generic", EvidenceStrength::MODERATE, "Product device matches generic emulator target"},
    {"ro.product.name", PropertyRule::MatchType::CONTAINS, "sdk_gphone", EvidenceStrength::MODERATE, "Product name matches sdk_gphone emulator profile"},
    {"ro.hardware.egl", PropertyRule::MatchType::CONTAINS, "emulation", EvidenceStrength::MODERATE, "Hardware EGL driver is configured for emulation"},
    {"ro.hardware.egl", PropertyRule::MatchType::CONTAINS, "swiftshader", EvidenceStrength::MODERATE, "Hardware EGL driver is configured for SwiftShader rasterizer"},
    {"ro.boottime.init.cold_boot_wait", PropertyRule::MatchType::NON_EMPTY, "", EvidenceStrength::MODERATE, "Cold boot wait property specific to emulator initialization is present"},
    {"init.svc.goldfish-logcat", PropertyRule::MatchType::NON_EMPTY, "", EvidenceStrength::MODERATE, "Goldfish logcat emulator service is running"},
    {"init.svc.goldfish-setup", PropertyRule::MatchType::NON_EMPTY, "", EvidenceStrength::MODERATE, "Goldfish setup emulator service is running"},
    {"init.svc.qemu-props", PropertyRule::MatchType::NON_EMPTY, "", EvidenceStrength::MODERATE, "QEMU property bridge service is running"},
    {"qemu.hw.mainkeys", PropertyRule::MatchType::NON_EMPTY, "", EvidenceStrength::MODERATE, "QEMU mainkeys navigation property is present"},
    {"qemu.sf.fake_camera", PropertyRule::MatchType::NON_EMPTY, "", EvidenceStrength::MODERATE, "QEMU fake camera driver property is present"}
};

bool checkFingerprint(const std::string& fp) {
    if (fp.empty()) return false;
    const std::string lower = lowercase_copy(fp);
    if (lower.rfind("google/sdk_gphone", 0) == 0) return true;
    if (lower.rfind("generic", 0) == 0) return true;
    if (lower.rfind("unknown/generic", 0) == 0) return true;
    if (lower.find("vbox86p") != std::string::npos) return true;
    if (lower.find("emulator") != std::string::npos) return true;
    return false;
}

}  // namespace

class EmulatorSystemProfileDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext&) override {
        nlohmann::json payload = {
            {"overview", {
                {"checkedPropertyCount", 0},
                {"matchedPropertyCount", 0},
                {"findingCount", 0},
                {"strongFindingCount", 0},
                {"moderateFindingCount", 0},
                {"weakFindingCount", 0}
            }},
            {"properties", nlohmann::json::array()},
            {"buildFingerprint", ""},
            {"fingerprintMatched", false},
            {"findings", nlohmann::json::array()},
            {"collectionErrors", nlohmann::json::array()}
        };

        int checkedCount = 0;
        int matchedPropCount = 0;
        int strongCount = 0;
        int moderateCount = 0;
        int weakCount = 0;

        for (const auto& rule : kQemuPropertyRules) {
            ++checkedCount;
            const std::string value = read_property_value(rule.property);
            bool matched = false;

            if (!value.empty()) {
                if (rule.matchType == PropertyRule::MatchType::EQUALS) {
                    matched = (value == rule.expectedValue);
                } else if (rule.matchType == PropertyRule::MatchType::CONTAINS) {
                    matched = contains_ignore_case(value, rule.expectedValue);
                } else if (rule.matchType == PropertyRule::MatchType::NON_EMPTY) {
                    matched = (value != "0" && value != "false");
                }
            }

            if (!value.empty()) {
                payload["properties"].push_back({
                    {"property", rule.property},
                    {"value", value},
                    {"matched", matched},
                    {"severity", strengthName(rule.strength)}
                });
            }

            if (matched) {
                ++matchedPropCount;
                if (rule.strength == EvidenceStrength::STRONG) ++strongCount;
                if (rule.strength == EvidenceStrength::MODERATE) ++moderateCount;
                if (rule.strength == EvidenceStrength::WEAK) ++weakCount;

                payload["findings"].push_back({
                    {"id", "qemu_system_property"},
                    {"unitId", "emulator-profile.qemu-properties"},
                    {"property", rule.property},
                    {"value", value},
                    {"strength", strengthName(rule.strength)},
                    {"summary", rule.summary},
                    {"detail", std::string("Property ") + rule.property +
                                   matchTypeDescription(rule.matchType, rule.expectedValue) + " '" +
                                   value + "'"}
                });
            }
        }

        // Check build fingerprint
        const std::string buildFp = read_property_value("ro.build.fingerprint");
        const std::string bootImageFp = read_property_value("ro.bootimage.build.fingerprint");
        const std::string fp = !buildFp.empty() ? buildFp : bootImageFp;
        payload["buildFingerprint"] = fp;

        const bool fpMatched = checkFingerprint(fp);
        payload["fingerprintMatched"] = fpMatched;
        if (fpMatched) {
            ++weakCount;
            payload["findings"].push_back({
                {"id", "emulator_build_fingerprint"},
                {"unitId", "emulator-profile.build-fingerprint"},
                {"property", "ro.build.fingerprint"},
                {"value", fp},
                {"strength", strengthName(EvidenceStrength::WEAK)},
                {"summary", "Build fingerprint matches emulator image profile"},
                {"detail", "Fingerprint '" + fp + "' matches generic emulator pattern"}
            });
        }

        // An empty property read means "absent or unreadable"; the emulator rules are all
        // legitimately absent on real hardware, so absence there is expected. The build
        // fingerprint is the anchor: every Android build has one, so if neither fingerprint
        // property can be read the property channel is unavailable rather than clean.
        const bool fingerprintReadable = !fp.empty();
        if (!fingerprintReadable) {
            payload["collectionErrors"].push_back(
                {{"source", "system_properties"},
                 {"message", "Neither ro.build.fingerprint nor ro.bootimage.build.fingerprint "
                             "could be read, so no build identity was available to evaluate."}});
        }

        const int totalFindings = strongCount + moderateCount + weakCount;
        payload["overview"]["checkedPropertyCount"] = checkedCount;
        payload["overview"]["matchedPropertyCount"] = matchedPropCount;
        payload["overview"]["findingCount"] = totalFindings;
        payload["overview"]["strongFindingCount"] = strongCount;
        payload["overview"]["moderateFindingCount"] = moderateCount;
        payload["overview"]["weakFindingCount"] = weakCount;

        DetectionAssessment assessment = DetectionAssessment::notObserved();
        if (strongCount > 0) {
            assessment = DetectionAssessment::strongObserved();
        } else if (moderateCount > 0) {
            assessment = DetectionAssessment::moderateObserved();
        } else if (weakCount > 0) {
            assessment = DetectionAssessment::weakObserved();
        } else if (!fingerprintReadable) {
            assessment = DetectionAssessment::inconclusive();
        }

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "EMULATOR_SYSTEM_PROFILE"; }
};

REGISTER_DETECTION(EmulatorSystemProfileDetection);

}  // namespace tamperprobe
