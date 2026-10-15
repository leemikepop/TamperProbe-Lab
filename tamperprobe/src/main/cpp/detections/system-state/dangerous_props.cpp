#include <android/api-level.h>

#include <string>

#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"
#include "property_detector_logic.h"
#include "property_observation.h"

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

DetectionAssessment aggregateAssessment(const DangerousPropertiesAssessment& rules) {
    if (rules.strongestFinding == EvidenceStrength::MODERATE) {
        return DetectionAssessment::moderateObserved();
    }
    if (rules.strongestFinding == EvidenceStrength::WEAK) {
        return DetectionAssessment::weakObserved();
    }
    if (rules.availableRuleCount == 0) return DetectionAssessment::inconclusive();
    return DetectionAssessment::notObserved();
}

constexpr const char* kSettingsGlobalSource = "settings_global";
constexpr const char* kAdbEnabledSetting = "adb_enabled";

PropertyObservation unavailableSetting(const char* message) {
    return {kAdbEnabledSetting, kSettingsGlobalSource, PropertyObservationState::UNAVAILABLE, {},
            message, 0};
}

// Settings.Global.ADB_ENABLED is a public, @Readable setting, so an untrusted app reads it
// through its own ContentResolver without a permission. The raw string is kept, rather than
// getInt(), because a value getInt() cannot parse is part of what the rule grades. From
// Android 17 QPR1 the read still succeeds but returns 0 to a third-party app; the caller
// passes the result through applyAdbEnabledPlatformRedaction.
PropertyObservation observeAdbEnabledSetting(const DetectionContext& context) {
    JNIEnv* env = context.env;
    if (env == nullptr || context.androidContext == nullptr) {
        return unavailableSetting("JNI environment or Android context is unavailable");
    }
    jclass contextClass = env->GetObjectClass(context.androidContext);
    jmethodID getContentResolver =
        contextClass == nullptr
            ? nullptr
            : env->GetMethodID(contextClass, "getContentResolver",
                               "()Landroid/content/ContentResolver;");
    if (contextClass != nullptr) env->DeleteLocalRef(contextClass);
    if (getContentResolver == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        return unavailableSetting("Context.getContentResolver is unavailable");
    }
    jobject resolver = env->CallObjectMethod(context.androidContext, getContentResolver);
    if (env->ExceptionCheck() || resolver == nullptr) {
        env->ExceptionClear();
        if (resolver != nullptr) env->DeleteLocalRef(resolver);
        return unavailableSetting("Context.getContentResolver failed");
    }
    jclass globalClass = env->FindClass("android/provider/Settings$Global");
    if (globalClass == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(resolver);
        return unavailableSetting("android.provider.Settings.Global is unavailable");
    }
    jmethodID getString = env->GetStaticMethodID(
        globalClass, "getString",
        "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
    if (getString == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(globalClass);
        env->DeleteLocalRef(resolver);
        return unavailableSetting("Settings.Global.getString is unavailable");
    }
    jstring name = env->NewStringUTF(kAdbEnabledSetting);
    auto* javaValue =
        static_cast<jstring>(env->CallStaticObjectMethod(globalClass, getString, resolver, name));
    const bool raised = env->ExceptionCheck();
    if (raised) env->ExceptionClear();
    if (name != nullptr) env->DeleteLocalRef(name);
    env->DeleteLocalRef(globalClass);
    env->DeleteLocalRef(resolver);
    if (raised) {
        if (javaValue != nullptr) env->DeleteLocalRef(javaValue);
        return unavailableSetting("Settings.Global.getString threw an exception");
    }
    if (javaValue == nullptr) {
        return {kAdbEnabledSetting, kSettingsGlobalSource, PropertyObservationState::MISSING,
                {}, {}, 0};
    }
    const char* characters = env->GetStringUTFChars(javaValue, nullptr);
    if (characters == nullptr) {
        env->ExceptionClear();
        env->DeleteLocalRef(javaValue);
        return unavailableSetting("setting value could not be converted to UTF-8");
    }
    PropertyObservation observation = {kAdbEnabledSetting, kSettingsGlobalSource,
                                       PropertyObservationState::PRESENT, characters, {}, 0};
    env->ReleaseStringUTFChars(javaValue, characters);
    env->DeleteLocalRef(javaValue);
    return observation;
}

std::string adbEnabledRedactionDetail(int apiLevel) {
    const std::string level = apiLevel > 0 ? "API level " + std::to_string(apiLevel)
                                           : "an API level that could not be read";
    return "Settings.Global returned 0 for adb_enabled on " + level +
           ". From Android 17 QPR1 (API 37) the platform returns 0 for this setting to every "
           "third-party app whatever the device holds, so this 0 is not an answer and the "
           "adb_enabled rule was not evaluated.";
}

}  // namespace

class DangerousPropsDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& context) override {
        const auto securityObservations = observeBionicProperties(securityPropertyKeys());
        const auto postureObservations = observeBionicProperties(posturePropertyKeys());
        // android_get_device_api_level() reads ro.build.version.sdk, the property
        // Build.VERSION.SDK_INT is initialised from; -1 when it cannot be read.
        const int apiLevel = android_get_device_api_level();
        const PropertyObservation adbSetting =
            applyAdbEnabledPlatformRedaction(observeAdbEnabledSetting(context), apiLevel);
        DangerousPropertiesAssessment rules = assessDangerousProperties(securityObservations);
        assessAdbEnabledSetting(rules, adbSetting, postureObservations);
        const auto telemetry =
            assessPropertyPostureTelemetry(securityObservations, postureObservations);

        nlohmann::json payload = {
            {"overview", {{"checkedRuleCount", rules.checkedRuleCount},
                          {"availableRuleCount", rules.availableRuleCount},
                          {"findingCount", rules.findings.size()},
                          {"telemetryCount", telemetry.size()},
                          {"weakFindingCount", 0},
                          {"moderateFindingCount", 0}}},
            {"observations", nlohmann::json::array()},
            {"findings", nlohmann::json::array()},
            {"telemetry", nlohmann::json::array()},
            {"collectionErrors", nlohmann::json::array()},
            {"collectionWarnings", nlohmann::json::array()},
        };

        const auto appendObservation = [&](const PropertyObservation& observation) {
            nlohmann::json item = {
                {"property", observation.property},
                {"source", observation.source},
                {"state", propertyObservationStateName(observation.state)},
            };
            if (observation.state == PropertyObservationState::PRESENT) {
                item["value"] = observation.value;
            }
            if (!observation.error.empty()) item["error"] = observation.error;
            if (observation.errorNumber != 0) item["errno"] = observation.errorNumber;
            const bool redacted =
                observation.state == PropertyObservationState::REDACTED_BY_PLATFORM;
            // A redacted read publishes no value: the 0 it returned is the platform's.
            if (redacted) item["apiLevel"] = apiLevel;
            payload["observations"].push_back(std::move(item));

            const char* issueKey = propertyObservationIssueKey(observation.state);
            if (issueKey == nullptr) return;
            nlohmann::json issue = {{"source", observation.source},
                                    {"property", observation.property}};
            if (redacted) {
                issue["state"] = propertyObservationStateName(observation.state);
                issue["apiLevel"] = apiLevel;
                issue["detail"] = adbEnabledRedactionDetail(apiLevel);
            } else {
                issue["errno"] = observation.errorNumber;
                issue["message"] = observation.error;
            }
            payload[issueKey].push_back(std::move(issue));
        };
        for (const auto& observation : securityObservations) appendObservation(observation);
        for (const auto& observation : postureObservations) appendObservation(observation);
        // Not a property: source settings_global marks the Settings.Global read. A failed read
        // (collectionErrors) and a platform-redacted 0 on API 37+ (collectionWarnings) both
        // carry property=adb_enabled, so either routes to environment-posture only.
        appendObservation(adbSetting);

        int weakCount = 0;
        int moderateCount = 0;
        for (const auto& finding : rules.findings) {
            if (finding.strength == EvidenceStrength::WEAK) ++weakCount;
            if (finding.strength == EvidenceStrength::MODERATE) ++moderateCount;
            payload["findings"].push_back(
                {{"id", finding.id},
                 {"property", finding.property},
                 {"actual", finding.actual},
                 {"expected", finding.expected},
                 {"comparison", finding.comparison},
                 {"strength", strengthName(finding.strength)},
                 {"summary", finding.summary},
                 {"detail", finding.detail}});
        }
        payload["overview"]["weakFindingCount"] = weakCount;
        payload["overview"]["moderateFindingCount"] = moderateCount;
        for (const auto& item : telemetry) {
            payload["telemetry"].push_back(
                {{"id", item.id},
                 {"classification", item.classification},
                 {"assessmentImpact", item.assessmentImpact},
                 {"summary", item.summary},
                 {"detail", item.detail},
                 {"properties", item.properties},
                 {"values", item.values}});
        }

        // posture telemetry is research-only and is intentionally excluded here. The
        // adb_enabled_nonstandard finding is part of rules and does count.
        const DetectionAssessment assessment = aggregateAssessment(rules);
        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "DANGEROUS_PROPS"; }
};

REGISTER_DETECTION(DangerousPropsDetection);

}  // namespace tamperprobe
