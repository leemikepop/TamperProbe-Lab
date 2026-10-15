#include "property_detector_logic.h"

#include <sys/stat.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <map>
#include <set>
#include <sstream>

namespace tamperprobe {
namespace {

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

const PropertyObservation* presentObservation(
    const std::map<std::string, const PropertyObservation*>& observations,
    const char* property) {
    const auto found = observations.find(property);
    return found != observations.end() &&
                   found->second->state == PropertyObservationState::PRESENT
               ? found->second
               : nullptr;
}

void addPropertyFinding(DangerousPropertiesAssessment& assessment, const char* id,
                        const char* property, const std::string& actual,
                        const char* expected, const char* comparison,
                        EvidenceStrength strength, const char* summary,
                        const std::string& detail) {
    assessment.findings.push_back(
        {id, property, actual, expected, comparison, strength, summary, detail});
    if (static_cast<int>(strength) > static_cast<int>(assessment.strongestFinding)) {
        assessment.strongestFinding = strength;
    }
}

bool contains(const std::string& value, const char* marker) {
    return value.find(marker) != std::string::npos;
}

bool containsCommaSeparatedToken(const std::string& value, const char* expectedToken) {
    std::size_t start = 0;
    while (start <= value.size()) {
        const std::size_t end = value.find(',', start);
        std::string token = value.substr(
            start, end == std::string::npos ? std::string::npos : end - start);
        const auto first = token.find_first_not_of(" \t\r\n");
        const auto last = token.find_last_not_of(" \t\r\n");
        if (first != std::string::npos &&
            lowercase(token.substr(first, last - first + 1)) == expectedToken) {
            return true;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return false;
}

void appendTelemetryObservation(PropertyTelemetry& telemetry,
                                const PropertyObservation& observation) {
    telemetry.properties.push_back(observation.property);
    telemetry.values.push_back(observation.value);
}

}  // namespace

DangerousPropertiesAssessment assessDangerousProperties(
    const std::vector<PropertyObservation>& observations) {
    DangerousPropertiesAssessment assessment;
    assessment.checkedRuleCount = 8;

    std::map<std::string, const PropertyObservation*> byProperty;
    for (const auto& observation : observations) {
        if (byProperty.find(observation.property) == byProperty.end()) {
            byProperty[observation.property] = &observation;
        }
    }

    const auto assessSingle = [&](const char* property, auto matcher, auto addFinding) {
        const PropertyObservation* observation = presentObservation(byProperty, property);
        if (observation == nullptr) return;
        ++assessment.availableRuleCount;
        if (matcher(lowercase(observation->value))) addFinding(*observation);
    };

    assessSingle("ro.secure", [](const std::string& value) { return value == "0"; },
                 [&](const PropertyObservation& observation) {
                     addPropertyFinding(assessment, "ro_secure_disabled", "ro.secure",
                                        observation.value, "not 0", "equals",
                                        EvidenceStrength::MODERATE,
                                        "Android secure mode is disabled",
                                        "ro.secure is explicitly 0.");
                 });
    assessSingle("ro.boot.verifiedbootstate", [](const std::string& value) {
                     return value == "orange" || value == "red";
                 }, [&](const PropertyObservation& observation) {
                     addPropertyFinding(assessment, "verified_boot_untrusted",
                                        "ro.boot.verifiedbootstate", observation.value,
                                        "not orange or red", "one_of",
                                        EvidenceStrength::MODERATE,
                                        "Verified Boot reports an untrusted state",
                                        "The boot state is explicitly orange or red.");
                 });
    assessSingle("ro.boot.flash.locked", [](const std::string& value) { return value == "0"; },
                 [&](const PropertyObservation& observation) {
                     addPropertyFinding(assessment, "flash_unlocked", "ro.boot.flash.locked",
                                        observation.value, "not 0", "equals",
                                        EvidenceStrength::MODERATE,
                                        "Bootloader flash lock is disabled",
                                        "ro.boot.flash.locked is explicitly 0.");
                 });
    assessSingle("ro.boot.vbmeta.device_state", [](const std::string& value) {
                     return value == "unlocked";
                 }, [&](const PropertyObservation& observation) {
                     addPropertyFinding(assessment, "vbmeta_unlocked",
                                        "ro.boot.vbmeta.device_state", observation.value,
                                        "not unlocked", "equals",
                                        EvidenceStrength::MODERATE,
                                        "VBMeta device state is unlocked",
                                        "ro.boot.vbmeta.device_state is explicitly unlocked.");
                 });

    const PropertyObservation* adbRoot = presentObservation(byProperty, "service.adb.root");
    const PropertyObservation* debuggable = presentObservation(byProperty, "ro.debuggable");
    if (adbRoot != nullptr && debuggable != nullptr) {
        ++assessment.availableRuleCount;
        if (lowercase(adbRoot->value) == "1" && lowercase(debuggable->value) == "1") {
            addPropertyFinding(assessment, "adb_root_debuggable", "service.adb.root",
                               adbRoot->value + "; ro.debuggable=" + debuggable->value,
                               "not both 1", "combined_equals", EvidenceStrength::MODERATE,
                               "ADB root is enabled on a debuggable build",
                               "service.adb.root and ro.debuggable are both explicitly 1.");
        }
    }

    assessSingle("ro.debuggable", [](const std::string& value) { return value == "1"; },
                 [&](const PropertyObservation& observation) {
                     addPropertyFinding(assessment, "debuggable_build", "ro.debuggable",
                                        observation.value, "not 1", "equals",
                                        EvidenceStrength::WEAK,
                                        "The Android build is debuggable",
                                        "ro.debuggable is explicitly 1.");
                 });
    assessSingle("ro.build.type", [](const std::string& value) {
                     return value == "eng" || value == "userdebug";
                 }, [&](const PropertyObservation& observation) {
                     addPropertyFinding(assessment, "development_build_type", "ro.build.type",
                                        observation.value, "not eng or userdebug", "one_of",
                                        EvidenceStrength::WEAK,
                                        "The Android build type is intended for development",
                                        "ro.build.type is eng or userdebug.");
                 });
    assessSingle("ro.build.tags", [](const std::string& value) {
                     return contains(value, "test-keys") || contains(value, "dev-keys");
                 }, [&](const PropertyObservation& observation) {
                     addPropertyFinding(assessment, "development_signing_keys", "ro.build.tags",
                                        observation.value, "no test-keys or dev-keys", "contains",
                                        EvidenceStrength::WEAK,
                                        "The Android build uses development signing tags",
                                        "ro.build.tags contains test-keys or dev-keys.");
                 });
    return assessment;
}

namespace {

// Mirrors Integer.parseInt(value, 10), which Settings.Global.getInt uses: an optional sign, at
// least one digit, no surrounding whitespace, and the 32-bit int range. False where parseInt
// would throw.
bool parseJavaInt(const std::string& rawValue, long long& value) {
    std::size_t index = 0;
    bool negative = false;
    if (!rawValue.empty() && (rawValue[0] == '+' || rawValue[0] == '-')) {
        negative = rawValue[0] == '-';
        index = 1;
    }
    if (index >= rawValue.size()) return false;
    long long magnitude = 0;
    for (; index < rawValue.size(); ++index) {
        const char character = rawValue[index];
        if (character < '0' || character > '9') return false;
        magnitude = magnitude * 10 + (character - '0');
        if (magnitude > 2147483648LL) return false;
    }
    if (!negative && magnitude > 2147483647LL) return false;
    value = negative ? -magnitude : magnitude;
    return true;
}

}  // namespace

AdbEnabledSettingClass classifyAdbEnabledSetting(const std::string& rawValue) {
    long long value = 0;
    if (!parseJavaInt(rawValue, value)) return AdbEnabledSettingClass::UNPARSABLE;
    if (value == 0 || value == 1) return AdbEnabledSettingClass::STANDARD;
    return value > 1 ? AdbEnabledSettingClass::NONSTANDARD_ENABLED
                     : AdbEnabledSettingClass::NONSTANDARD_DISABLED;
}

const char* adbEnabledSettingClassName(AdbEnabledSettingClass settingClass) {
    switch (settingClass) {
        case AdbEnabledSettingClass::STANDARD: return "standard";
        case AdbEnabledSettingClass::NONSTANDARD_ENABLED: return "nonstandard_enabled";
        case AdbEnabledSettingClass::NONSTANDARD_DISABLED: return "nonstandard_disabled";
        case AdbEnabledSettingClass::UNPARSABLE: return "unparsable";
    }
    return "unparsable";
}

PropertyObservation applyAdbEnabledPlatformRedaction(const PropertyObservation& adbSetting,
                                                     int apiLevel) {
    // An unreadable API level cannot rule the redaction out, so it is treated like API 37+.
    const bool platformMayRedact = apiLevel <= 0 || apiLevel >= kAdbEnabledRedactionApiLevel;
    long long value = 0;
    if (!platformMayRedact || adbSetting.state != PropertyObservationState::PRESENT ||
        !parseJavaInt(adbSetting.value, value) || value != 0) {
        return adbSetting;
    }
    PropertyObservation redacted = adbSetting;
    redacted.state = PropertyObservationState::REDACTED_BY_PLATFORM;
    redacted.value.clear();
    return redacted;
}

void assessAdbEnabledSetting(DangerousPropertiesAssessment& assessment,
                             const PropertyObservation& adbSetting,
                             const std::vector<PropertyObservation>& postureObservations) {
    ++assessment.checkedRuleCount;
    // Neither a failed read nor a value the platform manufactures is an answer.
    if (adbSetting.state == PropertyObservationState::UNAVAILABLE ||
        adbSetting.state == PropertyObservationState::REDACTED_BY_PLATFORM) {
        return;
    }
    // A missing row is an answer: AdbService and the Settings UI read it as 0.
    ++assessment.availableRuleCount;
    if (adbSetting.state != PropertyObservationState::PRESENT) return;

    const AdbEnabledSettingClass settingClass = classifyAdbEnabledSetting(adbSetting.value);
    if (settingClass == AdbEnabledSettingClass::STANDARD) return;

    std::string usbConfigWithAdb;
    for (const auto& observation : postureObservations) {
        if ((observation.property == "sys.usb.config" ||
             observation.property == "persist.sys.usb.config") &&
            observation.state == PropertyObservationState::PRESENT &&
            containsCommaSeparatedToken(observation.value, "adb")) {
            usbConfigWithAdb = observation.property;
            break;
        }
    }
    // Only a value the system still treats as enabled keeps adbd running while an
    // == 1 check fails, and only a USB configuration carrying adb shows the function is live.
    const bool corroborated =
        settingClass == AdbEnabledSettingClass::NONSTANDARD_ENABLED && !usbConfigWithAdb.empty();
    std::string detail = std::string("adb_enabled holds a value outside {0, 1}, which neither the "
                                     "Settings UI nor AdbService writes; classification=") +
                         adbEnabledSettingClassName(settingClass);
    if (corroborated) {
        detail += "; " + usbConfigWithAdb + " contains adb, so the adb function is live.";
    } else if (settingClass == AdbEnabledSettingClass::NONSTANDARD_ENABLED) {
        detail += "; no app-visible USB configuration contains adb.";
    } else {
        detail += "; AdbService treats this value as disabled.";
    }
    addPropertyFinding(assessment, "adb_enabled_nonstandard", "adb_enabled", adbSetting.value,
                       "0 or 1", "integer_one_of",
                       corroborated ? EvidenceStrength::MODERATE : EvidenceStrength::WEAK,
                       "The adb_enabled setting holds a non-standard value", detail);
}

const char* propertyObservationIssueKey(PropertyObservationState state) {
    switch (state) {
        case PropertyObservationState::UNAVAILABLE: return "collectionErrors";
        case PropertyObservationState::REDACTED_BY_PLATFORM: return "collectionWarnings";
        case PropertyObservationState::PRESENT:
        case PropertyObservationState::MISSING: return nullptr;
    }
    return nullptr;
}

std::vector<PropertyTelemetry> assessPropertyPostureTelemetry(
    const std::vector<PropertyObservation>& securityObservations,
    const std::vector<PropertyObservation>& postureObservations) {
    std::map<std::string, const PropertyObservation*> securityByProperty;
    for (const auto& observation : securityObservations) {
        if (securityByProperty.find(observation.property) == securityByProperty.end()) {
            securityByProperty[observation.property] = &observation;
        }
    }
    std::map<std::string, const PropertyObservation*> postureByProperty;
    for (const auto& observation : postureObservations) {
        if (postureByProperty.find(observation.property) == postureByProperty.end()) {
            postureByProperty[observation.property] = &observation;
        }
    }

    std::vector<PropertyTelemetry> telemetry;
    PropertyTelemetry emulator = {
        "emulator_environment", "device_posture", "telemetry_only",
        "Emulator environment properties are active",
        "One or more QEMU environment properties are explicitly 1.", {}, {}};
    for (const char* property : {"ro.boot.qemu", "ro.kernel.qemu"}) {
        const PropertyObservation* observation = presentObservation(postureByProperty, property);
        if (observation != nullptr && lowercase(observation->value) == "1") {
            appendTelemetryObservation(emulator, *observation);
        }
    }
    if (!emulator.properties.empty()) telemetry.push_back(std::move(emulator));

    PropertyTelemetry adbTransport = {
        "adb_transport_enabled", "device_posture", "telemetry_only",
        "ADB transport is enabled in the USB configuration",
        "One or more USB configuration properties contain the adb function.", {}, {}};
    for (const char* property : {"sys.usb.config", "persist.sys.usb.config"}) {
        const PropertyObservation* observation = presentObservation(postureByProperty, property);
        if (observation != nullptr && containsCommaSeparatedToken(observation->value, "adb")) {
            appendTelemetryObservation(adbTransport, *observation);
        }
    }
    if (!adbTransport.properties.empty()) telemetry.push_back(std::move(adbTransport));

    const PropertyObservation* adbRoot =
        presentObservation(securityByProperty, "service.adb.root");
    const PropertyObservation* debuggable =
        presentObservation(securityByProperty, "ro.debuggable");
    if (adbRoot != nullptr && lowercase(adbRoot->value) == "1" &&
        (debuggable == nullptr || lowercase(debuggable->value) != "1")) {
        PropertyTelemetry adbRootRequested = {
            "adb_root_requested", "device_posture", "telemetry_only",
            "ADB root was requested",
            "service.adb.root is explicitly 1 without a confirmed debuggable-build combination.",
            {}, {}};
        appendTelemetryObservation(adbRootRequested, *adbRoot);
        telemetry.push_back(std::move(adbRootRequested));
    }
    return telemetry;
}

namespace {

// Grades a mismatch by the trust distance the disagreement crosses, so the strength
// reflects which source is lying rather than merely how many sources answered.
void gradePropertyComparison(PropertyComparison& comparison) {
    bool kernelOutlier = false;
    bool rawAreaOutlier = false;
    bool nativeOutlier = false;
    bool javaOutlier = false;
    bool cachedOutlier = false;
    bool externalOutlier = false;
    for (const auto& source : comparison.outlierSources) {
        switch (propertySourceTrust(source)) {
            case PropertySourceTrust::KERNEL: kernelOutlier = true; break;
            case PropertySourceTrust::RAW_AREA: rawAreaOutlier = true; break;
            case PropertySourceTrust::NATIVE_ACCESSOR: nativeOutlier = true; break;
            case PropertySourceTrust::JAVA_API: javaOutlier = true; break;
            case PropertySourceTrust::CACHED_SNAPSHOT: cachedOutlier = true; break;
            case PropertySourceTrust::EXTERNAL_PROCESS: externalOutlier = true; break;
        }
    }

    if (kernelOutlier) {
        // The kernel command line records what the bootloader actually reported. A
        // user-space property that contradicts it crosses a real trust boundary.
        comparison.strength = EvidenceStrength::STRONG;
        comparison.findingId = "boot_property_inconsistency";
        comparison.rationale =
            "The kernel boot parameter disagrees with the Android property value.";
        return;
    }
    if (rawAreaOutlier || (nativeOutlier && !javaOutlier)) {
        // Either the bytes in the property area differ from what the accessor reports,
        // or the accessor differs from every other reader. Both mean the bionic
        // accessor and the stored data no longer agree.
        comparison.strength = EvidenceStrength::STRONG;
        comparison.findingId = "property_accessor_contradiction";
        comparison.rationale =
            "The property-area bytes and the bionic accessor report different values "
            "for the same property.";
        return;
    }
    if (javaOutlier || externalOutlier) {
        comparison.strength = EvidenceStrength::MODERATE;
        comparison.findingId = "property_source_mismatch";
        comparison.rationale =
            javaOutlier
                ? "The Java property API disagrees with the lower-level sources, which "
                  "is consistent with a hook on android.os.SystemProperties."
                : "A separate process reads a different value than this process does.";
        return;
    }
    if (cachedOutlier) {
        // Build fields are captured when the class initializes. Divergence means the
        // property changed after this process started, which has benign causes.
        comparison.strength = EvidenceStrength::WEAK;
        comparison.findingId = "property_snapshot_drift";
        comparison.rationale =
            "android.os.Build disagrees with the live property, so the value changed "
            "after this process started.";
        return;
    }
    comparison.strength = EvidenceStrength::MODERATE;
    comparison.findingId = "property_source_mismatch";
    comparison.rationale = "Equivalent property sources disagree.";
}

}  // namespace

PropertySourceTrust propertySourceTrust(const std::string& source) {
    if (source == "proc_cmdline") return PropertySourceTrust::KERNEL;
    if (source.rfind("property_area", 0) == 0) return PropertySourceTrust::RAW_AREA;
    if (source == "getprop") return PropertySourceTrust::EXTERNAL_PROCESS;
    if (source == "android_system_properties") return PropertySourceTrust::JAVA_API;
    if (source == "android_build") return PropertySourceTrust::CACHED_SNAPSHOT;
    return PropertySourceTrust::NATIVE_ACCESSOR;
}

const char* propertySourceTrustName(PropertySourceTrust trust) {
    switch (trust) {
        case PropertySourceTrust::KERNEL: return "kernel";
        case PropertySourceTrust::RAW_AREA: return "raw_area";
        case PropertySourceTrust::NATIVE_ACCESSOR: return "native_accessor";
        case PropertySourceTrust::EXTERNAL_PROCESS: return "external_process";
        case PropertySourceTrust::JAVA_API: return "java_api";
        case PropertySourceTrust::CACHED_SNAPSHOT: return "cached_snapshot";
    }
    return "native_accessor";
}

namespace {

// Properties whose value is written differently by different producers without any
// change of meaning. Comparing these literally produces mismatches on stock devices.
bool isBooleanStyleProperty(const std::string& property) {
    static const std::set<std::string> kBooleanStyle = {
        "ro.boot.flash.locked",
        "ro.secure",
        "ro.debuggable",
        "ro.adb.secure",
        "service.adb.root",
        "sys.oem_unlock_allowed",
        "ro.oem_unlock_supported",
    };
    return kBooleanStyle.count(property) != 0;
}

}  // namespace

std::string normalizePropertyValue(const std::string& property, const std::string& value) {
    std::size_t begin = 0;
    std::size_t end = value.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(value[begin]))) ++begin;
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) --end;
    const std::string normalized = lowercase(value.substr(begin, end - begin));
    if (!isBooleanStyleProperty(property)) {
        return normalized;
    }
    if (normalized == "1" || normalized == "true" || normalized == "locked" ||
        normalized == "yes" || normalized == "green") {
        return "true";
    }
    if (normalized == "0" || normalized == "false" || normalized == "unlocked" ||
        normalized == "no") {
        return "false";
    }
    return normalized;
}

std::vector<PropertyComparison> compareEquivalentPropertySources(
    const std::vector<std::string>& keys,
    const std::vector<PropertyObservation>& observations) {
    std::vector<PropertyComparison> comparisons;
    comparisons.reserve(keys.size());
    for (const auto& key : keys) {
        PropertyComparison comparison;
        comparison.property = key;
        std::vector<std::string> normalizedValues;
        std::map<std::string, int> valueCounts;
        for (const auto& observation : observations) {
            if (observation.property != key ||
                observation.state != PropertyObservationState::PRESENT) {
                continue;
            }
            // Bionic's legacy accessor substitutes a fixed notice for values above
            // PROP_VALUE_MAX. Treating that text as a value would make every long
            // property disagree with every other source on every device.
            if (observation.value.find("__system_property_read_callback") !=
                std::string::npos) {
                continue;
            }
            // Known false-positive risk, left in place on purpose: the bionic_legacy
            // source keeps the length __system_property_get returns, which is the stored
            // length and can include a NUL inside the value. The callback, getprop and
            // Java sources all stop at that NUL. A clean, locked Xiaomi 13T Pro stores
            // ro.boot.vbmeta.digest as 64 hex digits plus a NUL (measured 2026-09-24), so
            // any compared property stored that way would make bionic_legacy the lone
            // dissenter here, and normalizePropertyValue does not strip NUL. None of the
            // keys compared today has shown it. It is not trimmed because a disagreement
            // between the two bionic entry points is this detector's evidence of a hook,
            // and trimming would change what that evidence can show. A mismatch whose
            // only difference is trailing NUL bytes should be read as this, not as tampering.
            const std::string normalized = normalizePropertyValue(key, observation.value);
            if (normalized.empty()) continue;
            ++comparison.availableSourceCount;
            comparison.sources.push_back(observation.source);
            comparison.values.push_back(observation.value);
            normalizedValues.push_back(normalized);
            ++valueCounts[normalized];
        }
        comparison.distinctValueCount = static_cast<int>(valueCounts.size());
        comparison.comparable = comparison.availableSourceCount >= 2;
        comparison.mismatch = comparison.comparable && comparison.distinctValueCount >= 2;
        if (comparison.mismatch) {
            // The majority value is the reference; every source that disagrees with it
            // is an outlier. Ties resolve to the first value seen, which keeps the
            // classification deterministic without pretending to know which is correct.
            int bestCount = 0;
            for (const auto& normalized : normalizedValues) {
                const int count = valueCounts[normalized];
                if (count > bestCount) {
                    bestCount = count;
                    comparison.majorityValue = normalized;
                }
            }
            for (std::size_t index = 0; index < normalizedValues.size(); ++index) {
                if (normalizedValues[index] != comparison.majorityValue) {
                    comparison.outlierSources.push_back(comparison.sources[index]);
                }
            }
            gradePropertyComparison(comparison);
        }
        comparisons.push_back(std::move(comparison));
    }
    return comparisons;
}

const char* selinuxModeName(SelinuxMode mode) {
    switch (mode) {
        case SelinuxMode::ENFORCING: return "enforcing";
        case SelinuxMode::PERMISSIVE: return "permissive";
        case SelinuxMode::DISABLED: return "disabled";
        case SelinuxMode::UNKNOWN: return "unknown";
    }
    return "unknown";
}

bool selinuxDacPermitsRead(unsigned int mode, unsigned int ownerUid, unsigned int ownerGid,
                           unsigned int callerUid, const std::vector<unsigned int>& callerGroups) {
    // Classic UNIX DAC, evaluated the way the kernel's generic_permission() does: exactly one
    // permission class applies. selinuxfs has no POSIX ACLs. An app holds no
    // CAP_DAC_OVERRIDE / CAP_DAC_READ_SEARCH, so capability overrides are not modelled.
    if (callerUid == ownerUid) return (mode & S_IRUSR) != 0;
    if (std::find(callerGroups.begin(), callerGroups.end(), ownerGid) != callerGroups.end()) {
        return (mode & S_IRGRP) != 0;
    }
    return (mode & S_IROTH) != 0;
}

SelinuxReadDenialInference inferSelinuxReadDenial(const SelinuxReadDenialInput& input) {
    SelinuxReadDenialInference inference;
    if (input.readErrno == 0) return inference;  // not_applicable: the read answered directly
    inference.state = "not_inferred";
    // Only EACCES is the shape of an LSM refusal. EPERM, ENOENT, EIO, ... are not inferred.
    if (input.readErrno != EACCES) {
        inference.reason = "read_errno_not_eacces";
        return inference;
    }
    // The kernel-mode argument holds only for the selinuxfs node itself; without the
    // SELINUX_MAGIC check the path could be anything (a bind mount, a stub tmpfs).
    if (!input.selinuxfsVerified) {
        inference.reason = "selinuxfs_not_verified";
        return inference;
    }
    if (!input.statAttempted) {
        inference.reason = "stat_not_attempted";
        return inference;
    }
    if (input.statErrno == 0) {
        inference.dacBasis = "measured_mode";
        if (!S_ISREG(static_cast<mode_t>(input.statMode))) {
            inference.reason = "enforce_node_not_regular_file";
            inference.anomaly = "enforce_node_not_regular_file";
            return inference;
        }
        inference.dacPermitsRead = selinuxDacPermitsRead(input.statMode, input.statUid,
                                                         input.statGid, input.callerUid,
                                                         input.callerGroups);
        if (!inference.dacPermitsRead) {
            // Not the kernel's 0644: DAC alone could have refused the read, so the refusal
            // proves nothing about SELinux. Recorded, never graded.
            inference.reason = "dac_denies_read";
            inference.anomaly = "enforce_node_dac_not_kernel_default";
            return inference;
        }
    } else if (input.statErrno == EACCES) {
        // stat() is refused too (no getattr on the node). Fall back to the mode the kernel
        // assigns unconditionally, and say so: this basis is a constant, not a measurement.
        inference.dacBasis = "kernel_constant";
        inference.dacPermitsRead = selinuxDacPermitsRead(
            kSelinuxEnforceKernelMode, kSelinuxEnforceKernelUid, kSelinuxEnforceKernelGid,
            input.callerUid, input.callerGroups);
        if (!inference.dacPermitsRead) {
            inference.reason = "dac_denies_read";
            return inference;
        }
    } else {
        inference.reason = "stat_failed";
        return inference;
    }
    inference.state = "inferred";
    inference.mode = SelinuxMode::ENFORCING;
    inference.reason = "eacces_on_dac_readable_node";
    return inference;
}

SelinuxAssessment assessSelinux(const SelinuxAssessmentInput& input) {
    SelinuxAssessment assessment;
    // The write probe does NOT establish a reliable observation on its own. A denied
    // open() of the enforce node is the expected result on any device, rooted or not, and
    // says nothing about the global enforcement mode. Until 2026-09-12 a denied write probe
    // set this flag, so the detector returned NOT_OBSERVED -- a clean verdict -- in all
    // fourteen ablation cells even though neither global enforcement source was readable.
    // Only an enforcement source that actually reported a mode answers this detector's
    // question; that is set in the loop below. A *writable* enforce node remains STRONG
    // evidence and reaches OBSERVED through strongestFinding regardless of this flag.
    if (input.writeProbeAvailable && input.enforceNodeWritable) {
        assessment.strongestFinding = EvidenceStrength::STRONG;
        assessment.findings.push_back(
            {"enforce_node_writable", EvidenceStrength::STRONG,
             "The SELinux enforce node is writable",
             "Opening /sys/fs/selinux/enforce with O_WRONLY succeeded without writing."});
    }

    // An inferred source (selinuxfs_read_denial) answers like any other, so on its own it can
    // move the detector from INCONCLUSIVE to NOT_OBSERVED. In the contradiction rule it
    // takes part, but cannot carry a STRONG claim by itself: a disagreement between two
    // *read* sources stays STRONG, while one that needs the inferred source to exist is
    // graded MODERATE (inferred_enforcement_contradiction). The inference rests on more
    // assumptions than a read -- that SELinux is the only refuser of a DAC-readable node --
    // and the false-positive cost of a STRONG claim outweighs the gain.
    std::set<SelinuxMode> availableModes;
    std::set<SelinuxMode> readModes;
    bool hasPermissive = false;
    bool hasDisabled = false;
    for (const auto& source : input.enforcementSources) {
        if (!source.available || source.mode == SelinuxMode::UNKNOWN) continue;
        assessment.hasReliableObservation = true;
        availableModes.insert(source.mode);
        if (!source.inferred) readModes.insert(source.mode);
        hasPermissive = hasPermissive || source.mode == SelinuxMode::PERMISSIVE;
        hasDisabled = hasDisabled || source.mode == SelinuxMode::DISABLED;
    }
    if (readModes.size() < 2 && availableModes.size() >= 2) {
        std::ostringstream detail;
        detail << "An inferred enforcement answer disagrees with a read source:";
        for (const auto& source : input.enforcementSources) {
            if (source.available && source.mode != SelinuxMode::UNKNOWN) {
                detail << ' ' << source.source << '=' << selinuxModeName(source.mode)
                       << (source.inferred ? "(inferred)" : "");
            }
        }
        assessment.findings.push_back(
            {"inferred_enforcement_contradiction", EvidenceStrength::MODERATE,
             "An inferred SELinux enforcement answer contradicts a read source", detail.str()});
        if (assessment.strongestFinding == EvidenceStrength::NONE) {
            assessment.strongestFinding = EvidenceStrength::MODERATE;
        }
    }
    if (readModes.size() >= 2) {
        assessment.strongestFinding = EvidenceStrength::STRONG;
        std::ostringstream detail;
        detail << "Available global enforcement sources disagree:";
        for (const auto& source : input.enforcementSources) {
            if (source.available && source.mode != SelinuxMode::UNKNOWN) {
                detail << ' ' << source.source << '=' << selinuxModeName(source.mode);
            }
        }
        assessment.findings.push_back(
            {"enforcement_source_contradiction", EvidenceStrength::STRONG,
             "SELinux enforcement sources contradict each other", detail.str()});
    }
    if (hasDisabled) {
        assessment.findings.push_back(
            {"selinux_disabled", EvidenceStrength::MODERATE,
             "SELinux is globally disabled",
             "An available global enforcement source explicitly reports Disabled."});
        if (assessment.strongestFinding == EvidenceStrength::NONE) {
            assessment.strongestFinding = EvidenceStrength::MODERATE;
        }
    } else if (hasPermissive) {
        assessment.findings.push_back(
            {"selinux_permissive", EvidenceStrength::MODERATE,
             "SELinux is globally permissive",
             "An available global enforcement source explicitly reports Permissive."});
        if (assessment.strongestFinding == EvidenceStrength::NONE) {
            assessment.strongestFinding = EvidenceStrength::MODERATE;
        }
    }
    return assessment;
}

}  // namespace tamperprobe
