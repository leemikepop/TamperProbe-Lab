#ifndef TAMPERPROBE_PROPERTY_DETECTOR_LOGIC_H
#define TAMPERPROBE_PROPERTY_DETECTOR_LOGIC_H

#include <string>
#include <vector>

#include "../../core/detection_result.h"
#include "property_observation.h"

namespace tamperprobe {

struct PropertyFinding {
    std::string id;
    std::string property;
    std::string actual;
    std::string expected;
    std::string comparison;
    EvidenceStrength strength = EvidenceStrength::NONE;
    std::string summary;
    std::string detail;
};

struct DangerousPropertiesAssessment {
    int checkedRuleCount = 0;
    int availableRuleCount = 0;
    EvidenceStrength strongestFinding = EvidenceStrength::NONE;
    std::vector<PropertyFinding> findings;
};

DangerousPropertiesAssessment assessDangerousProperties(
    const std::vector<PropertyObservation>& observations);

// How a Settings.Global adb_enabled value relates to what AOSP itself writes. The Settings UI
// (SettingsLib AbstractEnableAdbPreferenceController) and AdbService.systemReady() write only
// 0 or 1, while AdbService.AdbSettingsObserver starts adbd for any value > 0 and
// Settings.Global.getInt(..., 0) falls back to 0 for a value that does not parse.
enum class AdbEnabledSettingClass {
    STANDARD,              // 0 or 1
    NONSTANDARD_ENABLED,   // an integer > 1: adbd stays enabled, a getInt(...) == 1 check fails
    NONSTANDARD_DISABLED,  // a negative integer: the observer treats it as disabled
    UNPARSABLE,            // not a Java int: getInt(..., 0) reads it as 0
};

AdbEnabledSettingClass classifyAdbEnabledSetting(const std::string& rawValue);

const char* adbEnabledSettingClassName(AdbEnabledSettingClass settingClass);

// From Android 17 QPR1 the platform redacts ADB_ENABLED for third-party apps. Google's
// Settings.Global reference says of it (and of DEVELOPMENT_SETTINGS_ENABLED) "This will always
// return 0 for all third-party apps"; field reports tie the change to build CP3A.260905.009 and
// the flag android.provider.enable_redacted_value_for_readable, and say it holds even with
// WRITE_SECURE_SETTINGS. QPR1 does not raise the API level, so 37 is the first level at which
// a 0 may be manufactured; it cannot tell a redacting build from one that is not.
constexpr int kAdbEnabledRedactionApiLevel = 37;

// Applies that redaction to the adb_enabled read. On API 37 or later -- or when the API level
// could not be read (apiLevel <= 0) -- a PRESENT value Integer.parseInt reads as 0 is exactly
// what the redaction returns, so it becomes REDACTED_BY_PLATFORM with its value cleared: not an
// observed 0 and not a clean answer, even on a build that happens to return the real value.
// Everything else is returned unchanged. A non-zero value cannot be the redaction's output,
// which only ever yields 0, so it is still the device's real setting (base Android 17 before
// QPR1, or a build with the flag off) and is graded as below API 37. A missing row (null) is
// not the redaction's output either and stays an answer.
PropertyObservation applyAdbEnabledPlatformRedaction(const PropertyObservation& adbSetting,
                                                     int apiLevel);

// Adds the adb_enabled_nonstandard rule to an assessment. adbSetting is the Settings.Global
// adb_enabled read (source settings_global) after applyAdbEnabledPlatformRedaction;
// postureObservations supply the USB configuration that corroborates a live adb function. An
// unavailable or platform-redacted read is not counted as an answered rule, so neither a dead
// channel nor a manufactured 0 can make the detector look clean.
void assessAdbEnabledSetting(DangerousPropertiesAssessment& assessment,
                             const PropertyObservation& adbSetting,
                             const std::vector<PropertyObservation>& postureObservations);

// The payload issue array an observation raises, or nullptr when the read answered: a failed
// read is a "collectionErrors" entry, a platform-redacted value a "collectionWarnings" entry
// (the read worked, but the platform withheld the answer).
const char* propertyObservationIssueKey(PropertyObservationState state);

struct PropertyTelemetry {
    std::string id;
    std::string classification;
    std::string assessmentImpact;
    std::string summary;
    std::string detail;
    std::vector<std::string> properties;
    std::vector<std::string> values;
};

std::vector<PropertyTelemetry> assessPropertyPostureTelemetry(
    const std::vector<PropertyObservation>& securityObservations,
    const std::vector<PropertyObservation>& postureObservations);

// How far a source sits from the accessor an attacker normally mediates. The
// grading of a disagreement depends on which side of these boundaries it crosses,
// not on how many sources happen to be populated.
enum class PropertySourceTrust {
    KERNEL,         // /proc/cmdline: below user space entirely
    RAW_AREA,       // property-area bytes read directly, bypassing the accessor
    NATIVE_ACCESSOR,  // bionic __system_property_* in this process
    EXTERNAL_PROCESS,  // getprop in a forked child
    JAVA_API,       // android.os.SystemProperties in this process
    CACHED_SNAPSHOT,  // android.os.Build, captured at class initialization
};

PropertySourceTrust propertySourceTrust(const std::string& source);

const char* propertySourceTrustName(PropertySourceTrust trust);

std::string normalizePropertyValue(const std::string& property, const std::string& value);

struct PropertyComparison {
    std::string property;
    int availableSourceCount = 0;
    int distinctValueCount = 0;
    bool comparable = false;
    bool mismatch = false;
    std::vector<std::string> sources;
    std::vector<std::string> values;
    // Sources whose normalized value differs from the most common one.
    std::vector<std::string> outlierSources;
    std::string majorityValue;
    EvidenceStrength strength = EvidenceStrength::NONE;
    std::string findingId;
    std::string rationale;
};

std::vector<PropertyComparison> compareEquivalentPropertySources(
    const std::vector<std::string>& keys,
    const std::vector<PropertyObservation>& observations);

enum class SelinuxMode {
    ENFORCING,
    PERMISSIVE,
    DISABLED,
    UNKNOWN,
};

struct SelinuxEnforcementObservation {
    std::string source;
    bool available = false;
    SelinuxMode mode = SelinuxMode::UNKNOWN;
    // True for a mode deduced from a refusal rather than read from a source. An inferred
    // answer counts as an answer, but a disagreement it takes part in is graded MODERATE,
    // never STRONG: see assessSelinux.
    bool inferred = false;
};

// Linux security/selinux/selinuxfs.c, sel_fill_super():
//   [SEL_ENFORCE] = {"enforce", &sel_enforce_ops, S_IRUGO|S_IWUSR}
// simple_fill_super() creates the node owned by uid 0 / gid 0, so every uid passes the DAC
// read check. Used only when stat() of the node is itself refused.
constexpr unsigned int kSelinuxEnforceKernelMode = 0100644;  // S_IFREG | 0644
constexpr unsigned int kSelinuxEnforceKernelUid = 0;
constexpr unsigned int kSelinuxEnforceKernelGid = 0;

struct SelinuxReadDenialInput {
    // errno of the O_RDONLY open() or read() of /sys/fs/selinux/enforce; 0 when it succeeded.
    int readErrno = 0;
    // statfs("/sys/fs/selinux") reported SELINUX_MAGIC.
    bool selinuxfsVerified = false;
    // stat() of the enforce node: statErrno 0 means mode/uid/gid are measured.
    bool statAttempted = false;
    int statErrno = 0;
    unsigned int statMode = 0;
    unsigned int statUid = 0;
    unsigned int statGid = 0;
    // The caller's credentials for the DAC evaluation.
    unsigned int callerUid = 0;
    std::vector<unsigned int> callerGroups;  // effective gid plus supplementary groups
};

struct SelinuxReadDenialInference {
    // "inferred", "not_inferred", or "not_applicable" (the read did not fail).
    std::string state = "not_applicable";
    SelinuxMode mode = SelinuxMode::UNKNOWN;
    // "measured_mode" (stat succeeded) or "kernel_constant" (stat refused); empty otherwise.
    std::string dacBasis;
    bool dacPermitsRead = false;
    std::string reason;
    // Non-empty when stat() contradicted the kernel's fixed mode. Telemetry only.
    std::string anomaly;
};

bool selinuxDacPermitsRead(unsigned int mode, unsigned int ownerUid, unsigned int ownerGid,
                           unsigned int callerUid, const std::vector<unsigned int>& callerGroups);
SelinuxReadDenialInference inferSelinuxReadDenial(const SelinuxReadDenialInput& input);

struct SelinuxAssessmentInput {
    std::vector<SelinuxEnforcementObservation> enforcementSources;
    bool writeProbeAvailable = false;
    bool enforceNodeWritable = false;
};

struct SelinuxFinding {
    std::string id;
    EvidenceStrength strength = EvidenceStrength::NONE;
    std::string summary;
    std::string detail;
};

struct SelinuxAssessment {
    EvidenceStrength strongestFinding = EvidenceStrength::NONE;
    bool hasReliableObservation = false;
    std::vector<SelinuxFinding> findings;
};

const char* selinuxModeName(SelinuxMode mode);
SelinuxAssessment assessSelinux(const SelinuxAssessmentInput& input);

}  // namespace tamperprobe

#endif  // TAMPERPROBE_PROPERTY_DETECTOR_LOGIC_H
