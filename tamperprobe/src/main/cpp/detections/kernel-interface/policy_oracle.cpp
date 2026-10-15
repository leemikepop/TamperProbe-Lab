#include "policy_oracle.h"

#include "../../common/log.h"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <array>
#include <cstring>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace tamperprobe {
namespace {

constexpr int kRepeatCount = 2;

struct SelinuxApi {
    void* handle = nullptr;
    bool ownsHandle = false;
    int (*isEnabled)() = nullptr;
    int (*getEnforce)() = nullptr;
    int (*checkContext)(const char*) = nullptr;
    int (*checkAccess)(const char*, const char*, const char*, const char*, void*) = nullptr;
    void (*closeStatus)() = nullptr;

    SelinuxApi() = default;
    SelinuxApi(const SelinuxApi&) = delete;
    SelinuxApi& operator=(const SelinuxApi&) = delete;
    SelinuxApi(SelinuxApi&& other) noexcept
        : handle(other.handle),
          ownsHandle(other.ownsHandle),
          isEnabled(other.isEnabled),
          getEnforce(other.getEnforce),
          checkContext(other.checkContext),
          checkAccess(other.checkAccess),
          closeStatus(other.closeStatus) {
        other.handle = nullptr;
        other.ownsHandle = false;
        other.closeStatus = nullptr;
    }

    ~SelinuxApi() {
        if (closeStatus != nullptr) closeStatus();
        if (ownsHandle && handle != nullptr) dlclose(handle);
    }

    // Only the symbols a policy query actually needs. security_check_context and
    // selinux_status_close are not exported by AOSP's libselinux - verified absent on
    // Redmi 13C (Android 13) and Pixel 7 (Android 17) - so requiring them here made this
    // unsatisfiable on every device and discarded the three symbols that do resolve.
    // Both remaining users already handle a null pointer: contextState() reports
    // "unavailable" and the destructor skips teardown.
    bool complete() const {
        return isEnabled != nullptr && getEnforce != nullptr && checkAccess != nullptr;
    }
};

struct JavaSelinuxApi {
    JNIEnv* env = nullptr;
    jclass clazz = nullptr;
    jmethodID isEnforced = nullptr;
    jmethodID checkAccess = nullptr;

    ~JavaSelinuxApi() {
        if (env != nullptr && clazz != nullptr) env->DeleteLocalRef(clazz);
    }

    bool enforcementAvailable() const { return clazz != nullptr && isEnforced != nullptr; }
    bool queryAvailable() const { return clazz != nullptr && checkAccess != nullptr; }
};

struct Decision {
    bool available = false;
    std::string value = "unavailable";
};

struct RuleSpec {
    const char* id;
    const char* source;
    const char* target;
    const char* targetClass;
    const char* permission;
    const char* assessmentImpact;
};

void clearJniException(JNIEnv* env) {
    if (env != nullptr && env->ExceptionCheck()) env->ExceptionClear();
}

void addError(nlohmann::json& errors, const std::string& source,
              const std::string& message, int errorNumber = 0) {
    errors.push_back({{"source", source}, {"errno", errorNumber}, {"message", message}});
}

std::string readTextFile(const char* path, int& errorNumber) {
    errorNumber = 0;
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        errorNumber = errno;
        return {};
    }
    std::array<char, 512> buffer{};
    const ssize_t count = read(fd, buffer.data(), buffer.size() - 1);
    const int readError = count < 0 ? errno : 0;
    close(fd);
    if (count < 0) {
        errorNumber = readError;
        return {};
    }
    std::string value(buffer.data(), static_cast<std::size_t>(count));
    while (!value.empty() &&
           (value.back() == '\n' || value.back() == '\r' || value.back() == '\0')) {
        value.pop_back();
    }
    return value;
}

std::string readProperty(const char* name) {
    std::array<char, PROP_VALUE_MAX> value{};
    const int length = __system_property_get(name, value.data());
    // Stop at the first NUL, as getprop does: the returned length can include a NUL stored
    // inside the value.
    return length > 0 ? std::string(value.data(), strnlen(value.data(), value.size()))
                      : std::string();
}

std::string contextDomain(const std::string& context) {
    const std::size_t first = context.find(':');
    if (first == std::string::npos) return {};
    const std::size_t second = context.find(':', first + 1);
    if (second == std::string::npos) return {};
    const std::size_t third = context.find(':', second + 1);
    if (third == std::string::npos) return {};
    return context.substr(second + 1, third - second - 1);
}

template <typename Function>
Function resolve(void* handle, const char* name) {
    dlerror();
    return reinterpret_cast<Function>(dlsym(handle, name));
}

std::string missingSymbolList(const SelinuxApi& api) {
    std::string missing;
    auto note = [&missing](bool absent, const char* name) {
        if (!absent) return;
        if (!missing.empty()) missing += ", ";
        missing += name;
    };
    note(api.isEnabled == nullptr, "is_selinux_enabled");
    note(api.getEnforce == nullptr, "security_getenforce");
    note(api.checkAccess == nullptr, "selinux_check_access");
    return missing.empty() ? "none" : missing;
}

// Counts descriptors open in this process. Used to verify, rather than assume, that a
// native SELinux query leaves no descriptor behind before the carrier issues more of
// them. Returns -1 when procfs cannot be read.
int countOpenDescriptors() {
    DIR* dir = opendir("/proc/self/fd");
    if (dir == nullptr) return -1;
    int count = 0;
    while (struct dirent* entry = readdir(dir)) {
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') ++count;
    }
    closedir(dir);
    return count;
}

SelinuxApi loadSelinuxApi(nlohmann::json& errors) {
    SelinuxApi api;
    api.handle = RTLD_DEFAULT;
    api.isEnabled = resolve<decltype(api.isEnabled)>(api.handle, "is_selinux_enabled");
    api.getEnforce = resolve<decltype(api.getEnforce)>(api.handle, "security_getenforce");
    api.checkContext = resolve<decltype(api.checkContext)>(api.handle, "security_check_context");
    api.checkAccess = resolve<decltype(api.checkAccess)>(api.handle, "selinux_check_access");
    api.closeStatus = resolve<decltype(api.closeStatus)>(api.handle, "selinux_status_close");
    if (api.complete()) return api;

    // RTLD_NOLOAD: libselinux is already mapped into every app process by the framework,
    // and an application's linker namespace will refuse to load it fresh. Asking for the
    // already-loaded image succeeds where a plain dlopen cannot.
    void* loaded = dlopen("libselinux.so", RTLD_NOW | RTLD_NOLOAD);
    if (loaded == nullptr) {
        // Whatever RTLD_DEFAULT already resolved stays usable; only the still-missing
        // entry points are reported. Previously this path cleared the handle and threw
        // away working symbols, which is why the native tier never produced anything.
        addError(errors, "native_libselinux",
                 std::string("libselinux.so is not available to this process; missing ") +
                     missingSymbolList(api) + ".");
        return api;
    }
    api.handle = loaded;
    api.ownsHandle = true;
    api.isEnabled = resolve<decltype(api.isEnabled)>(loaded, "is_selinux_enabled");
    api.getEnforce = resolve<decltype(api.getEnforce)>(loaded, "security_getenforce");
    api.checkContext = resolve<decltype(api.checkContext)>(loaded, "security_check_context");
    api.checkAccess = resolve<decltype(api.checkAccess)>(loaded, "selinux_check_access");
    api.closeStatus = resolve<decltype(api.closeStatus)>(loaded, "selinux_status_close");
    if (!api.complete()) {
        addError(errors, "native_libselinux",
                 std::string("Required libselinux policy-query symbols are unavailable: ") +
                     missingSymbolList(api) + ".");
    }
    return api;
}

JavaSelinuxApi loadJavaSelinuxApi(JNIEnv* env, nlohmann::json& errors) {
    JavaSelinuxApi api;
    api.env = env;
    if (env == nullptr) {
        addError(errors, "hidden_android_selinux", "JNI environment is unavailable.");
        return api;
    }
    api.clazz = env->FindClass("android/os/SELinux");
    if (api.clazz == nullptr) {
        clearJniException(env);
        addError(errors, "hidden_android_selinux", "android.os.SELinux is unavailable.");
        return api;
    }
    api.isEnforced = env->GetStaticMethodID(api.clazz, "isSELinuxEnforced", "()Z");
    if (api.isEnforced == nullptr) clearJniException(env);
    api.checkAccess = env->GetStaticMethodID(
        api.clazz, "checkSELinuxAccess",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z");
    if (api.checkAccess == nullptr) clearJniException(env);
    if (!api.enforcementAvailable() && !api.queryAvailable()) {
        addError(errors, "hidden_android_selinux",
                 "Hidden Android SELinux methods are unavailable.");
    }
    return api;
}

// AOSP does not export security_check_context, and libselinux is outside an
// application's linker namespace, so context validity is resolved by writing the
// candidate context to the selinuxfs node instead. The kernel canonicalises a context
// the loaded policy defines and fails with EINVAL for one it does not. This needs no
// libselinux at all and works from the app-zygote carrier, which is exactly where the
// dlsym path is unavailable.
std::string contextStateViaSelinuxFs(const char* context) {
    const int fd = open("/sys/fs/selinux/context", O_RDWR | O_CLOEXEC);
    if (fd < 0) return "unavailable";
    errno = 0;
    const ssize_t written = write(fd, context, std::strlen(context) + 1);
    const int writeErrno = errno;
    close(fd);
    if (written >= 0) return "valid";
    return writeErrno == EINVAL ? "absent" : "unavailable";
}

std::string contextState(const SelinuxApi& api, const char* context) {
    if (api.checkContext != nullptr) {
        errno = 0;
        if (api.checkContext(context) == 0) return "valid";
        if (errno == EINVAL) return "absent";
    }
    return contextStateViaSelinuxFs(context);
}

Decision nativeDecision(const SelinuxApi& api, const char* source, const char* target,
                        const char* targetClass, const char* permission) {
    if (api.checkAccess == nullptr) return {};
    errno = 0;
    if (api.checkAccess(source, target, targetClass, permission, nullptr) == 0) {
        return {true, "allowed"};
    }
    if (errno == EACCES || errno == EPERM) return {true, "denied"};
    return {};
}

Decision javaDecision(JavaSelinuxApi& api, const char* source, const char* target,
                      const char* targetClass, const char* permission) {
    if (!api.queryAvailable()) return {};
    jstring sourceValue = api.env->NewStringUTF(source);
    jstring targetValue = api.env->NewStringUTF(target);
    jstring classValue = api.env->NewStringUTF(targetClass);
    jstring permissionValue = api.env->NewStringUTF(permission);
    if (sourceValue == nullptr || targetValue == nullptr || classValue == nullptr ||
        permissionValue == nullptr) {
        clearJniException(api.env);
        if (sourceValue != nullptr) api.env->DeleteLocalRef(sourceValue);
        if (targetValue != nullptr) api.env->DeleteLocalRef(targetValue);
        if (classValue != nullptr) api.env->DeleteLocalRef(classValue);
        if (permissionValue != nullptr) api.env->DeleteLocalRef(permissionValue);
        return {};
    }
    const jboolean allowed = api.env->CallStaticBooleanMethod(
        api.clazz, api.checkAccess, sourceValue, targetValue, classValue, permissionValue);
    const bool failed = api.env->ExceptionCheck();
    clearJniException(api.env);
    api.env->DeleteLocalRef(sourceValue);
    api.env->DeleteLocalRef(targetValue);
    api.env->DeleteLocalRef(classValue);
    api.env->DeleteLocalRef(permissionValue);
    if (failed) return {};
    return {true, allowed == JNI_TRUE ? "allowed" : "denied"};
}

std::string repeatedValue(const nlohmann::json& row, const char* key,
                          const char* availableKey, const char* stableKey) {
    if (!row.is_object() || !row.value(availableKey, false) ||
        !row.value(stableKey, false) || !row.contains(key) || !row[key].is_array() ||
        row[key].size() != kRepeatCount || !row[key][0].is_string() ||
        !row[key][1].is_string()) {
        return "unavailable";
    }
    const std::string first = row[key][0].get<std::string>();
    return first == row[key][1].get<std::string>() ? first : "unavailable";
}

nlohmann::json repeatedProbe(const SelinuxApi& nativeApi, JavaSelinuxApi& javaApi,
                             const RuleSpec& spec, bool nativeContextsValid) {
    nlohmann::json nativeDecisions = nlohmann::json::array();
    nlohmann::json javaDecisions = nlohmann::json::array();
    std::vector<Decision> nativeResults;
    std::vector<Decision> javaResults;
    for (int repetition = 0; repetition < kRepeatCount; ++repetition) {
        if (nativeContextsValid) {
            nativeResults.push_back(nativeDecision(nativeApi, spec.source, spec.target,
                                                   spec.targetClass, spec.permission));
        }
        javaResults.push_back(javaDecision(javaApi, spec.source, spec.target,
                                           spec.targetClass, spec.permission));
    }
    for (const auto& result : nativeResults) {
        if (result.available) nativeDecisions.push_back(result.value);
    }
    for (const auto& result : javaResults) {
        if (result.available) javaDecisions.push_back(result.value);
    }

    const bool nativeAvailable = nativeDecisions.size() == kRepeatCount;
    const bool javaAvailable = javaDecisions.size() == kRepeatCount;
    const bool nativeStable = nativeAvailable && nativeDecisions[0] == nativeDecisions[1];
    const bool javaStable = javaAvailable && javaDecisions[0] == javaDecisions[1];
    const bool stable = (nativeAvailable || javaAvailable) &&
                        (!nativeAvailable || nativeStable) &&
                        (!javaAvailable || javaStable);
    const bool sourcesAgree = !(nativeAvailable && javaAvailable) ||
                              (nativeStable && javaStable &&
                               nativeDecisions[0] == javaDecisions[0]);
    const bool contradiction = nativeAvailable && javaAvailable && !sourcesAgree;
    const bool observationAvailable = stable && sourcesAgree;
    const std::string decision = observationAvailable
                                     ? (nativeAvailable
                                            ? nativeDecisions[0].get<std::string>()
                                            : javaDecisions[0].get<std::string>())
                                     : "unavailable";
    return {{"nativeAvailable", nativeAvailable},
            {"nativeDecisions", nativeDecisions},
            {"javaAvailable", javaAvailable},
            {"javaDecisions", javaDecisions},
            {"nativeStable", nativeStable},
            {"javaStable", javaStable},
            {"stable", stable},
            {"sourcesAgree", sourcesAgree},
            {"contradiction", contradiction},
            {"observationAvailable", observationAvailable},
            {"decision", decision},
            {"trustedTier", "untrusted"}};
}

nlohmann::json makeControl(const RuleSpec& spec, const char* expected,
                           const SelinuxApi& nativeApi, JavaSelinuxApi& javaApi,
                           bool nativeContextsValid) {
    auto row = repeatedProbe(nativeApi, javaApi, spec, nativeContextsValid);
    row.update({{"id", spec.id},
                {"sourceContext", spec.source},
                {"targetContext", spec.target},
                {"targetClass", spec.targetClass},
                {"permission", spec.permission},
                {"expected", expected},
                {"contextsValid", nativeContextsValid}});
    row["nativePassed"] = policyOracleNativeDecision(row) == expected;
    row["javaPassed"] = policyOracleJavaDecision(row) == expected;
    return row;
}

nlohmann::json makeRule(const RuleSpec& spec, const SelinuxApi& nativeApi,
                        JavaSelinuxApi& javaApi) {
    const std::string sourceState = contextState(nativeApi, spec.source);
    const std::string targetState = contextState(nativeApi, spec.target);
    auto row = repeatedProbe(nativeApi, javaApi, spec,
                             sourceState == "valid" && targetState == "valid");
    const bool absentAllowedContradiction =
        targetState == "absent" && policyOracleJavaDecision(row) == "allowed";
    row["contradiction"] = row.value("contradiction", false) ||
                           absentAllowedContradiction;
    row.update({{"id", spec.id},
                {"sourceContext", spec.source},
                {"targetContext", spec.target},
                {"targetClass", spec.targetClass},
                {"permission", spec.permission},
                {"sourceContextState", sourceState},
                {"targetContextState", targetState},
                {"assessmentImpact", spec.assessmentImpact}});
    return row;
}

const nlohmann::json* findBySource(const nlohmann::json& rows, const std::string& source) {
    if (!rows.is_array()) return nullptr;
    for (const auto& row : rows) {
        if (row.is_object() && row.value("source", std::string()) == source) return &row;
    }
    return nullptr;
}

bool presentEnforcing(const nlohmann::json* row) {
    return row != nullptr && row->value("state", std::string()) == "present" &&
           row->value("mode", std::string()) == "enforcing";
}

bool anyRowContradiction(const nlohmann::json& rows) {
    if (!rows.is_array()) return false;
    for (const auto& row : rows) {
        if (!row.is_object()) continue;
        if (row.value("contradiction", false)) return true;
        if (row.value("nativeAvailable", false) && row.value("javaAvailable", false) &&
            !row.value("sourcesAgree", true)) {
            return true;
        }
    }
    return false;
}

void annotateTrust(nlohmann::json& snapshot) {
    const auto& carrier = snapshot["carrier"];
    const bool carrierValid = carrier.value("state", std::string()) == "present" &&
                              carrier.value("domain", std::string()) == "app_zygote";
    const bool uidValid = carrier.value("uidMatches", false);
    const auto* nativeEnforcement = findBySource(snapshot["enforcementSources"], "libselinux");
    const auto* javaEnforcement =
        findBySource(snapshot["enforcementSources"], "hidden_android_selinux");
    const bool nativeEnforcing = presentEnforcing(nativeEnforcement) &&
                                 nativeEnforcement->value("enabled", false);
    const bool javaEnforcing = presentEnforcing(javaEnforcement);
    const bool enforcementContradiction =
        nativeEnforcement != nullptr && javaEnforcement != nullptr &&
        nativeEnforcement->value("state", std::string()) == "present" &&
        javaEnforcement->value("state", std::string()) == "present" &&
        nativeEnforcement->value("mode", std::string()) !=
            javaEnforcement->value("mode", std::string());
    const auto* nativeQuery = findBySource(snapshot["querySources"], "native_libselinux");
    const auto* javaQuery =
        findBySource(snapshot["querySources"], "hidden_android_selinux");
    const bool nativeQueryAvailable = nativeQuery != nullptr &&
                                      nativeQuery->value("state", std::string()) == "available";
    const bool javaQueryAvailable = javaQuery != nullptr &&
                                    javaQuery->value("state", std::string()) == "available";
    const auto* positive = findPolicyOracleRow(
        snapshot["controls"], "positive_app_zygote_dyntransition");
    const auto* negative = findPolicyOracleRow(
        snapshot["controls"], "negative_untrusted_app_ptrace_init");
    const bool nativeControlsPassed = positive != nullptr && negative != nullptr &&
                                      positive->value("nativePassed", false) &&
                                      negative->value("nativePassed", false);
    const bool javaControlsPassed = positive != nullptr && negative != nullptr &&
                                    positive->value("javaPassed", false) &&
                                    negative->value("javaPassed", false);
    const bool contradiction = enforcementContradiction ||
                               anyRowContradiction(snapshot["controls"]);
    const bool nativeTrusted = carrierValid && uidValid && nativeEnforcing &&
                               nativeQueryAvailable && nativeControlsPassed && !contradiction;
    const bool javaControlled = carrierValid && uidValid && javaEnforcing &&
                                javaQueryAvailable && javaControlsPassed && !contradiction;

    for (auto& control : snapshot["controls"]) {
        const bool nativeTier = nativeTrusted && control.value("nativePassed", false);
        const bool javaTier = javaControlled && control.value("javaPassed", false);
        control["trustedTier"] = nativeTier ? "native_trusted"
                                              : (javaTier ? "java_controlled" : "untrusted");
    }
    for (auto& rule : snapshot["rules"]) {
        const bool ruleContradiction = rule.value("contradiction", false);
        const std::string targetState =
            rule.value("targetContextState", std::string("unavailable"));
        const bool nativeTier = nativeTrusted && !ruleContradiction &&
                                rule.value("sourceContextState", std::string()) == "valid" &&
                                (targetState == "absent" ||
                                 (targetState == "valid" &&
                                  policyOracleNativeDecision(rule) != "unavailable"));
        const bool javaTier = javaControlled && !ruleContradiction &&
                              rule.value("targetContextState", std::string()) != "absent" &&
                              policyOracleJavaDecision(rule) != "unavailable";
        rule["trustedTier"] = nativeTier ? "native_trusted"
                                           : (javaTier ? "java_controlled" : "untrusted");
    }
    snapshot["trust"] = {{"nativeTrusted", nativeTrusted},
                         {"javaControlled", javaControlled},
                         {"contradiction", contradiction}};
}

nlohmann::json emptyPayload() {
    return {{"overview", {{"oracleState", "inconclusive"},
                           {"gateCount", 6},
                           {"passedGateCount", 0},
                           {"ruleCount", 0},
                           {"findingCount", 0},
                           {"trustedNegativeCount", 0},
                           {"concealableNegativeCount", 0}}},
            {"carrier", nlohmann::json::object()},
            {"device", nlohmann::json::object()},
            {"trust", {{"nativeTrusted", false},
                       {"javaControlled", false},
                       {"contradiction", false}}},
            {"enforcementSources", nlohmann::json::array()},
            {"querySources", nlohmann::json::array()},
            {"controls", nlohmann::json::array()},
            {"rules", nlohmann::json::array()},
            {"findings", nlohmann::json::array()},
            {"concealableNegatives", nlohmann::json::array()},
            {"collectionErrors", nlohmann::json::array()}};
}

void copyArray(const nlohmann::json& source, nlohmann::json& target, const char* key) {
    if (source.contains(key) && source[key].is_array()) target[key] = source[key];
}

}  // namespace

const nlohmann::json* findPolicyOracleRow(const nlohmann::json& rows,
                                          const std::string& id) {
    if (!rows.is_array()) return nullptr;
    for (const auto& row : rows) {
        if (row.is_object() && row.value("id", std::string()) == id) return &row;
    }
    return nullptr;
}

std::string policyOracleNativeDecision(const nlohmann::json& row) {
    return repeatedValue(row, "nativeDecisions", "nativeAvailable", "nativeStable");
}

std::string policyOracleJavaDecision(const nlohmann::json& row) {
    return repeatedValue(row, "javaDecisions", "javaAvailable", "javaStable");
}

PolicyOracleNegatives collectPolicyOracleNegatives(
    const std::vector<const nlohmann::json*>& requiredRules) {
    PolicyOracleNegatives negatives;
    negatives.complete = true;
    for (const auto* rule : requiredRules) {
        if (rule == nullptr || rule->value("contradiction", false)) {
            negatives.complete = false;
            continue;
        }
        const std::string targetState =
            rule->value("targetContextState", std::string("unavailable"));
        if (targetState == "valid" &&
            rule->value("trustedTier", std::string()) == "native_trusted" &&
            policyOracleNativeDecision(*rule) == "denied") {
            ++negatives.trustedCount;
        } else if (targetState == "absent" &&
                   rule->value("sourceContextState", std::string()) == "valid" &&
                   policyOracleJavaDecision(*rule) != "allowed") {
            // Context validity is read by contextState() whichever tier answers the
            // query, and a hiding tool that removes the type defeats it either way, so a
            // native-trusted absence is no less concealable than a Java-controlled one.
            negatives.concealable.push_back(
                {{"ruleId", rule->value("id", std::string())},
                 {"targetContext", rule->value("targetContext", std::string())},
                 {"targetContextState", "absent"},
                 {"concealable", true},
                 {"trustedTier", rule->value("trustedTier", std::string("untrusted"))}});
        } else {
            negatives.complete = false;
        }
    }
    return negatives;
}

void addPolicyOracleWarning(nlohmann::json& payload, const std::string& source,
                            const std::string& message) {
    payload["collectionErrors"].push_back(
        {{"source", source}, {"errno", 0}, {"message", message}});
    // Every early return from snapshot evaluation funnels through here, and all of them
    // surface to the consumer as an undifferentiated INCONCLUSIVE. Logging the reason is
    // what makes an unusable oracle diagnosable on a device.
    LOGI_TAG("POLICY_ORACLE", "event=policy_oracle_warning source=%s message=%s",
             source.c_str(), message.c_str());
}

nlohmann::json collectPolicyOracleSnapshot(JNIEnv* env, jint applicationUid) {
    nlohmann::json snapshot = {{"schemaVersion", 2},
                               {"carrier", nlohmann::json::object()},
                               {"device", {{"buildType", readProperty("ro.build.type")}}},
                               {"trust", nlohmann::json::object()},
                               {"enforcementSources", nlohmann::json::array()},
                               {"querySources", nlohmann::json::array()},
                               {"controls", nlohmann::json::array()},
                               {"rules", nlohmann::json::array()},
                               {"collectionErrors", nlohmann::json::array()}};
    auto& errors = snapshot["collectionErrors"];

    int contextError = 0;
    const std::string currentContext = readTextFile("/proc/self/attr/current", contextError);
    const jint currentUid = static_cast<jint>(getuid());
    snapshot["carrier"] = {{"state", currentContext.empty() ? "unavailable" : "present"},
                           {"context", currentContext},
                           {"domain", contextDomain(currentContext)},
                           {"uid", currentUid},
                           {"applicationUid", applicationUid},
                           {"uidMatches", currentUid == applicationUid}};
    if (currentContext.empty()) {
        addError(errors, "carrier_context", "Unable to read /proc/self/attr/current.",
                 contextError);
    }

    SelinuxApi nativeApi = loadSelinuxApi(errors);
    JavaSelinuxApi javaApi = loadJavaSelinuxApi(env, errors);
    // An app zygote that leaks a descriptor into every forked child violates the zygote
    // descriptor contract, so a native query must not leave one behind. That used to be
    // approximated by requiring selinux_status_close to resolve, but AOSP does not export
    // that symbol at all, so the check never passed and the native tier was dead on every
    // device. Measure the invariant instead: issue one warm-up query and compare the
    // descriptor count around it.
    if (nativeApi.complete()) {
        const int before = countOpenDescriptors();
        nativeApi.isEnabled();
        const int after = countOpenDescriptors();
        const bool leaked = before >= 0 && after > before;
        snapshot["nativeWarmup"] = {{"descriptorsBefore", before},
                                    {"descriptorsAfter", after},
                                    {"leaked", leaked},
                                    {"teardownAvailable", nativeApi.closeStatus != nullptr}};
        if (leaked && nativeApi.closeStatus != nullptr) {
            nativeApi.closeStatus();
            snapshot["nativeWarmup"]["descriptorsAfterTeardown"] = countOpenDescriptors();
        }
        if (leaked && nativeApi.closeStatus == nullptr) {
            // Only now is the original concern real: a descriptor was retained and there
            // is no way to release it. Stop issuing native queries, keep the Java tier.
            nativeApi.isEnabled = nullptr;
            nativeApi.getEnforce = nullptr;
            nativeApi.checkContext = nullptr;
            nativeApi.checkAccess = nullptr;
            addError(errors, "native_libselinux",
                     "A native SELinux query retained a descriptor and no teardown symbol "
                     "is available; native policy queries were skipped to preserve the "
                     "app-zygote descriptor contract.");
        }
    }
    if (!nativeApi.complete() && !javaApi.queryAvailable()) {
        snapshot["collectionFailure"] = {
            {"source", "native_libselinux"},
            {"message",
             "Neither libselinux nor the hidden Android SELinux API offered a usable "
             "policy query path."}};
        return snapshot;
    }
    snapshot["querySources"].push_back(
        {{"source", "native_libselinux"},
         {"state", nativeApi.complete() ? "available" : "unavailable"},
         {"required", false}});
    snapshot["querySources"].push_back(
        {{"source", "hidden_android_selinux"},
         {"state", javaApi.queryAvailable() ? "available" : "unavailable"},
         {"required", false}});

    int enabled = -1;
    int enforcing = -1;
    if (nativeApi.isEnabled != nullptr) enabled = nativeApi.isEnabled();
    if (enabled > 0 && nativeApi.getEnforce != nullptr) enforcing = nativeApi.getEnforce();
    std::string nativeMode = "unknown";
    if (enabled == 0) nativeMode = "disabled";
    if (enabled > 0 && enforcing == 0) nativeMode = "permissive";
    if (enabled > 0 && enforcing == 1) nativeMode = "enforcing";
    snapshot["enforcementSources"].push_back(
        {{"source", "libselinux"},
         {"state", nativeMode == "unknown" ? "unavailable" : "present"},
         {"enabled", enabled > 0},
         {"mode", nativeMode}});
    if (nativeMode == "unknown") {
        addError(errors, "libselinux_enforcement",
                 "Native SELinux enforcement state is unavailable.");
    }

    if (javaApi.enforcementAvailable()) {
        const jboolean value = env->CallStaticBooleanMethod(javaApi.clazz, javaApi.isEnforced);
        const bool failed = env->ExceptionCheck();
        clearJniException(env);
        snapshot["enforcementSources"].push_back(
            {{"source", "hidden_android_selinux"},
             {"state", failed ? "unavailable" : "present"},
             {"enabled", failed ? false : true},
             {"mode", failed ? "unknown" : (value == JNI_TRUE ? "enforcing" : "permissive")}});
        if (failed) {
            addError(errors, "hidden_android_selinux_enforcement",
                     "Hidden Android SELinux enforcement query failed.");
        }
    } else {
        snapshot["enforcementSources"].push_back(
            {{"source", "hidden_android_selinux"},
             {"state", "unavailable"},
             {"enabled", false},
             {"mode", "unknown"}});
    }

    const RuleSpec positive = {"positive_app_zygote_dyntransition",
                               "u:r:app_zygote:s0", "u:r:isolated_app:s0",
                               "process", "dyntransition", "control"};
    const RuleSpec negative = {"negative_untrusted_app_ptrace_init",
                               "u:r:untrusted_app:s0", "u:r:init:s0",
                               "process", "ptrace", "control"};
    snapshot["controls"].push_back(makeControl(
        positive, "allowed", nativeApi, javaApi,
        contextState(nativeApi, positive.source) == "valid" &&
            contextState(nativeApi, positive.target) == "valid"));
    snapshot["controls"].push_back(makeControl(
        negative, "denied", nativeApi, javaApi,
        contextState(nativeApi, negative.source) == "valid" &&
            contextState(nativeApi, negative.target) == "valid"));

    static constexpr RuleSpec kRules[] = {
        {"lsposed_file_read", "u:r:untrusted_app:s0", "u:object_r:lsposed_file:s0",
         "file", "read", "moderate_or_weak_finding"},
        {"xposed_data_read", "u:r:untrusted_app:s0", "u:object_r:xposed_data:s0",
         "file", "read", "weak_finding"},
        {"system_server_execmem", "u:r:system_server:s0", "u:r:system_server:s0",
         "process", "execmem", "telemetry_only"},
        {"magisk_binder_call", "u:r:untrusted_app:s0", "u:r:magisk:s0",
         "binder", "call", "weak_finding"},
        {"ksu_file_read", "u:r:untrusted_app:s0", "u:object_r:ksu_file:s0",
         "file", "read", "weak_finding"},
        {"adbd_adbroot_binder_call", "u:r:adbd:s0", "u:r:adbroot:s0",
         "binder", "call", "weak_finding"},
        {"shell_su_transition", "u:r:shell:s0", "u:r:su:s0",
         "process", "transition", "user_build_weak_finding"},
    };
    for (const auto& spec : kRules) {
        snapshot["rules"].push_back(makeRule(spec, nativeApi, javaApi));
    }
    annotateTrust(snapshot);
    return snapshot;
}

PolicyOracleView evaluatePolicyOracleSnapshot(
    const nlohmann::json& snapshot,
    const std::vector<std::string>& consumerRuleIds) {
    PolicyOracleView view;
    view.payload = emptyPayload();
    if (!snapshot.is_object()) {
        addPolicyOracleWarning(view.payload, "carrier", "Policy-oracle snapshot is malformed.");
        return view;
    }
    if (snapshot.contains("carrier") && snapshot["carrier"].is_object()) {
        view.payload["carrier"] = snapshot["carrier"];
    }
    if (snapshot.contains("device") && snapshot["device"].is_object()) {
        view.payload["device"] = snapshot["device"];
    }
    copyArray(snapshot, view.payload, "enforcementSources");
    copyArray(snapshot, view.payload, "querySources");
    copyArray(snapshot, view.payload, "controls");
    copyArray(snapshot, view.payload, "collectionErrors");

    if (snapshot.value("schemaVersion", 0) != 2) {
        addPolicyOracleWarning(view.payload, "carrier",
                               "Unsupported policy-oracle snapshot schema.");
        return view;
    }
    if (snapshot.contains("collectionFailure") && snapshot["collectionFailure"].is_object()) {
        const auto& failure = snapshot["collectionFailure"];
        addPolicyOracleWarning(
            view.payload, failure.value("source", std::string("carrier")),
            failure.value("message", std::string("Policy-oracle snapshot is unavailable.")));
        return view;
    }
    if (!snapshot.contains("rules") || !snapshot["rules"].is_array()) {
        addPolicyOracleWarning(view.payload, "rules", "Policy-oracle rule registry is missing.");
        return view;
    }

    std::unordered_set<std::string> requested(consumerRuleIds.begin(), consumerRuleIds.end());
    for (const auto& rule : snapshot["rules"]) {
        if (rule.is_object() && requested.erase(rule.value("id", std::string())) > 0) {
            view.payload["rules"].push_back(rule);
        }
    }
    if (!requested.empty()) {
        addPolicyOracleWarning(view.payload, "rules",
                               "Policy-oracle snapshot omitted a required registered rule.");
        return view;
    }

    const auto& carrier = view.payload["carrier"];
    const bool carrierValid = carrier.is_object() &&
                              carrier.value("state", std::string()) == "present" &&
                              carrier.value("domain", std::string()) == "app_zygote";
    const bool uidValid = carrierValid && carrier.value("uidMatches", false);
    if (carrierValid) ++view.passedGateCount;
    if (uidValid) ++view.passedGateCount;

    const auto* nativeEnforcement =
        findBySource(view.payload["enforcementSources"], "libselinux");
    const auto* javaEnforcement =
        findBySource(view.payload["enforcementSources"], "hidden_android_selinux");
    const bool nativeEnforcing = presentEnforcing(nativeEnforcement) &&
                                 nativeEnforcement->value("enabled", false);
    const bool javaEnforcing = presentEnforcing(javaEnforcement);
    const bool enforcementContradiction =
        nativeEnforcement != nullptr && javaEnforcement != nullptr &&
        nativeEnforcement->value("state", std::string()) == "present" &&
        javaEnforcement->value("state", std::string()) == "present" &&
        nativeEnforcement->value("mode", std::string()) !=
            javaEnforcement->value("mode", std::string());
    if (nativeEnforcing || javaEnforcing) ++view.passedGateCount;

    const auto* nativeQuery =
        findBySource(view.payload["querySources"], "native_libselinux");
    const auto* javaQuery =
        findBySource(view.payload["querySources"], "hidden_android_selinux");
    const bool nativeQueryAvailable = nativeQuery != nullptr &&
                                      nativeQuery->value("state", std::string()) == "available";
    const bool javaQueryAvailable = javaQuery != nullptr &&
                                    javaQuery->value("state", std::string()) == "available";
    if (nativeQueryAvailable || javaQueryAvailable) ++view.passedGateCount;

    const auto* positive = findPolicyOracleRow(
        view.payload["controls"], "positive_app_zygote_dyntransition");
    const auto* negative = findPolicyOracleRow(
        view.payload["controls"], "negative_untrusted_app_ptrace_init");
    const bool nativeControlsPassed = positive != nullptr && negative != nullptr &&
                                      positive->value("nativePassed", false) &&
                                      negative->value("nativePassed", false);
    const bool javaControlsPassed = positive != nullptr && negative != nullptr &&
                                    positive->value("javaPassed", false) &&
                                    negative->value("javaPassed", false);
    if (nativeControlsPassed || javaControlsPassed) ++view.passedGateCount;

    view.contradiction = enforcementContradiction ||
                         anyRowContradiction(view.payload["controls"]) ||
                         anyRowContradiction(view.payload["rules"]);
    if (!view.contradiction) ++view.passedGateCount;
    view.nativeTrusted = carrierValid && uidValid && nativeEnforcing &&
                         nativeQueryAvailable && nativeControlsPassed && !view.contradiction;
    view.javaControlled = carrierValid && uidValid && javaEnforcing &&
                          javaQueryAvailable && javaControlsPassed && !view.contradiction;

    for (auto& rule : view.payload["rules"]) {
        const bool ruleContradiction = rule.value("contradiction", false) ||
            (rule.value("targetContextState", std::string()) == "absent" &&
             policyOracleJavaDecision(rule) == "allowed");
        rule["contradiction"] = ruleContradiction;
        if (ruleContradiction) view.contradiction = true;
    }
    if (view.contradiction) {
        view.nativeTrusted = false;
        view.javaControlled = false;
    }

    // Each gate is reported individually. Both consumers collapse any gate failure into a
    // single INCONCLUSIVE outcome, which is correct for the contract but leaves no way to
    // tell an unreadable carrier from a denied query or a contradicting source when
    // diagnosing a device.
    // Context-state counts make it visible whether the policy can be asked about a
    // context at all. Before the selinuxfs fallback these were always "unavailable",
    // which silently disabled the absent-target contradiction rule below.
    int contextValid = 0;
    int contextAbsent = 0;
    int contextUnavailable = 0;
    if (view.payload.contains("rules") && view.payload["rules"].is_array()) {
        for (const auto& rule : view.payload["rules"]) {
            for (const char* field : {"sourceContextState", "targetContextState"}) {
                const std::string state = rule.value(field, std::string("unavailable"));
                if (state == "valid") ++contextValid;
                else if (state == "absent") ++contextAbsent;
                else ++contextUnavailable;
            }
        }
    }
    LOGI_TAG("POLICY_ORACLE",
             "event=policy_oracle_contexts valid=%d absent=%d unavailable=%d",
             contextValid, contextAbsent, contextUnavailable);

    LOGI_TAG("POLICY_ORACLE",
             "event=policy_oracle_trust carrierValid=%d uidValid=%d carrierDomain=%s "
             "nativeEnforcing=%d javaEnforcing=%d nativeQuery=%d javaQuery=%d "
             "nativeControls=%d javaControls=%d contradiction=%d gates=%d/6 "
             "nativeTrusted=%d javaControlled=%d",
             carrierValid ? 1 : 0, uidValid ? 1 : 0,
             carrier.is_object() ? carrier.value("domain", std::string("?")).c_str() : "?",
             nativeEnforcing ? 1 : 0, javaEnforcing ? 1 : 0,
             nativeQueryAvailable ? 1 : 0, javaQueryAvailable ? 1 : 0,
             nativeControlsPassed ? 1 : 0, javaControlsPassed ? 1 : 0,
             view.contradiction ? 1 : 0, view.passedGateCount,
             view.nativeTrusted ? 1 : 0, view.javaControlled ? 1 : 0);

    for (auto& rule : view.payload["rules"]) {
        const std::string targetState =
            rule.value("targetContextState", std::string("unavailable"));
        const bool nativeTier = view.nativeTrusted &&
                                rule.value("sourceContextState", std::string()) == "valid" &&
                                (targetState == "absent" ||
                                 (targetState == "valid" &&
                                  policyOracleNativeDecision(rule) != "unavailable"));
        const bool javaTier = view.javaControlled && !rule.value("contradiction", false) &&
                              rule.value("targetContextState", std::string()) != "absent" &&
                              policyOracleJavaDecision(rule) != "unavailable";
        rule["trustedTier"] = nativeTier ? "native_trusted"
                                           : (javaTier ? "java_controlled" : "untrusted");
    }
    view.payload["trust"] = {{"nativeTrusted", view.nativeTrusted},
                             {"javaControlled", view.javaControlled},
                             {"contradiction", view.contradiction}};
    view.structurallyValid = true;
    return view;
}

PolicyOracleView evaluatePolicyOracleSnapshotBytes(
    const std::string& snapshotBytes,
    const std::vector<std::string>& consumerRuleIds) {
    if (snapshotBytes.empty()) {
        PolicyOracleView view;
        view.payload = emptyPayload();
        addPolicyOracleWarning(view.payload, "carrier",
                               "No app-zygote policy snapshot was supplied for this scan.");
        return view;
    }
    if (snapshotBytes.size() > kMaximumPolicyOracleSnapshotBytes) {
        PolicyOracleView view;
        view.payload = emptyPayload();
        addPolicyOracleWarning(view.payload, "carrier",
                               "App-zygote policy snapshot exceeded 64 KiB.");
        return view;
    }
    return evaluatePolicyOracleSnapshot(
        nlohmann::json::parse(snapshotBytes, nullptr, false), consumerRuleIds);
}

}  // namespace tamperprobe

extern "C" JNIEXPORT jbyteArray JNICALL
Java_io_leemikepop_tamperprobe_lab_internal_policyoracle_PolicyOracleNativeBridge_nativeCollectSnapshot(
    JNIEnv* env, jclass, jint applicationUid) {
    try {
        const std::string value =
            tamperprobe::collectPolicyOracleSnapshot(env, applicationUid).dump();
        jbyteArray result = env->NewByteArray(static_cast<jsize>(value.size()));
        if (result != nullptr && !value.empty()) {
            env->SetByteArrayRegion(result, 0, static_cast<jsize>(value.size()),
                                    reinterpret_cast<const jbyte*>(value.data()));
        }
        return result;
    } catch (...) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return nullptr;
    }
}
