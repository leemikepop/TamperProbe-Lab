#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "../../common/log.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"
#include "dangerous_packages_logic.h"
#include "package_targets.h"

namespace tamperprobe {

PathProbeResult probePathStatus(const char* path) {
    struct stat fileStat{};

#if defined(__aarch64__) || defined(__x86_64__)
    const int resultCode = static_cast<int>(syscall(__NR_newfstatat, AT_FDCWD, path, &fileStat, 0));
#else
    const int resultCode = static_cast<int>(syscall(__NR_fstatat64, AT_FDCWD, path, &fileStat, 0));
#endif

    const int errorCode = errno;
    return classifyPathProbeResult(resultCode, errorCode);
}

namespace {

constexpr std::size_t kMaxRetainedIssues = 16;

struct UnitIssue {
    std::string code;
    std::string message;
    nlohmann::json attributes = nlohmann::json::object();
};

struct PackageIdentityObservation {
    int targetCount = 0;
    int completedQueryCount = 0;
    int visiblePackageCount = -1;
    std::string selfPackageName;
    std::vector<std::string> detectedPackages;
    std::vector<UnitIssue> issues;
    int droppedIssueCount = 0;
};

struct AppDataPathObservation {
    int attemptedPathCount = 0;
    int completedPathCount = 0;
    int notFoundPathCount = 0;
    int unconfirmedNotFoundCount = 0;
    std::string selfControl = "not_attempted";
    std::string crossPackageControl = "not_attempted";
    bool isolationDetected = false;
    std::vector<std::string> foundPaths;
    std::vector<std::string> inaccessiblePaths;
    std::vector<UnitIssue> issues;
    int droppedIssueCount = 0;
};

void addIssue(std::vector<UnitIssue>& issues, int& droppedIssueCount,
              std::string code, std::string message,
              nlohmann::json attributes = nlohmann::json::object()) {
    if (issues.size() < kMaxRetainedIssues) {
        issues.push_back({std::move(code), std::move(message), std::move(attributes)});
    } else {
        ++droppedIssueCount;
    }
}

nlohmann::json serializeIssues(const std::vector<UnitIssue>& issues, int droppedIssueCount) {
    nlohmann::json result = nlohmann::json::array();
    for (const auto& issue : issues) {
        result.push_back({{"code", issue.code},
                          {"message", issue.message},
                          {"attributes", issue.attributes}});
    }
    if (droppedIssueCount > 0) {
        result.push_back({{"code", "collection-issues-truncated"},
                          {"message", "Additional collection issues were omitted"},
                          {"attributes", {{"droppedCount", std::to_string(droppedIssueCount)}}}});
    }
    return result;
}

bool clearPackageQueryException(JNIEnv* env, const char* event) {
    if (!env->ExceptionCheck()) return false;
    env->ExceptionClear();
    LOGW_TAG("PackageManager", "event=%s", event);
    return true;
}

void collectPackageIdentityVisibility(
    const DetectionContext& context, const std::vector<std::string>& targets,
    PackageIdentityObservation& observation) {
    observation.targetCount = static_cast<int>(targets.size());
    JNIEnv* env = context.env;
    if (env == nullptr || context.androidContext == nullptr) {
        addIssue(observation.issues, observation.droppedIssueCount,
                 "package-manager-unavailable", "JNI context is unavailable");
        return;
    }

    jclass contextClass = env->GetObjectClass(context.androidContext);
    if (contextClass == nullptr) {
        clearPackageQueryException(env, "context_class_lookup_failed");
        addIssue(observation.issues, observation.droppedIssueCount,
                 "package-manager-unavailable", "Android Context class lookup failed");
        return;
    }

    jmethodID getPackageManager =
        env->GetMethodID(contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    if (getPackageManager == nullptr) {
        clearPackageQueryException(env, "get_package_manager_lookup_failed");
        env->DeleteLocalRef(contextClass);
        addIssue(observation.issues, observation.droppedIssueCount,
                 "package-manager-unavailable", "PackageManager method lookup failed");
        return;
    }

    jobject packageManager = env->CallObjectMethod(context.androidContext, getPackageManager);
    env->DeleteLocalRef(contextClass);
    if (clearPackageQueryException(env, "get_package_manager_failed") || packageManager == nullptr) {
        if (packageManager != nullptr) env->DeleteLocalRef(packageManager);
        addIssue(observation.issues, observation.droppedIssueCount,
                 "package-manager-unavailable", "PackageManager acquisition failed");
        return;
    }

    jclass packageManagerClass = env->GetObjectClass(packageManager);
    jclass intentClass = env->FindClass("android/content/Intent");
    jclass listClass = env->FindClass("java/util/List");
    if (packageManagerClass == nullptr || intentClass == nullptr || listClass == nullptr) {
        clearPackageQueryException(env, "framework_class_lookup_failed");
        if (packageManagerClass != nullptr) env->DeleteLocalRef(packageManagerClass);
        if (intentClass != nullptr) env->DeleteLocalRef(intentClass);
        if (listClass != nullptr) env->DeleteLocalRef(listClass);
        env->DeleteLocalRef(packageManager);
        addIssue(observation.issues, observation.droppedIssueCount,
                 "package-manager-unavailable", "Required framework class lookup failed");
        return;
    }

    jmethodID getApplicationInfo = env->GetMethodID(
        packageManagerClass, "getApplicationInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;");
    jmethodID getLaunchIntent = env->GetMethodID(
        packageManagerClass, "getLaunchIntentForPackage",
        "(Ljava/lang/String;)Landroid/content/Intent;");
    jmethodID queryIntentActivities = env->GetMethodID(
        packageManagerClass, "queryIntentActivities",
        "(Landroid/content/Intent;I)Ljava/util/List;");
    jmethodID intentConstructor = env->GetMethodID(intentClass, "<init>", "(Ljava/lang/String;)V");
    jmethodID listIsEmpty = env->GetMethodID(listClass, "isEmpty", "()Z");
    if (getApplicationInfo == nullptr || getLaunchIntent == nullptr || queryIntentActivities == nullptr ||
        intentConstructor == nullptr || listIsEmpty == nullptr) {
        clearPackageQueryException(env, "framework_method_lookup_failed");
        env->DeleteLocalRef(listClass);
        env->DeleteLocalRef(intentClass);
        env->DeleteLocalRef(packageManagerClass);
        env->DeleteLocalRef(packageManager);
        addIssue(observation.issues, observation.droppedIssueCount,
                 "package-manager-unavailable", "Required framework method lookup failed");
        return;
    }

    // Positive control. An application can always resolve itself regardless of package
    // visibility, so if this query fails the query mechanism is broken and a run that
    // finds nothing means nothing. Without it, a detector that cannot see any package
    // is indistinguishable from a device that has none.
    bool selfQuerySucceeded = false;
    {
        jclass selfContextClass = env->GetObjectClass(context.androidContext);
        jmethodID getPackageName = selfContextClass == nullptr
                                       ? nullptr
                                       : env->GetMethodID(selfContextClass, "getPackageName",
                                                          "()Ljava/lang/String;");
        if (getPackageName != nullptr) {
            auto* ownName = static_cast<jstring>(
                env->CallObjectMethod(context.androidContext, getPackageName));
            if (!clearPackageQueryException(env, "self_package_name_failed") &&
                ownName != nullptr) {
                // Kept for the app-data path unit, whose positive control is this
                // application's own data directory.
                if (const char* chars = env->GetStringUTFChars(ownName, nullptr)) {
                    observation.selfPackageName = chars;
                    env->ReleaseStringUTFChars(ownName, chars);
                }
                jobject ownInfo =
                    env->CallObjectMethod(packageManager, getApplicationInfo, ownName, 0);
                const bool raised = clearPackageQueryException(env, "self_package_query_failed");
                selfQuerySucceeded = !raised && ownInfo != nullptr;
                if (ownInfo != nullptr) env->DeleteLocalRef(ownInfo);
                env->DeleteLocalRef(ownName);
            }
        } else {
            clearPackageQueryException(env, "self_package_name_lookup_failed");
        }
        if (selfContextClass != nullptr) env->DeleteLocalRef(selfContextClass);
    }
    // Cross-package control. "android" is forceQueryable on every device, so it must
    // resolve regardless of package-visibility filtering. Querying only our own package
    // is too weak: an application can always see itself even when every cross-package
    // query is being filtered.
    bool frameworkQuerySucceeded = false;
    {
        jstring frameworkName = env->NewStringUTF("android");
        if (frameworkName != nullptr) {
            jobject frameworkInfo =
                env->CallObjectMethod(packageManager, getApplicationInfo, frameworkName, 0);
            const bool raised = clearPackageQueryException(env, "framework_package_query_failed");
            frameworkQuerySucceeded = !raised && frameworkInfo != nullptr;
            if (frameworkInfo != nullptr) env->DeleteLocalRef(frameworkInfo);
            env->DeleteLocalRef(frameworkName);
        }
    }
    // How much of the package inventory this process can see at all. A high count with
    // zero target hits is a meaningful negative; a count of one or two means the channel
    // is filtered and an empty result carries no information.
    int visiblePackageCount = -1;
    std::unordered_set<std::string> visibleNames;
    {
        jmethodID getInstalled = env->GetMethodID(
            packageManagerClass, "getInstalledApplications", "(I)Ljava/util/List;");
        if (getInstalled != nullptr) {
            jobject installed = env->CallObjectMethod(packageManager, getInstalled, 0);
            if (!clearPackageQueryException(env, "installed_applications_failed") &&
                installed != nullptr) {
                jmethodID listSize = env->GetMethodID(listClass, "size", "()I");
                jmethodID listGet = env->GetMethodID(listClass, "get", "(I)Ljava/lang/Object;");
                if (listSize != nullptr && listGet != nullptr) {
                    visiblePackageCount = env->CallIntMethod(installed, listSize);
                    if (env->ExceptionCheck()) {
                        env->ExceptionClear();
                        visiblePackageCount = -1;
                    }
                    // Read the inventory once and match names locally. Enumerating is
                    // both cheaper than one query per target and immune to whatever
                    // makes the per-package lookup miss packages this same process can
                    // plainly see in the list.
                    for (int index = 0; index < visiblePackageCount; ++index) {
                        jobject entry = env->CallObjectMethod(installed, listGet, index);
                        if (clearPackageQueryException(env, "installed_entry_failed") ||
                            entry == nullptr) {
                            continue;
                        }
                        jclass entryClass = env->GetObjectClass(entry);
                        jfieldID nameField =
                            entryClass == nullptr
                                ? nullptr
                                : env->GetFieldID(entryClass, "packageName",
                                                  "Ljava/lang/String;");
                        if (nameField != nullptr) {
                            auto* nameString =
                                static_cast<jstring>(env->GetObjectField(entry, nameField));
                            if (nameString != nullptr) {
                                const char* chars = env->GetStringUTFChars(nameString, nullptr);
                                if (chars != nullptr) {
                                    visibleNames.insert(std::string(chars));
                                    env->ReleaseStringUTFChars(nameString, chars);
                                }
                                env->DeleteLocalRef(nameString);
                            }
                        } else {
                            env->ExceptionClear();
                        }
                        if (entryClass != nullptr) env->DeleteLocalRef(entryClass);
                        env->DeleteLocalRef(entry);
                    }
                }
            }
            if (installed != nullptr) env->DeleteLocalRef(installed);
        } else {
            clearPackageQueryException(env, "installed_applications_lookup_failed");
        }
    }
    observation.visiblePackageCount = visiblePackageCount;
    LOGI_TAG("PackageManager",
             "event=query_controls self=%d framework=%d visiblePackages=%d",
             selfQuerySucceeded ? 1 : 0, frameworkQuerySucceeded ? 1 : 0, visiblePackageCount);
    if (!frameworkQuerySucceeded) {
        addIssue(observation.issues, observation.droppedIssueCount,
                 "package-query-control-failed",
                 "The cross-package query control failed, so an empty result cannot be "
                 "read as an absence of the target packages.");
    }
    if (!selfQuerySucceeded) {
        addIssue(observation.issues, observation.droppedIssueCount,
                 "package-query-control-failed",
                 "The PackageManager self-query control failed, so an empty result cannot "
                 "be read as an absence of the target packages.");
    }

    std::unordered_set<std::string> detected;
    for (const auto& packageName : targets) {
        jstring javaPackageName = env->NewStringUTF(packageName.c_str());
        if (javaPackageName == nullptr) {
            clearPackageQueryException(env, "package_string_allocation_failed");
            addIssue(observation.issues, observation.droppedIssueCount,
                     "package-query-failed", "Package query string allocation failed",
                     {{"package", packageName}});
            continue;
        }

        jobject applicationInfo =
            env->CallObjectMethod(packageManager, getApplicationInfo, javaPackageName, 0);
        const bool packageQueryRaised = env->ExceptionCheck();
        if (packageQueryRaised) env->ExceptionClear();
        // Enumeration is the primary source; the per-package lookup only fills gaps.
        const bool enumerated = visibleNames.count(packageName) != 0;
        const bool applicationVisible =
            enumerated || (!packageQueryRaised && applicationInfo != nullptr);
        if (applicationInfo != nullptr) env->DeleteLocalRef(applicationInfo);

        bool launcherVisible = false;
        bool launcherQueryFailed = false;
        if (!applicationVisible) {
            jobject launchIntent = env->CallObjectMethod(packageManager, getLaunchIntent, javaPackageName);
            launcherQueryFailed = clearPackageQueryException(env, "launcher_query_failed");
            launcherVisible = !launcherQueryFailed && launchIntent != nullptr;
            if (launchIntent != nullptr) env->DeleteLocalRef(launchIntent);
        }

        env->DeleteLocalRef(javaPackageName);
        if (launcherQueryFailed) {
            addIssue(observation.issues, observation.droppedIssueCount,
                     "package-query-failed", "Package launch-intent query failed",
                     {{"package", packageName}});
            continue;
        }
        ++observation.completedQueryCount;
        if (applicationVisible || launcherVisible) detected.insert(packageName);
    }

    std::vector<PackageIntentRule> intentRules;
    if (collectPackageIntentRules(context, intentRules)) {
        for (const auto& rule : intentRules) {
            if (detected.find(rule.packageName) != detected.end()) continue;

            jstring javaAction = env->NewStringUTF(rule.action.c_str());
            if (javaAction == nullptr) {
                clearPackageQueryException(env, "intent_action_allocation_failed");
                addIssue(observation.issues, observation.droppedIssueCount,
                         "intent-query-failed", "Intent action allocation failed",
                         {{"package", rule.packageName}, {"action", rule.action}});
                continue;
            }
            jobject intent = env->NewObject(intentClass, intentConstructor, javaAction);
            env->DeleteLocalRef(javaAction);
            if (clearPackageQueryException(env, "intent_construction_failed") || intent == nullptr) {
                if (intent != nullptr) env->DeleteLocalRef(intent);
                addIssue(observation.issues, observation.droppedIssueCount,
                         "intent-query-failed", "Intent construction failed",
                         {{"package", rule.packageName}, {"action", rule.action}});
                continue;
            }

            jobject resolvers = env->CallObjectMethod(packageManager, queryIntentActivities, intent, 0);
            env->DeleteLocalRef(intent);
            if (clearPackageQueryException(env, "intent_query_failed") || resolvers == nullptr) {
                if (resolvers != nullptr) env->DeleteLocalRef(resolvers);
                addIssue(observation.issues, observation.droppedIssueCount,
                         "intent-query-failed", "Intent resolver query failed",
                         {{"package", rule.packageName}, {"action", rule.action}});
                continue;
            }
            const bool resolvable = env->CallBooleanMethod(resolvers, listIsEmpty) == JNI_FALSE;
            const bool queryFailed = clearPackageQueryException(env, "intent_result_failed");
            env->DeleteLocalRef(resolvers);
            if (queryFailed) {
                addIssue(observation.issues, observation.droppedIssueCount,
                         "intent-query-failed", "Intent resolver result could not be read",
                         {{"package", rule.packageName}, {"action", rule.action}});
            } else if (resolvable) {
                detected.insert(rule.packageName);
            }
        }
    } else {
        LOGW_TAG("PackageManager", "event=intent_rules_unavailable");
        addIssue(observation.issues, observation.droppedIssueCount,
                 "intent-rules-unavailable", "Generated package Intent rules are unavailable");
    }

    observation.detectedPackages.insert(
        observation.detectedPackages.end(), detected.begin(), detected.end());
    std::sort(observation.detectedPackages.begin(), observation.detectedPackages.end());

    env->DeleteLocalRef(listClass);
    env->DeleteLocalRef(intentClass);
    env->DeleteLocalRef(packageManagerClass);
    env->DeleteLocalRef(packageManager);
}

const char* pathProbeStateName(PathProbeState state) {
    switch (state) {
        case PathProbeState::Exists:
            return "exists";
        case PathProbeState::NotFound:
            return "not_found";
        case PathProbeState::Inaccessible:
            return "inaccessible";
        case PathProbeState::Error:
            return "error";
    }
    return "error";
}

// Installed on every Android build, never a concealment target, and - unlike
// com.google.android.gms, which stayed visible on both fleet devices - not exempted from
// app data isolation. If its data directory is hidden, so is every other application's.
constexpr const char* kCrossPackageDataControl = "com.android.settings";

AppDataPathObservation collectAppDataPathVisibility(const std::vector<std::string>& targets,
                                                    const std::string& selfPackageName) {
    AppDataPathObservation observation;

    // Controls. Current Android isolates app data: each application's view of /data/data
    // and /data/user/0 contains its own directory and hides almost every other one, so an
    // installed package's directory reads ENOENT exactly as an absent one does. Without
    // these controls that not-found was counted as a completed answer, and the unit
    // reported a confident negative it had no way to observe. Measured on both fleet
    // devices (Android 13 and 17): own directory visible, com.android.settings and the
    // installed indicator packages not found.
    if (selfPackageName.empty()) {
        addIssue(observation.issues, observation.droppedIssueCount, "app-data-controls-not-run",
                 "This application's package name was unavailable, so the path probe "
                 "controls could not run");
    } else {
        observation.selfControl =
            pathProbeStateName(probePathStatus(("/data/data/" + selfPackageName).c_str()).state);
        observation.crossPackageControl = pathProbeStateName(
            probePathStatus((std::string("/data/data/") + kCrossPackageDataControl).c_str())
                .state);
        if (observation.selfControl != "exists") {
            addIssue(observation.issues, observation.droppedIssueCount,
                     "app-data-self-control-failed",
                     "This application's own data directory was not visible, so the path "
                     "probe cannot be trusted",
                     {{"selfControl", observation.selfControl}});
        }
    }
    // A not-found only answers the question when both controls are visible.
    const bool notFoundIsAnswer =
        observation.selfControl == "exists" && observation.crossPackageControl == "exists";
    // Isolation is structural: this process sees itself and not others. A failed self
    // control is a different thing - the channel itself is broken - and does not count.
    observation.isolationDetected =
        observation.selfControl == "exists" && observation.crossPackageControl != "exists";

    for (const auto& packageName : targets) {
        const std::vector<std::string> paths = {
            "/data/data/" + packageName,
            "/data/user/0/" + packageName,
        };
        for (const auto& path : paths) {
            ++observation.attemptedPathCount;
            const PathProbeResult probe = probePathStatus(path.c_str());
            switch (probe.state) {
                case PathProbeState::Exists:
                    ++observation.completedPathCount;
                    observation.foundPaths.push_back(path);
                    LOGI_TAG("PackagePaths", "event=path_visible path=%s", path.c_str());
                    break;
                case PathProbeState::NotFound:
                    if (notFoundIsAnswer) {
                        ++observation.completedPathCount;
                        ++observation.notFoundPathCount;
                    } else {
                        ++observation.unconfirmedNotFoundCount;
                    }
                    break;
                case PathProbeState::Inaccessible:
                    observation.inaccessiblePaths.push_back(path);
                    addIssue(observation.issues, observation.droppedIssueCount,
                             "path-inaccessible", "Package-derived path could not be observed conclusively",
                             {{"path", path}, {"errno", std::to_string(probe.errorCode)}});
                    LOGI_TAG("PackagePaths", "event=path_inaccessible path=%s errno=%d", path.c_str(),
                             probe.errorCode);
                    break;
                case PathProbeState::Error:
                    addIssue(observation.issues, observation.droppedIssueCount,
                             "path-probe-failed", "Package-derived path probe failed",
                             {{"path", path}, {"errno", std::to_string(probe.errorCode)}});
                    LOGW_TAG("PackagePaths", "event=path_probe_failed path=%s errno=%d",
                             path.c_str(), probe.errorCode);
                    break;
            }
        }
    }
    if (observation.isolationDetected) {
        addIssue(observation.issues, observation.droppedIssueCount, "app-data-isolated",
                 "Other applications' data directories are not visible from this process, so "
                 "a not-found result carries no information about an indicator package",
                 {{"selfControl", observation.selfControl},
                  {"crossPackageControl", observation.crossPackageControl},
                  {"controlPackage", kCrossPackageDataControl},
                  {"unconfirmedNotFoundCount",
                   std::to_string(observation.unconfirmedNotFoundCount)}});
    }
    return observation;
}

nlohmann::json serializePackageIdentity(const PackageIdentityObservation& observation) {
    // Package visibility is easy to lose silently: a missing <queries> entry looks
    // identical to an absent package. Reporting the three counts together makes a dead
    // channel obvious on any device.
    LOGI_TAG("DangerousPackages",
             "event=package_identity_summary targets=%d completedQueries=%d detected=%d "
             "issues=%d",
             observation.targetCount, observation.completedQueryCount,
             static_cast<int>(observation.detectedPackages.size()),
             static_cast<int>(observation.issues.size()));
    return {{"targetCount", observation.targetCount},
            {"completedQueryCount", observation.completedQueryCount},
            {"visiblePackageCount", observation.visiblePackageCount},
            {"detectedPackages", observation.detectedPackages},
            {"issues", serializeIssues(observation.issues, observation.droppedIssueCount)}};
}

nlohmann::json serializeAppDataPath(const AppDataPathObservation& observation) {
    return {{"attemptedPathCount", observation.attemptedPathCount},
            {"completedPathCount", observation.completedPathCount},
            {"notFoundPathCount", observation.notFoundPathCount},
            {"foundPaths", observation.foundPaths},
            {"inaccessiblePaths", observation.inaccessiblePaths},
            {"unconfirmedNotFoundCount", observation.unconfirmedNotFoundCount},
            {"selfControl", observation.selfControl},
            {"crossPackageControl", observation.crossPackageControl},
            {"isolationDetected", observation.isolationDetected},
            {"issues", serializeIssues(observation.issues, observation.droppedIssueCount)}};
}

DetectionAssessment aggregateAssessment(
    const PackageIdentityObservation& packageIdentity,
    const AppDataPathObservation& appDataPath) {
    return aggregateDangerousPackageAssessment(
        !packageIdentity.detectedPackages.empty(),
        !appDataPath.foundPaths.empty(),
        packageIdentity.completedQueryCount > 0,
        // Structural isolation leaves the path unit unable to answer on every current
        // device. It must not turn the whole detector INCONCLUSIVE: the package unit's
        // negative stands on its own controls. A broken path channel still blocks.
        // Mirrored in DangerousPackagesEvidenceAdapter's expected outcome.
        appDataPath.completedPathCount > 0 || appDataPath.isolationDetected);
}

}  // namespace

class DangerousPackagesDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        std::vector<std::string> targetPackageNames;
        if (!scanContext.env || !scanContext.androidContext ||
            !collectTargetPackageNames(scanContext, targetPackageNames)) {
            // A well-formed payload with an issue on each unit. It used to be a bare
            // {"collectionError": ...} object, which the typed adapter cannot decode, so the
            // result surfaced as a non-recoverable PAYLOAD_DECODE_FAILED - blaming the SDK
            // for an environment condition and losing the reason.
            PackageIdentityObservation packageIdentity;
            AppDataPathObservation appDataPath;
            const char* reason = "Unable to collect target package names";
            addIssue(packageIdentity.issues, packageIdentity.droppedIssueCount,
                     "target-list-unavailable", reason);
            addIssue(appDataPath.issues, appDataPath.droppedIssueCount,
                     "target-list-unavailable", reason);
            nlohmann::json payload = {
                {"packageIdentity", serializePackageIdentity(packageIdentity)},
                {"appDataPath", serializeAppDataPath(appDataPath)},
            };
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        PackageIdentityObservation packageIdentity;
        collectPackageIdentityVisibility(scanContext, targetPackageNames, packageIdentity);
        const AppDataPathObservation appDataPath =
            collectAppDataPathVisibility(targetPackageNames, packageIdentity.selfPackageName);
        const DetectionAssessment assessment = aggregateAssessment(packageIdentity, appDataPath);

        nlohmann::json payload = {
            {"packageIdentity", serializePackageIdentity(packageIdentity)},
            {"appDataPath", serializeAppDataPath(appDataPath)},
        };
        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "DANGEROUS_PACKAGES"; }
};

REGISTER_DETECTION(DangerousPackagesDetection);

}  // namespace tamperprobe
