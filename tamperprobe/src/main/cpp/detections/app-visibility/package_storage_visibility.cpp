#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "../../common/log.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"
#include "package_storage_visibility_logic.h"
#include "package_targets.h"

namespace tamperprobe {
namespace {

constexpr unsigned int kAndroidUserOffset = 100000U;
constexpr size_t kMaximumCollectionErrors = 16;

struct UnicodeRepresentative {
    unsigned int codePoint;
    const char* id;
};

constexpr std::array<UnicodeRepresentative, 17> kUnicodeRepresentatives = {{
    {0x00AD, "soft_hyphen"},
    {0x034F, "combining_grapheme_joiner"},
    {0x061C, "arabic_letter_mark"},
    {0x115F, "hangul_filler"},
    {0x17B4, "khmer_inherent_vowel"},
    {0x180B, "mongolian_variation_selector"},
    {0x200B, "zero_width_space"},
    {0x202A, "bidi_embedding"},
    {0x2060, "word_joiner"},
    {0x3164, "hangul_filler_compat"},
    {0xFE00, "variation_selector"},
    {0xFEFF, "zero_width_no_break_space"},
    {0xFFA0, "halfwidth_hangul_filler"},
    {0x1BCA0, "shorthand_format"},
    {0x1D173, "musical_format"},
    {0xE0000, "tag_base"},
    {0xE0100, "variation_selector_supplement"},
}};

struct PathVariant {
    std::string id;
    std::string path;
    bool unicode = false;
    std::string codePoint;
    std::string placement;
};

struct Corroboration {
    StorageProbeOutcome access;
    StorageProbeOutcome open;
    StorageProbeOutcome list;
};

StorageProbeOutcome outcomeFromResult(int result, int errorCode, const struct stat* status = nullptr) {
    if (result == 0) {
        return {StorageProbeState::PRESENT, 0,
                status == nullptr ? 0ULL : static_cast<unsigned long long>(status->st_ino),
                status == nullptr ? 0ULL : static_cast<unsigned long long>(status->st_dev)};
    }
    if (errorCode == ENOENT || errorCode == ENOTDIR) {
        return {StorageProbeState::NOT_FOUND, errorCode, 0, 0};
    }
    if (errorCode == EACCES || errorCode == EPERM) {
        return {StorageProbeState::DENIED, errorCode, 0, 0};
    }
    return {StorageProbeState::ERROR, errorCode, 0, 0};
}

StorageProbeOutcome probeStat(const std::string& path) {
    struct stat status {};
    errno = 0;
#if defined(__aarch64__) || defined(__x86_64__)
    const int result = static_cast<int>(syscall(__NR_newfstatat, AT_FDCWD, path.c_str(), &status, 0));
#else
    const int result = static_cast<int>(syscall(__NR_fstatat64, AT_FDCWD, path.c_str(), &status, 0));
#endif
    return outcomeFromResult(result, errno, &status);
}

StorageProbeOutcome probeAccess(const std::string& path) {
    errno = 0;
#ifdef __NR_faccessat2
    int result = static_cast<int>(syscall(__NR_faccessat2, AT_FDCWD, path.c_str(), F_OK, AT_EACCESS));
    int errorCode = errno;
    if (result < 0 && errorCode == ENOSYS) {
        errno = 0;
        result = static_cast<int>(syscall(__NR_faccessat, AT_FDCWD, path.c_str(), F_OK));
        errorCode = errno;
    }
#else
    const int result = static_cast<int>(syscall(__NR_faccessat, AT_FDCWD, path.c_str(), F_OK));
    const int errorCode = errno;
#endif
    return outcomeFromResult(result, errorCode);
}

StorageProbeOutcome probeOpen(const std::string& path) {
    errno = 0;
    const int fd = static_cast<int>(syscall(__NR_openat, AT_FDCWD, path.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC, 0));
    const int errorCode = errno;
    if (fd >= 0) close(fd);
    return outcomeFromResult(fd >= 0 ? 0 : -1, errorCode);
}

StorageProbeOutcome probeList(const std::string& path) {
    errno = 0;
    const int fd =
        static_cast<int>(syscall(__NR_openat, AT_FDCWD, path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0));
    if (fd < 0) return outcomeFromResult(-1, errno);

    std::array<char, 256> buffer{};
    errno = 0;
    const int result = static_cast<int>(syscall(__NR_getdents64, fd, buffer.data(), buffer.size()));
    const int errorCode = errno;
    close(fd);
    return outcomeFromResult(result >= 0 ? 0 : -1, errorCode);
}

Corroboration corroborate(const std::string& path) {
    return {probeAccess(path), probeOpen(path), probeList(path)};
}

std::string encodeUtf8(unsigned int codePoint) {
    std::string encoded;
    if (codePoint <= 0x7F) {
        encoded.push_back(static_cast<char>(codePoint));
    } else if (codePoint <= 0x7FF) {
        encoded.push_back(static_cast<char>(0xC0 | (codePoint >> 6)));
        encoded.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
    } else if (codePoint <= 0xFFFF) {
        encoded.push_back(static_cast<char>(0xE0 | (codePoint >> 12)));
        encoded.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
        encoded.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
    } else {
        encoded.push_back(static_cast<char>(0xF0 | (codePoint >> 18)));
        encoded.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
        encoded.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
        encoded.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
    }
    return encoded;
}

std::string codePointName(unsigned int codePoint) {
    char value[16]{};
    snprintf(value, sizeof(value), "U+%04X", codePoint);
    return value;
}

std::string insertAt(std::string value, size_t position, const std::string& insertion) {
    value.insert(position, insertion);
    return value;
}

std::vector<PathVariant> buildVariants(const std::string& storageRoot, const std::string& protectedRoot,
                                       const std::string& packageName) {
    std::vector<PathVariant> variants;
    variants.push_back({"mixed_case",
                        storageRoot + "/aNdRoId/" + (protectedRoot == "data" ? "DaTa/" : "ObB/") + packageName, false,
                        "", "mixed_case"});

    for (const auto& representative : kUnicodeRepresentatives) {
        const std::string value = encodeUtf8(representative.codePoint);
        const std::string prefix = std::string(representative.id) + "_";
        const std::string codePoint = codePointName(representative.codePoint);
        const std::string androidPrefix = value + "Android";
        const std::string androidInside = insertAt("Android", 3, value);
        const std::string rootPrefix = value + protectedRoot;
        const std::string rootInside = insertAt(protectedRoot, protectedRoot.size() / 2, value);

        variants.push_back({prefix + "android_prefix",
                            storageRoot + "/" + androidPrefix + "/" + protectedRoot + "/" + packageName, true,
                            codePoint, "android_prefix"});
        variants.push_back({prefix + "android_inside",
                            storageRoot + "/" + androidInside + "/" + protectedRoot + "/" + packageName, true,
                            codePoint, "android_inside"});
        variants.push_back({prefix + protectedRoot + "_prefix",
                            storageRoot + "/Android/" + rootPrefix + "/" + packageName, true, codePoint,
                            protectedRoot + "_prefix"});
        variants.push_back({prefix + protectedRoot + "_inside",
                            storageRoot + "/Android/" + rootInside + "/" + packageName, true, codePoint,
                            protectedRoot + "_inside"});
    }
    return variants;
}

nlohmann::json outcomeJson(const StorageProbeOutcome& outcome) {
    nlohmann::json value = {
        {"state", storageProbeStateName(outcome.state)},
        {"errno", outcome.errorCode},
    };
    if (outcome.state == StorageProbeState::PRESENT && outcome.inode != 0) {
        value["inode"] = outcome.inode;
        value["device"] = outcome.device;
    }
    return value;
}

std::string readProperty(const char* name, bool& available) {
    std::array<char, PROP_VALUE_MAX> value{};
    const int length = __system_property_get(name, value.data());
    available = length > 0;
    // Stop at the first NUL, as getprop does: the returned length can include a NUL stored
    // inside the value.
    return available ? std::string(value.data(), strnlen(value.data(), value.size()))
                     : std::string();
}

void addCollectionError(nlohmann::json& errors, int& droppedErrors, const std::string& source,
                        const StorageProbeOutcome& outcome) {
    if (errors.size() < kMaximumCollectionErrors) {
        errors.push_back({
            {"source", source},
            {"errno", outcome.errorCode},
            {"message", strerror(outcome.errorCode)},
        });
    } else {
        ++droppedErrors;
    }
}

}  // namespace

const char* storageProbeStateName(StorageProbeState state) {
    switch (state) {
        case StorageProbeState::PRESENT:
            return "present";
        case StorageProbeState::NOT_FOUND:
            return "not_found";
        case StorageProbeState::DENIED:
            return "denied";
        case StorageProbeState::ERROR:
            return "error";
        default:
            return "error";
    }
}

int androidUserIdForUid(unsigned int uid) {
    return static_cast<int>(uid / kAndroidUserOffset);
}

std::string packageStoragePathForUid(unsigned int uid, const std::string& protectedRoot,
                                     const std::string& packageName) {
    return "/storage/emulated/" + std::to_string(androidUserIdForUid(uid)) + "/Android/" + protectedRoot + "/" +
           packageName;
}

bool reservePackageStorageFinding(std::unordered_set<std::string>& findingKeys, const std::string& packageName,
                                  const std::string& protectedRoot, const std::string& ruleId) {
    return findingKeys.insert(packageName + "|" + protectedRoot + "|" + ruleId).second;
}

bool canRetainPackageStorageObservation(std::size_t retainedCount) {
    return retainedCount < kMaximumPackageStorageObservationRecords;
}

PackageStorageOverallState assessPackageStorageOverall(StorageProbeState storageRootState, int completedBaselineCount,
                                                       int findingCount) {
    if (findingCount > 0) return PackageStorageOverallState::OBSERVED;
    if (storageRootState != StorageProbeState::PRESENT || completedBaselineCount == 0) {
        return PackageStorageOverallState::INCONCLUSIVE;
    }
    return PackageStorageOverallState::NOT_OBSERVED;
}

StorageCandidateAssessment assessStorageCandidate(bool unicodeVariant, const StorageProbeOutcome& canonicalStat,
                                                  const StorageProbeOutcome& canonicalAccess,
                                                  const StorageProbeOutcome& canonicalOpen,
                                                  const StorageProbeOutcome& variantStat,
                                                  const StorageProbeOutcome& variantAccess,
                                                  const StorageProbeOutcome& variantOpen) {
    const auto canonicalHidden = [](StorageProbeState state) { return state == StorageProbeState::NOT_FOUND; };
    const int canonicalHiddenCount = static_cast<int>(canonicalHidden(canonicalStat.state)) +
                                     static_cast<int>(canonicalHidden(canonicalAccess.state)) +
                                     static_cast<int>(canonicalHidden(canonicalOpen.state));
    const int variantPresentCount = static_cast<int>(variantStat.state == StorageProbeState::PRESENT) +
                                    static_cast<int>(variantAccess.state == StorageProbeState::PRESENT) +
                                    static_cast<int>(variantOpen.state == StorageProbeState::PRESENT);
    const int variantDeniedCount = static_cast<int>(variantStat.state == StorageProbeState::DENIED) +
                                   static_cast<int>(variantAccess.state == StorageProbeState::DENIED) +
                                   static_cast<int>(variantOpen.state == StorageProbeState::DENIED);
    const bool consistentVariantBoundary = variantPresentCount >= 2 || variantDeniedCount >= 2;
    const bool differential = canonicalStat.state != variantStat.state ||
                              canonicalAccess.state != variantAccess.state || canonicalOpen.state != variantOpen.state;

    if (canonicalStat.state == StorageProbeState::PRESENT) {
        const bool unicodeAlias = unicodeVariant && consistentVariantBoundary;
        return {true, differential || unicodeAlias, "canonical_package_data"};
    }

    if (unicodeVariant && differential && canonicalHiddenCount >= 2 && consistentVariantBoundary) {
        return {true, true, "unicode_alias"};
    }
    return {false, differential, ""};
}

class PackageStorageVisibilityDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        nlohmann::json payload = {
            {"storageContext", nlohmann::json::object()},     {"overview", nlohmann::json::object()},
            {"packageObservations", nlohmann::json::array()}, {"findings", nlohmann::json::array()},
            {"telemetry", nlohmann::json::array()},           {"collectionErrors", nlohmann::json::array()},
        };

        const unsigned int uid = getuid();
        const int userId = androidUserIdForUid(uid);
        const std::string storageRoot = "/storage/emulated/" + std::to_string(userId);
        payload["storageContext"]["userId"] = userId;
        payload["storageContext"]["storageRoot"] = storageRoot;

        struct statfs filesystem {};
        errno = 0;
        if (statfs(storageRoot.c_str(), &filesystem) == 0) {
            payload["storageContext"]["statfsAvailable"] = true;
            payload["storageContext"]["fsType"] = static_cast<unsigned long long>(filesystem.f_type);
        } else {
            payload["storageContext"]["statfsAvailable"] = false;
            payload["storageContext"]["statfsErrno"] = errno;
        }

        bool fuseBpfAvailable = false;
        bool appDataIsolationAvailable = false;
        const std::string fuseBpf = readProperty("ro.fuse.bpf.is_running", fuseBpfAvailable);
        const std::string appDataIsolation =
            readProperty("persist.sys.vold_app_data_isolation_enabled", appDataIsolationAvailable);
        payload["storageContext"]["fuseBpfState"] = fuseBpfAvailable ? fuseBpf : "unavailable";
        payload["storageContext"]["appDataIsolationState"] =
            appDataIsolationAvailable ? appDataIsolation : "unavailable";

        const StorageProbeOutcome rootStatus = probeStat(storageRoot);
        payload["storageContext"]["rootProbe"] = outcomeJson(rootStatus);

        std::vector<std::string> targets;
        if (!collectTargetPackageNames(scanContext, targets)) {
            payload["collectionErrors"].push_back({
                {"source", "package_targets"},
                {"errno", 0},
                {"message", "Unable to collect target package names"},
            });
            payload["overview"] = {
                {"targetCount", 0},
                {"completedBaselineCount", 0},
                {"transformedProbeCount", 0},
                {"candidateCount", 0},
                {"findingCount", 0},
                {"telemetryCount", 0},
                {"droppedObservationCount", 0},
                {"droppedCollectionErrorCount", 0},
            };
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        int completedBaselineCount = 0;
        int transformedProbeCount = 0;
        int candidateCount = 0;
        int findingCount = 0;
        int telemetryCount = 0;
        int droppedObservations = 0;
        int droppedErrors = 0;
        bool platformDifferential = false;
        std::unordered_set<std::string> findingDedupe;

        for (const auto& packageName : targets) {
            for (const char* protectedRoot : {"data", "obb"}) {
                const std::string canonicalPath = packageStoragePathForUid(uid, protectedRoot, packageName);
                const StorageProbeOutcome canonicalStat = probeStat(canonicalPath);
                if (canonicalStat.state != StorageProbeState::ERROR) {
                    ++completedBaselineCount;
                } else {
                    addCollectionError(payload["collectionErrors"], droppedErrors,
                                       std::string("canonical:") + protectedRoot, canonicalStat);
                }

                Corroboration canonicalCorroboration{};
                bool canonicalCorroborated = false;
                if (canonicalStat.state == StorageProbeState::PRESENT) {
                    canonicalCorroboration = corroborate(canonicalPath);
                    canonicalCorroborated = true;
                    if (reservePackageStorageFinding(findingDedupe, packageName, protectedRoot, "canonical")) {
                        payload["findings"].push_back({
                            {"id", "canonical_package_data"},
                            {"package", packageName},
                            {"protectedRoot", protectedRoot},
                            {"variantId", "canonical"},
                            {"strength", "weak"},
                            {"classification", "package_data_artifact"},
                            {"summary", "Dangerous-package storage artifact is directly visible"},
                        });
                        ++findingCount;
                    }
                }

                const auto variants = buildVariants(storageRoot, protectedRoot, packageName);
                bool rootFindingRecorded = canonicalStat.state == StorageProbeState::PRESENT;
                for (const auto& variant : variants) {
                    const StorageProbeOutcome variantStat = probeStat(variant.path);
                    ++transformedProbeCount;
                    const bool candidate =
                        variantStat.state != StorageProbeState::NOT_FOUND || variantStat.state != canonicalStat.state;
                    if (!candidate) continue;
                    ++candidateCount;

                    if (!canonicalCorroborated) {
                        canonicalCorroboration = corroborate(canonicalPath);
                        canonicalCorroborated = true;
                    }
                    const Corroboration variantCorroboration = corroborate(variant.path);
                    const auto assessment = assessStorageCandidate(
                        variant.unicode, canonicalStat, canonicalCorroboration.access, canonicalCorroboration.open,
                        variantStat, variantCorroboration.access, variantCorroboration.open);

                    if (assessment.telemetry) {
                        platformDifferential = true;
                        ++telemetryCount;
                    }
                    if (assessment.finding && assessment.ruleId == "unicode_alias" && !rootFindingRecorded) {
                        if (reservePackageStorageFinding(findingDedupe, packageName, protectedRoot, "unicode_alias")) {
                            payload["findings"].push_back({
                                {"id", "unicode_alias"},
                                {"package", packageName},
                                {"protectedRoot", protectedRoot},
                                {"variantId", variant.id},
                                {"codePoint", variant.codePoint},
                                {"placement", variant.placement},
                                {"strength", "weak"},
                                {"classification", "package_data_artifact"},
                                {"summary", "Unicode storage alias reveals a dangerous-package artifact"},
                            });
                            ++findingCount;
                            rootFindingRecorded = true;
                        }
                    }

                    if (canRetainPackageStorageObservation(payload["packageObservations"].size())) {
                        payload["packageObservations"].push_back({
                            {"package", packageName},
                            {"protectedRoot", protectedRoot},
                            {"variantId", variant.id},
                            {"variantType", variant.unicode ? "unicode" : "case_control"},
                            {"codePoint", variant.codePoint},
                            {"placement", variant.placement},
                            {"canonicalStat", outcomeJson(canonicalStat)},
                            {"canonicalAccess", outcomeJson(canonicalCorroboration.access)},
                            {"canonicalOpen", outcomeJson(canonicalCorroboration.open)},
                            {"variantStat", outcomeJson(variantStat)},
                            {"variantAccess", outcomeJson(variantCorroboration.access)},
                            {"variantOpen", outcomeJson(variantCorroboration.open)},
                            {"variantList", outcomeJson(variantCorroboration.list)},
                            {"assessmentImpact", assessment.finding ? "weak_finding" : "telemetry_only"},
                        });
                    } else {
                        ++droppedObservations;
                    }
                }
            }
        }

        if (platformDifferential) {
            payload["telemetry"].push_back({
                {"id", "platform_oracle"},
                {"classification", "storage_isolation_behavior"},
                {"assessmentImpact", "telemetry_only"},
                {"summary", "Storage path aliases produced a platform-level behavioral differential"},
                {"differentialCount", telemetryCount},
            });
        }

        payload["overview"] = {
            {"targetCount", targets.size()},
            {"completedBaselineCount", completedBaselineCount},
            {"transformedProbeCount", transformedProbeCount},
            {"candidateCount", candidateCount},
            {"findingCount", findingCount},
            {"telemetryCount", telemetryCount},
            {"droppedObservationCount", droppedObservations},
            {"droppedCollectionErrorCount", droppedErrors},
        };

        LOGI_TAG("PackageStorageVisibility",
                 "event=summary targetCount=%zu completedBaselineCount=%d "
                 "transformedProbeCount=%d candidateCount=%d findingCount=%d "
                 "telemetryCount=%d droppedObservationCount=%d",
                 targets.size(), completedBaselineCount, transformedProbeCount, candidateCount, findingCount,
                 telemetryCount, droppedObservations);

        DetectionAssessment assessment;
        switch (assessPackageStorageOverall(rootStatus.state, completedBaselineCount, findingCount)) {
            case PackageStorageOverallState::OBSERVED:
                assessment = DetectionAssessment::weakObserved();
                break;
            case PackageStorageOverallState::INCONCLUSIVE:
                assessment = DetectionAssessment::inconclusive();
                break;
            case PackageStorageOverallState::NOT_OBSERVED:
            default:
                assessment = DetectionAssessment::notObserved();
                break;
        }
        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "PACKAGE_STORAGE_VISIBILITY"; }
};

REGISTER_DETECTION(PackageStorageVisibilityDetection);

}  // namespace tamperprobe
