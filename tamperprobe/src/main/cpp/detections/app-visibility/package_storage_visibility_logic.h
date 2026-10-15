#ifndef TAMPERPROBE_PACKAGE_STORAGE_VISIBILITY_LOGIC_H
#define TAMPERPROBE_PACKAGE_STORAGE_VISIBILITY_LOGIC_H

#include <cstddef>
#include <string>
#include <unordered_set>

namespace tamperprobe {

enum class StorageProbeState {
    PRESENT,
    NOT_FOUND,
    DENIED,
    ERROR,
};

struct StorageProbeOutcome {
    StorageProbeState state = StorageProbeState::ERROR;
    int errorCode = 0;
    unsigned long long inode = 0;
    unsigned long long device = 0;
};

struct StorageCandidateAssessment {
    bool finding = false;
    bool telemetry = false;
    std::string ruleId;
};

enum class PackageStorageOverallState {
    OBSERVED,
    NOT_OBSERVED,
    INCONCLUSIVE,
};

constexpr std::size_t kMaximumPackageStorageObservationRecords = 128;

int androidUserIdForUid(unsigned int uid);

std::string packageStoragePathForUid(unsigned int uid, const std::string& protectedRoot,
                                     const std::string& packageName);

bool reservePackageStorageFinding(std::unordered_set<std::string>& findingKeys, const std::string& packageName,
                                  const std::string& protectedRoot, const std::string& ruleId);

bool canRetainPackageStorageObservation(std::size_t retainedCount);

PackageStorageOverallState assessPackageStorageOverall(StorageProbeState storageRootState, int completedBaselineCount,
                                                       int findingCount);

StorageCandidateAssessment assessStorageCandidate(bool unicodeVariant, const StorageProbeOutcome& canonicalStat,
                                                  const StorageProbeOutcome& canonicalAccess,
                                                  const StorageProbeOutcome& canonicalOpen,
                                                  const StorageProbeOutcome& variantStat,
                                                  const StorageProbeOutcome& variantAccess,
                                                  const StorageProbeOutcome& variantOpen);

const char* storageProbeStateName(StorageProbeState state);

}  // namespace tamperprobe

#endif  // TAMPERPROBE_PACKAGE_STORAGE_VISIBILITY_LOGIC_H
