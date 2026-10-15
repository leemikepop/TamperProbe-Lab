#include <dlfcn.h>

#include <chrono>
#include <fcntl.h>
#include <linux/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_set>
#include <vector>

#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../common/log.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {
namespace {

constexpr unsigned long kOverlayFsMagic = 0x794c7630UL;
constexpr unsigned int kStatxMountId = 0x00001000U;

#ifndef __NR_statx
#if defined(__aarch64__)
#define __NR_statx 291
#elif defined(__arm__)
#define __NR_statx 397
#elif defined(__x86_64__)
#define __NR_statx 332
#elif defined(__i386__)
#define __NR_statx 383
#endif
#endif

#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#endif

#ifndef STATX_BASIC_STATS
#define STATX_BASIC_STATS 0x000007ffU
#endif

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0x800
#endif

using StatxFunction = int (*)(int, const char*, int, unsigned int, struct statx*);

int invokeStatx(int dirfd, const char* pathname, int flags, unsigned int mask, struct statx* statxbuf) {
    static const auto dlsymStatx = reinterpret_cast<StatxFunction>(dlsym(RTLD_DEFAULT, "statx"));
    if (dlsymStatx != nullptr) {
        return dlsymStatx(dirfd, pathname, flags, mask, statxbuf);
    }
#ifdef __NR_statx
    return static_cast<int>(syscall(__NR_statx, dirfd, pathname, flags, mask, statxbuf));
#else
    errno = ENOSYS;
    return -1;
#endif
}

struct MountRow {
    unsigned long long id = 0;
    std::string source;
    std::string target;
    std::string fsType;
    std::string options;
};

struct MountTables {
    bool mountInfoReadable = false;
    bool overlayDeclared = false;
    bool rootPropagationPrivate = false;
    int mountInfoEntryCount = 0;
    std::unordered_set<unsigned long long> mountIds;
    // One vector. Until 2026-09-07 this held mountinfo and mounts concatenated, and a
    // second copy of the mountinfo rows lived alongside it.
    std::vector<MountRow> mountInfoRows;
};

struct AggregatedMountHeuristic {
    std::string ruleId;
    std::string partition;
    MountRow representative;
    size_t rowCount = 0;
};

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return value;
}

bool contains(const std::string& value, const char* marker) {
    return value.find(marker) != std::string::npos;
}

bool containsToken(const std::string& value, const std::string& token) {
    size_t position = value.find(token);
    while (position != std::string::npos) {
        const bool leftBoundary = position == 0 ||
                                  !std::isalnum(static_cast<unsigned char>(value[position - 1]));
        const size_t end = position + token.size();
        const bool rightBoundary = end == value.size() ||
                                   !std::isalnum(static_cast<unsigned char>(value[end]));
        if (leftBoundary && rightBoundary) return true;
        position = value.find(token, position + 1);
    }
    return false;
}

// Options arrive as whitespace-separated groups of comma-separated values. Called once
// per mount row, so it walks the string rather than building two streams per group.
bool hasOption(const std::string& options, const char* option) {
    const size_t optionLength = std::strlen(option);
    size_t position = 0;
    while (position < options.size()) {
        const size_t end = options.find_first_of(" \t,", position);
        const size_t length =
            (end == std::string::npos ? options.size() : end) - position;
        if (length == optionLength && options.compare(position, length, option) == 0) {
            return true;
        }
        if (end == std::string::npos) break;
        position = options.find_first_not_of(" \t,", end);
        if (position == std::string::npos) break;
    }
    return false;
}

std::string systemPartition(const std::string& path) {
    constexpr std::array<const char*, 6> kRoots = {
        "/system", "/system_root", "/vendor", "/product", "/system_ext", "/odm"};
    for (const char* root : kRoots) {
        const size_t length = strlen(root);
        if (path == root || (path.size() > length && path.compare(0, length, root) == 0 &&
                            path[length] == '/')) {
            return root;
        }
    }
    return {};
}

bool isSystemPath(const std::string& path) {
    return !systemPartition(path).empty();
}

bool isSensitiveTmpfsTarget(const std::string& target) {
    return target == "/sbin" || target == "/.magisk" || target == "/patch_hw" ||
           target.rfind("/.magisk/", 0) == 0 || target.rfind("/patch_hw/", 0) == 0;
}

void addCollectionError(nlohmann::json& errors, const char* source) {
    errors.push_back({{"source", source}, {"errno", errno}, {"message", strerror(errno)}});
}

// Splits on runs of spaces and tabs, in place, without allocating.
//
// This replaced a per-line std::istringstream. Measured 2026-09-07: parsing was 772 ms of
// MOUNT_INTEGRITY's 851 ms on a Redmi 13C, whose mountinfo carries 1,673 entries because
// Magisk's bind mounts are in it. Constructing a stream per line is an expensive way to
// split on whitespace, and the table is largest exactly on the devices this project cares
// about.
class FieldCursor {
   public:
    explicit FieldCursor(char* line) : cursor_(line) {}

    // The next field, or nullptr at end of line. The pointer is into the caller's buffer
    // and stays valid until the next call.
    const char* next() {
        while (*cursor_ == ' ' || *cursor_ == '\t') ++cursor_;
        if (*cursor_ == '\0' || *cursor_ == '\n') return nullptr;
        char* start = cursor_;
        while (*cursor_ != '\0' && *cursor_ != '\n' && *cursor_ != ' ' && *cursor_ != '\t') {
            ++cursor_;
        }
        if (*cursor_ != '\0') *cursor_++ = '\0';
        return start;
    }

    // Everything left on the line, without leading blanks or the trailing newline.
    std::string rest() {
        while (*cursor_ == ' ' || *cursor_ == '\t') ++cursor_;
        std::string remainder(cursor_);
        while (!remainder.empty() && (remainder.back() == '\n' || remainder.back() == '\r')) {
            remainder.pop_back();
        }
        return remainder;
    }

   private:
    char* cursor_;
};

// Reads a procfs file in one pass.
//
// getline() issues a read() per line, and every read() of a procfs seq_file re-enters the
// kernel to render the next chunk of a table it is generating on the fly. On a device
// whose mount table has 1,673 entries that cost dominated the whole detector. Pulling the
// file in large blocks and splitting in memory removes the per-line syscall entirely.
bool slurpProcFile(const char* path, std::string& out) {
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    out.clear();
    char buffer[65536];
    ssize_t bytes = 0;
    while ((bytes = read(fd, buffer, sizeof(buffer))) > 0) {
        out.append(buffer, static_cast<size_t>(bytes));
    }
    const bool succeeded = bytes >= 0;
    const int readErrno = errno;
    close(fd);
    if (!succeeded) errno = readErrno;
    return succeeded;
}

// Hands each line of an already-read buffer to the caller, in place. The buffer is
// modified: line terminators become NULs so the tokeniser can work without copying.
template <typename Handler>
void forEachLine(std::string& buffer, Handler handler) {
    char* cursor = buffer.empty() ? nullptr : &buffer[0];
    char* const end = cursor == nullptr ? nullptr : cursor + buffer.size();
    while (cursor != nullptr && cursor < end) {
        char* lineEnd = static_cast<char*>(memchr(cursor, '\n', static_cast<size_t>(end - cursor)));
        if (lineEnd != nullptr) *lineEnd = '\0';
        handler(cursor);
        if (lineEnd == nullptr) break;
        cursor = lineEnd + 1;
    }
}

MountTables readMountTables(nlohmann::json& collectionErrors) {
    MountTables tables;
    long long slurpMicros = 0;
    long long tokeniseMicros = 0;
    const auto stamp = []() { return std::chrono::steady_clock::now(); };
    const auto since = [](const std::chrono::steady_clock::time_point& from) {
        return std::chrono::duration_cast<std::chrono::microseconds>(
                   std::chrono::steady_clock::now() - from)
            .count();
    };

    std::string mountInfoBuffer;
    auto slurpStartedAt = stamp();
    const bool mountInfoRead = slurpProcFile("/proc/self/mountinfo", mountInfoBuffer);
    slurpMicros += since(slurpStartedAt);
    auto tokeniseStartedAt = stamp();
    if (mountInfoRead) {
        tables.mountInfoReadable = true;
        forEachLine(mountInfoBuffer, [&tables](char* line) {
            FieldCursor cursor(line);
            MountRow row;
            const char* idField = cursor.next();
            const char* parentField = cursor.next();
            const char* majorMinor = cursor.next();
            const char* root = cursor.next();
            const char* targetField = cursor.next();
            const char* mountOptionsField = cursor.next();
            if (idField == nullptr || parentField == nullptr || majorMinor == nullptr ||
                root == nullptr || targetField == nullptr || mountOptionsField == nullptr) {
                return;
            }
            errno = 0;
            char* idEnd = nullptr;
            row.id = std::strtoull(idField, &idEnd, 10);
            if (idEnd == idField || errno != 0) return;
            row.target = targetField;
            const std::string mountOptions = mountOptionsField;
            ++tables.mountInfoEntryCount;
            tables.mountIds.insert(row.id);

            std::string optionalFields;
            bool hasPropagation = false;
            const char* field = nullptr;
            while ((field = cursor.next()) != nullptr && std::strcmp(field, "-") != 0) {
                if (!optionalFields.empty()) optionalFields += ' ';
                optionalFields += field;
                if (std::strncmp(field, "shared:", 7) == 0 ||
                    std::strncmp(field, "master:", 7) == 0 ||
                    std::strcmp(field, "unbindable") == 0) {
                    hasPropagation = true;
                }
            }
            const char* fsTypeField = cursor.next();
            const char* sourceField = cursor.next();
            if (fsTypeField == nullptr || sourceField == nullptr) return;
            row.fsType = fsTypeField;
            row.source = sourceField;
            // The previous parser appended std::getline's remainder, which retains the
            // single space that separated it from the source field. rest() trims that, so
            // it is put back: every downstream matcher sees the same option string it saw
            // before this rewrite.
            const std::string remainder = cursor.rest();
            row.options = mountOptions;
            if (!optionalFields.empty()) row.options += " " + optionalFields;
            if (!remainder.empty()) row.options += " " + remainder;
            if (row.fsType == "overlay" || row.fsType == "overlayfs") {
                tables.overlayDeclared = true;
            }
            if (row.target == "/" && !hasPropagation) {
                tables.rootPropagationPrivate = true;
            }
            tables.mountInfoRows.push_back(std::move(row));
        });
    } else {
        addCollectionError(collectionErrors, "/proc/self/mountinfo");
    }

    tokeniseMicros += since(tokeniseStartedAt);

    // /proc/self/mounts is deliberately not read.
    //
    // It describes the same mounts in the same namespace as mountinfo, with a strict
    // subset of its fields, so the only thing it ever contributed here was overlayDeclared
    // - which the mountinfo loop above already computes from the same filesystem type.
    // Measured 2026-09-07 on a Redmi 13C with 1,673 mounts: reading it cost roughly 250 ms
    // of the detector's 851 ms and produced no information the first table had not.

    tokeniseMicros += since(tokeniseStartedAt);
    LOGI_TAG("MountIntegrity",
             "event=parse_split slurpMicros=%lld tokeniseMicros=%lld mountInfoBytes=%zu",
             slurpMicros, tokeniseMicros, mountInfoBuffer.size());
    return tables;
}

std::string readLink(const char* path) {
    std::array<char, 128> buffer{};
    const ssize_t length = readlink(path, buffer.data(), buffer.size() - 1);
    return length > 0 ? std::string(buffer.data(), static_cast<size_t>(length)) : std::string();
}

bool addFinding(nlohmann::json& findings, std::unordered_set<std::string>& dedupe,
                const char* ruleId, const char* family, const char* confidence,
                const char* marker, const MountRow& row, const std::string& summary) {
    const std::string key = std::string(ruleId) + '\n' + row.source + '\n' + row.target + '\n' +
                            row.fsType;
    if (!dedupe.insert(key).second) return false;
    findings.push_back({{"id", ruleId},
                        {"ruleId", ruleId},
                        {"family", family},
                        {"confidence", confidence},
                        {"marker", marker},
                        {"summary", summary},
                        {"path", row.target},
                        {"detail", row.source + " -> " + row.target + " (" + row.fsType + ")"},
                        {"source", row.source},
                        {"target", row.target},
                        {"fsType", row.fsType},
                        {"options", row.options}});
    return true;
}

void aggregateMountHeuristic(std::vector<AggregatedMountHeuristic>& aggregates,
                             std::unordered_set<std::string>& rowDedupe,
                             const char* ruleId, const std::string& partition,
                             const MountRow& row) {
    const std::string rowKey = std::string(ruleId) + '\n' + row.source + '\n' + row.target +
                               '\n' + row.fsType;
    if (!rowDedupe.insert(rowKey).second) return;
    for (auto& aggregate : aggregates) {
        if (aggregate.ruleId == ruleId && aggregate.partition == partition) {
            ++aggregate.rowCount;
            return;
        }
    }
    aggregates.push_back({ruleId, partition, row, 1});
}

void evaluateMountRows(const MountTables& tables, nlohmann::json& payload, int& strongCount,
                       int& weakCount) {
    std::unordered_set<std::string> dedupe;
    std::unordered_set<std::string> directBlockDedupe;
    std::unordered_set<std::string> heuristicRowDedupe;
    std::vector<AggregatedMountHeuristic> heuristicAggregates;
    payload["directBlockMounts"] = nlohmann::json::array();
    payload["genericMountHeuristics"] = nlohmann::json::array();

    for (const MountRow& row : tables.mountInfoRows) {
        const std::string source = lowercase(row.source);
        const std::string target = lowercase(row.target);
        const std::string fsType = lowercase(row.fsType);
        const std::string options = lowercase(row.options);
        const std::string searchable = source + '\n' + target + '\n' + options;

        const char* magiskMarker = nullptr;
        if (contains(searchable, ".magisk")) magiskMarker = ".magisk";
        else if (contains(searchable, "magisk/mirror")) magiskMarker = "magisk/mirror";
        else if (contains(target, "/data/adb/modules")) magiskMarker = "/data/adb/modules";
        if (magiskMarker && addFinding(payload["findings"], dedupe, "magisk_mount", "magisk",
                                       "strong", magiskMarker, row,
                                       "Magisk-specific mount marker is visible")) {
            ++strongCount;
        }

        const char* kernelSuMarker = nullptr;
        if (contains(searchable, "kernelsu")) kernelSuMarker = "kernelsu";
        else if (containsToken(searchable, "ksu")) kernelSuMarker = "ksu";
        else if (contains(searchable, "overlayfs_loop")) kernelSuMarker = "overlayfs_loop";
        if (kernelSuMarker &&
            addFinding(payload["findings"], dedupe, "kernelsu_mount", "kernelsu", "strong",
                       kernelSuMarker, row, "KernelSU-specific mount marker is visible")) {
            ++strongCount;
        }

        const char* magicMarker = nullptr;
        if (contains(searchable, "magic_mount")) magicMarker = "magic_mount";
        else if (contains(searchable, ".magic_mount")) magicMarker = ".magic_mount";
        else if (contains(searchable, "meta-hybrid")) magicMarker = "meta-hybrid";
        else if (contains(searchable, "meta_hybird")) magicMarker = "meta_hybird";
        else if (contains(options, "workdir=/data/adb")) magicMarker = "workdir=/data/adb";
        if (magicMarker &&
            addFinding(payload["findings"], dedupe, "magic_mount", "magic_mount", "strong",
                       magicMarker, row, "Magic Mount or Meta-Hybrid marker is visible")) {
            ++strongCount;
        }

        const std::string partition = systemPartition(target);
        const bool systemOverlay = !partition.empty() &&
                                   (fsType == "overlay" || fsType == "overlayfs");
        if (systemOverlay) {
            aggregateMountHeuristic(heuristicAggregates, heuristicRowDedupe,
                                    "system_overlay", partition, row);
        } else if (!partition.empty() && hasOption(options, "rw")) {
            aggregateMountHeuristic(heuristicAggregates, heuristicRowDedupe,
                                    "system_rw", partition, row);
        }
        if (isSystemPath(target) &&
            (contains(source, "/dev/block/loop") || contains(source, "/dev/loop") ||
             contains(source, "modules.img")) &&
            addFinding(payload["findings"], dedupe, "system_loop_source", "mount", "weak",
                       "loop", row, "System path is backed by a loop image")) {
            ++weakCount;
        }
        if (fsType == "tmpfs" && isSensitiveTmpfsTarget(target) &&
            addFinding(payload["findings"], dedupe, "sensitive_tmpfs", "mount", "weak",
                       "tmpfs", row, "Sensitive path is backed by tmpfs")) {
            ++weakCount;
        }

        if (isSystemPath(target) && source.rfind("/dev/block/", 0) == 0 &&
            source.rfind("/dev/block/dm-", 0) != 0 &&
            source.rfind("/dev/mapper/", 0) != 0 && fsType != "overlay" &&
            fsType != "overlayfs") {
            const std::string key = row.source + '\n' + row.target + '\n' + row.fsType;
            if (directBlockDedupe.insert(key).second) {
                payload["directBlockMounts"].push_back({{"source", row.source},
                                                        {"target", row.target},
                                                        {"fsType", row.fsType},
                                                        {"options", row.options}});
            }
        }
    }

    for (const auto& aggregate : heuristicAggregates) {
        const bool overlay = aggregate.ruleId == "system_overlay";
        payload["genericMountHeuristics"].push_back(
            {{"ruleId", aggregate.ruleId},
             {"partition", aggregate.partition},
             {"rowCount", aggregate.rowCount},
             {"assessmentImpact", overlay ? "telemetry_only" : "weak"},
             {"representativeSource", aggregate.representative.source},
             {"representativeTarget", aggregate.representative.target},
             {"fsType", aggregate.representative.fsType},
             {"options", aggregate.representative.options}});
        if (!overlay &&
            addFinding(payload["findings"], dedupe, aggregate.ruleId.c_str(), "mount", "weak",
                       "rw", aggregate.representative,
                       "System partition has a read-write mount")) {
            ++weakCount;
        }
    }
}

nlohmann::json buildSequenceTelemetry(const MountTables& tables) {
    nlohmann::json telemetry = {{"experimental", true},
                                {"artMountId", nullptr},
                                {"dataMirrorMountId", nullptr},
                                {"visibleCount", 0},
                                {"missingCount", 0},
                                {"maximumGap", 0},
                                {"gapRanges", nlohmann::json::array()}};
    unsigned long long artId = 0;
    unsigned long long dataMirrorId = 0;
    for (const MountRow& row : tables.mountInfoRows) {
        if (row.target == "/apex/com.android.art") artId = row.id;
        if (row.target == "/data_mirror") dataMirrorId = row.id;
    }
    if (artId == 0 || dataMirrorId <= artId) return telemetry;

    telemetry["artMountId"] = artId;
    telemetry["dataMirrorMountId"] = dataMirrorId;
    std::vector<unsigned long long> visible;
    for (unsigned long long id : tables.mountIds) {
        if (id > artId && id < dataMirrorId) visible.push_back(id);
    }
    std::sort(visible.begin(), visible.end());
    telemetry["visibleCount"] = static_cast<int>(visible.size());
    unsigned long long previous = artId;
    unsigned long long missingCount = 0;
    unsigned long long maximumGap = 0;
    visible.push_back(dataMirrorId);
    for (unsigned long long current : visible) {
        if (current > previous + 1) {
            const unsigned long long gapSize = current - previous - 1;
            missingCount += gapSize;
            maximumGap = std::max(maximumGap, gapSize);
            telemetry["gapRanges"].push_back(
                {{"start", previous + 1}, {"end", current - 1}, {"size", gapSize}});
        }
        previous = current;
    }
    telemetry["missingCount"] = missingCount;
    telemetry["maximumGap"] = maximumGap;
    return telemetry;
}

DetectionAssessment aggregateAssessment(int strongSignalCount, int moderateSignalCount,
                                        int weakSignalCount,
                                        bool mountInfoReadable,
                                        int completedKernelConsistencyChecks) {
    if (strongSignalCount > 0) return DetectionAssessment::strongObserved();
    if (moderateSignalCount > 0) return DetectionAssessment::moderateObserved();
    if (weakSignalCount > 0) return DetectionAssessment::weakObserved();
    if (!mountInfoReadable || completedKernelConsistencyChecks == 0) {
        return DetectionAssessment::inconclusive();
    }
    return DetectionAssessment::notObserved();
}

}  // namespace

class MountIntegrityDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext&) override {
        nlohmann::json payload = {{"findings", nlohmann::json::array()},
                                  {"collectionErrors", nlohmann::json::array()},
                                  {"statxChecks", nlohmann::json::array()},
                                  {"statfsChecks", nlohmann::json::array()}};

        // Phase telemetry. This detector's cost is dominated by the size of the mount
        // table, which is a property of the concealment stack rather than the device:
        // 159 entries on a stock-ish Pixel 7 against 1,661 with Magisk on a Redmi 13C.
        const auto parseStartedAt = std::chrono::steady_clock::now();
        MountTables tables = readMountTables(payload["collectionErrors"]);
        const auto parseMicros = std::chrono::duration_cast<std::chrono::microseconds>(
                                     std::chrono::steady_clock::now() - parseStartedAt)
                                     .count();
        payload["mountInfoReadable"] = tables.mountInfoReadable;

        payload["mountInfoEntryCount"] = tables.mountInfoEntryCount;

        payload["overlayDeclared"] = tables.overlayDeclared;
        payload["rootPropagationPrivate"] = tables.rootPropagationPrivate;
        payload["mountIdSequence"] = buildSequenceTelemetry(tables);

        const std::string selfNamespace = readLink("/proc/self/ns/mnt");
        const std::string initNamespace = readLink("/proc/1/ns/mnt");
        payload["selfNamespace"] = selfNamespace;
        payload["initNamespace"] = initNamespace;
        const bool sharesInitNamespace = !selfNamespace.empty() && selfNamespace == initNamespace;
        payload["sharesInitNamespace"] = sharesInitNamespace;

        int strongCount = 0;
        int moderateCount = 0;
        int weakCount = 0;
        const auto evaluateStartedAt = std::chrono::steady_clock::now();
        evaluateMountRows(tables, payload, strongCount, weakCount);
        LOGI_TAG("MountIntegrity",
                 "event=phase_timing mountInfoRows=%zu parseMicros=%lld "
                 "evaluateMicros=%lld",
                 tables.mountInfoRows.size(),
                 static_cast<long long>(parseMicros),
                 static_cast<long long>(
                     std::chrono::duration_cast<std::chrono::microseconds>(
                         std::chrono::steady_clock::now() - evaluateStartedAt)
                         .count()));
        std::unordered_set<std::string> consistencyDedupe;

        if (sharesInitNamespace) {
            MountRow nsRow{0, "/proc/1/ns/mnt", "/proc/self/ns/mnt", "nsfs", "self=" + selfNamespace};
            if (addFinding(payload["findings"], consistencyDedupe, "shared_init_namespace", "namespace",
                           "strong", "SHARED_INIT_NS", nsRow,
                           "Process shares the root init mount namespace without zygote isolation")) {
                ++strongCount;
            }
        }

        // The mount-ID sequence between the ART module and /data_mirror is telemetry only since
        // 2026-09-18. Its rule graded missing IDs as WEAK or MODERATE on the premise that a mount
        // removed from this process's view leaves a hole in the numbering. The fleet contradicts
        // it in both directions: a clean, locked Xiaomi 12 showed 160 missing IDs, the Redmi 13C
        // showed a MODERATE gap in one capture and none in another of the same configuration
        // (cells Z0 and L3, captured on different days), and no
        // ablation cell ever showed a gap while DenyList really did remove mounts from the view.
        // A rule that fires on an unmodified phone and cannot be tied to concealment on a
        // modified one is not evidence, so it no longer produces a finding. No other rule here
        // grades MODERATE, so moderateCount stays zero; the field is kept for payload stability.
        const auto& sequence = payload["mountIdSequence"];
        const bool sequenceAvailable = !sequence["artMountId"].is_null() &&
                                       !sequence["dataMirrorMountId"].is_null();
        payload["mountIdSequence"]["assessmentImpact"] = "telemetry_only";

        int completedStatxChecks = 0;
        int hiddenMountIds = 0;
        constexpr std::array<const char*, 7> kStatxPaths = {
            "/data/data", "/system", "/system/bin", "/vendor", "/vendor/bin", "/product", "/apex"};
        for (const char* path : kStatxPaths) {
            struct statx status {};
            errno = 0;
            const int result = invokeStatx(
                AT_FDCWD, path, AT_NO_AUTOMOUNT,
                STATX_BASIC_STATS | kStatxMountId, &status);
            nlohmann::json check = {{"path", path}, {"succeeded", result == 0}};
            if (result == 0 && (status.stx_mask & kStatxMountId) != 0) {
                ++completedStatxChecks;
                const auto mountId = static_cast<unsigned long long>(status.stx_mnt_id);
                const bool present = tables.mountIds.find(mountId) != tables.mountIds.end();
                check["mountId"] = mountId;
                check["presentInMountInfo"] = present;
                if (tables.mountInfoReadable && !present) {
                    ++hiddenMountIds;
                    ++strongCount;
                    MountRow row{mountId, "statx", path, "", ""};
                    addFinding(payload["findings"], consistencyDedupe,
                               "statx_mount_id_missing", "consistency", "strong",
                               "STATX_MNT_ID", row,
                               "Kernel mount ID is absent from mountinfo");
                }
            } else {
                check["errno"] = errno;
            }
            payload["statxChecks"].push_back(std::move(check));
        }

        if (completedStatxChecks == 0) {
            payload["collectionErrors"].push_back(
                {{"source", "statx"},
                 {"errno", ENOSYS},
                 {"message",
                  "statx syscall or libc symbol is unavailable; mount-ID cross-check was skipped."}});
            LOGI_TAG("MountIntegrity",
                     "event=statx_unavailable reason=syscall_or_symbol_missing hostContinues=true");
        }

        int completedStatfsChecks = 0;
        int hiddenOverlayPaths = 0;
        constexpr std::array<const char*, 5> kStatfsPaths = {
            "/system", "/system/bin", "/vendor", "/product", "/system_ext"};
        for (const char* path : kStatfsPaths) {
            struct statfs status {};
            errno = 0;
            const int result = statfs(path, &status);
            nlohmann::json check = {{"path", path}, {"succeeded", result == 0}};
            if (result == 0) {
                ++completedStatfsChecks;
                const auto fsType = static_cast<unsigned long>(status.f_type);
                const bool overlay = fsType == kOverlayFsMagic;
                check["fsType"] = fsType;
                check["overlay"] = overlay;
                // overlayDeclared is derived from mountinfo alone, so mountinfo's
                // readability is what separates "no overlay is declared" from "we could
                // not look".
                if (overlay && tables.mountInfoReadable && !tables.overlayDeclared) {
                    ++hiddenOverlayPaths;
                    ++strongCount;
                    MountRow row{0, "statfs", path, "overlay", ""};
                    addFinding(payload["findings"], consistencyDedupe, "hidden_overlayfs",
                               "consistency", "strong", "OVERLAYFS_SUPER_MAGIC", row,
                               "OverlayFS is visible through statfs but absent from mount tables");
                }
            } else {
                check["errno"] = errno;
            }
            payload["statfsChecks"].push_back(std::move(check));
        }

        payload["completedStatxChecks"] = completedStatxChecks;
        payload["completedStatfsChecks"] = completedStatfsChecks;
        payload["hiddenMountIdCount"] = hiddenMountIds;
        payload["hiddenOverlayCount"] = hiddenOverlayPaths;
        payload["strongFindingCount"] = strongCount;
        payload["moderateFindingCount"] = moderateCount;
        payload["weakFindingCount"] = weakCount;
        payload["findingCount"] = static_cast<int>(payload["findings"].size());

        LOGI_TAG("MountIntegrity",
                 "event=summary strongCount=%d moderateCount=%d weakCount=%d hiddenMountIdCount=%d "
                 "hiddenOverlayCount=%d directBlockCount=%zu genericHeuristicCount=%zu "
                 "gapAvailable=%s gapMissingCount=%llu maxGap=%llu sharesInitNamespace=%s",
                 strongCount, moderateCount, weakCount, hiddenMountIds, hiddenOverlayPaths,
                 payload["directBlockMounts"].size(),
                 payload["genericMountHeuristics"].size(),
                 sequenceAvailable ? "true" : "false",
                 sequenceAvailable ? sequence["missingCount"].get<unsigned long long>() : 0ULL,
                 sequenceAvailable ? sequence["maximumGap"].get<unsigned long long>() : 0ULL,
                 sharesInitNamespace ? "true" : "false");
        for (const auto& heuristic : payload["genericMountHeuristics"]) {
            LOGI_TAG("MountIntegrity",
                     "event=generic_mount_heuristic ruleId=%s partition=%s rowCount=%zu "
                     "assessmentImpact=%s",
                     heuristic.value("ruleId", "").c_str(),
                     heuristic.value("partition", "").c_str(),
                     heuristic["rowCount"].get<size_t>(),
                     heuristic.value("assessmentImpact", "").c_str());
        }
        if (sequenceAvailable) {
            LOGI_TAG("MountIntegrity",
                     "event=mount_id_sequence experimental=true artMountId=%llu "
                     "dataMirrorMountId=%llu visibleCount=%d missingCount=%llu "
                     "maximumGap=%llu gapRangeCount=%zu",
                     sequence["artMountId"].get<unsigned long long>(),
                     sequence["dataMirrorMountId"].get<unsigned long long>(),
                     sequence["visibleCount"].get<int>(),
                     sequence["missingCount"].get<unsigned long long>(),
                     sequence["maximumGap"].get<unsigned long long>(),
                     sequence["gapRanges"].size());
        }
        for (const auto& finding : payload["findings"]) {
            if (finding.value("confidence", "") != "strong" && finding.value("confidence", "") != "moderate") continue;
            LOGI_TAG("MountIntegrity",
                     "event=finding ruleId=%s family=%s confidence=%s marker=%s target=%s",
                     finding.value("ruleId", "").c_str(), finding.value("family", "").c_str(),
                     finding.value("confidence", "").c_str(), finding.value("marker", "").c_str(),
                     finding.value("target", "").c_str());
        }

        const DetectionAssessment assessment = aggregateAssessment(
            strongCount, moderateCount, weakCount, tables.mountInfoReadable,
            completedStatxChecks + completedStatfsChecks);
        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "MOUNT_INTEGRITY"; }
};

REGISTER_DETECTION(MountIntegrityDetection);

}  // namespace tamperprobe
