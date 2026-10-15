#include <dirent.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "../../common/log.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {

namespace {

constexpr char kComponent[] = "FdForensics";
constexpr char kTrapSignature[] = "tamperprobe:zygisk:fdtrap:v1";

// Bounds the sweep. Android app processes stay far below this; the cap keeps the
// probe cost fixed on devices that raise RLIMIT_NOFILE.
constexpr int kMaxScannedFd = 2048;

// A candidate must reproduce the same disagreement in every round before it is
// reported. One round is the initial sweep; the rest are confirmations.
constexpr int kConfirmationRounds = 3;

// Below this many table-open descriptors there is not enough material to tell a
// filtered procfs apart from an ordinary quiet process.
constexpr int kMinimumDescriptorsForProcfsVerdict = 8;

// Emitting every disagreement would let a hostile process inflate the payload.
constexpr size_t kMaxReportedContradictions = 16;

constexpr size_t kMaxSnapshotBytes = 64 * 1024;

// View 1: the descriptor table itself.
bool descriptorTableOpen(int fd) { return fcntl(fd, F_GETFD) != -1; }

// View 2: the procfs lookup path (proc_fd_link).
bool descriptorLookupOpen(int fd, std::string* target) {
    char path[64] = {};
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    char resolved[512] = {};
    const ssize_t length = readlink(path, resolved, sizeof(resolved) - 1);
    if (length < 0) {
        return false;
    }
    if (target != nullptr) {
        target->assign(resolved, static_cast<size_t>(length));
    }
    return true;
}

// View 3: the procfs iterate path (proc_readfd). Hiding implementations often
// filter the directory listing without also filtering lookup, which is exactly
// the disagreement this detector is built to notice.
bool collectIterateView(std::set<int>& out, int& ownDescriptor) {
    ownDescriptor = -1;
    DIR* dir = opendir("/proc/self/fd");
    if (dir == nullptr) {
        return false;
    }
    ownDescriptor = dirfd(dir);
    out.clear();
    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') {
            continue;
        }
        out.insert(static_cast<int>(strtol(entry->d_name, nullptr, 10)));
    }
    closedir(dir);
    return true;
}

// Classifies a descriptor target into a coarse bucket. Raw targets are never
// emitted: they carry storage paths and, for sockets, peer identifiers.
std::string classifyTarget(const std::string& target) {
    std::string bucket;
    if (target.rfind("socket:", 0) == 0) {
        bucket = "socket";
    } else if (target.rfind("pipe:", 0) == 0) {
        bucket = "pipe";
    } else if (target.rfind("anon_inode:", 0) == 0) {
        bucket = "anon_inode";
    } else if (target.rfind("memfd:", 0) == 0 || target.find("/memfd:") != std::string::npos) {
        bucket = "memfd";
    } else if (target.rfind("/dev/", 0) == 0) {
        bucket = "device";
    } else if (target.rfind("/apex/", 0) == 0 || target.rfind("/system/", 0) == 0 ||
               target.rfind("/vendor/", 0) == 0 || target.rfind("/product/", 0) == 0) {
        bucket = "system_image";
    } else if (target.rfind("/data/", 0) == 0) {
        bucket = "app_storage";
    } else if (target.empty()) {
        bucket = "unresolved";
    } else {
        bucket = "other";
    }
    if (target.size() >= 10 && target.compare(target.size() - 10, 10, " (deleted)") == 0) {
        bucket += "+deleted";
    }
    return bucket;
}

struct DescriptorViews {
    bool table = false;
    bool lookup = false;
    bool iterate = false;

    bool agrees(bool iterateReadable) const {
        if (table != lookup) {
            return false;
        }
        return !iterateReadable || lookup == iterate;
    }

    std::string signature() const {
        return std::string(table ? "t1" : "t0") + (lookup ? "l1" : "l0") +
               (iterate ? "i1" : "i0");
    }
};

// Names the direction of a disagreement. Only the two "hidden" categories imply
// filtering; the phantom categories are far more likely to be a lost race and are
// reported without being counted as filtering evidence.
std::string categorize(const DescriptorViews& views, bool iterateReadable) {
    if (views.table && !views.lookup) {
        return "hidden_from_lookup";
    }
    if (iterateReadable && views.lookup && !views.iterate) {
        return "hidden_from_iterate";
    }
    if (!views.table && views.lookup) {
        return "phantom_lookup";
    }
    if (iterateReadable && !views.lookup && views.iterate) {
        return "phantom_iterate";
    }
    return "unclassified";
}

/**
 * Cross-checks the three independent kernel views of this process's own
 * descriptor table. A stable disagreement is a contradiction inside the kernel's
 * own accounting rather than a threshold comparison, so no device calibration is
 * required to interpret it.
 */
nlohmann::json inspectDescriptorTable() {
    nlohmann::json report;

    int limit = kMaxScannedFd;
    struct rlimit bound {};
    if (getrlimit(RLIMIT_NOFILE, &bound) == 0 && bound.rlim_cur != RLIM_INFINITY &&
        static_cast<int>(bound.rlim_cur) < limit) {
        limit = static_cast<int>(bound.rlim_cur);
    }
    report["scannedDescriptorRange"] = limit;

    std::set<int> excluded;
    std::set<int> iterateView;
    int ownDescriptor = -1;
    const bool iterateReadable = collectIterateView(iterateView, ownDescriptor);
    if (ownDescriptor >= 0) {
        excluded.insert(ownDescriptor);
    }
    report["iterateViewReadable"] = iterateReadable;

    std::vector<int> candidates;
    std::map<int, DescriptorViews> observations;
    std::map<int, std::string> targetBuckets;
    int tableOpenCount = 0;
    int lookupOpenCount = 0;

    for (int fd = 0; fd < limit; ++fd) {
        if (excluded.count(fd) != 0) {
            continue;
        }
        DescriptorViews views;
        std::string target;
        views.table = descriptorTableOpen(fd);
        views.lookup = descriptorLookupOpen(fd, &target);
        views.iterate = iterateView.count(fd) != 0;
        if (views.table) {
            tableOpenCount++;
        }
        if (views.lookup) {
            lookupOpenCount++;
            targetBuckets[fd] = classifyTarget(target);
        }
        if (views.agrees(iterateReadable)) {
            continue;
        }
        candidates.push_back(fd);
        observations[fd] = views;
    }

    report["tableOpenCount"] = tableOpenCount;
    report["lookupOpenCount"] = lookupOpenCount;
    report["candidateCount"] = static_cast<int>(candidates.size());

    // Guard: if procfs resolves nothing at all while the table reports a healthy
    // population, the procfs view is unusable rather than filtered. Reporting that
    // as thousands of contradictions would be the detector's worst failure mode.
    const bool procfsUnusable = tableOpenCount >= kMinimumDescriptorsForProcfsVerdict &&
                                lookupOpenCount == 0;
    report["procfsUnusable"] = procfsUnusable;
    if (procfsUnusable) {
        report["confirmedCount"] = 0;
        report["hiddenFromIterateCount"] = 0;
        report["hiddenFromLookupCount"] = 0;
        report["phantomCount"] = 0;
        report["contradictions"] = nlohmann::json::array();
        report["collectionError"] =
            "The procfs descriptor views resolved no entries while the descriptor "
            "table reported open descriptors; the comparison was skipped.";
        return report;
    }

    // Confirmation rounds. A descriptor closed or opened by another thread between
    // the sweeps produces a disagreement once and then settles, so only a signature
    // that repeats unchanged survives.
    std::set<int> unstable;
    for (int round = 0; round < kConfirmationRounds && !candidates.empty(); ++round) {
        std::set<int> roundIterate;
        int roundOwnDescriptor = -1;
        const bool roundReadable = collectIterateView(roundIterate, roundOwnDescriptor);
        if (roundOwnDescriptor >= 0) {
            excluded.insert(roundOwnDescriptor);
        }
        for (int fd : candidates) {
            if (excluded.count(fd) != 0 || unstable.count(fd) != 0) {
                continue;
            }
            DescriptorViews views;
            views.table = descriptorTableOpen(fd);
            views.lookup = descriptorLookupOpen(fd, nullptr);
            views.iterate = roundIterate.count(fd) != 0;
            if (!roundReadable || views.signature() != observations[fd].signature()) {
                unstable.insert(fd);
            }
        }
    }

    nlohmann::json contradictions = nlohmann::json::array();
    int hiddenFromIterate = 0;
    int hiddenFromLookup = 0;
    int phantom = 0;
    for (int fd : candidates) {
        if (excluded.count(fd) != 0 || unstable.count(fd) != 0) {
            continue;
        }
        const DescriptorViews& views = observations[fd];
        const std::string category = categorize(views, iterateReadable);
        if (category == "hidden_from_iterate") {
            hiddenFromIterate++;
        } else if (category == "hidden_from_lookup") {
            hiddenFromLookup++;
        } else {
            phantom++;
        }
        if (contradictions.size() < kMaxReportedContradictions) {
            nlohmann::json record;
            record["descriptor"] = fd;
            record["tableOpen"] = views.table;
            record["lookupOpen"] = views.lookup;
            record["iterateOpen"] = views.iterate;
            record["category"] = category;
            const auto bucket = targetBuckets.find(fd);
            record["targetClass"] = bucket == targetBuckets.end() ? "unresolved" : bucket->second;
            contradictions.push_back(record);
        }
    }

    report["unstableCandidateCount"] = static_cast<int>(unstable.size());
    report["hiddenFromIterateCount"] = hiddenFromIterate;
    report["hiddenFromLookupCount"] = hiddenFromLookup;
    report["phantomCount"] = phantom;
    report["confirmedCount"] = hiddenFromIterate + hiddenFromLookup;
    report["contradictions"] = contradictions;
    return report;
}

/**
 * Verifies a trap descriptor handed across the Binder boundary.
 *
 * This reproduces Duck-Detector's cross-process FD trap so its result can be
 * recorded independently. It is telemetry only: the descriptor is installed into
 * the receiving process by the binder driver after that process has finished
 * specializing, so no Zygisk-style specialization-time descriptor sanitization can
 * ever have touched it. See the Chapter 3 note cross_process_fd_trap.md.
 */
nlohmann::json verifyTrapDescriptor(int trapFd) {
    nlohmann::json report;
    if (trapFd < 0) {
        report["status"] = "not_supplied";
        return report;
    }

    struct stat status {};
    if (fstat(trapFd, &status) != 0) {
        report["status"] = errno == EBADF ? "closed_ebadf" : "stat_failed";
        report["errorCode"] = errno;
        return report;
    }

    const size_t signatureLength = sizeof(kTrapSignature) - 1;
    char buffer[64] = {};
    const ssize_t readBytes = pread(trapFd, buffer, signatureLength, 0);
    if (readBytes != static_cast<ssize_t>(signatureLength) ||
        memcmp(buffer, kTrapSignature, signatureLength) != 0) {
        report["status"] = "corrupted";
        report["bytesRead"] = static_cast<int>(readBytes);
        return report;
    }

    std::string target;
    if (!descriptorLookupOpen(trapFd, &target)) {
        report["status"] = "procfs_anomaly";
        return report;
    }
    report["status"] = "survived";
    report["targetClass"] = classifyTarget(target);
    return report;
}

nlohmann::json collectCarrierSnapshot(int trapFd) {
    nlohmann::json snapshot;
    snapshot["schemaVersion"] = 1;
    snapshot["descriptorTable"] = inspectDescriptorTable();
    snapshot["trapDescriptor"] = verifyTrapDescriptor(trapFd);
    return snapshot;
}

nlohmann::json parseCarrierSnapshot(const std::string& bytes) {
    nlohmann::json view;
    if (bytes.empty()) {
        view["available"] = false;
        view["collectionError"] =
            "The descriptor-forensics carrier produced no snapshot for this scan.";
        return view;
    }
    if (bytes.size() > kMaxSnapshotBytes) {
        view["available"] = false;
        view["collectionError"] = "Descriptor-forensics carrier snapshot exceeded 64 KiB.";
        return view;
    }
    nlohmann::json parsed = nlohmann::json::parse(bytes, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) {
        view["available"] = false;
        view["collectionError"] = "Descriptor-forensics carrier snapshot was not valid JSON.";
        return view;
    }
    if (parsed.contains("collectionFailure")) {
        view["available"] = false;
        view["collectionError"] = parsed["collectionFailure"].value("message", "unknown");
        return view;
    }
    view["available"] = true;
    view["descriptorTable"] = parsed.value("descriptorTable", nlohmann::json::object());
    view["trapDescriptor"] = parsed.value("trapDescriptor", nlohmann::json::object());
    return view;
}

constexpr char kDifferentialUnitId[] = "zygisk-fd-forensics.descriptor-view-differential";

// Only the two "hidden" categories are promoted to findings. The phantom
// categories are far more likely to be a descriptor closed by another thread
// between two sweeps, so they stay in the raw contradiction list.
void appendFindings(const nlohmann::json& table, const char* process,
                    nlohmann::json& findings) {
    if (!table.is_object() || !table.contains("contradictions") ||
        !table["contradictions"].is_array()) {
        return;
    }
    for (const auto& entry : table["contradictions"]) {
        const std::string category = entry.value("category", std::string());
        const bool hiddenFromIterate = category == "hidden_from_iterate";
        if (!hiddenFromIterate && category != "hidden_from_lookup") {
            continue;
        }
        nlohmann::json finding;
        finding["id"] = hiddenFromIterate ? "descriptor_hidden_from_iterate"
                                          : "descriptor_hidden_from_lookup";
        finding["unitId"] = kDifferentialUnitId;
        finding["process"] = process;
        finding["category"] = category;
        finding["descriptor"] = entry.value("descriptor", -1);
        finding["targetClass"] = entry.value("targetClass", std::string("unresolved"));
        finding["strength"] = "MODERATE";
        finding["summary"] =
            hiddenFromIterate
                ? "A descriptor resolves through /proc/self/fd but is absent from its listing"
                : "A descriptor is open in the table but does not resolve through /proc/self/fd";
        finding["detail"] =
            hiddenFromIterate
                ? "The procfs lookup and iterate paths disagree about the same descriptor "
                  "across repeated sweeps, which is consistent with a filtered directory "
                  "listing rather than with a concurrent close."
                : "The descriptor table and the procfs lookup path disagree about the same "
                  "descriptor across repeated sweeps, which is consistent with a filtered "
                  "procfs rather than with a concurrent close.";
        findings.push_back(finding);
    }
}

void appendCollectionError(nlohmann::json& errors, const char* source,
                           const std::string& message) {
    nlohmann::json entry;
    entry["source"] = source;
    entry["message"] = message;
    errors.push_back(entry);
}

int confirmedCountOf(const nlohmann::json& descriptorTable) {
    if (!descriptorTable.is_object()) {
        return 0;
    }
    return descriptorTable.value("confirmedCount", 0);
}

bool tableUsable(const nlohmann::json& descriptorTable) {
    return descriptorTable.is_object() && !descriptorTable.value("procfsUnusable", false) &&
           !descriptorTable.contains("collectionError");
}

}  // namespace

/**
 * Cross-process descriptor forensics.
 *
 * 1. Cross-checks three independent kernel views of the descriptor table
 *    (fcntl(F_GETFD), /proc/self/fd lookup, /proc/self/fd iteration) in the host
 *    process, and again in a helper process forked fresh from Zygote. A stable
 *    disagreement means one procfs path is being filtered.
 * 2. Carries Duck-Detector's cross-process trap descriptor as telemetry so its
 *    published result can be reproduced; that channel cannot move the outcome.
 *
 * References: Duck-Detector zygisk/probes/fd_trap.cpp (Apache-2.0) for the trap
 * channel only. The view differential is an independent TamperProbe design.
 */
class ZygiskFdForensicsDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        nlohmann::json hostTable = inspectDescriptorTable();
        nlohmann::json carrier = parseCarrierSnapshot(scanContext.fdForensicsSnapshot);

        const bool carrierAvailable = carrier.value("available", false);
        const nlohmann::json carrierTable =
            carrierAvailable ? carrier.value("descriptorTable", nlohmann::json::object())
                             : nlohmann::json::object();
        const bool hostUsable = tableUsable(hostTable);
        const bool carrierUsable = carrierAvailable && tableUsable(carrierTable);
        const int hostConfirmed = hostUsable ? confirmedCountOf(hostTable) : 0;
        const int carrierConfirmed = carrierUsable ? confirmedCountOf(carrierTable) : 0;

        nlohmann::json findings = nlohmann::json::array();
        if (hostUsable) {
            appendFindings(hostTable, "host", findings);
        }
        if (carrierUsable) {
            appendFindings(carrierTable, "carrier", findings);
        }

        nlohmann::json collectionErrors = nlohmann::json::array();
        if (hostTable.contains("collectionError")) {
            appendCollectionError(collectionErrors, "host_process",
                                  hostTable["collectionError"].get<std::string>());
        }
        if (!carrierAvailable) {
            appendCollectionError(
                collectionErrors, "carrier_process",
                carrier.value("collectionError",
                              std::string("The descriptor-forensics carrier was unavailable.")));
        } else if (carrierTable.contains("collectionError")) {
            appendCollectionError(collectionErrors, "carrier_process",
                                  carrierTable["collectionError"].get<std::string>());
        }

        nlohmann::json overview;
        overview["hostConfirmedCount"] = hostConfirmed;
        overview["carrierConfirmedCount"] = carrierConfirmed;
        overview["findingCount"] = static_cast<int>(findings.size());
        overview["carrierAvailable"] = carrierAvailable;
        overview["hostViewsUsable"] = hostUsable;
        overview["carrierViewsUsable"] = carrierUsable;
        // Research only. A view filtered in one process but not the other is
        // interesting, but with no clean-device baseline it is not yet an assertion
        // this detector is willing to make on its own.
        overview["processDivergence"] =
            carrierUsable && hostUsable && ((hostConfirmed > 0) != (carrierConfirmed > 0));

        nlohmann::json trapChannel;
        trapChannel["carrierStatus"] =
            carrierAvailable
                ? carrier.value("trapDescriptor", nlohmann::json::object())
                      .value("status", std::string("unknown"))
                : std::string("unavailable");
        // Duck-Detector treats a failed trap as a top-tier strong signal. The
        // descriptor is installed by the binder driver after the carrier process has
        // finished specializing, so specialization-time sanitization cannot reach it
        // and no outcome of this channel may move the assessment.
        trapChannel["assessmentImpact"] = "telemetry_only";

        nlohmann::json payload;
        payload["overview"] = overview;
        payload["hostProcess"] = hostTable;
        payload["carrierProcess"] = carrier;
        payload["trapChannel"] = trapChannel;
        payload["findings"] = findings;
        payload["collectionErrors"] = collectionErrors;
        payload["collectionStatus"] = hostUsable && carrierUsable
                                          ? "complete"
                                          : (hostUsable || carrierUsable ? "partial" : "unavailable");

        LOGI_TAG(kComponent,
                 "event=descriptor_view_differential hostUsable=%d carrierUsable=%d "
                 "hostConfirmed=%d carrierConfirmed=%d findingCount=%d trapStatus=%s",
                 hostUsable ? 1 : 0, carrierUsable ? 1 : 0, hostConfirmed, carrierConfirmed,
                 static_cast<int>(findings.size()),
                 trapChannel["carrierStatus"].get<std::string>().c_str());

        if (!hostUsable && !carrierUsable) {
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        // A contradiction between two kernel views of one descriptor table is
        // threshold-free, but procfs is inherently racy and no clean-device baseline
        // exists yet, so this stays at MODERATE.
        DetectionAssessment assessment = DetectionAssessment::notObserved();
        if (!findings.empty()) {
            assessment = DetectionAssessment::moderateObserved();
        }
        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "ZYGISK_FD_FORENSICS"; }
};

REGISTER_DETECTION(ZygiskFdForensicsDetection);

}  // namespace tamperprobe

extern "C" JNIEXPORT jbyteArray JNICALL
Java_io_leemikepop_tamperprobe_lab_internal_fdforensics_FdForensicsNativeBridge_nativeCollectSnapshot(
    JNIEnv* env, jclass, jint trapFd) {
    try {
        const std::string value = tamperprobe::collectCarrierSnapshot(trapFd).dump();
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
