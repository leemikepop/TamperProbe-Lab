#include <dlfcn.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "../../common/log.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"
#include "property_detector_logic.h"

namespace tamperprobe {
namespace {

constexpr char kSelinuxDirectory[] = "/sys/fs/selinux";
constexpr char kEnforcePath[] = "/sys/fs/selinux/enforce";
constexpr char kProcessContextPath[] = "/proc/self/attr/current";

struct EnforcementSource {
    std::string source;
    std::string state = "unavailable";
    SelinuxMode mode = SelinuxMode::UNKNOWN;
    std::string error;
    int errorNumber = 0;
};

struct TextObservation {
    std::string state = "unavailable";
    std::string value;
    std::string error;
    int errorNumber = 0;
    std::string failedStep;  // "open" or "read" when state is unavailable
};

TextObservation readSmallFile(const char* path) {
    const int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        const int errorNumber = errno;
        return {"unavailable", {}, strerror(errorNumber), errorNumber, "open"};
    }
    std::array<char, 512> buffer{};
    const ssize_t length = read(descriptor, buffer.data(), buffer.size() - 1);
    const int errorNumber = errno;
    close(descriptor);
    if (length < 0) return {"unavailable", {}, strerror(errorNumber), errorNumber, "read"};
    if (length == 0) return {"invalid", {}, "file is empty", 0, {}};
    std::string value(buffer.data(), static_cast<std::size_t>(length));
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == '\0')) {
        value.pop_back();
    }
    return {"present", std::move(value), {}, 0, {}};
}

EnforcementSource readEnforceFile(TextObservation& observation) {
    observation = readSmallFile(kEnforcePath);
    EnforcementSource source;
    source.source = "selinuxfs_enforce";
    source.state = observation.state;
    source.error = observation.error;
    source.errorNumber = observation.errorNumber;
    if (observation.state != "present") return source;
    if (observation.value == "1") {
        source.mode = SelinuxMode::ENFORCING;
    } else if (observation.value == "0") {
        source.mode = SelinuxMode::PERMISSIVE;
    } else {
        source.state = "invalid";
        source.error = "enforce file contains an unsupported value";
    }
    return source;
}

EnforcementSource readLibselinux() {
    EnforcementSource source;
    source.source = "libselinux";
    using IsEnabledFunction = int (*)();
    using GetEnforceFunction = int (*)();

    // libselinux is already mapped into every app process by the framework, but an
    // application's linker namespace refuses to load it fresh, so a plain dlopen fails with
    // "library not found". Resolve against the symbols already in the process first, then
    // ask for the already-loaded image with RTLD_NOLOAD. A plain RTLD_LOCAL load was used
    // here until 2026-09-12, which is why this source reported "library not found" in every
    // cell of the ablation study on both devices. The same fix already exists in
    // policy_oracle.cpp, and Duck-Detector's selinux probes resolve symbols the same way.
    auto isEnabled = reinterpret_cast<IsEnabledFunction>(dlsym(RTLD_DEFAULT, "is_selinux_enabled"));
    auto getEnforce = reinterpret_cast<GetEnforceFunction>(dlsym(RTLD_DEFAULT, "security_getenforce"));

    void* library = nullptr;
    if (isEnabled == nullptr || getEnforce == nullptr) {
        library = dlopen("libselinux.so", RTLD_NOW | RTLD_NOLOAD);
        if (library == nullptr) {
            const char* error = dlerror();
            source.error = error == nullptr ? "libselinux is unavailable" : error;
            return source;
        }
        if (isEnabled == nullptr) {
            isEnabled = reinterpret_cast<IsEnabledFunction>(dlsym(library, "is_selinux_enabled"));
        }
        if (getEnforce == nullptr) {
            getEnforce = reinterpret_cast<GetEnforceFunction>(dlsym(library, "security_getenforce"));
        }
    }
    if (isEnabled == nullptr || getEnforce == nullptr) {
        source.error = "required libselinux symbols are unavailable";
        if (library != nullptr) dlclose(library);
        return source;
    }
    errno = 0;
    const int enabled = isEnabled();
    if (enabled == 0) {
        source.state = "present";
        source.mode = SelinuxMode::DISABLED;
    } else if (enabled > 0) {
        errno = 0;
        const int enforcing = getEnforce();
        if (enforcing == 1) {
            source.state = "present";
            source.mode = SelinuxMode::ENFORCING;
        } else if (enforcing == 0) {
            source.state = "present";
            source.mode = SelinuxMode::PERMISSIVE;
        } else {
            // Resolving the symbol does not grant access: security_getenforce reads
            // /sys/fs/selinux/enforce itself, which an app is normally denied. Record the
            // errno so this is distinguishable from a missing library.
            source.errorNumber = errno;
            source.error = std::string("security_getenforce failed: ") +
                           (errno != 0 ? strerror(errno) : "no errno reported");
        }
    } else {
        source.errorNumber = errno;
        source.error = std::string("is_selinux_enabled failed: ") +
                       (errno != 0 ? strerror(errno) : "no errno reported");
    }
    if (library != nullptr) dlclose(library);
    return source;
}

std::string processDomain(const std::string& context) {
    std::istringstream stream(context);
    std::string segment;
    for (int index = 0; std::getline(stream, segment, ':'); ++index) {
        if (index == 2) return segment;
    }
    return {};
}

void appendCollectionWarning(nlohmann::json& errors, const std::string& source,
                             const std::string& path, int errorNumber,
                             const std::string& message) {
    errors.push_back({{"source", source},
                      {"path", path},
                      {"errno", errorNumber},
                      {"message", message}});
}

std::string octalMode(unsigned int mode) {
    char buffer[8];
    std::snprintf(buffer, sizeof(buffer), "%04o", mode & 07777u);
    return buffer;
}

const char* fileTypeName(unsigned int mode) {
    const auto type = static_cast<mode_t>(mode);
    if (S_ISREG(type)) return "regular";
    if (S_ISDIR(type)) return "directory";
    if (S_ISLNK(type)) return "symlink";
    if (S_ISCHR(type)) return "char_device";
    if (S_ISBLK(type)) return "block_device";
    if (S_ISFIFO(type)) return "fifo";
    if (S_ISSOCK(type)) return "socket";
    return "other";
}

// Read-denial inference. The kernel creates selinuxfs "enforce" as S_IRUGO|S_IWUSR owned by
// root (security/selinux/selinuxfs.c, sel_fill_super), so DAC lets every uid read it. When the
// app's O_RDONLY open/read still fails with EACCES, the refusal came from SELinux enforcing a
// denial on the app's own domain: under global or per-domain permissive the read succeeds.
// The decision lives in inferSelinuxReadDenial (property_detector_logic.cpp) so the native
// fixtures can exercise it; this function only gathers stat() and the caller's credentials.
SelinuxReadDenialInference runReadDenialInference(const TextObservation& read,
                                                  bool selinuxfsVerified,
                                                  nlohmann::json& telemetry) {
    SelinuxReadDenialInput input;
    input.readErrno = read.state == "unavailable" ? read.errorNumber : 0;
    input.selinuxfsVerified = selinuxfsVerified;
    input.callerUid = static_cast<unsigned int>(geteuid());
    input.callerGroups.push_back(static_cast<unsigned int>(getegid()));
    telemetry = {{"readErrno", input.readErrno}};
    if (!read.failedStep.empty()) telemetry["readStep"] = read.failedStep;

    if (input.readErrno == EACCES) {
        const int groupCount = getgroups(0, nullptr);
        if (groupCount > 0) {
            std::vector<gid_t> groups(static_cast<std::size_t>(groupCount));
            const int filled = getgroups(groupCount, groups.data());
            for (int index = 0; index < filled; ++index) {
                input.callerGroups.push_back(static_cast<unsigned int>(groups[index]));
            }
        }
        input.statAttempted = true;
        struct stat nodeStatus {};
        errno = 0;
        if (stat(kEnforcePath, &nodeStatus) == 0) {
            input.statMode = static_cast<unsigned int>(nodeStatus.st_mode);
            input.statUid = static_cast<unsigned int>(nodeStatus.st_uid);
            input.statGid = static_cast<unsigned int>(nodeStatus.st_gid);
            telemetry["stat"] = {{"state", "present"},
                                 {"mode", octalMode(input.statMode)},
                                 {"fileType", fileTypeName(input.statMode)},
                                 {"uid", input.statUid},
                                 {"gid", input.statGid}};
        } else {
            input.statErrno = errno;
            telemetry["stat"] = {{"state", "unavailable"},
                                 {"errno", input.statErrno},
                                 {"error", strerror(input.statErrno)}};
        }
    }

    const SelinuxReadDenialInference inference = inferSelinuxReadDenial(input);
    telemetry["state"] = inference.state;
    if (!inference.reason.empty()) telemetry["reason"] = inference.reason;
    if (!inference.dacBasis.empty()) {
        telemetry["dacBasis"] = inference.dacBasis;
        telemetry["dacPermitsRead"] = inference.dacPermitsRead;
        if (inference.dacBasis == "kernel_constant") {
            telemetry["kernelMode"] = octalMode(kSelinuxEnforceKernelMode);
        }
    }
    if (!inference.anomaly.empty()) telemetry["anomaly"] = inference.anomaly;
    if (inference.state == "inferred") telemetry["scope"] = "app_domain";
    LOGI_TAG("SelinuxCheck",
             "event=read_denial_inference readErrno=%d selinuxfs=%d statAttempted=%d statErrno=%d "
             "mode=%s uid=%u state=%s reason=%s dacBasis=%s",
             input.readErrno, input.selinuxfsVerified ? 1 : 0, input.statAttempted ? 1 : 0,
             input.statErrno, input.statAttempted && input.statErrno == 0
                 ? octalMode(input.statMode).c_str() : "-",
             input.statUid, inference.state.c_str(), inference.reason.c_str(),
             inference.dacBasis.empty() ? "-" : inference.dacBasis.c_str());
    return inference;
}

DetectionAssessment aggregateAssessment(const SelinuxAssessment& assessment) {
    if (assessment.strongestFinding == EvidenceStrength::STRONG) {
        return DetectionAssessment::strongObserved();
    }
    if (assessment.strongestFinding == EvidenceStrength::MODERATE) {
        return DetectionAssessment::moderateObserved();
    }
    if (!assessment.hasReliableObservation) return DetectionAssessment::inconclusive();
    return DetectionAssessment::notObserved();
}

}  // namespace

class SELinuxDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext&) override {
        nlohmann::json payload = {
            {"filesystem", {{"path", kSelinuxDirectory}, {"state", "unavailable"}}},
            {"enforcementSources", nlohmann::json::array()},
            {"writeProbe", {{"path", kEnforcePath},
                             {"state", "unavailable"},
                             {"writable", false}}},
            {"processContext", {{"path", kProcessContextPath}, {"state", "unavailable"}}},
            {"findings", nlohmann::json::array()},
            {"collectionErrors", nlohmann::json::array()},
        };

        bool selinuxfsVerified = false;
        struct statfs filesystemStatus {};
        if (statfs(kSelinuxDirectory, &filesystemStatus) == 0) {
            const auto filesystemType = static_cast<unsigned long>(filesystemStatus.f_type);
            payload["filesystem"]["fsType"] = filesystemType;
            selinuxfsVerified = filesystemType == static_cast<unsigned long>(SELINUX_MAGIC);
            payload["filesystem"]["state"] =
                filesystemType == static_cast<unsigned long>(SELINUX_MAGIC)
                    ? "selinuxfs"
                    : "unexpected_filesystem";
            if (filesystemType != static_cast<unsigned long>(SELINUX_MAGIC)) {
                appendCollectionWarning(payload["collectionErrors"], "selinuxfs",
                                        kSelinuxDirectory, 0,
                                        "SELinux directory is not backed by selinuxfs");
            }
        } else {
            const int errorNumber = errno;
            payload["filesystem"]["errno"] = errorNumber;
            appendCollectionWarning(payload["collectionErrors"], "selinuxfs",
                                    kSelinuxDirectory, errorNumber, strerror(errorNumber));
        }

        TextObservation enforceRead;
        std::vector<EnforcementSource> enforcementSources;
        enforcementSources.push_back(readEnforceFile(enforceRead));

        nlohmann::json inferenceTelemetry;
        const SelinuxReadDenialInference readDenial =
            runReadDenialInference(enforceRead, selinuxfsVerified, inferenceTelemetry);
        payload["readDenialInference"] = std::move(inferenceTelemetry);
        const bool readDenialInferred = readDenial.state == "inferred";
        EnforcementSource readDenialSource;
        readDenialSource.source = "selinuxfs_read_denial";
        if (readDenialInferred) {
            readDenialSource.state = "present";
            readDenialSource.mode = readDenial.mode;
        } else if (readDenial.state == "not_applicable") {
            readDenialSource.state = "not_applicable";
        } else {
            readDenialSource.error = readDenial.reason;
        }
        enforcementSources.push_back(std::move(readDenialSource));
        enforcementSources.push_back(readLibselinux());

        SelinuxAssessmentInput assessmentInput;
        for (const auto& source : enforcementSources) {
            nlohmann::json item = {
                {"source", source.source},
                {"state", source.state},
                {"mode", selinuxModeName(source.mode)},
            };
            if (!source.error.empty()) item["error"] = source.error;
            if (source.errorNumber != 0) item["errno"] = source.errorNumber;
            payload["enforcementSources"].push_back(std::move(item));
            const bool inferred = source.source == "selinuxfs_read_denial";
            assessmentInput.enforcementSources.push_back(
                {source.source, source.state == "present", source.mode, inferred});
            // selinuxfs_read_denial never raises an issue of its own: it is attempted only
            // when the selinuxfs_enforce read failed, and that failure is reported already --
            // unless the inference turned the refusal into an answer, in which case the read
            // source has not failed to answer and raises nothing either.
            if (source.state == "present" || inferred) continue;
            if (source.source == "selinuxfs_enforce" && readDenialInferred) continue;
            appendCollectionWarning(payload["collectionErrors"], source.source,
                                    source.source == "selinuxfs_enforce" ? kEnforcePath : "libselinux.so",
                                    source.errorNumber, source.error);
        }
        const bool anySourceAnswered = std::any_of(
            assessmentInput.enforcementSources.begin(), assessmentInput.enforcementSources.end(),
            [](const SelinuxEnforcementObservation& source) {
                return source.available && source.mode != SelinuxMode::UNKNOWN;
            });
        if (!anySourceAnswered) {
            // Owned by the enforcement-state unit: one answered source satisfies that unit's
            // proposition, so a single failed source marks only the cross-source unit.
            appendCollectionWarning(payload["collectionErrors"], "enforcement_sources",
                                    kEnforcePath, 0, "no global enforcement source reported a mode");
        }

        errno = 0;
        const int writeDescriptor = open(kEnforcePath, O_WRONLY | O_CLOEXEC);
        if (writeDescriptor >= 0) {
            payload["writeProbe"]["state"] = "opened";
            payload["writeProbe"]["writable"] = true;
            assessmentInput.writeProbeAvailable = true;
            assessmentInput.enforceNodeWritable = true;
            close(writeDescriptor);
        } else {
            const int errorNumber = errno;
            payload["writeProbe"]["errno"] = errorNumber;
            if (errorNumber == EACCES || errorNumber == EPERM) {
                payload["writeProbe"]["state"] = "denied";
                assessmentInput.writeProbeAvailable = true;
            } else {
                appendCollectionWarning(payload["collectionErrors"], "write_probe",
                                        kEnforcePath, errorNumber, strerror(errorNumber));
            }
        }

        const TextObservation context = readSmallFile(kProcessContextPath);
        payload["processContext"]["state"] = context.state;
        if (context.state == "present") {
            payload["processContext"]["context"] = context.value;
            payload["processContext"]["domain"] = processDomain(context.value);
        } else {
            if (context.errorNumber != 0) payload["processContext"]["errno"] = context.errorNumber;
            appendCollectionWarning(payload["collectionErrors"], "process_context",
                                    kProcessContextPath, context.errorNumber, context.error);
        }

        const SelinuxAssessment selinuxAssessment = assessSelinux(assessmentInput);
        for (const auto& finding : selinuxAssessment.findings) {
            payload["findings"].push_back(
                {{"id", finding.id},
                 {"strength", finding.strength == EvidenceStrength::STRONG ? "strong" : "moderate"},
                 {"summary", finding.summary},
                 {"detail", finding.detail}});
        }

        const DetectionAssessment assessment = aggregateAssessment(selinuxAssessment);
        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "SELINUX_CHECK"; }
};

REGISTER_DETECTION(SELinuxDetection);

}  // namespace tamperprobe
