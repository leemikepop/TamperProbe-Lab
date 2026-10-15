#include "binary_artifact_probe.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <string>
#include <unordered_set>

#ifndef O_PATH
#define O_PATH 010000000
#endif

namespace tamperprobe {
namespace {

constexpr const char* kOperationNames[] = {"access", "lstat", "openPath", "fstat", "header"};

const char* classifyErrorState(int errorCode) {
    if (errorCode == ENOENT || errorCode == ENOTDIR) {
        return "not_found";
    }
    if (errorCode == EACCES || errorCode == EPERM) {
        return "denied";
    }
    return "error";
}

nlohmann::json successfulOperation() {
    return {{"state", "present"}, {"errno", 0}};
}

nlohmann::json failedOperation(int errorCode) {
    return {{"state", classifyErrorState(errorCode)}, {"errno", errorCode}};
}

nlohmann::json skippedOperation() {
    return {{"state", "not_attempted"}, {"errno", 0}};
}

const char* fileTypeName(mode_t mode) {
    if (S_ISREG(mode)) return "regular";
    if (S_ISDIR(mode)) return "directory";
    if (S_ISLNK(mode)) return "symlink";
    if (S_ISCHR(mode)) return "character_device";
    if (S_ISBLK(mode)) return "block_device";
    if (S_ISFIFO(mode)) return "fifo";
    if (S_ISSOCK(mode)) return "socket";
    return "unknown";
}

void addFileMetadata(nlohmann::json& operation, const struct stat& fileStat) {
    operation["fileType"] = fileTypeName(fileStat.st_mode);
    operation["mode"] = static_cast<unsigned int>(fileStat.st_mode & 07777);
    operation["uid"] = static_cast<unsigned int>(fileStat.st_uid);
    operation["gid"] = static_cast<unsigned int>(fileStat.st_gid);
    operation["size"] = static_cast<long long>(fileStat.st_size);
    operation["device"] = static_cast<unsigned long long>(fileStat.st_dev);
    operation["inode"] = static_cast<unsigned long long>(fileStat.st_ino);
}

bool operationIsPresent(const nlohmann::json& probe, const char* operationName) {
    const auto iterator = probe.find(operationName);
    return iterator != probe.end() && iterator->is_object() &&
           iterator->value("state", "") == "present";
}

bool isVisibleArtifact(const nlohmann::json& probe) {
    return operationIsPresent(probe, "access") || operationIsPresent(probe, "lstat") ||
           operationIsPresent(probe, "openPath") || operationIsPresent(probe, "fstat");
}

bool isConclusiveAbsence(const nlohmann::json& probe) {
    for (const char* operationName : {"access", "lstat", "openPath"}) {
        const auto iterator = probe.find(operationName);
        if (iterator == probe.end() || !iterator->is_object() ||
            iterator->value("state", "") != "not_found") {
            return false;
        }
    }
    return true;
}

bool isExecutableElf(const nlohmann::json& probe) {
    const auto statIterator = probe.find("fstat");
    const auto headerIterator = probe.find("header");
    if (statIterator == probe.end() || !statIterator->is_object() ||
        headerIterator == probe.end() || !headerIterator->is_object()) {
        return false;
    }

    const auto& resolvedStat = *statIterator;
    const auto& header = *headerIterator;
    return resolvedStat.value("state", "") == "present" &&
           resolvedStat.value("fileType", "") == "regular" &&
           (resolvedStat.value("mode", 0U) & 0111U) != 0U &&
           header.value("state", "") == "present" &&
           header.value("format", "") == "elf_magic" &&
           header.value("sameResolvedObject", false);
}

void countDiagnosticState(const nlohmann::json& operation, int& deniedCount, int& errorCount) {
    if (!operation.is_object()) return;

    const std::string state = operation.value("state", "");
    if (state == "denied") {
        ++deniedCount;
    } else if (state == "error") {
        ++errorCount;
    }
}

}  // namespace

nlohmann::json probeBinaryArtifact(const BinaryArtifactCandidate& candidate) {
    nlohmann::json probe = {{"path", candidate.path}, {"candidateSource", candidate.source}};

    errno = 0;
    if (access(candidate.path.c_str(), F_OK) == 0) {
        probe["access"] = successfulOperation();
    } else {
        probe["access"] = failedOperation(errno);
    }

    struct stat linkStat {};
    errno = 0;
    if (lstat(candidate.path.c_str(), &linkStat) == 0) {
        probe["lstat"] = successfulOperation();
        addFileMetadata(probe["lstat"], linkStat);
    } else {
        probe["lstat"] = failedOperation(errno);
    }

    struct stat resolvedStat {};
    errno = 0;
    const int pathDescriptor = open(candidate.path.c_str(), O_PATH | O_CLOEXEC);
    if (pathDescriptor >= 0) {
        probe["openPath"] = successfulOperation();

        errno = 0;
        if (fstat(pathDescriptor, &resolvedStat) == 0) {
            probe["fstat"] = successfulOperation();
            addFileMetadata(probe["fstat"], resolvedStat);
        } else {
            probe["fstat"] = failedOperation(errno);
        }
        close(pathDescriptor);
    } else {
        probe["openPath"] = failedOperation(errno);
        probe["fstat"] = skippedOperation();
    }

    probe["header"] = skippedOperation();
    probe["header"]["format"] = "not_applicable";
    probe["header"]["bytesRead"] = 0;
    probe["header"]["sameResolvedObject"] = false;

    if (probe["fstat"].value("state", "") == "present" &&
        probe["fstat"].value("fileType", "") == "regular") {
        errno = 0;
        const int readDescriptor = open(candidate.path.c_str(), O_RDONLY | O_CLOEXEC);
        if (readDescriptor < 0) {
            probe["header"] = failedOperation(errno);
            probe["header"]["format"] = "unavailable";
            probe["header"]["bytesRead"] = 0;
            probe["header"]["sameResolvedObject"] = false;
        } else {
            errno = 0;
            struct stat readStat {};
            if (fstat(readDescriptor, &readStat) != 0) {
                probe["header"] = failedOperation(errno);
                probe["header"]["format"] = "unavailable";
                probe["header"]["bytesRead"] = 0;
                probe["header"]["sameResolvedObject"] = false;
            } else {
                const bool sameResolvedObject =
                    readStat.st_dev == resolvedStat.st_dev && readStat.st_ino == resolvedStat.st_ino;
                unsigned char magic[4] = {};
                errno = 0;
                const ssize_t bytesRead = pread(readDescriptor, magic, sizeof(magic), 0);
                const int readError = errno;

                if (bytesRead < 0) {
                    probe["header"] = failedOperation(readError);
                    probe["header"]["format"] = "unavailable";
                    probe["header"]["bytesRead"] = 0;
                    probe["header"]["sameResolvedObject"] = sameResolvedObject;
                } else {
                    probe["header"] = successfulOperation();
                    addFileMetadata(probe["header"], readStat);
                    probe["header"]["bytesRead"] = bytesRead;
                    probe["header"]["sameResolvedObject"] = sameResolvedObject;
                    if (bytesRead == static_cast<ssize_t>(sizeof(magic)) && magic[0] == 0x7f &&
                        magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
                        probe["header"]["format"] = "elf_magic";
                    } else if (bytesRead == 0) {
                        probe["header"]["format"] = "empty";
                    } else if (bytesRead < static_cast<ssize_t>(sizeof(magic))) {
                        probe["header"]["format"] = "truncated";
                    } else {
                        probe["header"]["format"] = "other";
                    }
                }
            }
            close(readDescriptor);
        }
    }

    return probe;
}

BinaryArtifactEvaluation evaluateBinaryArtifactProbes(
    const std::vector<nlohmann::json>& probes, BinaryArtifactProfile profile) {
    nlohmann::json findings = nlohmann::json::array();
    nlohmann::json foundPaths = nlohmann::json::array();

    int environmentCandidateCount = 0;
    int availableCandidateCount = 0;
    int unavailableCandidateCount = 0;
    int strongFindingCount = 0;
    int weakFindingCount = 0;
    int deniedOperationCount = 0;
    int errorOperationCount = 0;

    for (const auto& probe : probes) {
        if (probe.value("candidateSource", "") == "environment_path") {
            ++environmentCandidateCount;
        }

        for (const char* operationName : kOperationNames) {
            const auto iterator = probe.find(operationName);
            if (iterator != probe.end()) {
                countDiagnosticState(*iterator, deniedOperationCount, errorOperationCount);
            }
        }

        if (!isVisibleArtifact(probe)) {
            if (isConclusiveAbsence(probe)) {
                ++availableCandidateCount;
            } else {
                ++unavailableCandidateCount;
            }
            continue;
        }
        ++availableCandidateCount;

        const std::string path = probe.value("path", "");
        const std::string candidateSource = probe.value("candidateSource", "fixed_path");
        const bool strongSuArtifact =
            profile == BinaryArtifactProfile::Su && candidateSource == "fixed_path" &&
            isExecutableElf(probe);

        nlohmann::json finding = {
            {"path", path},
            {"candidateSource", candidateSource},
            {"strength", strongSuArtifact ? "strong" : "weak"},
        };

        if (profile == BinaryArtifactProfile::Su) {
            finding["id"] = strongSuArtifact ? "executable_elf_magic" : "visible_path";
            finding["classification"] =
                strongSuArtifact ? "su_executable_elf_magic_artifact" : "su_path_artifact";
            finding["summary"] =
                strongSuArtifact
                    ? "Executable su artifact with ELF magic is visible"
                    : "A su-related path is visible, but source attribution or executable format is unconfirmed";
        } else {
            finding["id"] = "visible_artifact";
            finding["classification"] = "busybox_artifact";
            finding["summary"] =
                "A BusyBox artifact is visible; legitimate utility and custom-ROM producers remain possible";
        }

        findings.push_back(std::move(finding));
        foundPaths.push_back(path);
        if (strongSuArtifact) {
            ++strongFindingCount;
        } else {
            ++weakFindingCount;
        }
    }

    nlohmann::json payload;
    payload["overview"] = {
        {"candidateCount", probes.size()},
        {"environmentCandidateCount", environmentCandidateCount},
        {"availableCandidateCount", availableCandidateCount},
        {"unavailableCandidateCount", unavailableCandidateCount},
        {"findingCount", findings.size()},
        {"strongFindingCount", strongFindingCount},
        {"weakFindingCount", weakFindingCount},
        {"deniedOperationCount", deniedOperationCount},
        {"errorOperationCount", errorOperationCount},
    };
    payload["foundPaths"] = std::move(foundPaths);
    payload["findings"] = std::move(findings);
    payload["probes"] = probes;

    DetectionAssessment assessment =
        probes.empty() || availableCandidateCount == 0
            ? DetectionAssessment::inconclusive()
            : DetectionAssessment::notObserved();
    if (strongFindingCount > 0) {
        assessment = DetectionAssessment::strongObserved();
    } else if (weakFindingCount > 0) {
        assessment = DetectionAssessment::weakObserved();
    }

    return {assessment, std::move(payload)};
}

void appendPathCandidates(std::vector<BinaryArtifactCandidate>& candidates,
                          const std::string& executableName, const std::string& pathValue,
                          std::size_t maxAdditionalCandidates) {
    if (executableName.empty() || maxAdditionalCandidates == 0) return;
    std::unordered_set<std::string> seenPaths;
    for (const auto& candidate : candidates) {
        seenPaths.insert(candidate.path);
    }

    std::size_t start = 0;
    std::size_t added = 0;
    while (start <= pathValue.size() && added < maxAdditionalCandidates) {
        const std::size_t separator = pathValue.find(':', start);
        std::string directory =
            pathValue.substr(start, separator == std::string::npos ? std::string::npos
                                                                   : separator - start);
        while (directory.size() > 1 && directory.back() == '/') {
            directory.pop_back();
        }

        if (!directory.empty() && directory.front() == '/') {
            const std::string candidatePath =
                directory == "/" ? "/" + executableName : directory + "/" + executableName;
            if (seenPaths.insert(candidatePath).second) {
                candidates.push_back({candidatePath, "environment_path"});
                ++added;
            }
        }

        if (separator == std::string::npos) break;
        start = separator + 1;
    }
}

void appendEnvironmentPathCandidates(std::vector<BinaryArtifactCandidate>& candidates,
                                     const std::string& executableName,
                                     std::size_t maxAdditionalCandidates) {
    const char* pathValue = std::getenv("PATH");
    if (!pathValue) return;
    appendPathCandidates(candidates, executableName, pathValue, maxAdditionalCandidates);
}

}  // namespace tamperprobe
