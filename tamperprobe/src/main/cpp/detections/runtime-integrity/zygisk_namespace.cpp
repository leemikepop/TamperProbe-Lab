#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {

namespace {

struct PhdrContext {
    std::vector<std::string> suspiciousLibs;
    int totalLibCount = 0;
};

int phdrCallback(struct dl_phdr_info* info, size_t /* size */, void* data) {
    auto* ctx = static_cast<PhdrContext*>(data);
    ctx->totalLibCount++;

    if (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0') {
        return 0;
    }

    const std::string name(info->dlpi_name);

    // Check for libraries loaded from suspicious paths
    static const char* suspiciousPrefixes[] = {
        "/data/adb/",
        "/data/local/tmp/",
        "/data/data/",
        "/data/user/",
        "memfd:",
    };

    for (const char* prefix : suspiciousPrefixes) {
        // A plain substring test. The former "find(prefix) == 0 || find(prefix) != npos"
        // read as if it treated a leading match specially, but the first disjunct is a
        // subset of the second, so the behaviour was always "contains anywhere".
        if (name.find(prefix) != std::string::npos) {
            ctx->suspiciousLibs.push_back(name);
            break;
        }
    }

    // Also check for deleted libraries (injectors remove files after loading)
    if (name.find("(deleted)") != std::string::npos) {
        ctx->suspiciousLibs.push_back(name);
    }

    return 0;
}

struct ThreadScanResult {
    int scannedCount = 0;
    bool taskDirectoryReadable = false;
    std::vector<std::string> suspiciousThreads;
};

ThreadScanResult scanTaskCommNames() {
    ThreadScanResult result;
    DIR* dir = opendir("/proc/self/task");
    if (!dir) {
        // Not readable is not the same as nothing to see. Without this flag the caller
        // cannot tell an empty thread list from a directory it was never allowed to open.
        return result;
    }
    result.taskDirectoryReadable = true;

    static const char* suspiciousKeywords[] = {
        "zygisk",
        "magisk",
        "riru",
        "xposed",
        "lspd",
        "frida",
        "gum-",
        "linjector"
    };

    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        bool isNumeric = true;
        for (int i = 0; entry->d_name[i] != '\0'; ++i) {
            if (entry->d_name[i] < '0' || entry->d_name[i] > '9') {
                isNumeric = false;
                break;
            }
        }
        if (!isNumeric) continue;

        result.scannedCount++;
        std::string commPath = std::string("/proc/self/task/") + entry->d_name + "/comm";
        int fd = open(commPath.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;

        char buf[256] = {};
        ssize_t bytesRead = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (bytesRead <= 0) continue;

        buf[bytesRead] = '\0';
        while (bytesRead > 0 && (buf[bytesRead - 1] == '\n' || buf[bytesRead - 1] == '\r' || buf[bytesRead - 1] == ' ')) {
            buf[--bytesRead] = '\0';
        }

        std::string name(buf);
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });

        for (const char* keyword : suspiciousKeywords) {
            if (lower.find(keyword) != std::string::npos) {
                result.suspiciousThreads.push_back(name);
                break;
            }
        }
    }
    closedir(dir);
    return result;
}

constexpr char kTrapSignature[] = "tamperprobe:zygisk:fdtrap:v1";

std::string executeFdTrap(const std::string& baseDir) {
    const std::string dir = baseDir.empty() ? "/data/local/tmp" : baseDir;
    int fd = -1;
#ifdef O_TMPFILE
    fd = open(dir.c_str(), O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
#endif
    if (fd < 0) {
        std::string templatePath = dir + "/tp_fdtrap_XXXXXX";
        std::vector<char> scratch(templatePath.begin(), templatePath.end());
        scratch.push_back('\0');
        fd = mkstemp(scratch.data());
        if (fd < 0) {
            return "unavailable";
        }
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        unlink(scratch.data());
    }

    const size_t sigLen = sizeof(kTrapSignature) - 1;
    ssize_t wrote = write(fd, kTrapSignature, sigLen);
    if (wrote != static_cast<ssize_t>(sigLen)) {
        close(fd);
        return "write_failed";
    }
    fsync(fd);
    lseek(fd, 0, SEEK_SET);

    struct stat st {};
    if (fstat(fd, &st) != 0) {
        int err = errno;
        close(fd);
        if (err == EBADF) return "closed_ebadf";
        return "stat_failed";
    }

    char readBuf[64] = {};
    ssize_t bytesRead = pread(fd, readBuf, sigLen, 0);
    if (bytesRead != static_cast<ssize_t>(sigLen) || memcmp(readBuf, kTrapSignature, sigLen) != 0) {
        close(fd);
        return "corrupted";
    }

    char procPath[64] = {};
    snprintf(procPath, sizeof(procPath), "/proc/self/fd/%d", fd);
    char linkTarget[512] = {};
    ssize_t linkLen = readlink(procPath, linkTarget, sizeof(linkTarget) - 1);
    close(fd);

    if (linkLen <= 0) {
        return "procfs_anomaly";
    }
    return "clean";
}

}  // namespace

/**
 * Detects Zygisk and injected runtime modules by:
 * 1. Auditing dynamic linker namespaces via dl_iterate_phdr (/data/adb/, /data/local/tmp/, memfd:, deleted files).
 * 2. Scanning thread comm names in /proc/self/task/ for zygisk, magisk, riru, xposed, lspd, frida, gum-.
 * 3. Verifying anonymous unlinked file descriptor isolation (cross-process FD trap).
 *
 * References: Duck-Detector zygisk/probes/namespace_probe.cpp, thread_probe.cpp, fd_trap.cpp
 */
class ZygiskNamespaceDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        PhdrContext ctx;
        dl_iterate_phdr(phdrCallback, &ctx);

        ThreadScanResult threadRes = scanTaskCommNames();
        std::string fdTrapStatus = executeFdTrap(scanContext.filesDir);

        nlohmann::json payload;
        payload["totalLibCount"] = ctx.totalLibCount;
        payload["suspiciousLibs"] = nlohmann::json::array();
        for (const auto& lib : ctx.suspiciousLibs) {
            payload["suspiciousLibs"].push_back(lib);
        }

        payload["scannedThreadCount"] = threadRes.scannedCount;
        payload["suspiciousThreads"] = nlohmann::json::array();
        for (const auto& threadName : threadRes.suspiciousThreads) {
            payload["suspiciousThreads"].push_back(threadName);
        }

        payload["fdTrapStatus"] = fdTrapStatus;
        // The in-process trap creates and verifies the descriptor microseconds apart
        // in one process, so no specialization-time descriptor sanitization can have
        // touched it: closed_ebadf and corrupted are unreachable here and must not
        // drive the outcome. The cross-process differential lives in
        // ZYGISK_FD_FORENSICS; this stays as telemetry.
        payload["fdTrapImpact"] = "telemetry_only";

        payload["taskDirectoryReadable"] = threadRes.taskDirectoryReadable;
        payload["linkerObjectCount"] = ctx.totalLibCount;
        payload["collectionErrors"] = nlohmann::json::array();

        if (!ctx.suspiciousLibs.empty() || !threadRes.suspiciousThreads.empty()) {
            return {DetectionAssessment::strongObserved(), payload.dump()};
        }

        // Both channels are needed for a clean answer to mean anything. Until 2026-09-12
        // this detector had no inconclusive path at all -- the word did not appear in the
        // file -- so a failed opendir on /proc/self/task combined with a linker enumeration
        // that returned nothing produced exactly the same NOT_OBSERVED as a healthy scan.
        // The docs claimed INCONCLUSIVE was reachable "in extreme cases"; it was not.
        const bool linkerEnumerated = ctx.totalLibCount > 0;
        if (!threadRes.taskDirectoryReadable) {
            payload["collectionErrors"].push_back(
                    {{"source", "proc_task"},
                     {"message", "/proc/self/task could not be opened; no thread name was "
                                 "inspected."}});
        }
        if (!linkerEnumerated) {
            payload["collectionErrors"].push_back(
                    {{"source", "dl_iterate_phdr"},
                     {"message", "The linker enumerated no shared objects; no library path "
                                 "was inspected."}});
        }
        if (!threadRes.taskDirectoryReadable && !linkerEnumerated) {
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        return {DetectionAssessment::notObserved(), payload.dump()};
    }

    const char* getId() const override { return "ZYGISK_NAMESPACE"; }
};

REGISTER_DETECTION(ZygiskNamespaceDetection);

}  // namespace tamperprobe
