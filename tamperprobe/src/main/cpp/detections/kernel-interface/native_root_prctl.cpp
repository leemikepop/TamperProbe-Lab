#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/io_utils.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {

namespace {

struct linux_dirent64 {
    std::uint64_t d_ino;
    std::int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

#if defined(__aarch64__)
struct LatencyResult {
    double fullLatencyUs;
    double emptyLatencyUs;
    double diffUs;
    bool success;
};

static inline uint64_t get_cntfrq() {
    uint64_t val = 0;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(val));
    return val;
}

static inline uint64_t get_cntvct() {
    uint64_t val = 0;
    asm volatile("isb; mrs %0, cntvct_el0; isb" : "=r"(val));
    return val;
}

static double measureSyscall45Latency(const char* buffer) {
    constexpr int kIterations = 100000;
    constexpr int kSupercallNr = 45;
    constexpr unsigned long kSupercallHello = 0x1000;
    const uint64_t freq = get_cntfrq();
    if (freq == 0) return 0.0;

    // Warmup
    syscall(kSupercallNr, buffer, kSupercallHello);

    uint64_t totalTicks = 0;
    for (int i = 0; i < kIterations; ++i) {
        uint64_t start = get_cntvct();
        syscall(kSupercallNr, buffer, kSupercallHello);
        uint64_t end = get_cntvct();
        totalTicks += (end - start);
    }
    return (static_cast<double>(totalTicks) * 1000000.0) / (static_cast<double>(freq) * kIterations);
}

static bool runSupercallBenchmark(LatencyResult& outResult, bool& seccompBlocked) {
    int pipeFds[2] = {-1, -1};
    if (pipe(pipeFds) != 0) return false;
    fcntl(pipeFds[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipeFds[1], F_SETFD, FD_CLOEXEC);

    pid_t pid = fork();
    if (pid < 0) {
        close(pipeFds[0]);
        close(pipeFds[1]);
        return false;
    }

    if (pid == 0) {
        close(pipeFds[0]);
        char buffer[128];
        std::memset(buffer, 'A', 127);
        buffer[127] = '\0';
        double fullLat = measureSyscall45Latency(buffer);

        std::memset(buffer, 0, sizeof(buffer));
        double emptyLat = measureSyscall45Latency(buffer);

        LatencyResult res{};
        res.fullLatencyUs = fullLat;
        res.emptyLatencyUs = emptyLat;
        res.diffUs = fullLat - emptyLat;
        res.success = (fullLat > 0.0 && emptyLat > 0.0);

        ssize_t written = write(pipeFds[1], &res, sizeof(res));
        (void)written;
        close(pipeFds[1]);
        _exit(0);
    }

    close(pipeFds[1]);
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        close(pipeFds[0]);
        return false;
    }

    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
        seccompBlocked = true;
        close(pipeFds[0]);
        return false;
    }

    ssize_t bytesRead = read(pipeFds[0], &outResult, sizeof(outResult));
    close(pipeFds[0]);

    return (WIFEXITED(status) && WEXITSTATUS(status) == 0 && bytesRead == sizeof(outResult));
}
#endif

}  // namespace

/**
 * Detects native root frameworks (KernelSU, APatch, KernelPatch):
 * 1. KernelSU prctl(0xDEADBEEF) syscall protocol probe
 * 2. APatch/KernelPatch supercall latency probe (syscall 45 benchmark on ARM64)
 * 3. cgroup process allocation check (/proc/self/cgroup)
 * 4. Root driver descriptor (/proc/self/fd for [ksu_driver]) and self SELinux context
 *
 * References: Duck-Detector nativeroot/probes (prctl_probe, kernelpatch_nr_supercall_latency_probe,
 * cgroup_process_probe, self_process_ioc_probe)
 */
class NativeRootPrctlDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        nlohmann::json payload;
        payload["findings"] = nlohmann::json::array();
        int hitCount = 0;

        // 1. KernelSU prctl protocol probe
        constexpr unsigned long kKernelSuMagic = 0xDEADBEEF;
        constexpr int kVersionCommand = 2;
        constexpr int kAltCommands[] = {0, 1, 3, 4, 10};

        bool ksuDetected = false;
        long ksuVersion = 0;

        errno = 0;
        long version = prctl(kKernelSuMagic, kVersionCommand, 0, 0, 0);
        if (version > 0) {
            ksuDetected = true;
            ksuVersion = version;
            hitCount++;
            nlohmann::json f;
            f["check"] = "kernelsu_prctl";
            f["probe"] = "prctl(0xDEADBEEF, 2)";
            f["result"] = "KernelSU version " + std::to_string(version);
            f["severity"] = "DANGER";
            f["value"] = std::to_string(version);
            f["detail"] = "KernelSU prctl version query succeeded with version " + std::to_string(version);
            payload["findings"].push_back(f);
        } else {
            int primaryErrno = errno;
            if (primaryErrno != 0 && primaryErrno != EINVAL && primaryErrno != ENOSYS) {
                nlohmann::json f;
                f["check"] = "kernelsu_prctl_errno";
                f["probe"] = "prctl(0xDEADBEEF, 2)";
                f["result"] = "Unexpected errno=" + std::to_string(primaryErrno);
                f["severity"] = "WARNING";
                f["value"] = "errno=" + std::to_string(primaryErrno);
                f["detail"] = "Unexpected errno from prctl(0xDEADBEEF, 2)";
                payload["findings"].push_back(f);
            }

            for (int cmd : kAltCommands) {
                errno = 0;
                long response = prctl(kKernelSuMagic, cmd, 0, 0, 0);
                if (response >= 0 && errno == 0) {
                    ksuDetected = true;
                    if (response > 0) ksuVersion = response;
                    hitCount++;
                    nlohmann::json f;
                    f["check"] = "kernelsu_prctl_alt";
                    f["probe"] = "prctl(0xDEADBEEF, " + std::to_string(cmd) + ")";
                    f["result"] = "Accepted";
                    f["severity"] = "DANGER";
                    f["value"] = std::to_string(response);
                    f["detail"] = "KernelSU accepted alternative command " + std::to_string(cmd);
                    payload["findings"].push_back(f);
                    break;
                }
            }
        }

        payload["ksuDetected"] = ksuDetected;
        payload["ksuVersion"] = ksuVersion;

        // 2. APatch / KernelPatch supercall latency probe (ARM64 with fallback)
        bool apatchDetected = false;
        double supercallLatencyDiffUs = 0.0;
        bool supercallTested = false;

#if defined(__aarch64__)
        LatencyResult latResult{0.0, 0.0, 0.0, false};
        bool seccompBlocked = false;
        supercallTested = true;
        if (runSupercallBenchmark(latResult, seccompBlocked)) {
            if (latResult.success) {
                supercallLatencyDiffUs = latResult.diffUs;
                if (latResult.diffUs > 3.0) {
                    apatchDetected = true;
                    hitCount++;
                    nlohmann::json f;
                    f["check"] = "supercall_latency_deviation";
                    f["probe"] = "syscall(45)";
                    f["result"] = "Latency diff: " + std::to_string(latResult.diffUs) + " us";
                    f["severity"] = "DANGER";
                    f["value"] = std::to_string(latResult.diffUs);
                    f["detail"] = "APatch/KernelPatch supercall latency deviation detected (> 3.0 us)";
                    payload["findings"].push_back(f);
                }
            }
        } else if (seccompBlocked) {
            nlohmann::json f;
            f["check"] = "supercall_seccomp_filtered";
            f["probe"] = "syscall(45)";
            f["result"] = "SIGSYS";
            f["severity"] = "INFO";
            f["value"] = "SIGSYS";
            f["detail"] = "Syscall 45 was blocked by Seccomp on ARM64";
            payload["findings"].push_back(f);
        }
#endif

        payload["supercallTested"] = supercallTested;
        payload["supercallLatencyDiffUs"] = supercallLatencyDiffUs;
        payload["apatchDetected"] = apatchDetected;

        // 3. cgroup process allocation check
        bool cgroupChecked = false;
        bool cgroupAnomaly = false;
        std::string cgroupText = read_text_file("/proc/self/cgroup", 2048);
        if (!cgroupText.empty()) {
            cgroupChecked = true;
            uid_t uid = getuid();
            std::string uidMarker = "uid_" + std::to_string(uid);
            if (uid >= 10000) {
                bool hasUidCgroup = (cgroupText.find(uidMarker) != std::string::npos);
                bool hasRootOrDaemonSlice = (cgroupText == "0::/\n" || cgroupText == "0::/" ||
                                             cgroupText.find("/magisk/") != std::string::npos ||
                                             cgroupText.find("/ksud") != std::string::npos ||
                                             (cgroupText.find(":/\n") != std::string::npos && !hasUidCgroup));
                if (!hasUidCgroup && hasRootOrDaemonSlice) {
                    cgroupAnomaly = true;
                    hitCount++;
                    nlohmann::json f;
                    f["check"] = "cgroup_allocation_anomaly";
                    f["probe"] = "/proc/self/cgroup";
                    f["result"] = "Root/daemon cgroup";
                    f["severity"] = "WARNING";
                    f["value"] = trim_copy(cgroupText.substr(0, 100));
                    f["detail"] = "Process with app UID " + std::to_string(uid) + " is running under root/daemon cgroup hierarchy";
                    payload["findings"].push_back(f);
                }
            }
        }
        payload["cgroupChecked"] = cgroupChecked;
        payload["cgroupAnomaly"] = cgroupAnomaly;

        // 4. Root driver descriptor check (/proc/self/fd) and SELinux context
        std::string selfContext = read_text_file("/proc/self/attr/current", 256);
        payload["selfSelinuxContext"] = selfContext;
        bool selfRootContext = false;
        if (!selfContext.empty() && (selfContext == "u:r:su:s0" || selfContext.find(":su:") != std::string::npos)) {
            selfRootContext = true;
            hitCount++;
            nlohmann::json f;
            f["check"] = "self_root_context";
            f["probe"] = "/proc/self/attr/current";
            f["result"] = selfContext;
            f["severity"] = "DANGER";
            f["value"] = selfContext;
            f["detail"] = "Process is running under the su SELinux context domain";
            payload["findings"].push_back(f);
        }

        int driverFdCount = 0;
        int fdwrapperCount = 0;
        int procFd = syscall_openat_readonly("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (procFd >= 0) {
            char dentBuffer[2048];
            while (true) {
                int bytesRead = syscall_getdents64_fd(procFd, dentBuffer, sizeof(dentBuffer));
                if (bytesRead <= 0) break;
                int offset = 0;
                while (offset < bytesRead) {
                    auto* entry = reinterpret_cast<linux_dirent64*>(dentBuffer + offset);
                    if (entry->d_reclen == 0 || offset + entry->d_reclen > bytesRead) break;
                    size_t maxLen = entry->d_reclen - offsetof(linux_dirent64, d_name);
                    if (is_numeric_name(entry->d_name, maxLen)) {
                        char linkPath[128];
                        std::snprintf(linkPath, sizeof(linkPath), "/proc/self/fd/%s", entry->d_name);
                        std::string target = read_link_target(linkPath, 256);
                        if (target.find("[ksu_driver]") != std::string::npos) {
                            driverFdCount++;
                        }
                        if (target.find("[ksu_fdwrapper]") != std::string::npos) {
                            fdwrapperCount++;
                        }
                    }
                    offset += entry->d_reclen;
                }
            }
            syscall_close_fd(procFd);
        }
        const bool fdTableScanned = (procFd >= 0);
        payload["driverFdCount"] = driverFdCount;
        payload["fdwrapperCount"] = fdwrapperCount;

        if (driverFdCount > 0 || fdwrapperCount > 0) {
            hitCount++;
            nlohmann::json f;
            f["check"] = "root_driver_fd_present";
            f["probe"] = "/proc/self/fd";
            f["result"] = "driver=" + std::to_string(driverFdCount) + " wrapper=" + std::to_string(fdwrapperCount);
            f["severity"] = "DANGER";
            f["value"] = "driver=" + std::to_string(driverFdCount) + " wrapper=" + std::to_string(fdwrapperCount);
            f["detail"] = "Process holds open KernelSU driver / wrapper file descriptors";
            payload["findings"].push_back(f);
        }

        payload["hitCount"] = hitCount;

        DetectionAssessment assessment = DetectionAssessment::notObserved();
        // apatchDetected comes from an uncalibrated timing threshold (see the supercall
        // benchmark above) and is deliberately NOT treated as a hard marker. Direct
        // protocol markers -- the KernelSU prctl reply, an su process context, and open
        // KernelSU driver/wrapper descriptors -- remain the only STRONG evidence here.
        if (ksuDetected || selfRootContext || driverFdCount > 0 || fdwrapperCount > 0) {
            assessment = DetectionAssessment::strongObserved();
        } else if (apatchDetected || cgroupAnomaly || hitCount > 0 || !payload["findings"].empty()) {
            assessment = DetectionAssessment::moderateObserved();
        } else if (!supercallTested && !cgroupChecked && !fdTableScanned) {
            // Every channel failed: the supercall benchmark did not run, cgroup was
            // unreadable, and the descriptor table could not be scanned. A not-found is
            // not a clean answer.
            assessment = DetectionAssessment::inconclusive();
            payload["collectionErrors"] = nlohmann::json::array();
            payload["collectionErrors"].push_back(
                {{"source", "prctl"}, {"errno", 0},
                 {"message", "No KernelSU protocol channel could be exercised from this process."}});
        }

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "NATIVE_ROOT_PRCTL"; }
};

REGISTER_DETECTION(NativeRootPrctlDetection);

}  // namespace tamperprobe
