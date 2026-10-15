#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
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

}  // namespace

/**
 * Detects KernelSU and root driver anomalies by checking:
 * 1. devpts (pseudo-terminal) file permissions and security.selinux xattrs
 * 2. Freshly allocated PTY metadata via posix_openpt
 * 3. Self file descriptors in /proc/self/fd pointing to [ksu_driver] or [ksu_fdwrapper]
 *
 * References: Duck-Detector nativeroot/probes (devpts_abnormal_permission_probe, self_process_ioc_probe)
 */
class NativeRootDevptsDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        nlohmann::json payload;
        payload["findings"] = nlohmann::json::array();
        int checkedCount = 0;
        int hitCount = 0;
        int driverFdCount = 0;
        int fdwrapperCount = 0;

        // 1. Sample PTY devices 0-100
        char pathBuf[32];
        for (int i = 0; i <= 100; ++i) {
            snprintf(pathBuf, sizeof(pathBuf), "/dev/pts/%d", i);
            struct stat st{};
            if (lstat(pathBuf, &st) != 0) continue;

            checkedCount++;
            bool abnormal = false;
            nlohmann::json finding;
            finding["path"] = pathBuf;

            if (st.st_uid == 0) {
                abnormal = true;
                finding["owner"] = "root (uid=0)";
            }

            char attrVal[256] = {0};
            ssize_t len = getxattr(pathBuf, "security.selinux", attrVal, sizeof(attrVal) - 1);
            if (len >= 0) {
                attrVal[len] = '\0';
                finding["selinuxContext"] = std::string(attrVal);
                if (strstr(attrVal, "ksu_file") != nullptr) {
                    abnormal = true;
                    finding["ksuFileContext"] = true;
                }
            }

            if (abnormal) {
                hitCount++;
                payload["findings"].push_back(finding);
            }
        }

        // 2. Try allocating a fresh PTY
        int masterFd = posix_openpt(O_RDWR | O_NOCTTY);
        if (masterFd >= 0) {
            if (grantpt(masterFd) == 0 && unlockpt(masterFd) == 0) {
                char* ptsName = ptsname(masterFd);
                if (ptsName) {
                    struct stat st{};
                    if (lstat(ptsName, &st) == 0) {
                        checkedCount++;
                        nlohmann::json finding;
                        finding["path"] = ptsName;
                        finding["freshPty"] = true;
                        bool abnormal = false;

                        if (st.st_uid == 0) {
                            abnormal = true;
                            finding["owner"] = "root (uid=0)";
                        }

                        char attrVal[256] = {0};
                        ssize_t len = getxattr(ptsName, "security.selinux", attrVal, sizeof(attrVal) - 1);
                        if (len >= 0) {
                            attrVal[len] = '\0';
                            finding["selinuxContext"] = std::string(attrVal);
                            if (strstr(attrVal, "ksu_file")) {
                                abnormal = true;
                                finding["ksuFileContext"] = true;
                            }
                        }

                        if (abnormal) {
                            hitCount++;
                            payload["findings"].push_back(finding);
                        }
                    }
                }
            }
            close(masterFd);
        }

        // 3. Scan /proc/self/fd for root driver descriptors
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
                            hitCount++;
                            nlohmann::json finding;
                            finding["path"] = linkPath;
                            finding["fdTarget"] = "[ksu_driver]";
                            finding["driverType"] = "kernelsu_driver";
                            payload["findings"].push_back(finding);
                        }
                        if (target.find("[ksu_fdwrapper]") != std::string::npos) {
                            fdwrapperCount++;
                            hitCount++;
                            nlohmann::json finding;
                            finding["path"] = linkPath;
                            finding["fdTarget"] = "[ksu_fdwrapper]";
                            finding["driverType"] = "kernelsu_fdwrapper";
                            payload["findings"].push_back(finding);
                        }
                    }
                    offset += entry->d_reclen;
                }
            }
            syscall_close_fd(procFd);
        }

        payload["driverFdCount"] = driverFdCount;
        payload["fdwrapperCount"] = fdwrapperCount;
        payload["checkedCount"] = checkedCount;
        payload["hitCount"] = hitCount;

        DetectionAssessment assessment = DetectionAssessment::notObserved();
        if (hitCount > 0) {
            if (driverFdCount > 0 || hitCount >= 2) {
                assessment = DetectionAssessment::strongObserved();
            } else {
                assessment = DetectionAssessment::moderateObserved();
            }
        } else if (checkedCount == 0) {
            // Nothing was enumerable: no /dev/pts node was inspectable and /proc/self/fd
            // could not be read. A not-found here is not a clean answer.
            assessment = DetectionAssessment::inconclusive();
            payload["collectionErrors"] = nlohmann::json::array();
            payload["collectionErrors"].push_back(
                {{"source", "devpts"}, {"errno", 0},
                 {"message", "No pty metadata could be inspected from this process."}});
        }

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "NATIVE_ROOT_DEVPTS"; }
};

REGISTER_DETECTION(NativeRootDevptsDetection);

}  // namespace tamperprobe
