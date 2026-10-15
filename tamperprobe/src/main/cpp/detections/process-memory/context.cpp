#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <dirent.h>
#include <vector>

#include "../../common/io_utils.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {

namespace {

constexpr const char* kSelfContextPath = "/proc/self/attr/current";
constexpr const char* kProcDirPath = "/proc";
// O_NOFOLLOW (0400000) | O_CLOEXEC (02000000) | O_DIRECTORY (0200000). O_DIRECTORY was
// missing despite the constant's name; /proc is always a directory, so this only makes the
// open refuse a target that is not one.
constexpr int kOpenDirectoryFlags = 131072 | 524288 | 65536;

struct linux_dirent64 {
    std::uint64_t d_ino;
    std::int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

bool is_suspicious_context(const std::string& context) {
    return contains_any_ignore_case(
            context,
            {"magisk", "apatch", "kernelsu", ":su:", "permissive"}
    );
}

bool is_normal_context(const std::string& context) {
    return contains_any_ignore_case(
            context,
            {"untrusted_app", "platform_app", "system_app", "priv_app"}
    );
}

bool is_abnormal_context(const std::string& context) {
    if (context.empty()) {
        return false;
    }
    return is_suspicious_context(context) || !is_normal_context(context);
}

nlohmann::json collect_context_snapshot() {
    const std::string self_context = read_text_file(kSelfContextPath, 512);
    const bool self_abnormal = is_abnormal_context(self_context);

    std::vector<std::string> suspicious_processes;
    int checked_processes = 0;
    int denied_processes = 0;

    const bool self_context_readable = !self_context.empty();

    const int proc_fd = syscall_openat_readonly(kProcDirPath, kOpenDirectoryFlags);
    if (proc_fd >= 0) {
        char dent_buffer[4096];
        while (true) {
            const int bytes_read = syscall_getdents64_fd(proc_fd, dent_buffer, sizeof(dent_buffer));
            if (bytes_read <= 0) {
                break;
            }

            int offset = 0;
            while (offset < bytes_read) {
                if (offset + static_cast<int>(offsetof(linux_dirent64, d_name)) >= bytes_read) {
                    break;
                }

                auto* entry = reinterpret_cast<linux_dirent64*>(dent_buffer + offset);
                if (entry->d_reclen == 0 || offset + entry->d_reclen > bytes_read) {
                    break;
                }

                const size_t max_name_length = entry->d_reclen - offsetof(linux_dirent64, d_name);
                const bool is_process_dir =
                        (entry->d_type == DT_DIR || entry->d_type == DT_UNKNOWN) &&
                        is_numeric_name(entry->d_name, max_name_length);

                if (is_process_dir) {
                    char attr_path[256];
                    std::snprintf(attr_path, sizeof(attr_path), "/proc/%s/attr/current",
                                  entry->d_name);
                    const std::string context = read_text_file(attr_path, 512);

                    if (!context.empty()) {
                        ++checked_processes;
                        if (is_suspicious_context(context)) {
                            suspicious_processes.emplace_back(
                                    std::string("PID ") + entry->d_name + ": " + context
                            );
                        }
                    } else {
                        ++denied_processes;
                    }
                }

                offset += entry->d_reclen;
            }
        }

        syscall_close_fd(proc_fd);
    }

    nlohmann::json context_payload;
    context_payload["selfContext"] = self_context;
    context_payload["selfAbnormal"] = self_abnormal;
    // read_text_file returns an empty string both for a denied read and for an empty file,
    // and is_abnormal_context deliberately reports an empty context as not abnormal. Without
    // these two flags the caller cannot tell a clean device from one where neither channel
    // answered, which is why this detector could only ever return STRONG or NOT_OBSERVED.
    context_payload["selfContextReadable"] = self_context_readable;
    context_payload["procEnumerated"] = proc_fd >= 0;
    context_payload["procChecked"] = checked_processes;
    context_payload["procDenied"] = denied_processes;
    context_payload["suspiciousProcesses"] = suspicious_processes;
    return context_payload;
}

}  // namespace

class SuContextDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        const nlohmann::json context_scan = collect_context_snapshot();
        const bool self_abnormal = context_scan.value("selfAbnormal", false);
        const bool has_suspicious_processes = !context_scan.value(
                "suspiciousProcesses",
                nlohmann::json::array()
        ).empty();

        nlohmann::json payload;
        payload["contextScan"] = context_scan;
        payload["collectionErrors"] = nlohmann::json::array();

        if (self_abnormal || has_suspicious_processes) {
            return {DetectionAssessment::strongObserved(), payload.dump()};
        }

        // Neither channel answered: this process's own SELinux context could not be read and
        // /proc could not be enumerated. Reporting NOT_OBSERVED here would state that no
        // abnormal domain was found, which is not something the scan established.
        const bool self_readable = context_scan.value("selfContextReadable", false);
        const bool proc_enumerated = context_scan.value("procEnumerated", false);
        if (!self_readable && !proc_enumerated) {
            payload["collectionErrors"].push_back(
                    {{"source", "proc_attr"},
                     {"message", "Neither /proc/self/attr/current nor a /proc enumeration "
                                 "produced a process context to evaluate."}});
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }
        if (!self_readable) {
            payload["collectionErrors"].push_back(
                    {{"source", "proc_attr"},
                     {"message", "/proc/self/attr/current could not be read; this process's "
                                 "own domain was not evaluated."}});
        }

        return {DetectionAssessment::notObserved(), payload.dump()};
    }

    const char* getId() const override { return "SU_CONTEXT"; }
};

REGISTER_DETECTION(SuContextDetection);

}  // namespace tamperprobe
