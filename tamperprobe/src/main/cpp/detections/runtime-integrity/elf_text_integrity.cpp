#include <elf.h>
#include <link.h>

#include <array>
#include <cstdint>
#include <limits>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "../../common/log.h"
#include "../../common/proc_maps.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"
#include "elf_integrity.h"

namespace tamperprobe {
namespace {

struct ModuleTarget {
    const char* library;
    bool required;
};

constexpr std::array<ModuleTarget, 3> kModuleTargets = {{
        {.library = "libc.so", .required = true},
        {.library = "libart.so", .required = false},
        {.library = "libinput.so", .required = false},
}};

struct ExecutableSegment {
    size_t index = 0;
    std::uintptr_t memoryStart = 0;
    std::uint64_t fileOffset = 0;
    size_t byteCount = 0;
};

struct SelectedModule {
    std::string library;
    std::string path;
    bool required = false;
    std::vector<ExecutableSegment> segments;
};

int collectSelectedModule(dl_phdr_info* info, size_t, void* data) {
    if (info->dlpi_name == nullptr) return 0;
    auto* modules = static_cast<std::vector<SelectedModule>*>(data);
    for (const ModuleTarget& target : kModuleTargets) {
        if (!pathHasBasename(info->dlpi_name, target.library)) continue;

        SelectedModule module{.library = target.library,
                              .path = info->dlpi_name,
                              .required = target.required};
        for (size_t index = 0; index < info->dlpi_phnum; ++index) {
            const ElfW(Phdr)& header = info->dlpi_phdr[index];
            if (header.p_type != PT_LOAD || (header.p_flags & PF_X) == 0 ||
                (header.p_flags & PF_W) != 0 || header.p_filesz == 0 ||
                header.p_filesz > std::numeric_limits<size_t>::max()) {
                continue;
            }
            const auto start = static_cast<std::uintptr_t>(info->dlpi_addr + header.p_vaddr);
            const auto byteCount = static_cast<size_t>(header.p_filesz);
            if (start > std::numeric_limits<std::uintptr_t>::max() - byteCount) continue;
            module.segments.push_back({.index = index,
                                       .memoryStart = start,
                                       .fileOffset = header.p_offset,
                                       .byteCount = byteCount});
        }
        modules->push_back(std::move(module));
        break;
    }
    return 0;
}

nlohmann::json segmentPayload(const SelectedModule& module, const ExecutableSegment& segment,
                              const ByteComparisonResult& comparison) {
    return {{"library", module.library},
            {"path", module.path},
            {"segmentIndex", segment.index},
            {"memoryStart", segment.memoryStart},
            {"fileOffset", segment.fileOffset},
            {"byteCount", segment.byteCount},
            {"comparedBytes", comparison.comparedBytes},
            {"firstMismatchOffset", comparison.firstMismatchOffset},
            {"reason", comparison.reason}};
}

}  // namespace

class ElfTextIntegrityDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        (void)scanContext;
        nlohmann::json payload;
        payload["targetLibraries"] = nlohmann::json::array();
        payload["requiredLibraries"] = nlohmann::json::array();
        payload["resolvedModules"] = nlohmann::json::array();
        payload["missingRequiredLibraries"] = nlohmann::json::array();
        payload["missingOptionalLibraries"] = nlohmann::json::array();
        payload["comparisonMethod"] = "public_phdr_to_backing_elf";
        payload["checkedSegments"] = nlohmann::json::array();
        payload["modifiedSegments"] = nlohmann::json::array();
        payload["unavailableSegments"] = nlohmann::json::array();
        payload["collectionErrors"] = nlohmann::json::array();

        const ProcMapsSnapshot maps = readProcMaps();
        payload["mapsReadable"] = maps.readable && !maps.entries.empty();
        payload["malformedMapLines"] = maps.malformedLineCount;
        if (!maps.readable || maps.entries.empty()) {
            payload["collectionErrors"].push_back(
                    {{"source", "/proc/self/maps"},
                     {"errno", maps.error},
                     {"message", "Process maps unavailable"}});
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        for (const ModuleTarget& target : kModuleTargets) {
            payload["targetLibraries"].push_back(target.library);
            if (target.required) payload["requiredLibraries"].push_back(target.library);
        }

        std::vector<SelectedModule> modules;
        dl_iterate_phdr(collectSelectedModule, &modules);
        std::set<std::string> resolvedLibraries;
        for (const SelectedModule& module : modules) {
            resolvedLibraries.insert(module.library);
            LOGD("event=elf_text_module library=%s path=%s executableSegments=%zu",
                 module.library.c_str(), module.path.c_str(), module.segments.size());
            payload["resolvedModules"].push_back(
                    {{"library", module.library},
                     {"path", module.path},
                     {"required", module.required},
                     {"executableSegmentCount", module.segments.size()}});
        }
        for (const ModuleTarget& target : kModuleTargets) {
            if (resolvedLibraries.find(target.library) != resolvedLibraries.end()) continue;
            if (target.required) {
                payload["missingRequiredLibraries"].push_back(target.library);
            } else {
                payload["missingOptionalLibraries"].push_back(target.library);
            }
        }
        if (!payload["missingRequiredLibraries"].empty()) {
            payload["collectionErrors"].push_back(
                    {{"source", "dl_iterate_phdr"},
                     {"errno", 0},
                     {"message", "Required executable module was not enumerated"}});
        }

        for (const SelectedModule& module : modules) {
            if (module.segments.empty()) {
                payload["unavailableSegments"].push_back(
                        {{"library", module.library},
                         {"path", module.path},
                         {"reason", "no_non_writable_executable_segment"}});
                continue;
            }
            for (const ExecutableSegment& segment : module.segments) {
                const ByteComparisonResult comparison = compareMemoryRangeWithFile(
                        module.path, segment.memoryStart, segment.fileOffset, segment.byteCount,
                        maps, true);
                const nlohmann::json item = segmentPayload(module, segment, comparison);
                if (comparison.status == ByteComparisonStatus::MATCH) {
                    payload["checkedSegments"].push_back(item);
                } else if (comparison.status == ByteComparisonStatus::DIFFERENT) {
                    payload["modifiedSegments"].push_back(item);
                } else {
                    payload["unavailableSegments"].push_back(item);
                }
            }
        }

        payload["checkedSegmentCount"] = payload["checkedSegments"].size();
        payload["modifiedSegmentCount"] = payload["modifiedSegments"].size();
        payload["unavailableSegmentCount"] = payload["unavailableSegments"].size();
        DetectionAssessment assessment = DetectionAssessment::notObserved();
        if (!payload["modifiedSegments"].empty()) {
            assessment = DetectionAssessment::moderateObserved();
        } else if (!payload["missingRequiredLibraries"].empty() ||
                   !payload["unavailableSegments"].empty() ||
                   payload["checkedSegments"].empty()) {
            assessment = DetectionAssessment::inconclusive();
        }
        LOGI("event=elf_text_scan_complete resolvedModules=%zu checked=%zu modified=%zu unavailable=%zu missingRequired=%zu missingOptional=%zu",
             modules.size(), payload["checkedSegments"].size(),
             payload["modifiedSegments"].size(), payload["unavailableSegments"].size(),
             payload["missingRequiredLibraries"].size(),
             payload["missingOptionalLibraries"].size());
        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "ELF_TEXT_INTEGRITY"; }
};

REGISTER_DETECTION(ElfTextIntegrityDetection);

}  // namespace tamperprobe
