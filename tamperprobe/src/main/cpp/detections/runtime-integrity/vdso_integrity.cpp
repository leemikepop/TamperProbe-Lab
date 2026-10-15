#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/auxv.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <limits>
#include <string>

#include "../../common/proc_maps.h"
#include "elf_integrity.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {
namespace {

constexpr size_t kMaximumProgramHeaders = 256;

#if defined(__LP64__)
using ElfHeader = Elf64_Ehdr;
using ProgramHeader = Elf64_Phdr;
constexpr unsigned char kExpectedElfClass = ELFCLASS64;
#else
using ElfHeader = Elf32_Ehdr;
using ProgramHeader = Elf32_Phdr;
constexpr unsigned char kExpectedElfClass = ELFCLASS32;
#endif

// The vDSO is not file-backed, so process_vm_readv could not dirty a library page here, but
// all three self-reading detectors now share one reader so none of them reintroduces it.
bool readSelfMemory(std::uintptr_t address, void* output, size_t byteCount) {
    return readSelfMemoryRange(address, output, byteCount);
}

bool containsRange(const ProcMapEntry& mapping, std::uintptr_t start, size_t byteCount) {
    return byteCount > 0 && start >= mapping.start &&
           start <= std::numeric_limits<std::uintptr_t>::max() - byteCount &&
           start + byteCount <= mapping.end;
}

void addFinding(nlohmann::json& payload, const char* type, const char* detail) {
    payload["findings"].push_back(
            {{"type", type}, {"detail", detail}, {"assessmentImpact", "moderate"}});
}

struct LinkerOwner {
    std::uintptr_t vdsoBase = 0;
    bool found = false;
    std::string path;
};

int findLinkerOwner(dl_phdr_info* info, size_t, void* data) {
    auto* owner = static_cast<LinkerOwner*>(data);
    if (static_cast<std::uintptr_t>(info->dlpi_addr) != owner->vdsoBase) return 0;
    owner->found = true;
    owner->path = info->dlpi_name == nullptr ? "" : info->dlpi_name;
    return 1;
}

}  // namespace

class VdsoIntegrityDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        (void)scanContext;
        nlohmann::json payload;
        payload["findings"] = nlohmann::json::array();
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

        const ProcMapEntry* vdso = nullptr;
        size_t mappingCount = 0;
        for (const ProcMapEntry& entry : maps.entries) {
            if (entry.path != "[vdso]") continue;
            ++mappingCount;
            if (vdso == nullptr) vdso = &entry;
        }
        payload["mappingCount"] = mappingCount;
        if (vdso == nullptr) {
            payload["collectionErrors"].push_back(
                    {{"source", "[vdso]"}, {"errno", 0}, {"message", "VDSO mapping missing"}});
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }
        payload["mappingStart"] = vdso->start;
        payload["mappingEnd"] = vdso->end;
        payload["mappingPermissions"] = vdso->permissions;
        if (mappingCount != 1) addFinding(payload, "multiple_vdso_mappings", "Expected one VDSO map");
        if (!vdso->readable || !vdso->executable || vdso->writable) {
            addFinding(payload, "vdso_mapping_permissions",
                       "VDSO mapping is not readable, executable, and non-writable");
        }

        errno = 0;
        const std::uintptr_t auxiliaryBase =
                static_cast<std::uintptr_t>(getauxval(AT_SYSINFO_EHDR));
        payload["auxvAddress"] = auxiliaryBase;
        if (auxiliaryBase == 0) {
            payload["collectionErrors"].push_back(
                    {{"source", "AT_SYSINFO_EHDR"},
                     {"errno", errno},
                     {"message", "Auxiliary VDSO base unavailable"}});
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }
        const bool auxvMatchesMapping = auxiliaryBase == vdso->start;
        payload["auxvMatchesMapping"] = auxvMatchesMapping;
        if (!auxvMatchesMapping) {
            addFinding(payload, "auxv_mapping_mismatch",
                       "AT_SYSINFO_EHDR does not match the VDSO mapping base");
        }

        bool elfHeaderValid = false;
        bool loadSegmentsValid = false;
        ElfHeader header{};
        if (!containsRange(*vdso, auxiliaryBase, sizeof(header)) ||
            !readSelfMemory(auxiliaryBase, &header, sizeof(header))) {
            payload["collectionErrors"].push_back(
                    {{"source", "[vdso] ELF header"},
                     {"errno", errno},
                     {"message", "VDSO ELF header unreadable"}});
        } else {
            elfHeaderValid = std::memcmp(header.e_ident, ELFMAG, SELFMAG) == 0 &&
                             header.e_ident[EI_CLASS] == kExpectedElfClass &&
                             header.e_type == ET_DYN &&
                             header.e_phentsize == sizeof(ProgramHeader) && header.e_phnum > 0 &&
                             header.e_phnum <= kMaximumProgramHeaders;
            if (!elfHeaderValid) {
                addFinding(payload, "invalid_vdso_elf_header", "VDSO ELF header is inconsistent");
            } else {
                loadSegmentsValid = true;
                const size_t tableBytes = static_cast<size_t>(header.e_phnum) * sizeof(ProgramHeader);
                if (header.e_phoff > std::numeric_limits<std::uintptr_t>::max() - auxiliaryBase ||
                    !containsRange(*vdso, auxiliaryBase + header.e_phoff, tableBytes)) {
                    loadSegmentsValid = false;
                } else {
                    bool sawLoadSegment = false;
                    for (size_t index = 0; index < header.e_phnum; ++index) {
                        ProgramHeader programHeader{};
                        const std::uintptr_t address = auxiliaryBase + header.e_phoff +
                                                       index * sizeof(ProgramHeader);
                        if (!readSelfMemory(address, &programHeader, sizeof(programHeader))) {
                            loadSegmentsValid = false;
                            break;
                        }
                        if (programHeader.p_type != PT_LOAD || programHeader.p_memsz == 0) continue;
                        sawLoadSegment = true;
                        if (programHeader.p_vaddr >
                            std::numeric_limits<std::uintptr_t>::max() - auxiliaryBase) {
                            loadSegmentsValid = false;
                            break;
                        }
                        const auto segmentStart =
                                auxiliaryBase + static_cast<std::uintptr_t>(programHeader.p_vaddr);
                        if (programHeader.p_memsz > std::numeric_limits<size_t>::max() ||
                            !containsRange(*vdso, segmentStart,
                                           static_cast<size_t>(programHeader.p_memsz))) {
                            loadSegmentsValid = false;
                            break;
                        }
                    }
                    if (!sawLoadSegment) loadSegmentsValid = false;
                }
                if (!loadSegmentsValid) {
                    addFinding(payload, "invalid_vdso_load_range",
                               "A VDSO PT_LOAD range escapes the executable mapping");
                }
            }
        }
        payload["elfHeaderValid"] = elfHeaderValid;
        payload["loadSegmentsValid"] = loadSegmentsValid;

        LinkerOwner owner{.vdsoBase = auxiliaryBase};
        dl_iterate_phdr(findLinkerOwner, &owner);
        payload["linkerOwnerFound"] = owner.found;
        payload["linkerOwnerPath"] = owner.path;
        if (!owner.found) {
            addFinding(payload, "vdso_linker_owner_missing",
                       "Public linker enumeration does not own the VDSO base");
        }

        const char* symbols[] = {"__kernel_clock_gettime", "__kernel_gettimeofday",
                                 "__kernel_rt_sigreturn"};
        bool symbolCheckAvailable = false;
        bool symbolOwnedByVdso = false;
        for (const char* symbol : symbols) {
            dlerror();
            void* address = dlsym(RTLD_DEFAULT, symbol);
            if (dlerror() != nullptr || address == nullptr) continue;
            symbolCheckAvailable = true;
            payload["checkedSymbol"] = symbol;
            payload["resolvedSymbolAddress"] = reinterpret_cast<std::uintptr_t>(address);
            symbolOwnedByVdso = reinterpret_cast<std::uintptr_t>(address) >= vdso->start &&
                                reinterpret_cast<std::uintptr_t>(address) < vdso->end;
            if (!symbolOwnedByVdso) {
                addFinding(payload, "vdso_symbol_owner_mismatch",
                           "A resolved kernel helper symbol is outside the VDSO mapping");
            }
            break;
        }
        payload["symbolCheckAvailable"] = symbolCheckAvailable;
        payload["symbolOwnedByVdso"] = symbolOwnedByVdso;
        payload["findingCount"] = payload["findings"].size();

        DetectionAssessment assessment = DetectionAssessment::notObserved();
        if (!payload["findings"].empty()) {
            assessment = DetectionAssessment::moderateObserved();
        } else if (!payload["collectionErrors"].empty()) {
            assessment = DetectionAssessment::inconclusive();
        }
        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "VDSO_INTEGRITY"; }
};

REGISTER_DETECTION(VdsoIntegrityDetection);

}  // namespace tamperprobe
