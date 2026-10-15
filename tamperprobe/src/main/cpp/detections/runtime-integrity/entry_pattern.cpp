#include "entry_pattern.h"

#include <cstring>

namespace tamperprobe {
namespace {

std::uint32_t readUint32(const std::uint8_t* bytes) {
    std::uint32_t value = 0;
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

EntryPatternObservation classifyAArch64(const std::uint8_t* bytes, size_t byteCount) {
    EntryPatternObservation observation;
    observation.supported = true;
    if (bytes == nullptr || byteCount < sizeof(std::uint32_t)) return observation;

    const std::uint32_t first = readUint32(bytes);
    const bool directBranch = (first >> 26) == 0x05 || (first >> 26) == 0x25;
    const bool registerBranch = (first & 0xFFFFFC1F) == 0xD61F0000 ||
                                (first & 0xFFFFFC1F) == 0xD63F0000;
    observation.branchLike = directBranch || registerBranch;
    observation.expectedPrologue =
            (first & 0xFFC003FF) == 0xA9BF7BFD ||
            (first & 0xFF8003FF) == 0xD10003FF || first == 0x910003FD ||
            first == 0xD503201F || first == 0xD503233F ||
            (first & 0x9F000000) == 0x90000000;

    if (byteCount >= 2 * sizeof(std::uint32_t)) {
        const std::uint32_t second = readUint32(bytes + sizeof(std::uint32_t));
        const bool loadLiteral = (first & 0xFF000000) == 0x58000000;
        const bool branchRegister = (second & 0xFFFFFC00) == 0xD61F0000;
        if (loadLiteral && branchRegister) {
            observation.trampolineLike = true;
            observation.suspiciousJump = true;
            return observation;
        }
    }
    observation.trampolineLike = directBranch;
    return observation;
}

EntryPatternObservation classifyX86_64(const std::uint8_t* bytes, size_t byteCount) {
    EntryPatternObservation observation;
    observation.supported = true;
    if (bytes == nullptr || byteCount == 0) return observation;

    const bool relativeJump = bytes[0] == 0xE9 || bytes[0] == 0xEB;
    const bool indirectJump = byteCount >= 2 && bytes[0] == 0xFF && bytes[1] == 0x25;
    const bool absoluteJump = byteCount >= 12 && bytes[0] == 0x48 && bytes[1] == 0xB8 &&
                              bytes[10] == 0xFF && bytes[11] == 0xE0;
    observation.branchLike = relativeJump || indirectJump || absoluteJump;
    observation.expectedPrologue =
            (byteCount >= 4 && bytes[0] == 0xF3 && bytes[1] == 0x0F &&
             bytes[2] == 0x1E && bytes[3] == 0xFA) ||
            bytes[0] == 0x55 ||
            (byteCount >= 3 && bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0xE5) ||
            (byteCount >= 3 && bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) ||
            (byteCount >= 3 && bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xEC);
    observation.trampolineLike = indirectJump || absoluteJump;
    observation.suspiciousJump = observation.trampolineLike;
    return observation;
}

}  // namespace

EntryPatternArchitecture currentEntryPatternArchitecture() {
#if defined(__aarch64__)
    return EntryPatternArchitecture::AARCH64;
#elif defined(__x86_64__)
    return EntryPatternArchitecture::X86_64;
#else
    return EntryPatternArchitecture::UNSUPPORTED;
#endif
}

const char* entryPatternArchitectureName(EntryPatternArchitecture architecture) {
    switch (architecture) {
        case EntryPatternArchitecture::AARCH64:
            return "aarch64";
        case EntryPatternArchitecture::X86_64:
            return "x86_64";
        case EntryPatternArchitecture::UNSUPPORTED:
            return "unsupported";
    }
    return "unsupported";
}

EntryPatternObservation classifyEntryPattern(const std::uint8_t* bytes, size_t byteCount,
                                             EntryPatternArchitecture architecture) {
    switch (architecture) {
        case EntryPatternArchitecture::AARCH64:
            return classifyAArch64(bytes, byteCount);
        case EntryPatternArchitecture::X86_64:
            return classifyX86_64(bytes, byteCount);
        case EntryPatternArchitecture::UNSUPPORTED:
            return {};
    }
    return {};
}

}  // namespace tamperprobe
