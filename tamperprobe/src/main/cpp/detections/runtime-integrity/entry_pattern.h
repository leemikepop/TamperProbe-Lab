#ifndef TAMPERPROBE_ENTRY_PATTERN_H
#define TAMPERPROBE_ENTRY_PATTERN_H

#include <cstddef>
#include <cstdint>

namespace tamperprobe {

enum class EntryPatternArchitecture {
    AARCH64,
    X86_64,
    UNSUPPORTED,
};

struct EntryPatternObservation {
    bool supported = false;
    bool branchLike = false;
    bool expectedPrologue = false;
    bool trampolineLike = false;
    bool suspiciousJump = false;
};

EntryPatternArchitecture currentEntryPatternArchitecture();

const char* entryPatternArchitectureName(EntryPatternArchitecture architecture);

EntryPatternObservation classifyEntryPattern(const std::uint8_t* bytes, size_t byteCount,
                                             EntryPatternArchitecture architecture);

}  // namespace tamperprobe

#endif  // TAMPERPROBE_ENTRY_PATTERN_H
