#ifndef TAMPERPROBE_ELF_INTEGRITY_H
#define TAMPERPROBE_ELF_INTEGRITY_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "../../common/proc_maps.h"

namespace tamperprobe {

enum class ByteComparisonStatus {
    MATCH,
    DIFFERENT,
    UNAVAILABLE,
};

struct ByteComparisonResult {
    ByteComparisonStatus status = ByteComparisonStatus::UNAVAILABLE;
    std::string reason;
    std::uint64_t backingFileOffset = 0;
    size_t comparedBytes = 0;
    size_t firstMismatchOffset = 0;
};

bool pathHasBasename(const char* path, const char* expectedBasename);

bool rangeHasPermissions(const ProcMapsSnapshot& maps, std::uintptr_t start, size_t byteCount,
                         bool requireExecutable, bool requireNonWritable);

// Reads this process's own memory without crashing on an invalid address and without
// changing the memory it reads.
//
// The bytes are written from the target address into a pipe and read back. The kernel copies
// them with copy_from_user, which reports an unmapped or unreadable address as EFAULT instead
// of delivering SIGSEGV, and which takes an ordinary read fault on a file-backed page.
//
// process_vm_readv was used until 2026-09-14 and has the same crash safety, but on the
// Redmi 13C's Linux 4.19 every page it read became Private_Dirty: one ELF_TEXT_INTEGRITY scan
// left libart.so, libc.so and libinput.so with 8416, 768 and 228 kB of private dirty code
// pages, about 9.4 MB held for the life of the host process, and ZYGISK_SMAPS then observed
// those pages as code tampering. The Pixel 7's Linux 6.1 did not show the effect.
//
// A reader keeps one pipe for a sequence of reads. Any failed read closes it, so a partial
// copy can never leave stale bytes to be mistaken for the next read's data.
class SelfMemoryReader {
   public:
    SelfMemoryReader() = default;
    ~SelfMemoryReader();
    SelfMemoryReader(const SelfMemoryReader&) = delete;
    SelfMemoryReader& operator=(const SelfMemoryReader&) = delete;

    bool read(std::uintptr_t address, void* output, size_t byteCount);

   private:
    bool open();
    void close();

    int readFd_ = -1;
    int writeFd_ = -1;
};

bool readSelfMemoryRange(std::uintptr_t address, void* output, size_t byteCount);

ByteComparisonResult compareMemoryRangeWithFile(const std::string& backingPath,
                                                std::uintptr_t memoryStart,
                                                std::uint64_t fileOffset, size_t byteCount,
                                                const ProcMapsSnapshot& maps,
                                                bool requireNonWritable);

ByteComparisonResult compareLoadedAddressWithBackingElf(const std::string& backingPath,
                                                        std::uintptr_t loadBase,
                                                        std::uintptr_t memoryStart,
                                                        size_t byteCount,
                                                        const ProcMapsSnapshot& maps);

}  // namespace tamperprobe

#endif  // TAMPERPROBE_ELF_INTEGRITY_H
