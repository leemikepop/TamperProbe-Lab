#include "elf_integrity.h"

#include <elf.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <limits>

#include "../../common/io_utils.h"

namespace tamperprobe {
namespace {

constexpr size_t kMaximumProgramHeaders = 256;
constexpr size_t kComparisonChunkBytes = 4096;
// No larger than PIPE_BUF. A pipe always has at least one page of capacity, even when the
// per-user pipe budget has shrunk new pipes to a single page, so a write of this size into an
// empty pipe is never short for lack of room.
constexpr size_t kPipeSliceBytes = 4096;

#if defined(__LP64__)
using ElfHeader = Elf64_Ehdr;
using ProgramHeader = Elf64_Phdr;
constexpr unsigned char kExpectedElfClass = ELFCLASS64;
#else
using ElfHeader = Elf32_Ehdr;
using ProgramHeader = Elf32_Phdr;
constexpr unsigned char kExpectedElfClass = ELFCLASS32;
#endif

bool readFullyAt(int fd, std::uint64_t fileOffset, void* buffer, size_t byteCount) {
    if (fileOffset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) return false;
    if (lseek(fd, static_cast<off_t>(fileOffset), SEEK_SET) < 0) return false;

    size_t totalRead = 0;
    auto* output = static_cast<unsigned char*>(buffer);
    while (totalRead < byteCount) {
        const ssize_t bytesRead = syscall_read_fd(fd, output + totalRead, byteCount - totalRead);
        if (bytesRead < 0 && errno == EINTR) continue;
        if (bytesRead <= 0) return false;
        totalRead += static_cast<size_t>(bytesRead);
    }
    return true;
}

bool validElfHeader(const ElfHeader& header) {
    return std::memcmp(header.e_ident, ELFMAG, SELFMAG) == 0 &&
           header.e_ident[EI_CLASS] == kExpectedElfClass &&
           header.e_phentsize == sizeof(ProgramHeader) && header.e_phnum > 0 &&
           header.e_phnum <= kMaximumProgramHeaders;
}

}  // namespace

SelfMemoryReader::~SelfMemoryReader() { close(); }

bool SelfMemoryReader::open() {
    if (readFd_ >= 0 && writeFd_ >= 0) return true;
    int fds[2] = {-1, -1};
    // Both ends non-blocking: a read or write that cannot complete immediately is treated as
    // a failure rather than left to block the scan.
    if (syscall(__NR_pipe2, fds, O_CLOEXEC | O_NONBLOCK) != 0) return false;
    readFd_ = fds[0];
    writeFd_ = fds[1];
    return true;
}

void SelfMemoryReader::close() {
    if (readFd_ >= 0) syscall_close_fd(readFd_);
    if (writeFd_ >= 0) syscall_close_fd(writeFd_);
    readFd_ = -1;
    writeFd_ = -1;
}

bool SelfMemoryReader::read(std::uintptr_t address, void* output, size_t byteCount) {
    if (address == 0 || output == nullptr || byteCount == 0 ||
        address > std::numeric_limits<std::uintptr_t>::max() - byteCount) {
        return false;
    }
    if (!open()) return false;

    auto* destination = static_cast<unsigned char*>(output);
    size_t done = 0;
    while (done < byteCount) {
        const size_t slice = std::min(kPipeSliceBytes, byteCount - done);
        const long written =
                syscall(__NR_write, writeFd_, reinterpret_cast<void*>(address + done), slice);
        if (written != static_cast<long>(slice)) {
            // EFAULT for an unreadable address, or a short copy at a mapping boundary. Either
            // way some bytes may be sitting in the pipe, so it is discarded.
            close();
            return false;
        }
        size_t drained = 0;
        while (drained < slice) {
            const long got = syscall(__NR_read, readFd_, destination + done + drained,
                                     slice - drained);
            if (got <= 0) {
                close();
                return false;
            }
            drained += static_cast<size_t>(got);
        }
        done += slice;
    }
    return true;
}

bool readSelfMemoryRange(std::uintptr_t address, void* output, size_t byteCount) {
    SelfMemoryReader reader;
    return reader.read(address, output, byteCount);
}

bool pathHasBasename(const char* path, const char* expectedBasename) {
    if (path == nullptr || expectedBasename == nullptr) return false;
    const char* separator = std::strrchr(path, '/');
    const char* basename = separator == nullptr ? path : separator + 1;
    return std::strcmp(basename, expectedBasename) == 0;
}

bool rangeHasPermissions(const ProcMapsSnapshot& maps, std::uintptr_t start, size_t byteCount,
                         bool requireExecutable, bool requireNonWritable) {
    if (!maps.readable || byteCount == 0 ||
        start > std::numeric_limits<std::uintptr_t>::max() - byteCount) {
        return false;
    }
    const std::uintptr_t end = start + byteCount;
    std::uintptr_t cursor = start;
    for (const ProcMapEntry& entry : maps.entries) {
        if (entry.end <= cursor) continue;
        if (entry.start > cursor || !entry.readable ||
            (requireExecutable && !entry.executable) ||
            (requireNonWritable && entry.writable)) {
            return false;
        }
        cursor = std::min(end, entry.end);
        if (cursor == end) return true;
    }
    return false;
}

ByteComparisonResult compareMemoryRangeWithFile(const std::string& backingPath,
                                                std::uintptr_t memoryStart,
                                                std::uint64_t fileOffset, size_t byteCount,
                                                const ProcMapsSnapshot& maps,
                                                bool requireNonWritable) {
    ByteComparisonResult result;
    result.backingFileOffset = fileOffset;
    if (backingPath.empty() || byteCount == 0) {
        result.reason = "invalid_comparison_range";
        return result;
    }
    if (!rangeHasPermissions(maps, memoryStart, byteCount, true, requireNonWritable)) {
        result.reason = "memory_range_not_readable_executable";
        return result;
    }

    const int fd = syscall_openat_readonly(backingPath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        result.reason = "backing_elf_not_readable";
        return result;
    }

    std::array<unsigned char, kComparisonChunkBytes> diskBytes{};
    std::array<unsigned char, kComparisonChunkBytes> memoryBytes{};
    SelfMemoryReader memoryReader;
    size_t compared = 0;
    while (compared < byteCount) {
        const size_t chunk = std::min(kComparisonChunkBytes, byteCount - compared);
        if (!readFullyAt(fd, fileOffset + compared, diskBytes.data(), chunk)) {
            syscall_close_fd(fd);
            result.reason = "backing_elf_read_failed";
            result.comparedBytes = compared;
            return result;
        }
        if (!memoryReader.read(memoryStart + compared, memoryBytes.data(), chunk)) {
            syscall_close_fd(fd);
            result.reason = "memory_read_failed";
            result.comparedBytes = compared;
            return result;
        }
        const auto mismatch = std::mismatch(memoryBytes.begin(), memoryBytes.begin() + chunk,
                                            diskBytes.begin());
        if (mismatch.first != memoryBytes.begin() + chunk) {
            syscall_close_fd(fd);
            result.status = ByteComparisonStatus::DIFFERENT;
            result.reason = "memory_differs_from_backing_elf";
            result.comparedBytes = compared + chunk;
            result.firstMismatchOffset =
                    compared + static_cast<size_t>(mismatch.first - memoryBytes.begin());
            return result;
        }
        compared += chunk;
    }
    syscall_close_fd(fd);
    result.status = ByteComparisonStatus::MATCH;
    result.reason = "memory_matches_backing_elf";
    result.comparedBytes = compared;
    return result;
}

ByteComparisonResult compareLoadedAddressWithBackingElf(const std::string& backingPath,
                                                        std::uintptr_t loadBase,
                                                        std::uintptr_t memoryStart,
                                                        size_t byteCount,
                                                        const ProcMapsSnapshot& maps) {
    ByteComparisonResult unavailable;
    if (memoryStart < loadBase || byteCount == 0) {
        unavailable.reason = "address_precedes_load_base";
        return unavailable;
    }

    const int fd = syscall_openat_readonly(backingPath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        unavailable.reason = "backing_elf_not_readable";
        return unavailable;
    }
    ElfHeader header{};
    if (!readFullyAt(fd, 0, &header, sizeof(header)) || !validElfHeader(header)) {
        syscall_close_fd(fd);
        unavailable.reason = "invalid_backing_elf";
        return unavailable;
    }

    const std::uint64_t relativeAddress = memoryStart - loadBase;
    std::uint64_t resolvedFileOffset = 0;
    bool resolved = false;
    for (size_t index = 0; index < header.e_phnum; ++index) {
        ProgramHeader programHeader{};
        const std::uint64_t headerOffset =
                static_cast<std::uint64_t>(header.e_phoff) + index * sizeof(ProgramHeader);
        if (!readFullyAt(fd, headerOffset, &programHeader, sizeof(programHeader))) break;
        if (programHeader.p_type != PT_LOAD || programHeader.p_filesz < byteCount ||
            relativeAddress < programHeader.p_vaddr) {
            continue;
        }
        const std::uint64_t segmentOffset = relativeAddress - programHeader.p_vaddr;
        if (segmentOffset > programHeader.p_filesz - byteCount) continue;
        resolvedFileOffset = programHeader.p_offset + segmentOffset;
        resolved = true;
        break;
    }
    syscall_close_fd(fd);
    if (!resolved) {
        unavailable.reason = "address_not_backed_by_load_segment";
        return unavailable;
    }
    return compareMemoryRangeWithFile(backingPath, memoryStart, resolvedFileOffset, byteCount, maps,
                                      false);
}

}  // namespace tamperprobe
