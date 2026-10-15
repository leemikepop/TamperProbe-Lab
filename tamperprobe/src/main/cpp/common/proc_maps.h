#ifndef TAMPERPROBE_PROC_MAPS_H
#define TAMPERPROBE_PROC_MAPS_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tamperprobe {

struct ProcMapEntry {
    std::uintptr_t start = 0;
    std::uintptr_t end = 0;
    std::uint64_t fileOffset = 0;
    unsigned long long inode = 0;
    std::string permissions;
    std::string device;
    std::string path;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool privateMapping = false;
    bool deleted = false;
};

struct ProcMapsSnapshot {
    bool readable = false;
    int error = 0;
    size_t malformedLineCount = 0;
    std::vector<ProcMapEntry> entries;
};

// Pure parsing seam used by controlled fixtures and by the live procfs collector.
bool parseProcMapLine(const std::string& line, ProcMapEntry& entry);

ProcMapsSnapshot readProcMaps(const char* path = "/proc/self/maps");

std::string normalizeDeletedMapPath(const std::string& path);

bool rangesOverlap(std::uintptr_t firstStart, std::uintptr_t firstEnd,
                   std::uintptr_t secondStart, std::uintptr_t secondEnd);

}  // namespace tamperprobe

#endif  // TAMPERPROBE_PROC_MAPS_H
