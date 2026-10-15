#include "proc_maps.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <utility>

namespace tamperprobe {
namespace {

std::string trimAscii(std::string value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.erase(value.begin());
    }
    while (!value.empty() &&
           (value.back() == ' ' || value.back() == '\t' || value.back() == '\r' ||
            value.back() == '\n')) {
        value.pop_back();
    }
    return value;
}

bool parseMapLine(const char* line, ProcMapEntry& entry) {
    unsigned long long start = 0;
    unsigned long long end = 0;
    unsigned long long fileOffset = 0;
    unsigned long long inode = 0;
    char permissions[5] = {};
    char device[32] = {};
    int pathOffset = 0;
    const int matched = std::sscanf(line, "%llx-%llx %4s %llx %31s %llu %n", &start, &end,
                                    permissions, &fileOffset, device, &inode, &pathOffset);
    if (matched < 6 || start >= end) {
        return false;
    }

    entry.start = static_cast<std::uintptr_t>(start);
    entry.end = static_cast<std::uintptr_t>(end);
    entry.fileOffset = fileOffset;
    entry.inode = inode;
    entry.permissions = permissions;
    entry.device = device;
    entry.readable = permissions[0] == 'r';
    entry.writable = permissions[1] == 'w';
    entry.executable = permissions[2] == 'x';
    entry.privateMapping = permissions[3] == 'p';
    if (pathOffset > 0 && static_cast<size_t>(pathOffset) < std::strlen(line)) {
        entry.path = trimAscii(line + pathOffset);
    }
    entry.deleted = entry.path.size() >= 10 &&
                    entry.path.compare(entry.path.size() - 10, 10, " (deleted)") == 0;
    return true;
}

}  // namespace

bool parseProcMapLine(const std::string& line, ProcMapEntry& entry) {
    return parseMapLine(line.c_str(), entry);
}

ProcMapsSnapshot readProcMaps(const char* path) {
    ProcMapsSnapshot snapshot;
    FILE* file = std::fopen(path, "r");
    if (file == nullptr) {
        snapshot.error = errno;
        return snapshot;
    }

    snapshot.readable = true;
    char line[2048] = {};
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        ProcMapEntry entry;
        if (parseProcMapLine(line, entry)) {
            snapshot.entries.push_back(std::move(entry));
        } else {
            ++snapshot.malformedLineCount;
        }
    }
    if (std::ferror(file) != 0) {
        snapshot.error = errno == 0 ? EIO : errno;
        snapshot.readable = false;
    }
    std::fclose(file);
    return snapshot;
}

std::string normalizeDeletedMapPath(const std::string& path) {
    constexpr const char* kDeletedSuffix = " (deleted)";
    constexpr size_t kDeletedSuffixLength = 10;
    if (path.size() >= kDeletedSuffixLength &&
        path.compare(path.size() - kDeletedSuffixLength, kDeletedSuffixLength, kDeletedSuffix) ==
                0) {
        return path.substr(0, path.size() - kDeletedSuffixLength);
    }
    return path;
}

bool rangesOverlap(std::uintptr_t firstStart, std::uintptr_t firstEnd,
                   std::uintptr_t secondStart, std::uintptr_t secondEnd) {
    return firstStart < secondEnd && secondStart < firstEnd;
}

}  // namespace tamperprobe
