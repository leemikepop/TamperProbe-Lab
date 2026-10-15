#include "smaps_dirt.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace tamperprobe {
namespace {

bool isSystemLibraryPath(const std::string& path) {
    return path.rfind("/system/", 0) == 0 || path.rfind("/vendor/", 0) == 0 ||
           path.rfind("/apex/", 0) == 0 || path.rfind("/product/", 0) == 0;
}

}  // namespace

SmapsDirtAccumulator::SmapsDirtAccumulator(size_t pageSizeBytes) : pageSizeBytes_(pageSizeBytes) {}

void SmapsDirtAccumulator::feedLine(const char* line) {
    if (line == nullptr) return;

    // A region header is identified by parsing it. Every header carries a device field such as
    // "fd:07" or "00:00", so tests based on the absence of ':' never match a real header.
    unsigned long long start = 0;
    unsigned long long end = 0;
    char perms[5] = {};
    unsigned long long offset = 0;
    char device[32] = {};
    unsigned long long inode = 0;
    int pathOffset = 0;
    const int matched = std::sscanf(line, "%llx-%llx %4s %llx %31s %llu %n", &start, &end, perms,
                                    &offset, device, &inode, &pathOffset);
    if (matched >= 6) {
        closeRegion();
        open_ = true;
        start_ = start;
        end_ = end;
        executable_ = std::strchr(perms, 'x') != nullptr;
        path_.clear();
        if (pathOffset > 0 && pathOffset < static_cast<int>(std::strlen(line))) {
            path_ = line + pathOffset;
            while (!path_.empty() &&
                   (path_.back() == '\n' || path_.back() == '\r' || path_.back() == ' ')) {
                path_.pop_back();
            }
        }
        system_ = isSystemLibraryPath(path_);
        return;
    }
    if (!open_) return;
    if (std::strncmp(line, "Private_Dirty:", 14) == 0) {
        privateDirtyKB_ = std::strtoul(line + 14, nullptr, 10);
    } else if (std::strncmp(line, "Shared_Dirty:", 13) == 0) {
        sharedDirtyKB_ = std::strtoul(line + 13, nullptr, 10);
    }
}

void SmapsDirtAccumulator::finish() { closeRegion(); }

void SmapsDirtAccumulator::closeRegion() {
    if (open_ && executable_ && system_) {
        LibraryDirt& library = libraries_[path_];
        library.path = path_;
        ++library.executableRegionCount;
        const size_t dirtyKB = privateDirtyKB_ + sharedDirtyKB_;
        if (dirtyKB > 0) {
            ++library.dirtyRegionCount;
            library.privateDirtyKB += privateDirtyKB_;
            library.sharedDirtyKB += sharedDirtyKB_;
            library.largestDirtyRegionKB = std::max(library.largestDirtyRegionKB, dirtyKB);
            if (pageSizeBytes_ > 0 && end_ > start_ && end_ - start_ == pageSizeBytes_) {
                ++library.singlePageDirtyRegionCount;
            }
        }
        if (dirtyKB >= kLegacyRegionThresholdKB) {
            legacyHits_.push_back({path_, privateDirtyKB_, sharedDirtyKB_});
        }
    }
    open_ = false;
    executable_ = false;
    system_ = false;
    start_ = 0;
    end_ = 0;
    path_.clear();
    privateDirtyKB_ = 0;
    sharedDirtyKB_ = 0;
}

std::vector<LibraryDirt> SmapsDirtAccumulator::dirtyLibraries() const {
    std::vector<LibraryDirt> result;
    for (const auto& entry : libraries_) {
        if (entry.second.dirtyRegionCount > 0) result.push_back(entry.second);
    }
    return result;
}

}  // namespace tamperprobe
