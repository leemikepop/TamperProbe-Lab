#ifndef TAMPERPROBE_SMAPS_DIRT_H
#define TAMPERPROBE_SMAPS_DIRT_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace tamperprobe {

// One executable system-library mapping region whose Private_Dirty plus Shared_Dirty reached
// the legacy per-region threshold.
struct DirtyRegion {
    std::string path;
    size_t privateDirtyKB = 0;
    size_t sharedDirtyKB = 0;
};

// Dirty executable pages of one system library, summed over every region the library's mappings
// have been split into.
//
// Patching code needs a protection change, and changing protection on part of a mapping splits
// it, so every patched page ends up as its own one-page region. On the Redmi 13C at cell L2 of
// the lsposed_control_2026 experiment, LSPlant's hooks left libart.so's text as nine one-page
// regions of 4 kB each among clean ranges. A per-region threshold of 8 kB can never see that,
// however many pages are patched. Summing per library, and counting one-page dirty regions
// separately, keeps both the amount and the shape.
struct LibraryDirt {
    std::string path;
    size_t executableRegionCount = 0;
    size_t dirtyRegionCount = 0;
    size_t singlePageDirtyRegionCount = 0;
    size_t privateDirtyKB = 0;
    size_t sharedDirtyKB = 0;
    size_t largestDirtyRegionKB = 0;
};

// Streams /proc/self/smaps one line at a time. Only executable mappings of files under /system/,
// /vendor/, /apex/ and /product/ are considered.
class SmapsDirtAccumulator {
   public:
    static constexpr size_t kLegacyRegionThresholdKB = 8;

    explicit SmapsDirtAccumulator(size_t pageSizeBytes);

    void feedLine(const char* line);
    // Closes the region still open after the last line. Call once, after the final feedLine.
    void finish();

    // Regions at or above kLegacyRegionThresholdKB, in file order: the original hitCount basis.
    const std::vector<DirtyRegion>& legacyRegionHits() const { return legacyHits_; }
    // Libraries with at least one dirty executable region, ordered by path.
    std::vector<LibraryDirt> dirtyLibraries() const;

   private:
    void closeRegion();

    size_t pageSizeBytes_;
    bool open_ = false;
    bool executable_ = false;
    bool system_ = false;
    std::uint64_t start_ = 0;
    std::uint64_t end_ = 0;
    std::string path_;
    size_t privateDirtyKB_ = 0;
    size_t sharedDirtyKB_ = 0;
    std::vector<DirtyRegion> legacyHits_;
    std::map<std::string, LibraryDirt> libraries_;
};

}  // namespace tamperprobe

#endif  // TAMPERPROBE_SMAPS_DIRT_H
