#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>

#include "smaps_dirt.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {

namespace {

struct Mallinfo2Compat {
    size_t arena;
    size_t ordblks;
    size_t smblks;
    size_t hblks;
    size_t hblkhd;
    size_t usmblks;
    size_t fsmblks;
    size_t uordblks;
    size_t fordblks;
    size_t keepcost;
};

using Mallinfo2Fn = Mallinfo2Compat (*)();

struct HeapEntropyResult {
    bool supported = false;
    size_t allocatedBytes = 0;
    size_t freeKeptBytes = 0;
    double freeRatio = 0.0;
    bool anomaly = false;
};

HeapEntropyResult checkHeapEntropy() {
    HeapEntropyResult res;
    void* sym = dlsym(RTLD_DEFAULT, "mallinfo2");
    if (!sym) {
        return res;
    }
    res.supported = true;
    auto fn = reinterpret_cast<Mallinfo2Fn>(sym);
    Mallinfo2Compat info = fn();
    res.allocatedBytes = info.uordblks;
    res.freeKeptBytes = info.fordblks;
    res.freeRatio = res.allocatedBytes > 0
        ? static_cast<double>(res.freeKeptBytes) / static_cast<double>(res.allocatedBytes)
        : 0.0;

    // Fragmentation spike: high free-kept heap space combined with high ratio
    if ((res.freeKeptBytes >= 256U * 1024U && res.freeRatio >= 0.20) ||
        (res.freeKeptBytes >= 512U * 1024U && res.freeRatio >= 0.35)) {
        res.anomaly = true;
    }
    return res;
}

}  // namespace

/**
 * Detects Zygisk/Xposed injection by:
 * 1. Scanning /proc/self/smaps for dirty pages in executable system library mappings (libc.so, libart.so, etc).
 * 2. Evaluating heap entropy via mallinfo2() for abnormal free-kept heap fragmentation ratios.
 *
 * References: Duck-Detector zygisk/probes/smaps_probe.cpp, heap_entropy_probe.cpp
 */
class ZygiskSmapsDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        nlohmann::json payload;
        payload["dirtyMappings"] = nlohmann::json::array();

        FILE* f = fopen("/proc/self/smaps", "r");
        if (!f) {
            payload["collectionError"] = "Cannot read /proc/self/smaps";
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        // Parsing lives in SmapsDirtAccumulator so it can be exercised by native fixtures with
        // the region layouts measured on devices; see smaps_dirt.h for why dirt is summed per
        // library as well as reported per region.
        const long pageSize = sysconf(_SC_PAGESIZE);
        SmapsDirtAccumulator accumulator(pageSize > 0 ? static_cast<size_t>(pageSize) : 4096);
        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            accumulator.feedLine(line);
        }
        // A read that stops part way looks exactly like the end of the file to fgets, and a
        // truncated smaps must not be reported as a complete, clean one.
        const bool readError = ferror(f) != 0;
        fclose(f);
        if (readError) {
            payload["collectionError"] = "Reading /proc/self/smaps failed part way through";
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }
        accumulator.finish();

        int hitCount = 0;
        for (const DirtyRegion& region : accumulator.legacyRegionHits()) {
            ++hitCount;
            payload["dirtyMappings"].push_back({{"path", region.path},
                                                {"privateDirtyKB", region.privateDirtyKB},
                                                {"sharedDirtyKB", region.sharedDirtyKB}});
        }

        constexpr size_t kMaxReportedLibraries = 32;
        payload["systemLibraryDirt"] = nlohmann::json::array();
        size_t singlePageDirtyRegionCount = 0;
        const std::vector<LibraryDirt> dirtyLibraries = accumulator.dirtyLibraries();
        for (const LibraryDirt& library : dirtyLibraries) {
            singlePageDirtyRegionCount += library.singlePageDirtyRegionCount;
            if (payload["systemLibraryDirt"].size() >= kMaxReportedLibraries) continue;
            payload["systemLibraryDirt"].push_back(
                    {{"path", library.path},
                     {"executableRegionCount", library.executableRegionCount},
                     {"dirtyRegionCount", library.dirtyRegionCount},
                     {"singlePageDirtyRegionCount", library.singlePageDirtyRegionCount},
                     {"privateDirtyKB", library.privateDirtyKB},
                     {"sharedDirtyKB", library.sharedDirtyKB},
                     {"largestDirtyRegionKB", library.largestDirtyRegionKB}});
        }
        payload["dirtySystemLibraryCount"] = dirtyLibraries.size();
        payload["singlePageDirtyRegionCount"] = singlePageDirtyRegionCount;

        HeapEntropyResult heapEntropy = checkHeapEntropy();

        payload["hitCount"] = hitCount;
        payload["heapAllocatedBytes"] = heapEntropy.allocatedBytes;
        payload["heapFreeKeptBytes"] = heapEntropy.freeKeptBytes;
        payload["heapFreeRatio"] = heapEntropy.freeRatio;
        payload["heapEntropyAnomaly"] = heapEntropy.anomaly;

        // Both of this detector's channels are context only, and neither may move the
        // assessment until a clean-device baseline exists.
        //
        // Heap fragmentation was already treated this way: its thresholds are uncalibrated
        // constants adapted from Duck-Detector that ordinary allocator fragmentation can
        // reach.
        //
        // The dirty-page channel joined it on 2026-09-12. Its region-header test could never
        // match a real smaps header, so hitCount had been structurally pinned at zero since
        // the detector was written -- every one of the fourteen ablation cells recorded
        // hitCount = 0. Repairing the parser immediately produced hitCount = 3 on a Redmi 13C,
        // on libart.so (8416 kB private dirty), bionic libc.so (768 kB) and libinput.so
        // (228 kB) -- and those pages were dirtied by TamperProbe itself. Measured on
        // 2026-09-14 by running single detectors under DetectorSetProbeTest and reading the
        // process's smaps from outside: a control detector leaves all three at 0 kB;
        // ELF_TEXT_INTEGRITY alone takes them from 0 to exactly 8416 / 768 / 228 kB, the
        // three libraries it compares against their backing files; PROLOGUE_SCANNER alone
        // dirties 28 kB of libc.so. Both read their own text through process_vm_readv, and on
        // that device's kernel every page read that way becomes Private_Dirty. Processes on
        // the same phone that really are injected -- zygote64 with Zygisk loaded, and
        // com.google.android.gms.unstable with Play Integrity Fix -- show 0 kB. The same
        // experiment on the Pixel 7 leaves every value at 0 kB, so the effect is
        // kernel-dependent: observed on the Redmi's Linux 4.19, absent on the Pixel's 6.1.
        // Detectors run in sequence in one process, so this channel observed the footprint of
        // whichever integrity checks ran before it. Those checks now read through
        // SelfMemoryReader, which does not dirty what it reads, and the same Redmi scan reports
        // hitCount = 0.
        //
        // A positive control then showed the per-region threshold itself was blind to the
        // technique it targets. With an Xposed module hooking inside the Sample App (cells L2 and
        // L3 of lsposed_control_2026), libart.so's text was patched in nine places, and each
        // patched page became a one-page region of 4 kB -- below the 8 kB threshold, so hitCount
        // stayed 0 while ELF_TEXT_INTEGRITY found the modified bytes. systemLibraryDirt and
        // singlePageDirtyRegionCount now carry the per-library sum and that split shape.
        //
        // On 2026-09-18 the split shape became this detector's one assessed signal, graded
        // MODERATE. A file-backed executable page only becomes dirty when something writes it,
        // and a one-page region only exists when protection was changed on that page alone:
        // together they are the footprint of patching code in place. Text relocations change
        // protection on a whole segment, and PLT hooks write the GOT, which is not executable,
        // so neither produces it. In every capture carrying this telemetry the count was 0
        // without a hook -- three clean or unrooted phones, the SUSFS ladder, and the hook-free
        // cells of both positive-control studies -- and 8 or 9 with one, on both phones and
        // under both Zygisk implementations. It matters most under Magisk's built-in Zygisk,
        // where the injected library leaves no name in the maps and the name-based detectors
        // see nothing. The count cannot say who patched: a crash or APM SDK that inline-hooks
        // libc in the host app produces the same shape, which is why this is MODERATE.
        //
        // The per-region threshold stays telemetry: it is blind to one-page patches and it
        // was the channel that TamperProbe's own reads once dirtied.
        payload["dirtyMappingImpact"] = "telemetry_only";
        payload["singlePageDirtyImpact"] = "moderate";
        payload["heapEntropyImpact"] = "telemetry_only";

        if (singlePageDirtyRegionCount > 0) {
            return {DetectionAssessment::moderateObserved(), payload.dump()};
        }
        return {DetectionAssessment::notObserved(), payload.dump()};
    }

    const char* getId() const override { return "ZYGISK_SMAPS"; }
};

REGISTER_DETECTION(ZygiskSmapsDetection);

}  // namespace tamperprobe
