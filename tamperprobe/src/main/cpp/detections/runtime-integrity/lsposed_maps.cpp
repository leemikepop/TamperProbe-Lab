#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {

/**
 * Detects LSPosed/Xposed framework injection by scanning /proc/self/maps
 * for characteristic library names and paths associated with these hooking
 * frameworks (lspd, xposed bridge, edxposed, etc.).
 *
 * References: Duck-Detector lsposed feature + lsposed skill
 */
class LSPosedMapsDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        static const char* markers[] = {
            "lspd",
            "libxposed",
            "xposed_art",
            "edxposed",
            "lsposed",
            "riru",
            "libriruloader",
            "liblspd",
            "de.robv.android.xposed",
            "/lspd/",
            "XposedBridge",
        };

        nlohmann::json payload;
        payload["findings"] = nlohmann::json::array();
        std::set<std::string> dedupe;
        int hitCount = 0;

        FILE* maps = fopen("/proc/self/maps", "r");
        if (!maps) {
            payload["collectionError"] = "Cannot read /proc/self/maps";
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        char line[1024];
        while (fgets(line, sizeof(line), maps)) {
            // We need the path portion of the maps line
            unsigned long long start, end;
            char perms[5] = {};
            unsigned long long offset;
            char dev[32] = {};
            unsigned long long inode;
            int pathOffset = 0;

            int matched = sscanf(line, "%llx-%llx %4s %llx %31s %llu %n",
                                 &start, &end, perms, &offset, dev, &inode, &pathOffset);
            if (matched < 6 || !pathOffset) continue;

            char* path = line + pathOffset;
            size_t len = strlen(path);
            while (len > 0 && (path[len - 1] == '\n' || path[len - 1] == ' '))
                path[--len] = '\0';

            if (len == 0) continue;

            // Check against all markers
            for (const char* marker : markers) {
                if (strstr(path, marker) != nullptr) {
                    std::string pathStr(path);
                    if (dedupe.insert(pathStr).second) {
                        hitCount++;
                        nlohmann::json f;
                        f["marker"] = marker;
                        f["path"] = pathStr;
                        payload["findings"].push_back(f);
                    }
                    break;
                }
            }
        }
        fclose(maps);

        payload["hitCount"] = hitCount;

        DetectionAssessment assessment = DetectionAssessment::notObserved();
        if (hitCount > 0) assessment = DetectionAssessment::strongObserved();

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "LSPOSED_MAPS"; }
};

REGISTER_DETECTION(LSPosedMapsDetection);

}  // namespace tamperprobe
