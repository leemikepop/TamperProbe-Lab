#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>

#include "../../common/io_utils.h"
#include "../../common/log.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {
namespace {

constexpr char kComponent[] = "BuildPatchCoherence";

// The security patch level is a release flag set by hand, independent of the compile time,
// and partners receive bulletin fixes at least a month before publication. A genuine image
// can therefore declare a patch dated after its own build: stock Pixel builds routinely do,
// by about two to nine weeks (+66 days at most across 245 stock Pixel release builds in
// community build.prop dumps, 2026-10-07), while the Samsung and Xiaomi builds sampled
// never exceeded 0. Forward skew far beyond that range is what a rewritten patch property
// leaves behind.
//
// Measured: a Pixel 7 with no property spoofing sits at +20 days (2026-09-05), and a
// Redmi 13C running Play Integrity Fix v4.7-1-inject-s sits at +701 days (2026-09-06).
// A spoofed Pixel 7 at +51 days lies inside the stock Pixel range, so no threshold can
// separate it. The bands rest on a non-random sample, not a calibrated distribution.
constexpr long long kModerateSkewDays = 180;
constexpr long long kStrongSkewDays = 365;

struct PartitionPair {
    const char* label;
    const char* patchProperty;
    const char* buildDateProperty;
};

// Only pairs whose two halves describe the same partition. Comparing one partition's
// patch level against another partition's build date would fire on ordinary
// mixed-partition builds, where system and vendor are legitimately months apart.
//
// Partitions that publish only one half - the usual case for odm, product and
// system_ext - are reported as not comparable and contribute nothing.
const std::vector<PartitionPair>& partitionPairs() {
    static const std::vector<PartitionPair> pairs = {
        {"system", "ro.build.version.security_patch", "ro.build.date.utc"},
        {"vendor", "ro.vendor.build.security_patch", "ro.vendor.build.date.utc"},
        {"boot", "ro.vendor.boot.security_patch", "ro.bootimage.build.date.utc"},
        {"odm", "ro.odm.build.security_patch", "ro.odm.build.date.utc"},
        {"product", "ro.product.build.security_patch", "ro.product.build.date.utc"},
        {"system_ext", "ro.system_ext.build.security_patch", "ro.system_ext.build.date.utc"},
    };
    return pairs;
}

const char* evidenceStrengthLabel(EvidenceStrength strength) {
    switch (strength) {
        case EvidenceStrength::STRONG: return "strong";
        case EvidenceStrength::MODERATE: return "moderate";
        case EvidenceStrength::WEAK: return "weak";
        case EvidenceStrength::NONE: return "none";
    }
    return "none";
}

EvidenceStrength strongerOf(EvidenceStrength left, EvidenceStrength right) {
    return static_cast<int>(left) >= static_cast<int>(right) ? left : right;
}

// Days since the epoch for a YYYY-MM-DD patch level. Anything that is not exactly that
// shape is treated as unavailable rather than as an anomaly, so an OEM using its own
// notation cannot be graded as tampering.
bool patchLevelToDays(const std::string& value, long long& outDays) {
    if (value.size() < 10) return false;
    int year = 0;
    int month = 0;
    int day = 0;
    if (std::sscanf(value.c_str(), "%4d-%2d-%2d", &year, &month, &day) != 3) return false;
    if (year < 2000 || year > 2200 || month < 1 || month > 12 || day < 1 || day > 31) {
        return false;
    }
    std::tm parts {};
    parts.tm_year = year - 1900;
    parts.tm_mon = month - 1;
    parts.tm_mday = day;
    const time_t seconds = timegm(&parts);
    if (seconds == static_cast<time_t>(-1)) return false;
    outDays = static_cast<long long>(seconds) / 86400;
    return true;
}

// Build timestamps are seconds since the epoch, as written by the build system.
bool buildDateToDays(const std::string& value, long long& outDays) {
    const std::string trimmed = trim_copy(value);
    if (trimmed.empty()) return false;
    errno = 0;
    char* end = nullptr;
    const long long seconds = std::strtoll(trimmed.c_str(), &end, 10);
    if (errno != 0 || end == trimmed.c_str() || seconds <= 0) return false;
    outDays = seconds / 86400;
    return true;
}

}  // namespace

/**
 * Cross-checks each partition's declared security-patch level against the compile
 * timestamp of that same partition.
 *
 * The comparison stays entirely inside the property set, so - unlike a comparison
 * against the attested patch level - it still holds when key attestation itself is
 * being forged, which is exactly the condition on a device running a keybox-spoofing
 * module. The cost is the mirror-image blind spot: an attacker who also rewrites the
 * build timestamps defeats it.
 */
class BuildPatchCoherenceDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& /* scanContext */) override {
        nlohmann::json payload = {
            {"partitions", nlohmann::json::array()},
            {"findings", nlohmann::json::array()},
            {"comparablePartitionCount", 0},
            {"maximumSkewDays", 0},
            {"collectionErrors", nlohmann::json::array()},
        };

        int comparableCount = 0;
        long long maximumSkew = 0;
        EvidenceStrength strongest = EvidenceStrength::NONE;

        for (const auto& pair : partitionPairs()) {
            const std::string patchValue = read_property_value(pair.patchProperty);
            const std::string buildValue = read_property_value(pair.buildDateProperty);

            long long patchDays = 0;
            long long buildDays = 0;
            const bool patchUsable = patchLevelToDays(patchValue, patchDays);
            const bool buildUsable = buildDateToDays(buildValue, buildDays);

            nlohmann::json row = {
                {"partition", pair.label},
                {"patchProperty", pair.patchProperty},
                {"buildDateProperty", pair.buildDateProperty},
                {"patchLevel", patchValue},
                {"comparable", patchUsable && buildUsable},
                {"skewDays", 0},
            };

            // Per-partition reachability telemetry. A partition that silently drops out
            // must be visible in the log, otherwise a property this process cannot read
            // looks identical to a property the device does not define.
            LOGI_TAG(kComponent,
                     "event=partition_probe partition=%s patchReadable=%d buildReadable=%d",
                     pair.label, patchUsable ? 1 : 0, buildUsable ? 1 : 0);

            if (!patchUsable || !buildUsable) {
                row["reason"] = !patchUsable ? "patch level absent or not YYYY-MM-DD"
                                            : "build timestamp absent or not an epoch value";
                payload["partitions"].push_back(std::move(row));
                continue;
            }

            const long long skew = patchDays - buildDays;
            if (comparableCount == 0 || skew > maximumSkew) maximumSkew = skew;
            comparableCount++;
            row["skewDays"] = skew;

            if (skew > kModerateSkewDays) {
                const EvidenceStrength strength = skew > kStrongSkewDays
                                                      ? EvidenceStrength::STRONG
                                                      : EvidenceStrength::MODERATE;
                strongest = strongerOf(strongest, strength);
                payload["findings"].push_back({
                    {"id", "security_patch_postdates_build"},
                    {"unitId", "build-patch.security-patch-plausibility"},
                    {"partition", pair.label},
                    {"strength", evidenceStrengthLabel(strength)},
                    {"skewDays", skew},
                    {"patchLevel", patchValue},
                    {"summary",
                     "Declared security patch postdates the compile timestamp of the same "
                     "partition"},
                    {"detail",
                     std::string("Partition ") + pair.label + " declares security patch " +
                         patchValue + ", which is " + std::to_string(skew) +
                         " days later than that partition's own build timestamp. Stock "
                         "images may declare a patch a few weeks after their build, but not "
                         "a skew this large."},
                });
            }
            payload["partitions"].push_back(std::move(row));
        }

        payload["comparablePartitionCount"] = comparableCount;
        payload["maximumSkewDays"] = maximumSkew;

        LOGI_TAG(kComponent,
                 "event=build_patch_coherence comparable=%d maxSkewDays=%lld findings=%d "
                 "strongest=%s",
                 comparableCount, maximumSkew,
                 static_cast<int>(payload["findings"].size()),
                 evidenceStrengthLabel(strongest));

        // No comparable partition means the channel produced nothing, which is a
        // collection issue and not a clean device.
        if (comparableCount == 0) {
            payload["collectionErrors"].push_back(
                {{"source", "system_properties"},
                 {"message",
                  "No partition published both a parseable security-patch level and a "
                  "build timestamp."}});
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        if (strongest == EvidenceStrength::NONE) {
            return {DetectionAssessment::notObserved(), payload.dump()};
        }
        return {DetectionAssessment{DetectionOutcome::OBSERVED, strongest}, payload.dump()};
    }

    const char* getId() const override { return "BUILD_PATCH_COHERENCE"; }
};

REGISTER_DETECTION(BuildPatchCoherenceDetection);

}  // namespace tamperprobe
