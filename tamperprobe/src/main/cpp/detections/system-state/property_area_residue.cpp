#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "../../common/io_utils.h"
#include "../../common/log.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"
#include "property_area_parser.h"

namespace tamperprobe {
namespace {

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

bool isSensitiveSecurityProperty(const std::string& name) {
    static const std::set<std::string> kSensitive = {
        "ro.build.type",
        "ro.build.tags",
        "ro.build.fingerprint",
        "ro.build.id",
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
        "ro.boot.vbmeta.device_state",
        "ro.secure",
        "ro.debuggable",
        "ro.adb.secure",
        "ro.bootloader",
    };
    // Deliberately an explicit list and NOT an "ro.boot.*" prefix. Measured on
    // 2026-09-05: the prefix graded ro.boot.boottime, ro.boot.mode, ro.boot.hardware
    // and ro.boot.vbmeta.* as STRONG on both test devices, none of which any root tool
    // touches - init writes boot-timing and bootloader-supplied properties itself.
    return kSensitive.find(name) != kSensitive.end();
}

// Whether an anomaly on this property may move the detector outcome.
//
// A non-zero serial counter proves an ro.* property was rewritten after creation, but
// it does not prove who rewrote it: init legitimately updates several of them during
// boot. With no clean-device baseline yet, only the properties that root tools are
// known to spoof and that init writes exactly once are allowed to carry the verdict.
// Every other anomaly is still recorded in the payload as research telemetry.
bool anomalyMayDriveOutcome(const std::string& name) {
    return isSensitiveSecurityProperty(name);
}

constexpr std::size_t kMaxReportedFindings = 32;

}  // namespace

class PropertyAreaResidueDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& /* scanContext */) override {
        const std::vector<PropertyAreaRecord> areas = scanPropertyAreas();

        nlohmann::json payload = {
            {"parsedAreaCount", 0},
            {"totalPropertiesInspected", 0},
            {"serialAnomalyCount", 0},
            {"trailingResidueCount", 0},
            {"readOnlyTrailingResidueCount", 0},
            {"writableTrailingResidueCount", 0},
            {"findings", nlohmann::json::array()},
            {"collectionErrors", nlohmann::json::array()},
        };

        int parsedAreaCount = 0;
        std::size_t totalPropertiesInspected = 0;
        int serialAnomalyCount = 0;
        int trailingResidueCount = 0;
        int readOnlyTrailingResidueCount = 0;
        EvidenceStrength strongestFinding = EvidenceStrength::NONE;
        std::set<std::string> seenErrorDedupe;

        for (const auto& area : areas) {
            if (area.status != PropertyAreaStatus::PARSED) {
                const std::string key = area.path + '\n' + area.error;
                if (seenErrorDedupe.insert(key).second) {
                    payload["collectionErrors"].push_back({
                        {"path", area.path},
                        {"context", area.context},
                        {"status", propertyAreaStatusName(area.status)},
                        {"errno", area.errorNumber},
                        {"message", area.error},
                    });
                }
                continue;
            }

            parsedAreaCount++;
            for (const auto& prop : area.propertyDetails) {
                totalPropertiesInspected++;

                // 1. Check serial value-length vs actual string length
                // In Bionic: serial >> 24 is the length of short-property value string
                // A property bionic is updating right now legitimately has a serial
                // and a value that disagree; that window is collection noise, not
                // evidence, so it is skipped rather than reported.
                if (!prop.isLongProperty && !prop.isDirty && prop.valueLengthFromSerial > 0 &&
                    prop.valueLengthFromSerial != prop.stringLength) {
                    serialAnomalyCount++;
                    const EvidenceStrength strength = EvidenceStrength::STRONG;
                    if (anomalyMayDriveOutcome(prop.name)) {
                        strongestFinding = strongerOf(strongestFinding, strength);
                    }

                    std::ostringstream detail;
                    detail << "Property " << prop.name << " in " << area.context
                           << " has serial length " << prop.valueLengthFromSerial
                           << " but string length " << prop.stringLength
                           << " (in-place modification without serial update)";

                    if (payload["findings"].size() < kMaxReportedFindings) {
                        payload["findings"].push_back({
                            {"property", prop.name},
                            {"unitId", "system-property-residue.serial-anomaly"},
                            {"anomalyType", "LENGTH_MISMATCH"},
                            {"strength", evidenceStrengthLabel(strength)},
                            {"areaContext", area.context},
                            {"serial", prop.serial},
                            {"serialLength", prop.valueLengthFromSerial},
                            {"actualLength", prop.stringLength},
                            {"detail", detail.str()},
                        });
                    }
                }

                // 2. Check read-only serial update counter
                // In Bionic init: ro.* properties are created with serial counter == 0
                if (prop.isReadOnly) {
                    const std::uint32_t serialCounter = prop.serial & 0xffffff;
                    if (serialCounter > 0) {
                        serialAnomalyCount++;
                        const EvidenceStrength strength = EvidenceStrength::STRONG;
                        if (anomalyMayDriveOutcome(prop.name)) {
                            strongestFinding = strongerOf(strongestFinding, strength);
                        }

                        std::ostringstream detail;
                        detail << "Read-only property " << prop.name << " in " << area.context
                               << " has non-zero serial update counter " << serialCounter
                               << " (supposedly immutable property was updated at runtime)";

                        if (payload["findings"].size() < kMaxReportedFindings) {
                            payload["findings"].push_back({
                                {"property", prop.name},
                                {"unitId", "system-property-residue.serial-anomaly"},
                                {"anomalyType", "RO_SERIAL_MODIFIED"},
                                {"strength", evidenceStrengthLabel(strength)},
                                {"areaContext", area.context},
                                {"serial", prop.serial},
                                {"serialCounter", serialCounter},
                                {"detail", detail.str()},
                            });
                        }
                    }
                }

                // 3. Trailing non-zero bytes past the NUL terminator in the value buffer.
                //
                // Measured on 2026-09-05: 200 of 881 properties on a Pixel 7 and 15 of
                // 1133 on a Redmi 13C carry residue. Bionic does not clear the tail when
                // a value is overwritten in place, so every ordinary shortening update of
                // a dynamic property leaves some. Residue is therefore only evidence for
                // ro.* properties, which are supposed to be written once and never again;
                // everywhere else it is counted and reported but must not move the
                // outcome, or this detector would fire on every device.
                if (prop.hasTrailingBytes) {
                    trailingResidueCount++;
                    if (prop.isReadOnly) readOnlyTrailingResidueCount++;
                }
                if (prop.hasTrailingBytes && prop.isReadOnly) {
                    const EvidenceStrength strength = EvidenceStrength::STRONG;
                    if (anomalyMayDriveOutcome(prop.name)) {
                        strongestFinding = strongerOf(strongestFinding, strength);
                    }

                    std::ostringstream detail;
                    detail << "Property " << prop.name << " in " << area.context
                           << " carries " << prop.trailingBytesCount
                           << " trailing dirty byte(s) past NUL terminator [snippet: \""
                           << prop.trailingBytesSnippet << "\"]";

                    if (payload["findings"].size() < kMaxReportedFindings) {
                        payload["findings"].push_back({
                            {"property", prop.name},
                            {"unitId", "system-property-residue.trailing-bytes"},
                            {"anomalyType", "TRAILING_BYTES"},
                            {"strength", evidenceStrengthLabel(strength)},
                            {"areaContext", area.context},
                            {"trailingBytesCount", prop.trailingBytesCount},
                            {"trailingSnippet", prop.trailingBytesSnippet},
                            {"detail", detail.str()},
                        });
                    }
                }
            }
        }

        payload["parsedAreaCount"] = parsedAreaCount;
        payload["totalPropertiesInspected"] = totalPropertiesInspected;
        payload["serialAnomalyCount"] = serialAnomalyCount;
        payload["trailingResidueCount"] = trailingResidueCount;
        payload["readOnlyTrailingResidueCount"] = readOnlyTrailingResidueCount;
        // Residue on writable properties is ordinary bionic behaviour, recorded so the
        // ratio is visible rather than silently dropped.
        payload["writableTrailingResidueCount"] =
            trailingResidueCount - readOnlyTrailingResidueCount;

        // Names only, never values: a rewritten ro.* property name is the diagnostic
        // fact, and the value may carry an identifier.
        for (const auto& finding : payload["findings"]) {
            if (finding.value("unitId", std::string()) ==
                "system-property-residue.serial-anomaly") {
                LOGI_TAG("PropertyAreaResidue", "event=serial_anomaly property=%s type=%s strength=%s",
                         finding.value("property", std::string()).c_str(),
                         finding.value("anomalyType", std::string()).c_str(),
                         finding.value("strength", std::string()).c_str());
            }
        }

        LOGI_TAG("PropertyAreaResidue",
                 "areasParsed=%d totalProps=%zu serialAnomalies=%d trailingResidues=%d "
                 "roTrailingResidues=%d strongest=%s",
                 parsedAreaCount, totalPropertiesInspected, serialAnomalyCount,
                 trailingResidueCount, readOnlyTrailingResidueCount,
                 evidenceStrengthLabel(strongestFinding));

        if (parsedAreaCount == 0) {
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        DetectionAssessment assessment = (strongestFinding != EvidenceStrength::NONE)
                                             ? DetectionAssessment{DetectionOutcome::OBSERVED, strongestFinding}
                                             : DetectionAssessment::notObserved();

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "PROPERTY_AREA_RESIDUE"; }
};

REGISTER_DETECTION(PropertyAreaResidueDetection);

}  // namespace tamperprobe
