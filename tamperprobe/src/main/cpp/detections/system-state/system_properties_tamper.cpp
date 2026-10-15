#include <cstdio>
#include <cstring>
#include <map>
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
#include "property_detector_logic.h"
#include "property_observation.h"

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

constexpr std::size_t kMaxReportedPropertyAreas = 16;
constexpr std::size_t kMaxReportedRanges = 8;

EvidenceStrength strongerOf(EvidenceStrength left, EvidenceStrength right) {
    return static_cast<int>(left) >= static_cast<int>(right) ? left : right;
}

// The outcome is carried by the strongest graded finding rather than by a count of
// mismatches. A disagreement that never crossed a trust boundary is telemetry, not
// a reason to assert tampering.
DetectionAssessment aggregateAssessment(EvidenceStrength strongestFinding,
                                        bool sourceConsistencyAvailable,
                                        bool areaLayoutAvailable) {
    if (strongestFinding != EvidenceStrength::NONE) {
        return {DetectionOutcome::OBSERVED, strongestFinding};
    }
    if (!sourceConsistencyAvailable && !areaLayoutAvailable) {
        return DetectionAssessment::inconclusive();
    }
    return DetectionAssessment::notObserved();
}

}  // namespace

class SystemPropertiesTamperDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        const PropertySourceSnapshot snapshot = observeAllEquivalentPropertySources(
            scanContext.env, securityPropertyKeys());
        const auto comparisons = compareEquivalentPropertySources(
            securityPropertyKeys(), snapshot.observations);

        nlohmann::json payload = {
            {"sources", nlohmann::json::array()},
            {"comparisons", nlohmann::json::array()},
            {"propertyAreas", nlohmann::json::array()},
            {"findings", nlohmann::json::array()},
            {"collectionErrors", nlohmann::json::array()},
        };

        EvidenceStrength strongestFinding = EvidenceStrength::NONE;
        std::set<std::string> collectionErrorDedupe;
        for (const auto& observation : snapshot.observations) {
            nlohmann::json source = {
                {"property", observation.property},
                {"source", observation.source},
                {"state", propertyObservationStateName(observation.state)},
            };
            if (observation.state == PropertyObservationState::PRESENT) {
                source["value"] = observation.value;
            }
            if (!observation.error.empty()) source["error"] = observation.error;
            if (observation.errorNumber != 0) source["errno"] = observation.errorNumber;
            payload["sources"].push_back(std::move(source));

            if (observation.state == PropertyObservationState::UNAVAILABLE) {
                const std::string key = observation.source + '\n' + observation.error + '\n' +
                                        std::to_string(observation.errorNumber);
                if (collectionErrorDedupe.insert(key).second) {
                    payload["collectionErrors"].push_back(
                        {{"source", observation.source},
                         {"property", observation.property},
                         {"errno", observation.errorNumber},
                         {"message", observation.error}});
                }
            }
        }

        bool parsedAreaAvailable = false;
        int parsedAreaCount = 0;
        int unreferencedHoleCount = 0;
        for (const auto& area : snapshot.propertyAreas) {
            nlohmann::json areaPayload = {
                {"path", area.path},
                {"context", area.context},
                {"status", propertyAreaStatusName(area.status)},
                {"magic", area.magic},
                {"version", area.version},
                {"bytesUsed", area.bytesUsed},
                {"referencedBytes", area.referencedBytes},
                {"unreferencedBytes", area.unreferencedBytes},
                {"unreferencedRanges", nlohmann::json::array()},
            };
            for (const auto& range : area.unreferencedRanges) {
                if (areaPayload["unreferencedRanges"].size() >= kMaxReportedRanges) break;
                areaPayload["unreferencedRanges"].push_back(
                    {{"offset", range.offset}, {"length", range.length}});
            }
            if (!area.error.empty()) areaPayload["error"] = area.error;
            if (area.errorNumber != 0) areaPayload["errno"] = area.errorNumber;
            // A device maps dozens of context areas and almost all of them are
            // unremarkable. Only areas that failed to parse or that carry orphaned
            // allocations are published; the rest are covered by the counts in
            // areaSummary, which keeps the payload small enough to ship.
            const bool notable = area.status != PropertyAreaStatus::PARSED ||
                                 area.unreferencedBytes > 0;
            if (notable && payload["propertyAreas"].size() < kMaxReportedPropertyAreas) {
                payload["propertyAreas"].push_back(std::move(areaPayload));
            }

            if (area.status == PropertyAreaStatus::PARSED) {
                parsedAreaAvailable = true;
                ++parsedAreaCount;
                if (area.unreferencedBytes > 0 && !area.unreferencedRanges.empty()) {
                    unreferencedHoleCount++;
                    strongestFinding = strongerOf(strongestFinding, EvidenceStrength::STRONG);
                    std::ostringstream detail;
                    detail << "Property area " << area.path << " contains " << area.unreferencedBytes
                           << " unreferenced allocated bytes across " << area.unreferencedRanges.size()
                           << " range(s) (orphaned Trie nodes).";
                    payload["findings"].push_back(
                        {{"id", "prop_area_unreferenced_hole"},
                         {"property", area.path},
                         {"strength", "strong"},
                         {"summary", "Property area contains unreferenced allocated byte ranges (Trie hole)"},
                         {"detail", detail.str()},
                         {"sources", nlohmann::json::array({area.path})},
                         {"values", nlohmann::json::array({std::to_string(area.unreferencedBytes)})}});
                }
            } else {
                const std::string key = area.path + '\n' + area.error;
                if (collectionErrorDedupe.insert(key).second) {
                    payload["collectionErrors"].push_back(
                        {{"source", "property_area"},
                         {"path", area.path},
                         {"errno", area.errorNumber},
                         {"message", area.error}});
                }
            }
        }

        bool validComparisonAvailable = false;
        int mismatchCount = 0;
        for (const auto& comparison : comparisons) {
            validComparisonAvailable = validComparisonAvailable || comparison.comparable;
            payload["comparisons"].push_back(
                {{"property", comparison.property},
                 {"availableSourceCount", comparison.availableSourceCount},
                 {"distinctValueCount", comparison.distinctValueCount},
                 {"comparable", comparison.comparable},
                 {"mismatch", comparison.mismatch},
                 {"strength", evidenceStrengthLabel(comparison.strength)},
                 {"outlierSources", comparison.outlierSources},
                 {"majorityValue", comparison.majorityValue},
                 {"sources", comparison.sources},
                 {"values", comparison.values}});
            if (!comparison.mismatch) continue;

            ++mismatchCount;
            strongestFinding = strongerOf(strongestFinding, comparison.strength);
            std::ostringstream detail;
            detail << comparison.rationale << " Sources for " << comparison.property << ':';
            for (std::size_t index = 0; index < comparison.sources.size(); ++index) {
                detail << ' ' << comparison.sources[index] << '=' << comparison.values[index];
            }
            payload["findings"].push_back(
                {{"id", comparison.findingId},
                 {"property", comparison.property},
                 {"strength", evidenceStrengthLabel(comparison.strength)},
                 {"summary", "Equivalent Android property sources disagree"},
                 {"detail", detail.str()},
                 {"outlierSources", comparison.outlierSources},
                 {"sources", comparison.sources},
                 {"values", comparison.values}});
        }

        payload["areaSummary"] = {{"discoveredAreaCount", snapshot.propertyAreas.size()},
                                  {"parsedAreaCount", parsedAreaCount},
                                  {"unreferencedHoleAreaCount", unreferencedHoleCount},
                                  {"reportedAreaCount", payload["propertyAreas"].size()}};

        payload["overview"] = {{"comparedPropertyCount", comparisons.size()},
                               {"mismatchCount", mismatchCount},
                               {"unreferencedHoleCount", unreferencedHoleCount},
                               {"strongestFinding", evidenceStrengthLabel(strongestFinding)}};

        std::map<std::string, int> presentBySource;
        for (const auto& observation : snapshot.observations) {
            if (observation.state == PropertyObservationState::PRESENT) {
                ++presentBySource[observation.source];
            }
        }
        std::ostringstream sourceSummary;
        for (const auto& entry : presentBySource) {
            if (sourceSummary.tellp() > 0) sourceSummary << ',';
            sourceSummary << entry.first << ':' << entry.second;
        }
        LOGI_TAG("SystemProperties",
                 "event=property_source_crosscheck comparedProperties=%d mismatches=%d "
                 "strongest=%s areasParsed=%d/%d presentBySource=%s",
                 static_cast<int>(comparisons.size()), mismatchCount,
                 evidenceStrengthLabel(strongestFinding), parsedAreaCount,
                 static_cast<int>(snapshot.propertyAreas.size()), sourceSummary.str().c_str());

        const DetectionAssessment assessment = aggregateAssessment(
            strongestFinding, validComparisonAvailable, parsedAreaAvailable);
        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "SYSTEM_PROPERTIES_TAMPER"; }
};

REGISTER_DETECTION(SystemPropertiesTamperDetection);

}  // namespace tamperprobe
