#include "kernel_identity_coherence.h"

#include <algorithm>
#include <cctype>

#include "../../common/io_utils.h"

namespace tamperprobe {
namespace kernel_identity {

CoherenceResult compareReleases(const std::vector<ReleaseSource>& sources) {
    CoherenceResult result;
    for (const ReleaseSource& source : sources) {
        const std::string value = trim_copy(source.value);
        if (value.empty()) {
            result.unreadableSourceIds.push_back(source.id);
            continue;
        }
        result.readableSourceIds.push_back(source.id);
        if (std::find(result.distinctReleases.begin(), result.distinctReleases.end(), value) ==
            result.distinctReleases.end()) {
            result.distinctReleases.push_back(value);
        }
    }
    if (result.readableSourceIds.size() < 2) {
        result.state = CoherenceState::UNAVAILABLE;
    } else if (result.distinctReleases.size() > 1) {
        result.state = CoherenceState::DISAGREE;
    } else {
        result.state = CoherenceState::AGREE;
    }
    return result;
}

std::string parseProcVersionRelease(const std::string& procVersion) {
    std::vector<std::string> tokens;
    size_t index = 0;
    while (index < procVersion.size() && tokens.size() < 3) {
        while (index < procVersion.size() &&
               std::isspace(static_cast<unsigned char>(procVersion[index]))) {
            index++;
        }
        const size_t start = index;
        while (index < procVersion.size() &&
               !std::isspace(static_cast<unsigned char>(procVersion[index]))) {
            index++;
        }
        if (index > start) tokens.push_back(procVersion.substr(start, index - start));
    }
    if (tokens.size() < 3 || tokens[0] != "Linux" || tokens[1] != "version") return {};
    return tokens[2];
}

DetectionAssessment assessKernelCheck(const KernelCheckAssessmentInput& input) {
    if (input.postureHitCount >= 2) return DetectionAssessment::strongObserved();
    if (input.postureHitCount > 0 || input.coherence == CoherenceState::DISAGREE) {
        return DetectionAssessment::moderateObserved();
    }
    if (!input.anyPostureSourceReadable && input.coherence != CoherenceState::AGREE) {
        return DetectionAssessment::inconclusive();
    }
    return DetectionAssessment::notObserved();
}

const char* coherenceStateName(CoherenceState state) {
    switch (state) {
        case CoherenceState::AGREE: return "agree";
        case CoherenceState::DISAGREE: return "disagree";
        case CoherenceState::UNAVAILABLE: return "unavailable";
    }
    return "unavailable";
}

}  // namespace kernel_identity
}  // namespace tamperprobe
