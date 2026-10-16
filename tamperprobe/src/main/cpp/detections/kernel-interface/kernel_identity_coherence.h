#ifndef TAMPERPROBE_KERNEL_IDENTITY_COHERENCE_H
#define TAMPERPROBE_KERNEL_IDENTITY_COHERENCE_H

#include <string>
#include <vector>

#include "../../core/detection_result.h"

namespace tamperprobe {
namespace kernel_identity {

// One place the process can read the running kernel's release string from. An empty value
// (after trimming) means the source was unreadable; it never takes part in a comparison.
struct ReleaseSource {
    std::string id;
    std::string value;
};

enum class CoherenceState {
    UNAVAILABLE,  // fewer than two readable sources: nothing was compared
    AGREE,        // every readable source reports the same release
    DISAGREE,     // at least two readable sources report different releases
};

struct CoherenceResult {
    CoherenceState state = CoherenceState::UNAVAILABLE;
    std::vector<std::string> readableSourceIds;
    std::vector<std::string> unreadableSourceIds;
    std::vector<std::string> distinctReleases;  // first-seen order
};

// Pure comparison of the release strings, without any I/O, so the native fixtures can drive it.
// Values are compared after trimming surrounding whitespace and nothing else: the kernel copies
// one utsname release into every source, so any other difference is a real disagreement.
CoherenceResult compareReleases(const std::vector<ReleaseSource>& sources);

// "Linux version <release> (builder@host) ..." -> "<release>". Anything without that exact
// prefix yields an empty string (unreadable), so a truncated or reformatted banner cannot
// invent a disagreement on its own.
std::string parseProcVersionRelease(const std::string& procVersion);

const char* coherenceStateName(CoherenceState state);

struct KernelCheckAssessmentInput {
    int postureHitCount = 0;  // integrity-posture findings (banner, cmdline, kptr, symbols)
    CoherenceState coherence = CoherenceState::UNAVAILABLE;
    bool anyPostureSourceReadable = false;  // uname, /proc/version, cmdline or kallsyms
};

// KERNEL_CHECK's detector-level rule. Posture hits keep their existing grading (two or more
// STRONG, one MODERATE). A coherence disagreement is MODERATE on its own and raises a weaker
// result to MODERATE; it never makes the result STRONG by itself. With no hit, a detector that
// read nothing at all is INCONCLUSIVE; otherwise it is NOT_OBSERVED, which may rest only on
// concealable negatives (the payload lists them).
DetectionAssessment assessKernelCheck(const KernelCheckAssessmentInput& input);

}  // namespace kernel_identity
}  // namespace tamperprobe

#endif  // TAMPERPROBE_KERNEL_IDENTITY_COHERENCE_H
