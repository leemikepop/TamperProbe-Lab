#include <cmath>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <unordered_set>
#include <vector>

#include <sched.h>
#include <unistd.h>
#include <EGL/egl.h>
#include <GLES2/gl2.h>

#include "../../common/io_utils.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

namespace tamperprobe {
namespace {

const char* strengthName(EvidenceStrength strength) {
    switch (strength) {
        case EvidenceStrength::WEAK: return "weak";
        case EvidenceStrength::MODERATE: return "moderate";
        case EvidenceStrength::STRONG: return "strong";
        case EvidenceStrength::NONE: return "none";
    }
    return "none";
}

struct EglProbeResult {
    bool available = false;
    std::string renderer;
    std::string vendor;
    std::string version;
    bool isEmulator = false;
    std::string matchedMarker;
    std::string errorMessage;
};

EglProbeResult probeOffscreenEglRenderer() {
    EglProbeResult result;
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (display == EGL_NO_DISPLAY) {
        result.errorMessage = "eglGetDisplay returned EGL_NO_DISPLAY";
        return result;
    }

    EGLint major = 0, minor = 0;
    if (!eglInitialize(display, &major, &minor)) {
        result.errorMessage = "eglInitialize failed";
        return result;
    }

    const EGLint configAttribs[] = {
        EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
        EGL_RED_SIZE, 8,
        EGL_GREEN_SIZE, 8,
        EGL_BLUE_SIZE, 8,
        EGL_NONE
    };

    EGLConfig config = nullptr;
    EGLint numConfigs = 0;
    if (!eglChooseConfig(display, configAttribs, &config, 1, &numConfigs) || numConfigs <= 0) {
        result.errorMessage = "eglChooseConfig failed to find a valid config";
        eglTerminate(display);
        return result;
    }

    const EGLint pbufferAttribs[] = {
        EGL_WIDTH, 1,
        EGL_HEIGHT, 1,
        EGL_NONE
    };

    EGLSurface surface = eglCreatePbufferSurface(display, config, pbufferAttribs);
    if (surface == EGL_NO_SURFACE) {
        result.errorMessage = "eglCreatePbufferSurface failed";
        eglTerminate(display);
        return result;
    }

    const EGLint contextAttribs[] = {
        EGL_CONTEXT_CLIENT_VERSION, 2,
        EGL_NONE
    };

    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, contextAttribs);
    if (context == EGL_NO_CONTEXT) {
        result.errorMessage = "eglCreateContext failed";
        eglDestroySurface(display, surface);
        eglTerminate(display);
        return result;
    }

    if (eglMakeCurrent(display, surface, surface, context)) {
        result.available = true;
        const auto* rendererStr = reinterpret_cast<const char*>(glGetString(GL_RENDERER));
        const auto* vendorStr = reinterpret_cast<const char*>(glGetString(GL_VENDOR));
        const auto* versionStr = reinterpret_cast<const char*>(glGetString(GL_VERSION));

        if (rendererStr != nullptr) result.renderer = rendererStr;
        if (vendorStr != nullptr) result.vendor = vendorStr;
        if (versionStr != nullptr) result.version = versionStr;

        static const char* kEmulatorRenderers[] = {
            "swiftshader",
            "llvmpipe",
            "mesa",
            "android emulator opengl es translator",
            "vmgl",
            "virtualbox",
            "vmware",
            "software rasterizer"
        };

        const std::string lowerRenderer = lowercase_copy(result.renderer);
        for (const auto* marker : kEmulatorRenderers) {
            if (lowerRenderer.find(marker) != std::string::npos) {
                result.isEmulator = true;
                result.matchedMarker = marker;
                break;
            }
        }

        eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    } else {
        result.errorMessage = "eglMakeCurrent failed";
    }

    eglDestroyContext(display, context);
    eglDestroySurface(display, surface);
    eglTerminate(display);
    return result;
}

struct TimerProbeResult {
    bool supported = false;
    uint64_t frequencyHz = 0;
    uint64_t counterDelta = 0;
    uint64_t counterNs = 0;
    uint64_t wallDeltaNs = 0;
    int64_t driftNs = 0;
    bool isAnomalous = false;
    std::string detail;
};

TimerProbeResult probeArmTimerRegisters() {
    TimerProbeResult result;
#if defined(__aarch64__)
    result.supported = true;
    uint64_t frq = 0;
    uint64_t vct_start = 0;
    uint64_t vct_end = 0;

    asm volatile("mrs %0, cntfrq_el0" : "=r"(frq));
    result.frequencyHz = frq;

    if (frq == 0) {
        result.isAnomalous = true;
        result.detail = "ARM64 cntfrq_el0 frequency is zero";
        return result;
    }

    struct timespec ts_start = {}, ts_end = {};
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    asm volatile("mrs %0, cntvct_el0" : "=r"(vct_start));

    for (int i = 0; i < 256; ++i) {
        volatile pid_t p = getpid();
        (void)p;
    }

    asm volatile("mrs %0, cntvct_el0" : "=r"(vct_end));
    clock_gettime(CLOCK_MONOTONIC, &ts_end);

    const uint64_t wallNs = (static_cast<uint64_t>(ts_end.tv_sec - ts_start.tv_sec) * 1000000000ULL) +
                            static_cast<uint64_t>(ts_end.tv_nsec - ts_start.tv_nsec);
    result.wallDeltaNs = wallNs;

    if (vct_end < vct_start) {
        result.isAnomalous = true;
        result.detail = "ARM64 cntvct_el0 counter rolled backwards";
        return result;
    }

    const uint64_t counterDelta = vct_end - vct_start;
    result.counterDelta = counterDelta;
    const uint64_t counterNs = (counterDelta * 1000000000ULL) / frq;
    result.counterNs = counterNs;

    const int64_t diff = static_cast<int64_t>(counterNs) - static_cast<int64_t>(wallNs);
    result.driftNs = diff;
    const int64_t absDiff = std::abs(diff);

    if (counterDelta == 0 || (wallNs >= 5000 && absDiff > static_cast<int64_t>((wallNs * 3) / 4))) {
        result.isAnomalous = true;
        result.detail = "ARM64 virtual counter drift vs CLOCK_MONOTONIC exceeds 75% threshold";
    }
#else
    result.supported = false;
    result.detail = "ARM64 hardware timer registers not supported on this CPU architecture";
#endif
    return result;
}

struct SchedJitterResult {
    int sampleCount = 0;
    double meanNs = 0.0;
    double stdDevNs = 0.0;
    double cv = 0.0;
    int uniqueMicrosecondBuckets = 0;
    bool isAnomalous = false;
    std::string detail;
};

SchedJitterResult probeSchedYieldJitter() {
    SchedJitterResult result;
    constexpr int kIterations = 32;
    std::vector<uint64_t> samples;
    samples.reserve(kIterations);
    std::unordered_set<uint64_t> uniqueBuckets;

    for (int i = 0; i < kIterations; ++i) {
        struct timespec t1 = {}, t2 = {};
        // The return value is checked deliberately. If the clock is unavailable this probe
        // must be able to report that it collected nothing; previously the failure was
        // ignored, sampleCount was always kIterations, and the detector's INCONCLUSIVE
        // branch -- which tests sampleCount == 0 -- was unreachable dead code.
        if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0) continue;
        sched_yield();
        if (clock_gettime(CLOCK_MONOTONIC, &t2) != 0) continue;
        const uint64_t elapsedNs = (static_cast<uint64_t>(t2.tv_sec - t1.tv_sec) * 1000000000ULL) +
                                   static_cast<uint64_t>(t2.tv_nsec - t1.tv_nsec);
        samples.push_back(elapsedNs);
        uniqueBuckets.insert(elapsedNs / 1000ULL);
    }

    result.sampleCount = static_cast<int>(samples.size());
    result.uniqueMicrosecondBuckets = static_cast<int>(uniqueBuckets.size());

    double sum = 0.0;
    for (uint64_t s : samples) sum += static_cast<double>(s);
    const double mean = sum / samples.size();
    result.meanNs = mean;

    double sumSqDiff = 0.0;
    for (uint64_t s : samples) {
        const double diff = static_cast<double>(s) - mean;
        sumSqDiff += diff * diff;
    }
    const double variance = sumSqDiff / samples.size();
    const double stdDev = std::sqrt(variance);
    result.stdDevNs = stdDev;

    const double cv = (mean > 0.0) ? (stdDev / mean) : 0.0;
    result.cv = cv;

    // An extremely low CV (< 0.03) and <= 2 unique microsecond latency buckets indicates a deterministic virtual scheduler
    if (cv < 0.03 && result.uniqueMicrosecondBuckets <= 2 && mean < 250000.0) {
        result.isAnomalous = true;
        result.detail = "Scheduling latency exhibits unnaturally low jitter characteristic of a virtual hypervisor";
    }

    return result;
}

}  // namespace

class EmulatorHardwareIndicatorsDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext&) override {
        const EglProbeResult egl = probeOffscreenEglRenderer();
        const TimerProbeResult timer = probeArmTimerRegisters();
        const SchedJitterResult sched = probeSchedYieldJitter();

        nlohmann::json payload = {
            {"overview", {
                {"findingCount", 0},
                {"strongFindingCount", 0},
                {"moderateFindingCount", 0},
                {"weakFindingCount", 0}
            }},
            {"egl", {
                {"available", egl.available},
                {"renderer", egl.renderer},
                {"vendor", egl.vendor},
                {"version", egl.version},
                {"isEmulator", egl.isEmulator},
                {"matchedMarker", egl.matchedMarker}
            }},
            {"timer", {
                {"supported", timer.supported},
                {"frequencyHz", timer.frequencyHz},
                {"counterDelta", timer.counterDelta},
                {"counterNs", timer.counterNs},
                {"wallDeltaNs", timer.wallDeltaNs},
                {"driftNs", timer.driftNs},
                {"isAnomalous", timer.isAnomalous},
                {"detail", timer.detail}
            }},
            {"schedJitter", {
                {"sampleCount", sched.sampleCount},
                {"meanNs", sched.meanNs},
                {"stdDevNs", sched.stdDevNs},
                {"cv", sched.cv},
                {"uniqueMicrosecondBuckets", sched.uniqueMicrosecondBuckets},
                {"isAnomalous", sched.isAnomalous},
                {"detail", sched.detail}
            }},
            {"findings", nlohmann::json::array()},
            {"collectionErrors", nlohmann::json::array()}
        };

        // Honest availability. Each probe backs one evidence unit, and a probe that could
        // not run has not produced a clean answer -- it has produced no answer. Recording the
        // unavailable channel marks that unit PARTIAL instead of letting it read as clean.
        if (!egl.available) {
            payload["collectionErrors"].push_back({
                {"source", "egl"},
                {"message", egl.errorMessage.empty()
                                ? "An offscreen EGL context could not be created, so the "
                                  "renderer string could not be inspected."
                                : egl.errorMessage}
            });
        }
        if (!timer.supported) {
            payload["collectionErrors"].push_back({
                {"source", "timer"},
                {"message", timer.detail.empty()
                                ? "The ARM64 virtual counter registers are unavailable on this "
                                  "CPU, so timer deviation could not be measured."
                                : timer.detail}
            });
        }
        if (sched.sampleCount == 0) {
            payload["collectionErrors"].push_back({
                {"source", "sched"},
                {"message", "No scheduler yield samples could be collected."}
            });
        }

        int strongCount = 0;
        int moderateCount = 0;
        int weakCount = 0;

        if (egl.isEmulator) {
            ++strongCount;
            payload["findings"].push_back({
                {"id", "egl_renderer_indicator"},
                {"unitId", "emulator-hardware.egl-renderer"},
                {"strength", strengthName(EvidenceStrength::STRONG)},
                {"summary", "Offscreen OpenGL ES renderer identifies an emulator or virtual driver"},
                {"detail", "Matched emulator renderer marker: " + egl.matchedMarker + " in GL_RENDERER: " + egl.renderer}
            });
        }

        if (timer.isAnomalous) {
            ++moderateCount;
            payload["findings"].push_back({
                {"id", "timer_register_deviation"},
                {"unitId", "emulator-hardware.timer-register-deviation"},
                {"strength", strengthName(EvidenceStrength::MODERATE)},
                {"summary", "ARM64 virtual counter frequency or drift deviates from monotonic clock"},
                {"detail", timer.detail}
            });
        }

        if (sched.isAnomalous) {
            ++weakCount;
            payload["findings"].push_back({
                {"id", "sched_jitter_anomaly"},
                {"unitId", "emulator-hardware.sched-jitter"},
                {"strength", strengthName(EvidenceStrength::WEAK)},
                {"summary", "Scheduler yield latency shows deterministic virtual hypervisor timing"},
                {"detail", sched.detail}
            });
        }

        const int totalFindings = strongCount + moderateCount + weakCount;
        payload["overview"]["findingCount"] = totalFindings;
        payload["overview"]["strongFindingCount"] = strongCount;
        payload["overview"]["moderateFindingCount"] = moderateCount;
        payload["overview"]["weakFindingCount"] = weakCount;

        DetectionAssessment assessment = DetectionAssessment::notObserved();
        if (strongCount > 0) {
            assessment = DetectionAssessment::strongObserved();
        } else if (moderateCount > 0) {
            assessment = DetectionAssessment::moderateObserved();
        } else if (weakCount > 0) {
            assessment = DetectionAssessment::weakObserved();
        } else if (!egl.available && !timer.supported && sched.sampleCount == 0) {
            assessment = DetectionAssessment::inconclusive();
        }

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "EMULATOR_HARDWARE_INDICATORS"; }
};

REGISTER_DETECTION(EmulatorHardwareIndicatorsDetection);

}  // namespace tamperprobe
