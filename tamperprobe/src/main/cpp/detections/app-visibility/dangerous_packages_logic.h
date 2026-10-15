#pragma once

#include <cerrno>

#include "../../core/detection_result.h"

namespace tamperprobe {

enum class PathProbeState {
    Exists,
    NotFound,
    Inaccessible,
    Error,
};

struct PathProbeResult {
    PathProbeState state;
    int errorCode;
};

inline PathProbeResult classifyPathProbeResult(int resultCode, int errorCode) {
    if (resultCode == 0) {
        return {PathProbeState::Exists, 0};
    }
    if (errorCode == ENOENT) {
        return {PathProbeState::NotFound, errorCode};
    }
    if (errorCode == EACCES || errorCode == EPERM) {
        return {PathProbeState::Inaccessible, errorCode};
    }
    return {PathProbeState::Error, errorCode};
}

inline DetectionAssessment aggregateDangerousPackageAssessment(
    bool packageIdentitySignal, bool appDataPathSignal,
    bool packageIdentityCollectionAvailable, bool appDataPathCollectionAvailable) {
    if (packageIdentitySignal || appDataPathSignal) {
        return DetectionAssessment::weakObserved();
    }
    if (!packageIdentityCollectionAvailable || !appDataPathCollectionAvailable) {
        return DetectionAssessment::inconclusive();
    }
    return DetectionAssessment::notObserved();
}

}  // namespace tamperprobe
