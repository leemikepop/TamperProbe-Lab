#include "detection_registry.h"

namespace tamperprobe {

DetectionRegistry& DetectionRegistry::getInstance() {
    static DetectionRegistry instance;
    return instance;
}

void DetectionRegistry::registerDetection(std::unique_ptr<Detection> detection) {
    if (!detection) {
        return;
    }

    detectionMap_[detection->getId()] = detection.get();
    detections_.push_back(std::move(detection));
}

const std::vector<std::unique_ptr<Detection>>& DetectionRegistry::getAllDetections() const {
    return detections_;
}

Detection* DetectionRegistry::getDetectionById(const std::string& id) const {
    auto it = detectionMap_.find(id);
    return (it != detectionMap_.end()) ? it->second : nullptr;
}

size_t DetectionRegistry::getDetectionCount() const {
    return detections_.size();
}

}  // namespace tamperprobe
