#ifndef DETECTION_REGISTRY_H
#define DETECTION_REGISTRY_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "detection.h"

namespace tamperprobe {

class DetectionRegistry {
   public:
    static DetectionRegistry& getInstance();

    void registerDetection(std::unique_ptr<Detection> detection);

    const std::vector<std::unique_ptr<Detection>>& getAllDetections() const;

    Detection* getDetectionById(const std::string& id) const;

    size_t getDetectionCount() const;

   private:
    DetectionRegistry() = default;
    ~DetectionRegistry() = default;

    // Prevent copying and assignment
    DetectionRegistry(const DetectionRegistry&) = delete;
    DetectionRegistry& operator=(const DetectionRegistry&) = delete;

    std::vector<std::unique_ptr<Detection>> detections_;
    std::map<std::string, Detection*> detectionMap_;
};

/**
 * Helper class for automatic registration of Detection subclasses
 */
class DetectionRegistrar {
   public:
    DetectionRegistrar(std::unique_ptr<Detection> detection) {
        DetectionRegistry::getInstance().registerDetection(std::move(detection));
    }
};

/**
 * Macro for easy registration of Detection subclasses
 *
 * REGISTER_DETECTION(YourDetectionClassName);
 */
#define REGISTER_DETECTION(ClassName)                                                               \
    namespace {                                                                                     \
    static ::tamperprobe::DetectionRegistrar _registrar_##ClassName(std::make_unique<ClassName>()); \
    }

}  // namespace tamperprobe

#endif  // DETECTION_REGISTRY_H
