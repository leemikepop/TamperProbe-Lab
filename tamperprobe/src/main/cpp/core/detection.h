#ifndef DETECTION_BASE_H
#define DETECTION_BASE_H

#include <jni.h>

#include <string>

#include "detection_result.h"

namespace tamperprobe {

struct DetectionContext {
    JNIEnv* env;
    jobject androidContext;
    const std::string& filesDir;
    const std::string& policyOracleSnapshot;
    const std::string& fdForensicsSnapshot;
};

class Detection {
   public:
    virtual ~Detection() = default;

    virtual DetectionResult execute(const DetectionContext& context) = 0;

    virtual const char* getId() const = 0;
};

}  // namespace tamperprobe

#endif  // DETECTION_BASE_H
