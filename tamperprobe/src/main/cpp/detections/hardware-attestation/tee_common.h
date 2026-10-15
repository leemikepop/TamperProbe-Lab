#ifndef TAMPERPROBE_TEE_KEYSTORE_COMMON_H
#define TAMPERPROBE_TEE_KEYSTORE_COMMON_H

#include <jni.h>

#include <string>

namespace tamperprobe {
namespace tee_common {

struct CollectorResult {
    bool invoked = false;
    std::string json;
    std::string error;
};

CollectorResult collectAttestation(JNIEnv* env, jobject context, const char* logTag);
CollectorResult checkOversizedChallenge(JNIEnv* env, jobject context, int challengeSize,
                                         const char* logTag);
CollectorResult collectKeystoreConsistency(JNIEnv* env, jobject context, const char* logTag);

}  // namespace tee_common
}  // namespace tamperprobe

#endif  // TAMPERPROBE_TEE_KEYSTORE_COMMON_H
