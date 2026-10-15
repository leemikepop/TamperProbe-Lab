#include "tee_common.h"

#include "../../common/jni_call.hpp"
#include "../../common/log.h"

namespace tamperprobe {
namespace tee_common {
namespace {

constexpr const char* kCollectorClass =
        "io/leemikepop/tamperprobe/lab/internal/tee/TeeKeystoreCollector";

CollectorResult callCollector(JNIEnv* env, jobject context, const char* method,
                              const char* signature, const char* logTag,
                              int integerArgument = -1) {
    CollectorResult result;
    if (env == nullptr || context == nullptr) {
        result.error = "JNI/Context not initialized";
        return result;
    }
    try {
        jni::ScopedLocalRef<jstring> encoded(
                env,
                integerArgument < 0
                        ? jni::CallStaticMethod<jstring>(
                                  env, kCollectorClass, method, signature, context)
                        : jni::CallStaticMethod<jstring>(
                                  env, kCollectorClass, method, signature, context,
                                  static_cast<jint>(integerArgument)));
        if (!encoded.get()) {
            result.error = "Keystore collector returned no data";
            return result;
        }
        result.invoked = true;
        result.json = jni::JStringToString(env, encoded.get());
        return result;
    } catch (const jni::JNIException& error) {
        LOGE_TAG(logTag, "component=tee_collector event=invoke_failed method=%s error=%s",
                 method, error.what());
        result.error = "Keystore collector invocation failed";
        return result;
    }
}

}  // namespace

CollectorResult collectAttestation(JNIEnv* env, jobject context, const char* logTag) {
    return callCollector(
            env, context, "collectAttestation",
            "(Landroid/content/Context;)Ljava/lang/String;", logTag);
}

CollectorResult checkOversizedChallenge(JNIEnv* env, jobject context, int challengeSize,
                                         const char* logTag) {
    return callCollector(
            env, context, "checkOversizedChallenge",
            "(Landroid/content/Context;I)Ljava/lang/String;", logTag, challengeSize);
}

CollectorResult collectKeystoreConsistency(JNIEnv* env, jobject context, const char* logTag) {
    return callCollector(
            env, context, "collectKeystoreConsistency",
            "(Landroid/content/Context;)Ljava/lang/String;", logTag);
}

}  // namespace tee_common
}  // namespace tamperprobe
