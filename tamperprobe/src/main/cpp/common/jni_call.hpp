// SPDX-License-Identifier: GPL-3.0-only
//
// The few JNI helpers the native detectors need to call a Java collector: a static call by class
// name that turns a pending Java exception into a C++ exception, a scoped local reference, and a
// jstring conversion.

#pragma once

#include <jni.h>

#include <stdexcept>
#include <string>
#include <type_traits>

namespace jni {

// Thrown after a JNI call left a Java exception pending. The Java exception is logged and cleared
// before this is thrown, so the caller can return normally.
class JNIException : public std::runtime_error {
public:
    explicit JNIException(const char* message) : std::runtime_error(message) {}
};

inline void ThrowIfExceptionPending(JNIEnv* env) {
    if (!env->ExceptionCheck()) return;
    env->ExceptionDescribe();
    env->ExceptionClear();
    throw JNIException("JNI exception occurred");
}

template <typename T>
class ScopedLocalRef {
public:
    ScopedLocalRef(JNIEnv* env, T ref) : env_(env), ref_(ref) {}
    ~ScopedLocalRef() {
        if (ref_ != nullptr) env_->DeleteLocalRef(ref_);
    }

    ScopedLocalRef(const ScopedLocalRef&) = delete;
    ScopedLocalRef& operator=(const ScopedLocalRef&) = delete;

    T get() const { return ref_; }

private:
    JNIEnv* env_;
    T ref_;
};

inline std::string JStringToString(JNIEnv* env, jstring value) {
    if (value == nullptr) return {};
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) return {};
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    return result;
}

inline jvalue ToJValue(jobject value) {
    jvalue result{};
    result.l = value;
    return result;
}

inline jvalue ToJValue(jint value) {
    jvalue result{};
    result.i = value;
    return result;
}

// Calls a static method that returns an object, such as a String. The returned local reference is
// owned by the caller.
template <typename R, typename... Args>
R CallStaticMethod(JNIEnv* env, const char* className, const char* methodName,
                   const char* signature, Args... args) {
    static_assert(std::is_convertible_v<R, jobject>, "only object-returning methods are supported");
    ScopedLocalRef<jclass> cls(env, env->FindClass(className));
    ThrowIfExceptionPending(env);
    jmethodID method = env->GetStaticMethodID(cls.get(), methodName, signature);
    ThrowIfExceptionPending(env);
    const jvalue values[sizeof...(Args) > 0 ? sizeof...(Args) : 1] = {ToJValue(args)...};
    R result = static_cast<R>(env->CallStaticObjectMethodA(cls.get(), method, values));
    ThrowIfExceptionPending(env);
    return result;
}

}  // namespace jni
