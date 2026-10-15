#ifndef TAMPERPROBE_LOG_H
#define TAMPERPROBE_LOG_H

#include <android/log.h>

// One Logcat tag across SDK, native engine, sample app, and RASP.
#define LOG_TAG "TamperProbe"

// Log macros for different log levels
#define LOGV(format, ...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, "component=Native " format, ##__VA_ARGS__)
#define LOGD(format, ...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "component=Native " format, ##__VA_ARGS__)
#define LOGI(format, ...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "component=Native " format, ##__VA_ARGS__)
#define LOGW(format, ...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, "component=Native " format, ##__VA_ARGS__)
#define LOGE(format, ...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "component=Native " format, ##__VA_ARGS__)
#define LOGF(format, ...) __android_log_print(ANDROID_LOG_FATAL, LOG_TAG, "component=Native " format, ##__VA_ARGS__)

// Log macros with custom tags
#define LOGV_TAG(component, format, ...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, "component=%s " format, component, ##__VA_ARGS__)
#define LOGD_TAG(component, format, ...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "component=%s " format, component, ##__VA_ARGS__)
#define LOGI_TAG(component, format, ...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "component=%s " format, component, ##__VA_ARGS__)
#define LOGW_TAG(component, format, ...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, "component=%s " format, component, ##__VA_ARGS__)
#define LOGE_TAG(component, format, ...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "component=%s " format, component, ##__VA_ARGS__)
#define LOGF_TAG(component, format, ...) __android_log_print(ANDROID_LOG_FATAL, LOG_TAG, "component=%s " format, component, ##__VA_ARGS__)

#endif //TAMPERPROBE_LOG_H
