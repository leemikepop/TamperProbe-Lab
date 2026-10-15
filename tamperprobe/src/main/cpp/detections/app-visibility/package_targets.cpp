#include "package_targets.h"

#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>

#include <sstream>

#include "../../common/log.h"

namespace tamperprobe {
namespace {

constexpr const char* kPackageIndicatorsAsset = "tamperprobe/package_indicators.txt";
constexpr const char* kPackageIntentActionsAsset = "tamperprobe/package_intent_actions.txt";

bool readAssetText(const DetectionContext& context, const char* assetPath, std::string& content) {
    if (context.env == nullptr || context.androidContext == nullptr) return false;

    JNIEnv* env = context.env;
    jclass contextClass = env->GetObjectClass(context.androidContext);
    if (contextClass == nullptr) {
        env->ExceptionClear();
        LOGE_TAG("PackageTargets", "event=context_class_lookup_failed asset=%s", assetPath);
        return false;
    }

    jmethodID getAssets =
        env->GetMethodID(contextClass, "getAssets", "()Landroid/content/res/AssetManager;");
    if (getAssets == nullptr) {
        env->ExceptionClear();
        env->DeleteLocalRef(contextClass);
        LOGE_TAG("PackageTargets", "event=get_assets_lookup_failed asset=%s", assetPath);
        return false;
    }

    jobject javaAssetManager = env->CallObjectMethod(context.androidContext, getAssets);
    env->DeleteLocalRef(contextClass);
    if (env->ExceptionCheck() || javaAssetManager == nullptr) {
        env->ExceptionClear();
        if (javaAssetManager != nullptr) env->DeleteLocalRef(javaAssetManager);
        LOGE_TAG("PackageTargets", "event=get_assets_failed asset=%s", assetPath);
        return false;
    }

    AAssetManager* assetManager = AAssetManager_fromJava(env, javaAssetManager);
    if (assetManager == nullptr) {
        env->DeleteLocalRef(javaAssetManager);
        LOGE_TAG("PackageTargets", "event=native_asset_manager_failed asset=%s", assetPath);
        return false;
    }

    AAsset* asset = AAssetManager_open(assetManager, assetPath, AASSET_MODE_STREAMING);
    if (asset == nullptr) {
        env->DeleteLocalRef(javaAssetManager);
        LOGE_TAG("PackageTargets", "event=asset_open_failed asset=%s", assetPath);
        return false;
    }

    char buffer[4096];
    int bytesRead = 0;
    while ((bytesRead = AAsset_read(asset, buffer, sizeof(buffer))) > 0) {
        content.append(buffer, static_cast<std::size_t>(bytesRead));
    }
    AAsset_close(asset);
    env->DeleteLocalRef(javaAssetManager);
    if (bytesRead < 0) {
        content.clear();
        LOGE_TAG("PackageTargets", "event=asset_read_failed asset=%s", assetPath);
        return false;
    }
    return true;
}

std::vector<std::string> splitLines(const std::string& value) {
    std::vector<std::string> result;
    std::stringstream stream(value);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) result.push_back(line);
    }
    return result;
}

}  // namespace

bool collectTargetPackageNames(const DetectionContext& context, std::vector<std::string>& targetPackageNames) {
    std::string content;
    if (!readAssetText(context, kPackageIndicatorsAsset, content)) return false;
    const auto parsed = splitLines(content);
    targetPackageNames.insert(targetPackageNames.end(), parsed.begin(), parsed.end());
    return !targetPackageNames.empty();
}

bool collectPackageIntentRules(const DetectionContext& context, std::vector<PackageIntentRule>& intentRules) {
    std::string content;
    if (!readAssetText(context, kPackageIntentActionsAsset, content)) return false;

    for (const auto& line : splitLines(content)) {
        const std::size_t separator = line.find('\t');
        if (separator == std::string::npos || separator == 0 || separator + 1 >= line.size()) {
            LOGE_TAG("PackageTargets", "event=intent_rule_malformed");
            return false;
        }
        intentRules.push_back({line.substr(0, separator), line.substr(separator + 1)});
    }
    return true;
}

}  // namespace tamperprobe
