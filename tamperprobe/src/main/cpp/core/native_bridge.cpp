#include <jni.h>

#include <chrono>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/log.h"
#include "detection_registry.h"
#include "nlohmann/json.hpp"

namespace {

constexpr const char* kTag = "NativeBridge";
constexpr int kWireSchemaVersion = TAMPERPROBE_WIRE_SCHEMA_VERSION;
constexpr const char* kEngineVersion = TAMPERPROBE_ENGINE_VERSION;
constexpr const char* kCatalogVersion = TAMPERPROBE_CATALOG_VERSION;

std::string toString(JNIEnv* env, jstring value) {
    if (value == nullptr) return {};
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) return {};
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    return result;
}

std::set<std::string> toDetectorIds(JNIEnv* env, jobjectArray values) {
    std::set<std::string> ids;
    if (values == nullptr) return ids;

    const jsize count = env->GetArrayLength(values);
    for (jsize index = 0; index < count; ++index) {
        auto value = static_cast<jstring>(env->GetObjectArrayElement(values, index));
        std::string id = toString(env, value);
        if (value != nullptr) env->DeleteLocalRef(value);
        if (!id.empty()) ids.insert(std::move(id));
    }
    return ids;
}

std::string toByteString(JNIEnv* env, jbyteArray value) {
    if (value == nullptr) return {};
    const jsize length = env->GetArrayLength(value);
    if (length <= 0) return {};
    std::string result(static_cast<std::size_t>(length), '\0');
    env->GetByteArrayRegion(value, 0, length, reinterpret_cast<jbyte*>(result.data()));
    return result;
}

jbyteArray toByteArray(JNIEnv* env, const std::string& value) {
    auto result = env->NewByteArray(static_cast<jsize>(value.size()));
    if (result == nullptr || value.empty()) return result;
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(value.size()),
                            reinterpret_cast<const jbyte*>(value.data()));
    return result;
}

long long elapsedMicros(const std::chrono::steady_clock::time_point& startedAt) {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::steady_clock::now() - startedAt)
        .count();
}

nlohmann::json baseEnvelope() {
    return {{"schemaVersion", kWireSchemaVersion},
            {"engineVersion", kEngineVersion},
            {"catalogVersion", kCatalogVersion},
            {"completion", "COMPLETE"},
            {"durationMicros", 0},
            {"results", nlohmann::json::array()},
            {"engineError", nullptr}};
}

nlohmann::json failedEnvelope(const std::string& code, const std::string& message) {
    auto envelope = baseEnvelope();
    envelope["completion"] = "FAILED";
    envelope["engineError"] = {{"code", code}, {"message", message}};
    return envelope;
}

nlohmann::json resultJson(const char* detectorId, const tamperprobe::DetectionResult& result,
                          long long durationMicros, bool& partial) {
    nlohmann::json payload = nlohmann::json::object();
    std::string collectionError;

    if (result.payload.empty()) {
        collectionError = "Detector returned an empty payload";
    } else {
        payload = nlohmann::json::parse(result.payload, nullptr, false);
        if (payload.is_discarded() || !payload.is_object()) {
            payload = {{"rawPayload", result.payload}};
            collectionError = "Detector returned a malformed payload";
        } else if (payload.contains("collectionError") && payload["collectionError"].is_string()) {
            collectionError = payload["collectionError"].get<std::string>();
        }
    }

    if (!collectionError.empty()) partial = true;

    const auto outcome = collectionError.empty() ? result.outcome
                                                  : tamperprobe::DetectionOutcome::FAILED;
    const auto strength = collectionError.empty() ? result.evidenceStrength
                                                   : tamperprobe::EvidenceStrength::NONE;
    return {{"detectorId",       detectorId},
            {"outcome",          tamperprobe::detectionOutcomeName(outcome)},
            {"evidenceStrength", tamperprobe::evidenceStrengthName(strength)},
            {"durationMicros",   durationMicros},
            {"payload",          payload},
            {"collectionError", collectionError.empty() ? nlohmann::json(nullptr)
                                                          : nlohmann::json(collectionError)}};
}

nlohmann::json performScan(JNIEnv* env, jobject androidContext, const std::string& filesDir,
                           const std::set<std::string>& detectorIds,
                           const std::string& policyOracleSnapshot,
                           const std::string& fdForensicsSnapshot) {
    const auto scanStartedAt = std::chrono::steady_clock::now();
    if (androidContext == nullptr) {
        return failedEnvelope("INVALID_CONTEXT", "Android context is required");
    }
    if (filesDir.empty()) {
        return failedEnvelope("INVALID_FILES_DIR", "Application files directory is required");
    }
    if (detectorIds.empty()) {
        return failedEnvelope("EMPTY_SELECTION", "At least one detector must be selected");
    }

    auto& registry = tamperprobe::DetectionRegistry::getInstance();
    for (const auto& id : detectorIds) {
        if (registry.getDetectionById(id) == nullptr) {
            return failedEnvelope("UNKNOWN_DETECTOR", "Unknown detector ID: " + id);
        }
    }

    auto envelope = baseEnvelope();
    bool partial = false;
    const tamperprobe::DetectionContext context{
        env, androidContext, filesDir, policyOracleSnapshot, fdForensicsSnapshot};
    LOGI_TAG(kTag, "event=scan_start selectedCount=%zu engineVersion=%s catalogVersion=%s",
             detectorIds.size(), kEngineVersion, kCatalogVersion);

    for (const auto& detection : registry.getAllDetections()) {
        const char* detectorId = detection->getId();
        if (detectorIds.find(detectorId) == detectorIds.end()) continue;

        // Bracket execute() alone. Everything outside this pair - envelope assembly,
        // payload parsing, the JNI hop - is scan overhead rather than detector cost, and
        // the difference between the sum of these and the envelope duration is exactly
        // that overhead, which is worth being able to see.
        const auto detectorStartedAt = std::chrono::steady_clock::now();
        try {
            tamperprobe::DetectionResult result = detection->execute(context);
            const long long detectorMicros = elapsedMicros(detectorStartedAt);
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
                throw std::runtime_error("Detector left a pending JNI exception");
            }
            envelope["results"].push_back(
                resultJson(detectorId, result, detectorMicros, partial));
            LOGI_TAG(kTag,
                     "event=detector_result detectorId=%s outcome=%s strength=%s payloadBytes=%zu "
                     "durationMicros=%lld",
                     detectorId, tamperprobe::detectionOutcomeName(result.outcome),
                     tamperprobe::evidenceStrengthName(result.evidenceStrength),
                     result.payload.size(), detectorMicros);
        } catch (const std::exception& error) {
            // A detector that failed still consumed time, and a timing table with holes
            // in it is the kind of thing that gets misread later.
            const long long detectorMicros = elapsedMicros(detectorStartedAt);
            partial = true;
            envelope["results"].push_back(
                {{"detectorId", detectorId},
                 {"outcome", "FAILED"},
                 {"evidenceStrength", "NONE"},
                 {"durationMicros", detectorMicros},
                 {"payload", nlohmann::json::object()},
                 {"collectionError", std::string("Detector execution failed: ") + error.what()}});
            LOGE_TAG(kTag, "event=detector_failed detectorId=%s durationMicros=%lld error=%s",
                     detectorId, detectorMicros, error.what());
        } catch (...) {
            const long long detectorMicros = elapsedMicros(detectorStartedAt);
            partial = true;
            envelope["results"].push_back(
                {{"detectorId", detectorId},
                 {"outcome", "FAILED"},
                 {"evidenceStrength", "NONE"},
                 {"durationMicros", detectorMicros},
                 {"payload", nlohmann::json::object()},
                 {"collectionError", "Detector execution failed with an unknown error"}});
            LOGE_TAG(kTag, "event=detector_failed detectorId=%s durationMicros=%lld error=unknown",
                     detectorId, detectorMicros);
        }
    }

    envelope["completion"] = partial ? "PARTIAL" : "COMPLETE";
    const long long scanMicros = elapsedMicros(scanStartedAt);
    envelope["durationMicros"] = scanMicros;
    LOGI_TAG(kTag, "event=scan_complete completion=%s resultCount=%zu durationMicros=%lld",
             partial ? "PARTIAL" : "COMPLETE", envelope["results"].size(), scanMicros);
    return envelope;
}

}  // namespace

extern "C" JNIEXPORT jbyteArray JNICALL
Java_io_leemikepop_tamperprobe_lab_lib_core_NativeBridge_performScan(
    JNIEnv* env, jobject /* this */, jobject androidContext, jstring filesDirValue,
    jobjectArray detectorIdValues, jbyteArray policyOracleSnapshotValue,
    jbyteArray fdForensicsSnapshotValue) {
    try {
        const std::string filesDir = toString(env, filesDirValue);
        const std::set<std::string> detectorIds = toDetectorIds(env, detectorIdValues);
        const std::string policyOracleSnapshot = toByteString(env, policyOracleSnapshotValue);
        const std::string fdForensicsSnapshot = toByteString(env, fdForensicsSnapshotValue);
        const auto envelope = performScan(
            env, androidContext, filesDir, detectorIds, policyOracleSnapshot,
            fdForensicsSnapshot);
        return toByteArray(env, envelope.dump());
    } catch (const std::exception& error) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return toByteArray(env, failedEnvelope("ENGINE_EXCEPTION", error.what()).dump());
    } catch (...) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return toByteArray(env, failedEnvelope("ENGINE_EXCEPTION", "Unknown native engine failure").dump());
    }
}
