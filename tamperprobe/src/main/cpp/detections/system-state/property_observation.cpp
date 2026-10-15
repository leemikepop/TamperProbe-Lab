#include "property_observation.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/system_properties.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <map>
#include <string>
#include <utility>

namespace tamperprobe {
namespace {

using PropertyReadCallback = void (*)(void*, const char*, const char*, std::uint32_t);
using PropertyReadCallbackFunction = void (*)(const prop_info*, PropertyReadCallback, void*);

struct CallbackValue {
    bool called = false;
    std::string value;
};

void capturePropertyValue(void* cookie, const char*, const char* value, std::uint32_t) {
    auto* capture = static_cast<CallbackValue*>(cookie);
    capture->called = true;
    capture->value = value == nullptr ? std::string() : std::string(value);
}

PropertyReadCallbackFunction resolveReadCallback() {
    static PropertyReadCallbackFunction function = [] {
        void* symbol = dlsym(RTLD_DEFAULT, "__system_property_read_callback");
        return reinterpret_cast<PropertyReadCallbackFunction>(symbol);
    }();
    return function;
}

PropertyObservation unavailableObservation(const std::string& property,
                                           const std::string& source,
                                           std::string error, int errorNumber = 0) {
    return {property, source, PropertyObservationState::UNAVAILABLE, {},
            std::move(error), errorNumber};
}

std::vector<PropertyObservation> unavailableObservations(
    const std::vector<std::string>& keys, const std::string& source,
    const std::string& error, int errorNumber = 0) {
    std::vector<PropertyObservation> observations;
    observations.reserve(keys.size());
    for (const auto& key : keys) {
        observations.push_back(unavailableObservation(key, source, error, errorNumber));
    }
    return observations;
}

std::map<std::string, std::string> parseGetpropOutput(const std::string& output) {
    std::map<std::string, std::string> properties;
    std::size_t start = 0;
    while (start < output.size()) {
        const std::size_t end = output.find('\n', start);
        std::string line = output.substr(start, end == std::string::npos
                                                   ? std::string::npos
                                                   : end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.size() >= 6 && line.front() == '[' && line.back() == ']') {
            const std::size_t separator = line.find("]: [");
            if (separator != std::string::npos) {
                properties[line.substr(1, separator - 1)] =
                    line.substr(separator + 4, line.size() - separator - 5);
            }
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return properties;
}

struct ProcessOutput {
    bool available = false;
    std::string output;
    std::string error;
    int errorNumber = 0;
};

ProcessOutput runGetprop(int timeoutMilliseconds) {
    int descriptors[2];
#if defined(__ANDROID_API__) && __ANDROID_API__ >= 21
    if (pipe2(descriptors, O_CLOEXEC) != 0) {
#else
    if (pipe(descriptors) != 0) {
#endif
        return {false, {}, strerror(errno), errno};
    }

    const pid_t child = fork();
    if (child < 0) {
        const int errorNumber = errno;
        close(descriptors[0]);
        close(descriptors[1]);
        return {false, {}, strerror(errorNumber), errorNumber};
    }
    if (child == 0) {
        close(descriptors[0]);
        if (dup2(descriptors[1], STDOUT_FILENO) < 0) _exit(126);
        close(descriptors[1]);
        execl("/system/bin/getprop", "getprop", static_cast<char*>(nullptr));
        _exit(127);
    }

    close(descriptors[1]);
    const int originalFlags = fcntl(descriptors[0], F_GETFL, 0);
    if (originalFlags >= 0) fcntl(descriptors[0], F_SETFL, originalFlags | O_NONBLOCK);

    std::string output;
    bool endOfFile = false;
    bool timedOut = false;
    int childStatus = 0;
    bool childExited = false;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMilliseconds);
    while (!endOfFile || !childExited) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            timedOut = true;
            break;
        }
        const int remaining = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
        struct pollfd pollDescriptor {descriptors[0], POLLIN | POLLHUP, 0};
        poll(&pollDescriptor, 1, std::min(remaining, 100));
        if ((pollDescriptor.revents & (POLLIN | POLLHUP)) != 0) {
            std::array<char, 4096> buffer{};
            while (true) {
                const ssize_t length = read(descriptors[0], buffer.data(), buffer.size());
                if (length > 0) {
                    output.append(buffer.data(), static_cast<std::size_t>(length));
                    if (output.size() > 4 * 1024 * 1024) {
                        timedOut = true;
                        break;
                    }
                    continue;
                }
                if (length == 0) endOfFile = true;
                if (length < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    endOfFile = true;
                }
                break;
            }
        }
        if (timedOut) break;
        const pid_t waited = waitpid(child, &childStatus, WNOHANG);
        childExited = waited == child;
        if (waited < 0) {
            childExited = true;
            childStatus = -1;
        }
    }

    close(descriptors[0]);
    if (timedOut) {
        kill(child, SIGKILL);
        waitpid(child, &childStatus, 0);
        return {false, {}, "getprop snapshot timed out or exceeded the output limit", ETIMEDOUT};
    }
    if (!childExited) waitpid(child, &childStatus, 0);
    if (!WIFEXITED(childStatus) || WEXITSTATUS(childStatus) != 0) {
        return {false, {}, "getprop exited unsuccessfully", 0};
    }
    return {true, std::move(output), {}, 0};
}

}  // namespace

const char* propertyObservationStateName(PropertyObservationState state) {
    switch (state) {
        case PropertyObservationState::PRESENT: return "present";
        case PropertyObservationState::MISSING: return "missing";
        case PropertyObservationState::UNAVAILABLE: return "unavailable";
        case PropertyObservationState::REDACTED_BY_PLATFORM: return "redacted_by_platform";
    }
    return "unavailable";
}

const std::vector<std::string>& securityPropertyKeys() {
    static const std::vector<std::string> keys = {
        "ro.secure",
        "ro.debuggable",
        "ro.build.type",
        "ro.build.tags",
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
        "ro.boot.vbmeta.device_state",
        "service.adb.root",
    };
    return keys;
}

const std::vector<std::string>& posturePropertyKeys() {
    static const std::vector<std::string> keys = {
        "ro.boot.qemu",
        "ro.kernel.qemu",
        "sys.usb.config",
        "persist.sys.usb.config",
    };
    return keys;
}

std::vector<PropertyObservation> observeBionicProperties(
    const std::vector<std::string>& keys) {
    std::vector<PropertyObservation> observations;
    observations.reserve(keys.size());
    const PropertyReadCallbackFunction readCallback = resolveReadCallback();
    for (const auto& key : keys) {
        const prop_info* property = __system_property_find(key.c_str());
        if (property == nullptr) {
            observations.push_back({key, "bionic", PropertyObservationState::MISSING, {}, {}, 0});
            continue;
        }
        if (readCallback != nullptr) {
            CallbackValue capture;
            readCallback(property, capturePropertyValue, &capture);
            if (capture.called) {
                observations.push_back({key, "bionic", PropertyObservationState::PRESENT,
                                        std::move(capture.value), {}, 0});
            }
        }

        // The legacy accessor is recorded as its own source rather than only as a
        // fallback. Hooks frequently target __system_property_get alone, so a
        // disagreement between the two bionic entry points is itself evidence.
        // Values above PROP_VALUE_MAX come back as a fixed notice here; the
        // comparison discards that text rather than treating it as a value.
        // The value keeps the returned length, including any NUL stored inside it;
        // compareEquivalentPropertySources records why that is not trimmed.
        std::array<char, PROP_VALUE_MAX> value{};
        const int length = __system_property_get(key.c_str(), value.data());
        if (length >= 0) {
            observations.push_back({key, "bionic_legacy", PropertyObservationState::PRESENT,
                                    std::string(value.data(), static_cast<std::size_t>(length)), {}, 0});
        } else {
            observations.push_back(unavailableObservation(
                key, "bionic_legacy", "legacy Bionic property read failed"));
        }
    }
    return observations;
}

std::vector<PropertyObservation> observeAndroidSystemProperties(
    JNIEnv* env, const std::vector<std::string>& keys) {
    if (env == nullptr) {
        return unavailableObservations(keys, "android_system_properties", "JNI environment is unavailable");
    }
    jclass type = env->FindClass("android/os/SystemProperties");
    if (type == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        return unavailableObservations(keys, "android_system_properties",
                                       "android.os.SystemProperties is unavailable");
    }
    jmethodID method = env->GetStaticMethodID(
        type, "get", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if (method == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(type);
        return unavailableObservations(keys, "android_system_properties",
                                       "SystemProperties.get(String, String) is unavailable");
    }

    const std::string sentinel = "__tamperprobe_property_missing__";
    std::vector<PropertyObservation> observations;
    observations.reserve(keys.size());
    for (const auto& key : keys) {
        jstring javaKey = env->NewStringUTF(key.c_str());
        jstring javaDefault = env->NewStringUTF(sentinel.c_str());
        auto* javaValue = static_cast<jstring>(
            env->CallStaticObjectMethod(type, method, javaKey, javaDefault));
        env->DeleteLocalRef(javaKey);
        env->DeleteLocalRef(javaDefault);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            observations.push_back(unavailableObservation(
                key, "android_system_properties", "SystemProperties.get threw an exception"));
            continue;
        }
        if (javaValue == nullptr) {
            observations.push_back(unavailableObservation(
                key, "android_system_properties", "SystemProperties.get returned null"));
            continue;
        }
        const char* characters = env->GetStringUTFChars(javaValue, nullptr);
        if (characters == nullptr) {
            env->ExceptionClear();
            env->DeleteLocalRef(javaValue);
            observations.push_back(unavailableObservation(
                key, "android_system_properties", "property value could not be converted to UTF-8"));
            continue;
        }
        const std::string value(characters);
        env->ReleaseStringUTFChars(javaValue, characters);
        env->DeleteLocalRef(javaValue);
        observations.push_back({key, "android_system_properties",
                                value == sentinel ? PropertyObservationState::MISSING
                                                  : PropertyObservationState::PRESENT,
                                value == sentinel ? std::string() : value, {}, 0});
    }
    env->DeleteLocalRef(type);
    return observations;
}

std::vector<PropertyObservation> observeGetpropSnapshot(
    const std::vector<std::string>& keys, int timeoutMilliseconds) {
    const ProcessOutput process = runGetprop(timeoutMilliseconds);
    if (!process.available) {
        return unavailableObservations(keys, "getprop", process.error, process.errorNumber);
    }
    const auto properties = parseGetpropOutput(process.output);
    std::vector<PropertyObservation> observations;
    observations.reserve(keys.size());
    for (const auto& key : keys) {
        const auto found = properties.find(key);
        if (found == properties.end()) {
            observations.push_back({key, "getprop", PropertyObservationState::MISSING, {}, {}, 0});
        } else {
            observations.push_back({key, "getprop", PropertyObservationState::PRESENT,
                                    found->second, {}, 0});
        }
    }
    return observations;
}

namespace {

// android.os.Build fields that AOSP initialises by a direct, unconditional read of a
// single property. Fields backed by ro.product.* are deliberately excluded: those go
// through per-partition fallback logic, so a difference there is not evidence.
const char* buildFieldForProperty(const std::string& key) {
    if (key == "ro.build.type") return "TYPE";
    if (key == "ro.build.tags") return "TAGS";
    if (key == "ro.build.fingerprint") return "FINGERPRINT";
    if (key == "ro.build.id") return "ID";
    return nullptr;
}

// The kernel command line names boot parameters androidboot.<rest>, which init
// republishes as ro.boot.<rest>.
std::string cmdlineKeyForProperty(const std::string& key) {
    if (key == "ro.bootloader") return "androidboot.bootloader";
    if (key.rfind("ro.boot.", 0) == 0) {
        return "androidboot." + key.substr(std::strlen("ro.boot."));
    }
    return {};
}

std::string readSmallFile(const char* path) {
    std::FILE* file = std::fopen(path, "r");
    if (file == nullptr) return {};
    std::string content;
    std::array<char, 4096> buffer{};
    while (true) {
        const std::size_t bytes = std::fread(buffer.data(), 1, buffer.size(), file);
        if (bytes == 0) break;
        content.append(buffer.data(), bytes);
        if (content.size() > 256 * 1024) break;
    }
    std::fclose(file);
    return content;
}

std::string trimBootValue(std::string value) {
    std::size_t begin = 0;
    std::size_t end = value.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(value[begin]))) ++begin;
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) --end;
    // Bootconfig quotes every value; the kernel command line does not.
    if (end - begin >= 2 && value[begin] == '"' && value[end - 1] == '"') {
        ++begin;
        --end;
    }
    return value.substr(begin, end - begin);
}

// Boot parameters live on the kernel command line on older devices and in
// /proc/bootconfig from Android 12 onwards, where the bootloader hands them to init
// as bootconfig rather than as cmdline arguments. Both are read: a device that
// exposes neither simply contributes no boot source.
std::map<std::string, std::string> readCmdlineParameters() {
    std::map<std::string, std::string> parameters;

    std::string cmdline = readSmallFile("/proc/cmdline");
    if (!cmdline.empty()) {
        std::vector<char> scratch(cmdline.begin(), cmdline.end());
        scratch.push_back('\0');
        char* save = nullptr;
        char* token = strtok_r(scratch.data(), " \t\r\n", &save);
        while (token != nullptr) {
            char* separator = std::strchr(token, '=');
            if (separator != nullptr) {
                *separator = '\0';
                parameters[std::string(token)] = trimBootValue(std::string(separator + 1));
            }
            token = strtok_r(nullptr, " \t\r\n", &save);
        }
    }

    const std::string bootconfig = readSmallFile("/proc/bootconfig");
    std::size_t lineStart = 0;
    while (lineStart < bootconfig.size()) {
        std::size_t lineEnd = bootconfig.find('\n', lineStart);
        if (lineEnd == std::string::npos) lineEnd = bootconfig.size();
        const std::string line = bootconfig.substr(lineStart, lineEnd - lineStart);
        lineStart = lineEnd + 1;
        const std::size_t separator = line.find('=');
        if (separator == std::string::npos) continue;
        const std::string key = trimBootValue(line.substr(0, separator));
        if (key.empty()) continue;
        // The kernel command line wins where both carry the same key: it is the
        // channel the bootloader controls directly.
        parameters.emplace(key, trimBootValue(line.substr(separator + 1)));
    }
    return parameters;
}

}  // namespace

std::vector<PropertyObservation> observeBuildClassProperties(
    JNIEnv* env, const std::vector<std::string>& keys) {
    std::vector<PropertyObservation> observations;
    if (env == nullptr) return observations;
    jclass type = env->FindClass("android/os/Build");
    if (type == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        return observations;
    }
    for (const auto& key : keys) {
        const char* field = buildFieldForProperty(key);
        if (field == nullptr) continue;
        jfieldID identifier = env->GetStaticFieldID(type, field, "Ljava/lang/String;");
        if (identifier == nullptr || env->ExceptionCheck()) {
            env->ExceptionClear();
            observations.push_back(unavailableObservation(
                key, "android_build", "android.os.Build field is unavailable"));
            continue;
        }
        auto* javaValue = static_cast<jstring>(env->GetStaticObjectField(type, identifier));
        if (javaValue == nullptr || env->ExceptionCheck()) {
            env->ExceptionClear();
            observations.push_back({key, "android_build", PropertyObservationState::MISSING,
                                    {}, {}, 0});
            continue;
        }
        const char* characters = env->GetStringUTFChars(javaValue, nullptr);
        if (characters == nullptr) {
            env->ExceptionClear();
            env->DeleteLocalRef(javaValue);
            observations.push_back(unavailableObservation(
                key, "android_build", "Build field could not be converted to UTF-8"));
            continue;
        }
        observations.push_back({key, "android_build", PropertyObservationState::PRESENT,
                                std::string(characters), {}, 0});
        env->ReleaseStringUTFChars(javaValue, characters);
        env->DeleteLocalRef(javaValue);
    }
    env->DeleteLocalRef(type);
    return observations;
}

std::vector<PropertyObservation> observeCmdlineBootProperties(
    const std::vector<std::string>& keys) {
    std::vector<PropertyObservation> observations;
    const auto parameters = readCmdlineParameters();
    if (parameters.empty()) return observations;
    for (const auto& key : keys) {
        // The serial number is never cross-checked: it would place a device
        // identifier into the evidence payload and it carries no posture meaning.
        if (key == "ro.boot.serialno" || key == "ro.serialno") continue;
        const std::string cmdlineKey = cmdlineKeyForProperty(key);
        if (cmdlineKey.empty()) continue;
        const auto found = parameters.find(cmdlineKey);
        if (found == parameters.end()) {
            observations.push_back({key, "proc_cmdline", PropertyObservationState::MISSING,
                                    {}, {}, 0});
            continue;
        }
        observations.push_back({key, "proc_cmdline", PropertyObservationState::PRESENT,
                                found->second, {}, 0});
    }
    return observations;
}

PropertySourceSnapshot observeAllEquivalentPropertySources(
    JNIEnv* env, const std::vector<std::string>& keys) {
    PropertySourceSnapshot snapshot;
    auto append = [&](std::vector<PropertyObservation> observations) {
        snapshot.observations.insert(snapshot.observations.end(),
                                     std::make_move_iterator(observations.begin()),
                                     std::make_move_iterator(observations.end()));
    };
    append(observeBionicProperties(keys));
    append(observeAndroidSystemProperties(env, keys));
    append(observeGetpropSnapshot(keys));
    append(observeBuildClassProperties(env, keys));
    append(observeCmdlineBootProperties(keys));

    snapshot.propertyAreas = scanPropertyAreas();
    for (const auto& area : snapshot.propertyAreas) {
        if (area.status != PropertyAreaStatus::PARSED) continue;
        for (const auto& key : keys) {
            // A context area that simply does not own this property is not a missing
            // reading. Recording one per area would bury the real sources under
            // hundreds of empty entries and inflate the wire payload.
            const auto found = area.properties.find(key);
            if (found == area.properties.end()) continue;
            snapshot.observations.push_back(
                {key, "property_area:" + area.context, PropertyObservationState::PRESENT,
                 found->second, {}, 0});
        }
    }
    return snapshot;
}

}  // namespace tamperprobe
