#ifndef TAMPERPROBE_PROPERTY_OBSERVATION_H
#define TAMPERPROBE_PROPERTY_OBSERVATION_H

#include <jni.h>

#include <string>
#include <vector>

#include "property_area_parser.h"

namespace tamperprobe {

enum class PropertyObservationState {
    PRESENT,
    MISSING,
    UNAVAILABLE,
    // The read completed, but the value it returned is one the platform substitutes for the
    // real one, so it is not an answer. No property source produces it; only a Settings read
    // the platform redacts (applyAdbEnabledPlatformRedaction in property_detector_logic.h).
    REDACTED_BY_PLATFORM,
};

struct PropertyObservation {
    std::string property;
    std::string source;
    PropertyObservationState state = PropertyObservationState::UNAVAILABLE;
    std::string value;
    std::string error;
    int errorNumber = 0;
};

struct PropertySourceSnapshot {
    std::vector<PropertyObservation> observations;
    std::vector<PropertyAreaRecord> propertyAreas;
};

const char* propertyObservationStateName(PropertyObservationState state);

const std::vector<std::string>& securityPropertyKeys();

const std::vector<std::string>& posturePropertyKeys();

std::vector<PropertyObservation> observeBionicProperties(
    const std::vector<std::string>& keys);

std::vector<PropertyObservation> observeAndroidSystemProperties(
    JNIEnv* env, const std::vector<std::string>& keys);

std::vector<PropertyObservation> observeGetpropSnapshot(
    const std::vector<std::string>& keys, int timeoutMilliseconds = 2000);

std::vector<PropertyObservation> observeBuildClassProperties(
    JNIEnv* env, const std::vector<std::string>& keys);

std::vector<PropertyObservation> observeCmdlineBootProperties(
    const std::vector<std::string>& keys);

PropertySourceSnapshot observeAllEquivalentPropertySources(
    JNIEnv* env, const std::vector<std::string>& keys);

}  // namespace tamperprobe

#endif  // TAMPERPROBE_PROPERTY_OBSERVATION_H
