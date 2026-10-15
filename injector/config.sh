#!/bin/bash
# Tool locations for inject.sh. Every value can be overridden from the environment.

set -e

INJECTOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$INJECTOR_DIR/.." && pwd)"

# Android SDK build tools and a platform android.jar (used by d8 as the library classpath).
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
export BUILD_TOOLS_VERSION="${BUILD_TOOLS_VERSION:-36.1.0}"
export BUILD_TOOLS_DIR="${BUILD_TOOLS_DIR:-$ANDROID_SDK_ROOT/build-tools/$BUILD_TOOLS_VERSION}"
export ANDROID_PLATFORM_JAR="${ANDROID_PLATFORM_JAR:-$ANDROID_SDK_ROOT/platforms/android-36/android.jar}"
export D8="${D8:-$BUILD_TOOLS_DIR/d8}"
export ZIPALIGN="${ZIPALIGN:-$BUILD_TOOLS_DIR/zipalign}"
export APKSIGNER="${APKSIGNER:-$BUILD_TOOLS_DIR/apksigner}"

# apktool and baksmali are not redistributed here; download them into injector/tools/
# (see README) or point these variables at your own copies.
export APKTOOL_JAR="${APKTOOL_JAR:-$INJECTOR_DIR/tools/apktool.jar}"
export BAKSMALI_JAR="${BAKSMALI_JAR:-$INJECTOR_DIR/tools/baksmali.jar}"

export PYTHON="${PYTHON:-python3}"

# The research RASP bundle produced by `gradlew :tamperprobe-rasp:prepareRaspBundle`.
export TAMPERPROBE_RASP_BUNDLE="${TAMPERPROBE_RASP_BUNDLE:-$REPO_ROOT/tamperprobe-rasp/build/outputs/rasp-bundle/tamperprobe-rasp-bundle.zip}"

# Signing. The default is the Android SDK debug keystore, whose password is the public
# default "android". Use your own keystore for anything other than local experiments.
export KEYSTORE_PATH="${KEYSTORE_PATH:-$HOME/.android/debug.keystore}"
export KEYSTORE_PASS="${KEYSTORE_PASS:-android}"
export KEY_ALIAS="${KEY_ALIAS:-androiddebugkey}"

# Detector selection written into the target manifest. Empty means every detector.
export RASP_ENABLED_DETECTIONS="${RASP_ENABLED_DETECTIONS-}"
export RASP_DISABLED_DETECTIONS="${RASP_DISABLED_DETECTIONS-}"

export WORK_DIR="${WORK_DIR:-${TMPDIR:-/tmp}/tamperprobe-lab-inject}"

log_info() { echo "[INFO] $*"; }
log_error() { echo "[ERROR] $*" >&2; }
log_success() { echo "[OK] $*"; }

require_file() {
    if [ ! -f "$2" ]; then
        log_error "$1 not found: $2"
        return 1
    fi
}

verify_environment() {
    local ok=true
    if [ -z "$ANDROID_SDK_ROOT" ]; then
        log_error "Set ANDROID_SDK_ROOT (or ANDROID_HOME) to your Android SDK"
        ok=false
    fi
    require_file "apktool" "$APKTOOL_JAR" || ok=false
    require_file "baksmali" "$BAKSMALI_JAR" || ok=false
    require_file "android.jar" "$ANDROID_PLATFORM_JAR" || ok=false
    require_file "RASP bundle" "$TAMPERPROBE_RASP_BUNDLE" || ok=false
    require_file "keystore" "$KEYSTORE_PATH" || ok=false
    for tool in "$D8" "$ZIPALIGN" "$APKSIGNER"; do
        if [ ! -x "$tool" ] && [ ! -f "$tool.bat" ] && [ ! -x "$tool.exe" ]; then
            log_error "Build tool not found: $tool"
            ok=false
        fi
    done
    command -v java >/dev/null 2>&1 || { log_error "java not found"; ok=false; }
    command -v "$PYTHON" >/dev/null 2>&1 || { log_error "$PYTHON not found"; ok=false; }
    $ok
}
