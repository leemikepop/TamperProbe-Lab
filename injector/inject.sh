#!/bin/bash
# Injects the TamperProbe-Lab research RASP into an existing APK.
#
# Usage:
#   injector/inject.sh <input.apk> <output.apk>
#
# The injected app runs one scan of every detector at start-up, on a background thread, and
# writes the raw wire-schema report to Download/tamperprobe-lab/ (see README). It never blocks
# or terminates the host app. Configuration comes from config.sh and the environment:
#   RASP_ENABLED_DETECTIONS   comma-separated IDs; run only these
#   RASP_DISABLED_DETECTIONS  comma-separated IDs; run everything except these
# Use only with apps you are allowed to modify (the paper uses open-source F-Droid apps).

set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

if [ $# -lt 2 ]; then
    log_error "Usage: $0 <input.apk> <output.apk>"
    exit 1
fi
INPUT_APK="$1"
OUTPUT_APK="$2"
require_file "Input APK" "$INPUT_APK"

resolve_tool() {
    # Git Bash does not mark the SDK's Windows .bat wrappers (d8, apksigner) as executable.
    for candidate in "$1" "$1.exe"; do
        if [ -x "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    if [ -f "$1.bat" ]; then
        printf '%s' "$1.bat"
        return 0
    fi
    printf '%s' "$1"
}

verify_environment
D8="$(resolve_tool "$D8")"
ZIPALIGN="$(resolve_tool "$ZIPALIGN")"
APKSIGNER="$(resolve_tool "$APKSIGNER")"

mkdir -p "$WORK_DIR"
WORKSPACE="$(mktemp -d "$WORK_DIR/injection_XXXXXXXX")"
trap 'rm -rf "$WORKSPACE"' EXIT
log_info "Workspace: $WORKSPACE"

log_info "[1/9] Extracting and verifying the RASP bundle"
BUNDLE_DIR="$WORKSPACE/rasp_bundle"
mkdir -p "$BUNDLE_DIR"
unzip -q "$TAMPERPROBE_RASP_BUNDLE" -d "$BUNDLE_DIR"
"$PYTHON" "$SCRIPT_DIR/verify_bundle.py" "$BUNDLE_DIR"

log_info "[2/9] Converting the adapter JAR to DEX"
$D8 --min-api 29 --lib "$ANDROID_PLATFORM_JAR" --output "$WORKSPACE" "$BUNDLE_DIR/rasp-adapter.jar"

log_info "[3/9] Disassembling the adapter DEX to smali"
SMALI_DIR="$WORKSPACE/smali_output"
java -jar "$BAKSMALI_JAR" d "$WORKSPACE/classes.dex" -o "$SMALI_DIR"

log_info "[4/9] Decoding the target APK"
TARGET_DIR="$WORKSPACE/target_decompiled"
java -jar "$APKTOOL_JAR" d "$INPUT_APK" -o "$TARGET_DIR" -f

log_info "[5/9] Adding the adapter as a new smali_classes directory"
LAST_SMALI="$(find "$TARGET_DIR" -maxdepth 1 -type d -name 'smali_classes*' | sort -V | tail -1)"
if [ -z "$LAST_SMALI" ]; then
    TARGET_SMALI_DIR="$TARGET_DIR/smali_classes2"
elif [[ "$LAST_SMALI" =~ smali_classes([0-9]+)$ ]]; then
    TARGET_SMALI_DIR="$TARGET_DIR/smali_classes$((BASH_REMATCH[1] + 1))"
else
    log_error "Unable to determine the next smali directory from: $LAST_SMALI"
    exit 1
fi
mkdir -p "$TARGET_SMALI_DIR"
cp -r "$SMALI_DIR"/* "$TARGET_SMALI_DIR/"

log_info "[6/9] Adding native libraries and catalog assets"
mkdir -p "$TARGET_DIR/lib"
cp -r "$BUNDLE_DIR/jni"/* "$TARGET_DIR/lib/"
ASSET_TARGET="$TARGET_DIR/assets/tamperprobe"
mkdir -p "$ASSET_TARGET"
for asset in detections_manifest.json attestation_status.json attestation_roots.json \
             package_indicators.txt package_intent_actions.txt; do
    cp "$BUNDLE_DIR/$asset" "$ASSET_TARGET/$asset"
done

log_info "[7/9] Merging the manifest"
MANIFEST="$TARGET_DIR/AndroidManifest.xml"
NEEDS_STORED_NATIVE_LIBS=false
if grep -q 'android:extractNativeLibs="false"' "$MANIFEST"; then
    NEEDS_STORED_NATIVE_LIBS=true
fi
REPORT="$WORKSPACE/injection-result.json"
PACKAGE_NAME="$("$PYTHON" "$SCRIPT_DIR/merge_manifest.py" \
    --manifest "$MANIFEST" \
    --fragment "$BUNDLE_DIR/manifest-fragment.xml" \
    --queries "$BUNDLE_DIR/queries.xml" \
    --enabled-detections "$RASP_ENABLED_DETECTIONS" \
    --disabled-detections "$RASP_DISABLED_DETECTIONS" \
    --report "$REPORT")"
log_info "Target package: $PACKAGE_NAME"

log_info "[8/9] Rebuilding"
REPACKAGED_APK="$WORKSPACE/repackaged.apk"
java -jar "$APKTOOL_JAR" b "$TARGET_DIR" -o "$REPACKAGED_APK"
if [ "$NEEDS_STORED_NATIVE_LIBS" = true ]; then
    command -v zip >/dev/null 2>&1 || { log_error "zip is required to store native libraries uncompressed"; exit 1; }
    (
        cd "$TARGET_DIR"
        find lib -type f -name '*.so' -print0 | while IFS= read -r -d '' so_file; do
            zip -q -0 "$REPACKAGED_APK" "$so_file"
        done
    )
fi

log_info "[9/9] Aligning and signing"
ALIGNED_APK="$WORKSPACE/aligned.apk"
$ZIPALIGN -P 16 -f 4 "$REPACKAGED_APK" "$ALIGNED_APK"
$APKSIGNER sign \
    --ks "$KEYSTORE_PATH" \
    --ks-pass "pass:$KEYSTORE_PASS" \
    --ks-key-alias "$KEY_ALIAS" \
    --out "$OUTPUT_APK" \
    "$ALIGNED_APK"

cp "$REPORT" "${OUTPUT_APK%.apk}.injection.json"
log_success "Injected APK: $OUTPUT_APK"
log_success "Injection report: ${OUTPUT_APK%.apk}.injection.json"
