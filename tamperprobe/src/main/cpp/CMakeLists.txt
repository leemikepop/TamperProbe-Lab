# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html.
# For more examples on how to use CMake, see https://github.com/android/ndk-samples.

# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

# Declares the project name. The project name can be accessed via ${ PROJECT_NAME},
# Since this is the top level CMakeLists.txt, the project name is also accessible
# with ${CMAKE_PROJECT_NAME} (both CMake variables are in-sync within the top level
# build script scope).
# Library 的 native library 名稱
project("tamperprobe_native")

set(TAMPERPROBE_ENGINE_VERSION "1.0.0-SNAPSHOT" CACHE STRING "TamperProbe engine version")
set(TAMPERPROBE_CATALOG_VERSION "1.5" CACHE STRING "TamperProbe detector catalog version")
set(TAMPERPROBE_WIRE_SCHEMA_VERSION "1" CACHE STRING "TamperProbe wire schema version")

# Let sources include common headers relative to this directory.
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.
#
# In this top level CMakeLists.txt, ${CMAKE_PROJECT_NAME} is used to define
# the target library name; in the sub-module's CMakeLists.txt, ${PROJECT_NAME}
# is preferred for the same purpose.
#
# In order to load a library into your app from Java/Kotlin, you must call
# System.loadLibrary() and pass the name of the library defined here;
# for GameActivity/NativeActivity derived applications, the same library name must be
# used in the AndroidManifest.xml file.
add_library(${CMAKE_PROJECT_NAME} SHARED
        # List C/C++ source files with relative paths to this CMakeLists.txt.

        # Core architecture
        core/detection_registry.cpp
        core/native_bridge.cpp
        common/utils.cpp
        common/io_utils.cpp
        common/proc_maps.cpp

        # Binary Artifact Evidence
        detections/binary-artifact/binary_artifact_probe.cpp
        detections/binary-artifact/su.cpp
        detections/binary-artifact/busybox.cpp

        # Filesystem and Mount Evidence
        detections/filesystem-state/rw_paths.cpp
        detections/filesystem-state/mount_integrity.cpp
        detections/filesystem-state/native_root_paths.cpp

        # Kernel and Privilege Interfaces
        detections/kernel-interface/kernel_check.cpp
        detections/kernel-interface/lsposed_sepolicy.cpp
        detections/kernel-interface/native_root_prctl.cpp
        detections/kernel-interface/native_root_susfs.cpp
        detections/kernel-interface/native_root_devpts.cpp
        detections/kernel-interface/native_root_sepolicy.cpp
        detections/kernel-interface/policy_oracle.cpp

        # Process and Memory Evidence
        detections/process-memory/context.cpp
        detections/process-memory/memory_fd_anomaly.cpp
        detections/process-memory/memory_maps_anomaly.cpp
        detections/process-memory/memory_linker_visibility.cpp

        # Runtime Injection and Code Integrity
        detections/runtime-integrity/entry_pattern.cpp
        detections/runtime-integrity/elf_integrity.cpp
        detections/runtime-integrity/prologue_scanner.cpp
        detections/runtime-integrity/runtime_instrumentation.cpp
        detections/runtime-integrity/elf_text_integrity.cpp
        detections/runtime-integrity/vdso_integrity.cpp
        detections/runtime-integrity/smaps_dirt.cpp
        detections/runtime-integrity/zygisk_smaps.cpp
        detections/runtime-integrity/zygisk_namespace.cpp
        detections/runtime-integrity/zygisk_fd_forensics.cpp
        detections/runtime-integrity/lsposed_maps.cpp

        # System Configuration and Security State
        detections/system-state/property_area_parser.cpp
        detections/system-state/property_detector_logic.cpp
        detections/system-state/property_observation.cpp
        detections/system-state/dangerous_props.cpp
        detections/system-state/selinux_check.cpp
        detections/system-state/system_properties_tamper.cpp
        detections/system-state/custom_rom.cpp
        detections/system-state/emulator_hardware_indicators.cpp
        detections/system-state/emulator_system_profile.cpp
        detections/system-state/property_area_residue.cpp
        detections/system-state/build_patch_coherence.cpp

        # Package and Application Visibility
        detections/app-visibility/package_targets.cpp
        detections/app-visibility/dangerous_packages.cpp
        detections/app-visibility/package_storage_visibility.cpp

        # Key Attestation and Trusted Execution
        detections/hardware-attestation/tee_attestation.cpp
        detections/hardware-attestation/drm_credential_coherence.cpp
        detections/hardware-attestation/keystore_grant_split.cpp
        detections/hardware-attestation/tee_cert_parser.cpp
        detections/hardware-attestation/tee_common.cpp
        detections/hardware-attestation/tee_assessment.cpp
        detections/hardware-attestation/tee_keystore_consistency.cpp
        detections/hardware-attestation/tee_oversized_challenge.cpp

        )

string(TOLOWER "${CMAKE_BUILD_TYPE}" TAMPERPROBE_BUILD_TYPE_LOWER)
if(TAMPERPROBE_BUILD_TYPE_LOWER STREQUAL "debug")
    target_sources(${CMAKE_PROJECT_NAME} PRIVATE tests/native_fixture_bridge.cpp)
endif()

# Specifies libraries CMake should link to your target library. You
# can link libraries from various origins, such as libraries defined in this
# build script, prebuilt third-party libraries, or Android system libraries.
target_link_libraries(${CMAKE_PROJECT_NAME}
        # List libraries link to the target library
        android
        log
        EGL
        GLESv2)

target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
        TAMPERPROBE_ENGINE_VERSION="${TAMPERPROBE_ENGINE_VERSION}"
        TAMPERPROBE_CATALOG_VERSION="${TAMPERPROBE_CATALOG_VERSION}"
        TAMPERPROBE_WIRE_SCHEMA_VERSION=${TAMPERPROBE_WIRE_SCHEMA_VERSION})

# Support for 16KB page size devices (Android 15+)
# Ensure ELF LOAD segments are aligned to 16KB boundaries
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,-z,max-page-size=16384")
