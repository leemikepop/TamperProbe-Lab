# Builds Ruru's native library from the vendored sources (upstream/cpp, unchanged) with the
# sources, include paths and static library its Android.mk names, and the retrofit's own shadow
# probe as a separate library. Upstream builds with ndk-build; AGP accepts one native build per
# module, so both are described here. Flags follow the common part of upstream Application.mk.

cmake_minimum_required(VERSION 3.22.1)
project(ruru_retrofit CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(RURU_UPSTREAM ${CMAKE_CURRENT_SOURCE_DIR}/../../../upstream)

find_package(xposeddetector REQUIRED CONFIG)

add_library(applist_detector SHARED
        ${RURU_UPSTREAM}/cpp/environment.cpp
        ${RURU_UPSTREAM}/cpp/file_detection.cpp)
target_include_directories(applist_detector PRIVATE
        ${RURU_UPSTREAM}/external/linux_syscall_support
        ${RURU_UPSTREAM}/cpp)
target_compile_options(applist_detector PRIVATE
        -Wall -Wextra -fno-stack-protector -fomit-frame-pointer)
target_link_libraries(applist_detector xposeddetector::xposed_detector)
target_link_options(applist_detector PRIVATE -Wl,--exclude-libs,ALL -Wl,-z,max-page-size=16384)

add_library(ruru_shadow SHARED ruru_shadow.cpp)
target_compile_options(ruru_shadow PRIVATE -Wall -Wextra -Werror -fvisibility=hidden)
target_link_options(ruru_shadow PRIVATE -Wl,-z,max-page-size=16384)
