cmake_minimum_required(VERSION 3.22.1)

project(leona
    VERSION 0.1.0
    DESCRIPTION "Leona native detection core"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Hide symbols by default — any public JNI method is annotated with
# JNIEXPORT which re-exports it. Everything else stays internal.
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)

# Strip release symbols but keep JNI exports.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_link_options("-Wl,--exclude-libs,ALL")
    add_compile_options(-O2 -fno-strict-aliasing)
endif()

add_library(leona SHARED
    jni_bridge.cpp

    detection/injection_detector.cpp
    detection/environment_detector.cpp
    detection/root_detector.cpp
    detection/xposed_detector.cpp
    detection/unidbg_detector.cpp
    detection/tamper_detector.cpp
    detection/process_maps.cpp
    detection/frida_signatures.cpp
    detection/timing_probe.cpp

    report/collector.cpp

    honeypot/canary.cpp
    honeypot/fake_data.cpp

    util/evidence_builder.cpp
)

target_include_directories(leona PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

find_library(log-lib log)

target_link_libraries(leona
    PRIVATE
    ${log-lib}
)

target_compile_options(leona PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror=return-type
    -Werror=implicit-fallthrough
)
