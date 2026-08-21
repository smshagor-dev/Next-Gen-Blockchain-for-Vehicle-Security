cmake_minimum_required(VERSION 3.16)

project(SmartCarBlockchain LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(SMARTCAR_BUILD_BLOCKCHAIN "Build blockchain.cpp demo executable" ON)
option(SMARTCAR_BUILD_CAMERA_MODULE "Build camera_emergency_brake.cpp (OpenCV required)" OFF)
option(SMARTCAR_ENABLE_WARNINGS "Enable extra compiler warnings" ON)
option(SMARTCAR_ENABLE_NATIVE_OPT "Enable host-specific -march=native Release optimizations" OFF)
option(SMARTCAR_ENABLE_UNSAFE_FAST_MATH "Enable -ffast-math for controlled performance experiments only" OFF)
option(SMARTCAR_ENABLE_IPO "Enable interprocedural optimization/LTO when supported" OFF)
option(SMARTCAR_ALLOW_SIMULATED_PQC_BUILD "Allow blockchain.cpp to compile without liboqs for controlled lab/demo use" OFF)
option(SMARTCAR_FORCE_PQC_UNAVAILABLE_FOR_TESTS "Pretend liboqs is unavailable to validate fail-closed CMake behavior" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(SMARTCAR_ENABLE_WARNINGS)
    if(MSVC)
        add_compile_options(/W4 /permissive-)
    else()
        add_compile_options(-Wall -Wextra -Wpedantic)
    endif()
endif()

if(SMARTCAR_ENABLE_IPO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT SMARTCAR_IPO_SUPPORTED OUTPUT SMARTCAR_IPO_ERROR)
    if(SMARTCAR_IPO_SUPPORTED)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
        message(STATUS "IPO/LTO enabled for Release builds.")
    else()
        message(STATUS "IPO/LTO unavailable: ${SMARTCAR_IPO_ERROR}")
    endif()
endif()

function(smartcar_apply_release_options target_name)
    if(MSVC)
        target_compile_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:/O2 /Gy /Gw>
        )
        target_link_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:/OPT:REF /OPT:ICF>
        )
    else()
        target_compile_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:-O2>
        )
        if(SMARTCAR_ENABLE_UNSAFE_FAST_MATH)
            target_compile_options(${target_name} PRIVATE
                $<$<CONFIG:Release>:-ffast-math>
            )
            message(WARNING "SMARTCAR_ENABLE_UNSAFE_FAST_MATH=ON: floating-point semantics are relaxed; do not use this build for security/safety validation.")
        endif()
        if(SMARTCAR_ENABLE_NATIVE_OPT)
            target_compile_options(${target_name} PRIVATE
                $<$<CONFIG:Release>:-march=native>
            )
            message(WARNING "SMARTCAR_ENABLE_NATIVE_OPT=ON: output is host-specific and not reproducible across CPU targets.")
        endif()
        target_link_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:-Wl,--as-needed>
        )
    endif()
endfunction()

# nlohmann_json is required by blockchain.cpp. The fallback archive is pinned
# to the SHA-256 published for the v3.11.3 json.tar.xz release asset.
find_package(nlohmann_json CONFIG QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# The blockchain demo has a historical deterministic simulated-PQC path in the
# source tree. Standard native builds must not silently compile that path when
# liboqs is absent. Simulation therefore requires an explicit lab-only opt-in.
find_package(liboqs CONFIG QUIET)
if(SMARTCAR_FORCE_PQC_UNAVAILABLE_FOR_TESTS)
    set(liboqs_FOUND FALSE)
endif()

set(SMARTCAR_LIBOQS_TARGET "")
if(liboqs_FOUND)
    if(TARGET OQS::oqs)
        set(SMARTCAR_LIBOQS_TARGET OQS::oqs)
    elseif(TARGET oqs)
        set(SMARTCAR_LIBOQS_TARGET oqs)
    else()
        message(FATAL_ERROR "liboqs was reported as found but no supported CMake target (OQS::oqs or oqs) is available.")
    endif()
endif()

if(SMARTCAR_BUILD_BLOCKCHAIN)
    if(NOT SMARTCAR_LIBOQS_TARGET AND NOT SMARTCAR_ALLOW_SIMULATED_PQC_BUILD)
        message(FATAL_ERROR
            "liboqs is required for the blockchain native target. "
            "Install liboqs, or set SMARTCAR_ALLOW_SIMULATED_PQC_BUILD=ON only for controlled lab/demo validation. "
            "The simulated source path is not a post-quantum security mechanism."
        )
    endif()

    add_executable(smartcar_blockchain blockchain.cpp)
    target_link_libraries(smartcar_blockchain PRIVATE nlohmann_json::nlohmann_json)
    smartcar_apply_release_options(smartcar_blockchain)

    if(SMARTCAR_LIBOQS_TARGET)
        target_link_libraries(smartcar_blockchain PRIVATE ${SMARTCAR_LIBOQS_TARGET})
        message(STATUS "liboqs linked: native blockchain target may use the real PQC backend.")
    else()
        message(WARNING
            "SMARTCAR_ALLOW_SIMULATED_PQC_BUILD=ON with liboqs unavailable. "
            "This binary is LAB/DEMO ONLY and must not be described as post-quantum secure."
        )
    endif()
endif()

if(SMARTCAR_BUILD_CAMERA_MODULE)
    find_package(OpenCV REQUIRED COMPONENTS core imgproc highgui videoio objdetect)
    add_executable(camera_emergency_brake camera_emergency_brake.cpp)
    target_link_libraries(camera_emergency_brake PRIVATE ${OpenCV_LIBS})
    target_include_directories(camera_emergency_brake PRIVATE ${OpenCV_INCLUDE_DIRS})
    smartcar_apply_release_options(camera_emergency_brake)
endif()
