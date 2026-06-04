cmake_minimum_required(VERSION 3.16)

project(SmartCarBlockchain LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(SMARTCAR_BUILD_BLOCKCHAIN "Build blockchain.cpp demo executable" ON)
option(SMARTCAR_BUILD_CAMERA_MODULE "Build camera_emergency_brake.cpp (OpenCV required)" OFF)
option(SMARTCAR_ENABLE_WARNINGS "Enable extra compiler warnings" ON)
option(SMARTCAR_ENABLE_NATIVE_OPT "Enable native CPU optimizations for low-latency Release builds" ON)
option(SMARTCAR_ENABLE_IPO "Enable interprocedural optimization/LTO when supported" ON)

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

function(smartcar_apply_low_latency_options target_name)
    if(MSVC)
        target_compile_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:/O2 /Ob3 /GL /Gy /Gw>
        )
        target_link_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:/LTCG /OPT:REF /OPT:ICF>
        )
    else()
        target_compile_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:-O3 -ffast-math>
        )
        if(SMARTCAR_ENABLE_NATIVE_OPT)
            target_compile_options(${target_name} PRIVATE $<$<CONFIG:Release>:-march=native>)
        endif()
        target_link_options(${target_name} PRIVATE $<$<CONFIG:Release>:-Wl,--as-needed>)
    endif()
endfunction()

# nlohmann_json is required by blockchain.cpp
find_package(nlohmann_json CONFIG QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# liboqs is optional; code has compile-time fallback when headers are absent.
# If available, we link it so real PQC path can be enabled.
find_package(liboqs CONFIG QUIET)

if(SMARTCAR_BUILD_BLOCKCHAIN)
    add_executable(smartcar_blockchain blockchain.cpp)
    target_link_libraries(smartcar_blockchain PRIVATE nlohmann_json::nlohmann_json)
    smartcar_apply_low_latency_options(smartcar_blockchain)

    if(liboqs_FOUND)
        if(TARGET OQS::oqs)
            target_link_libraries(smartcar_blockchain PRIVATE OQS::oqs)
        elseif(TARGET oqs)
            target_link_libraries(smartcar_blockchain PRIVATE oqs)
        endif()
        message(STATUS "liboqs found: real PQC backend will be available at runtime.")
    else()
        message(STATUS "liboqs not found: blockchain.cpp will use simulated PQC fallback.")
    endif()
endif()

if(SMARTCAR_BUILD_CAMERA_MODULE)
    find_package(OpenCV REQUIRED COMPONENTS core imgproc highgui videoio objdetect)
    add_executable(camera_emergency_brake camera_emergency_brake.cpp)
    target_link_libraries(camera_emergency_brake PRIVATE ${OpenCV_LIBS})
    target_include_directories(camera_emergency_brake PRIVATE ${OpenCV_INCLUDE_DIRS})
    smartcar_apply_low_latency_options(camera_emergency_brake)
endif()
