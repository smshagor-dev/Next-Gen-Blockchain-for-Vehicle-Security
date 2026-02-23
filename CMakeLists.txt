cmake_minimum_required(VERSION 3.16)

project(SmartCarBlockchain LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SMARTCAR_BUILD_BLOCKCHAIN "Build blockchain.cpp demo executable" ON)
option(SMARTCAR_BUILD_CAMERA_MODULE "Build camera_emergency_brake.cpp (OpenCV required)" OFF)
option(SMARTCAR_ENABLE_WARNINGS "Enable extra compiler warnings" ON)

if(SMARTCAR_ENABLE_WARNINGS)
    if(MSVC)
        add_compile_options(/W4 /permissive-)
    else()
        add_compile_options(-Wall -Wextra -Wpedantic)
    endif()
endif()

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
endif()
