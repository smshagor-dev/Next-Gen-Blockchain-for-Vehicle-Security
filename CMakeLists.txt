cmake_minimum_required(VERSION 3.16)

project(SmartCarBlockchain VERSION 3.0.2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(SMARTCAR_BUILD_BLOCKCHAIN "Build the hardened native blockchain target" ON)
option(SMARTCAR_BUILD_PQC_KEYSTORE_SELFTEST "Build the durable PQC keystore validation target" OFF)
option(SMARTCAR_BUILD_LEGACY_CPP_DEMO "Build historical blockchain.cpp as an explicitly legacy/lab-only target" OFF)
option(SMARTCAR_BUILD_CAMERA_MODULE "Build camera_emergency_brake.cpp (OpenCV required)" OFF)
option(SMARTCAR_ENABLE_WARNINGS "Enable extra compiler warnings" ON)
option(SMARTCAR_ENABLE_NATIVE_OPT "Enable host-specific -march=native Release optimizations" OFF)
option(SMARTCAR_ENABLE_UNSAFE_FAST_MATH "Enable -ffast-math for controlled performance experiments only" OFF)
option(SMARTCAR_ENABLE_IPO "Enable interprocedural optimization/LTO when supported" OFF)
option(SMARTCAR_FETCH_PINNED_LIBOQS "Fetch pinned liboqs 0.16.0 when no system package is available" OFF)
option(SMARTCAR_FORCE_PQC_UNAVAILABLE_FOR_TESTS "Pretend liboqs is unavailable to validate fail-closed CMake behavior" OFF)

# Backward-compatible v3.1 lab flag. It no longer weakens the production target;
# it only enables the explicitly named legacy demo target.
option(SMARTCAR_ALLOW_SIMULATED_PQC_BUILD "Deprecated alias for SMARTCAR_BUILD_LEGACY_CPP_DEMO" OFF)
if(SMARTCAR_ALLOW_SIMULATED_PQC_BUILD)
    message(WARNING
        "SMARTCAR_ALLOW_SIMULATED_PQC_BUILD is deprecated. "
        "It now enables only smartcar_blockchain_legacy_demo; the production target remains real-PQC-only."
    )
    set(SMARTCAR_BUILD_LEGACY_CPP_DEMO ON)
endif()

set(SMARTCAR_LIBOQS_VERSION "0.16.0")
set(SMARTCAR_LIBOQS_COMMIT "5a1a854b0dc9f2141bdc771c555ee60c37950183")

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

# nlohmann/json fallback is checksum-pinned.
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

# OpenSSL provides authenticated AES-256-GCM storage and digest implementations
# used by the secure native core and durable PQC keystore.
if(SMARTCAR_BUILD_BLOCKCHAIN OR SMARTCAR_BUILD_PQC_KEYSTORE_SELFTEST)
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
endif()

# Prefer a system liboqs package. CI/reproducible source builds may explicitly
# fetch the fully pinned 0.16.0 release commit. The minimal build contains only
# ML-KEM-512 and ML-DSA-44, which are the algorithms used by the secure core.
if(NOT SMARTCAR_FORCE_PQC_UNAVAILABLE_FOR_TESTS)
    find_package(liboqs CONFIG QUIET)
endif()

set(SMARTCAR_LIBOQS_TARGET "")
if(liboqs_FOUND AND NOT SMARTCAR_FORCE_PQC_UNAVAILABLE_FOR_TESTS)
    if(TARGET OQS::oqs)
        set(SMARTCAR_LIBOQS_TARGET OQS::oqs)
    elseif(TARGET oqs)
        set(SMARTCAR_LIBOQS_TARGET oqs)
    endif()
endif()

if(NOT SMARTCAR_LIBOQS_TARGET AND SMARTCAR_FETCH_PINNED_LIBOQS AND NOT SMARTCAR_FORCE_PQC_UNAVAILABLE_FOR_TESTS)
    include(FetchContent)
    set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
    set(OQS_DIST_BUILD OFF CACHE BOOL "" FORCE)
    set(OQS_MINIMAL_BUILD "KEM_ml_kem_512;SIG_ml_dsa_44" CACHE STRING "" FORCE)
    set(OQS_STRICT_WARNINGS OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        liboqs
        GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
        GIT_TAG ${SMARTCAR_LIBOQS_COMMIT}
        GIT_SHALLOW FALSE
        GIT_PROGRESS FALSE
    )
    FetchContent_MakeAvailable(liboqs)
    if(TARGET OQS::oqs)
        set(SMARTCAR_LIBOQS_TARGET OQS::oqs)
    elseif(TARGET oqs)
        set(SMARTCAR_LIBOQS_TARGET oqs)
    endif()
endif()

if(SMARTCAR_BUILD_BLOCKCHAIN)
    if(NOT SMARTCAR_LIBOQS_TARGET)
        message(FATAL_ERROR
            "Real liboqs is required for the hardened native blockchain target. "
            "Install liboqs ${SMARTCAR_LIBOQS_VERSION}, or set SMARTCAR_FETCH_PINNED_LIBOQS=ON to fetch commit ${SMARTCAR_LIBOQS_COMMIT}. "
            "Simulated PQC is not compiled into smartcar_blockchain."
        )
    endif()

    add_executable(
        smartcar_blockchain
        native/secure_blockchain.cpp
        native/pqc_key_store.cpp
    )
    target_include_directories(smartcar_blockchain PRIVATE native)
    target_link_libraries(
        smartcar_blockchain
        PRIVATE
            nlohmann_json::nlohmann_json
            OpenSSL::Crypto
            ${SMARTCAR_LIBOQS_TARGET}
    )
    target_compile_definitions(
        smartcar_blockchain
        PRIVATE
            SMARTCAR_SECURE_NATIVE_CORE=1
            SMARTCAR_RELEASE_VERSION="${PROJECT_VERSION}"
    )
    smartcar_apply_release_options(smartcar_blockchain)
    message(STATUS
        "Hardened native target ${PROJECT_VERSION}: OpenSSL AES-256-GCM + liboqs ML-DSA-44/ML-KEM-512; durable PQC keystore module compiled; simulated PQC excluded."
    )
endif()

if(SMARTCAR_BUILD_PQC_KEYSTORE_SELFTEST)
    if(NOT SMARTCAR_LIBOQS_TARGET)
        message(FATAL_ERROR
            "Real liboqs is required for smartcar_pqc_keystore_selftest. "
            "Install liboqs ${SMARTCAR_LIBOQS_VERSION}, or set SMARTCAR_FETCH_PINNED_LIBOQS=ON."
        )
    endif()
    add_executable(
        smartcar_pqc_keystore_selftest
        native/pqc_key_store.cpp
        native/pqc_key_store_selftest.cpp
    )
    target_include_directories(smartcar_pqc_keystore_selftest PRIVATE native)
    target_link_libraries(
        smartcar_pqc_keystore_selftest
        PRIVATE
            nlohmann_json::nlohmann_json
            OpenSSL::Crypto
            ${SMARTCAR_LIBOQS_TARGET}
    )
    smartcar_apply_release_options(smartcar_pqc_keystore_selftest)
endif()

# Historical source remains available only as an explicitly named lab/demo
# target. This target contains the legacy XOR storage helper and historical
# simulated-PQC fallback and is outside the hardened production build profile.
if(SMARTCAR_BUILD_LEGACY_CPP_DEMO)
    add_executable(smartcar_blockchain_legacy_demo blockchain.cpp)
    target_link_libraries(smartcar_blockchain_legacy_demo PRIVATE nlohmann_json::nlohmann_json)
    if(SMARTCAR_LIBOQS_TARGET)
        target_link_libraries(smartcar_blockchain_legacy_demo PRIVATE ${SMARTCAR_LIBOQS_TARGET})
    endif()
    smartcar_apply_release_options(smartcar_blockchain_legacy_demo)
    message(WARNING
        "Building smartcar_blockchain_legacy_demo: LAB/COMPATIBILITY ONLY. "
        "It is not the supported v3.2 security target."
    )
endif()

if(SMARTCAR_BUILD_CAMERA_MODULE)
    find_package(OpenCV REQUIRED COMPONENTS core imgproc highgui videoio objdetect)
    add_executable(camera_emergency_brake camera_emergency_brake.cpp)
    target_link_libraries(camera_emergency_brake PRIVATE ${OpenCV_LIBS})
    target_include_directories(camera_emergency_brake PRIVATE ${OpenCV_INCLUDE_DIRS})
    smartcar_apply_release_options(camera_emergency_brake)
endif()
