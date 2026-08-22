cmake_minimum_required(VERSION 3.16)

project(SmartCarBlockchain VERSION 3.0.3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(SMARTCAR_BUILD_BLOCKCHAIN "Build the hardened v3.0.3 native blockchain runtime" ON)
option(SMARTCAR_BUILD_PQC_KEYSTORE_SELFTEST "Build the durable PQC keystore validation target" OFF)
option(SMARTCAR_BUILD_PQC_KEY_ADMIN "Build the local guarded PQC key administration tool" OFF)
option(SMARTCAR_BUILD_PQC_TRUST_ADMIN "Build the explicit PQC trust-keyring administration tool" OFF)
option(SMARTCAR_BUILD_PQC_HISTORY_VERIFY "Build the persisted historical PQC ledger verifier" OFF)
option(SMARTCAR_BUILD_PQC_STATE_ADMIN "Build local PQC rollback/recovery state administration" OFF)
option(SMARTCAR_BUILD_CAMERA_MODULE "Build camera_emergency_brake.cpp (OpenCV required)" OFF)
option(SMARTCAR_ENABLE_WARNINGS "Enable extra compiler warnings" ON)
option(SMARTCAR_ENABLE_NATIVE_OPT "Enable host-specific -march=native Release optimizations" OFF)
option(SMARTCAR_ENABLE_UNSAFE_FAST_MATH "Enable -ffast-math for controlled performance experiments only" OFF)
option(SMARTCAR_ENABLE_IPO "Enable interprocedural optimization/LTO when supported" OFF)
option(SMARTCAR_FETCH_PINNED_LIBOQS "Fetch pinned liboqs 0.16.0 when no system package is available" OFF)
option(SMARTCAR_FORCE_PQC_UNAVAILABLE_FOR_TESTS "Pretend liboqs is unavailable to validate fail-closed CMake behavior" OFF)
option(SMARTCAR_ENFORCE_VALIDATION_TOOLCHAIN "Require the hosted validation compiler family/version" OFF)
option(SMARTCAR_ENABLE_PKCS11_PROVIDER "Compile the opt-in PKCS#11 v3.2 hardware PQC provider" OFF)

set(SMARTCAR_LIBOQS_VERSION "0.16.0")
set(SMARTCAR_LIBOQS_COMMIT "5a1a854b0dc9f2141bdc771c555ee60c37950183")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(SMARTCAR_ENFORCE_VALIDATION_TOOLCHAIN)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        message(FATAL_ERROR "Validation toolchain requires GNU C++.")
    endif()
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "13.3" OR CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "14")
        message(FATAL_ERROR "Validation toolchain requires GCC 13.3.x.")
    endif()
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

if(SMARTCAR_BUILD_BLOCKCHAIN OR
   SMARTCAR_BUILD_PQC_KEYSTORE_SELFTEST OR
   SMARTCAR_BUILD_PQC_KEY_ADMIN OR
   SMARTCAR_BUILD_PQC_TRUST_ADMIN OR
   SMARTCAR_BUILD_PQC_HISTORY_VERIFY OR
   SMARTCAR_BUILD_PQC_STATE_ADMIN)
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
endif()

if(SMARTCAR_ENABLE_PKCS11_PROVIDER)
    find_path(
        SMARTCAR_PKCS11_INCLUDE_DIR
        NAMES pkcs11.h
        PATH_SUFFIXES p11-kit p11-kit-1/p11-kit
    )
    if(NOT SMARTCAR_PKCS11_INCLUDE_DIR)
        message(FATAL_ERROR
            "SMARTCAR_ENABLE_PKCS11_PROVIDER=ON requires a PKCS#11 v3.2 development header (pkcs11.h). "
            "The header must define the standardized ML-DSA/ML-KEM v3.2 mechanisms."
        )
    endif()
endif()

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

function(smartcar_require_real_pqc target_label)
    if(NOT SMARTCAR_LIBOQS_TARGET)
        message(FATAL_ERROR
            "Real liboqs is required for ${target_label}. "
            "Install liboqs ${SMARTCAR_LIBOQS_VERSION}, or set SMARTCAR_FETCH_PINNED_LIBOQS=ON to fetch commit ${SMARTCAR_LIBOQS_COMMIT}. "
            "Simulated PQC is not available in the supported v3.0.3 build graph."
        )
    endif()
endfunction()

if(SMARTCAR_BUILD_BLOCKCHAIN)
    smartcar_require_real_pqc("the hardened native blockchain target")
    add_executable(
        smartcar_blockchain
        native/secure_blockchain_v303.cpp
        native/pqc_key_store.cpp
        native/pqc_trust_keyring.cpp
        native/pqc_state_guard.cpp
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
    if(SMARTCAR_ENABLE_PKCS11_PROVIDER)
        target_sources(smartcar_blockchain PRIVATE native/pqc_pkcs11_provider.cpp)
        target_include_directories(smartcar_blockchain PRIVATE ${SMARTCAR_PKCS11_INCLUDE_DIR})
        target_compile_definitions(smartcar_blockchain PRIVATE SMARTCAR_ENABLE_PKCS11_PROVIDER=1)
        target_link_libraries(smartcar_blockchain PRIVATE ${CMAKE_DL_LIBS})
        message(STATUS
            "PKCS#11 v3.2 provider compiled: runtime still requires a real CKF_HW_SLOT token and operational ML-DSA-44/ML-KEM-512 proof before claiming hardware-backed protection."
        )
    endif()
    smartcar_apply_release_options(smartcar_blockchain)
    message(STATUS
        "Hardened native target ${PROJECT_VERSION}: persisted mixed-generation verification + AES-256-GCM + real ML-DSA-44/ML-KEM-512 + optional authenticated rollback anchor."
    )
endif()

if(SMARTCAR_BUILD_PQC_KEYSTORE_SELFTEST)
    smartcar_require_real_pqc("smartcar_pqc_keystore_selftest")
    add_executable(
        smartcar_pqc_keystore_selftest
        native/pqc_key_store.cpp
        native/pqc_key_store_selftest.cpp
    )
    target_include_directories(smartcar_pqc_keystore_selftest PRIVATE native)
    target_link_libraries(smartcar_pqc_keystore_selftest PRIVATE nlohmann_json::nlohmann_json OpenSSL::Crypto ${SMARTCAR_LIBOQS_TARGET})
    smartcar_apply_release_options(smartcar_pqc_keystore_selftest)
endif()

if(SMARTCAR_BUILD_PQC_KEY_ADMIN)
    smartcar_require_real_pqc("smartcar_pqc_key_admin")
    add_executable(
        smartcar_pqc_key_admin
        native/pqc_key_store.cpp
        native/pqc_key_admin.cpp
    )
    target_include_directories(smartcar_pqc_key_admin PRIVATE native)
    target_link_libraries(smartcar_pqc_key_admin PRIVATE nlohmann_json::nlohmann_json OpenSSL::Crypto ${SMARTCAR_LIBOQS_TARGET})
    smartcar_apply_release_options(smartcar_pqc_key_admin)
    message(STATUS "Building local smartcar_pqc_key_admin: explicit operator rotation only; no remote key-rotation API.")
endif()

if(SMARTCAR_BUILD_PQC_TRUST_ADMIN)
    smartcar_require_real_pqc("smartcar_pqc_trust_admin")
    add_executable(
        smartcar_pqc_trust_admin
        native/pqc_key_store.cpp
        native/pqc_trust_keyring.cpp
        native/pqc_trust_admin.cpp
    )
    target_include_directories(smartcar_pqc_trust_admin PRIVATE native)
    target_link_libraries(smartcar_pqc_trust_admin PRIVATE nlohmann_json::nlohmann_json OpenSSL::Crypto ${SMARTCAR_LIBOQS_TARGET})
    smartcar_apply_release_options(smartcar_pqc_trust_admin)
    message(STATUS "Building local smartcar_pqc_trust_admin: explicit signed trust mutation only; no remote trust API.")
endif()

if(SMARTCAR_BUILD_PQC_HISTORY_VERIFY)
    smartcar_require_real_pqc("smartcar_pqc_history_verify")
    add_executable(
        smartcar_pqc_history_verify
        native/pqc_key_store.cpp
        native/pqc_trust_keyring.cpp
        native/pqc_history_verifier.cpp
    )
    target_include_directories(smartcar_pqc_history_verify PRIVATE native)
    target_link_libraries(smartcar_pqc_history_verify PRIVATE nlohmann_json::nlohmann_json OpenSSL::Crypto ${SMARTCAR_LIBOQS_TARGET})
    smartcar_apply_release_options(smartcar_pqc_history_verify)
endif()

if(SMARTCAR_BUILD_PQC_STATE_ADMIN)
    smartcar_require_real_pqc("smartcar_pqc_state_admin")
    add_executable(
        smartcar_pqc_state_admin
        native/pqc_key_store.cpp
        native/pqc_trust_keyring.cpp
        native/pqc_state_guard.cpp
        native/pqc_state_admin.cpp
    )
    target_include_directories(smartcar_pqc_state_admin PRIVATE native)
    target_link_libraries(smartcar_pqc_state_admin PRIVATE nlohmann_json::nlohmann_json OpenSSL::Crypto ${SMARTCAR_LIBOQS_TARGET})
    smartcar_apply_release_options(smartcar_pqc_state_admin)
    message(STATUS
        "Building smartcar_pqc_state_admin: local authenticated rollback-anchor and recovery-check tooling; automatic historical-key restore is prohibited."
    )
endif()

if(SMARTCAR_BUILD_CAMERA_MODULE)
    find_package(OpenCV REQUIRED COMPONENTS core imgproc highgui videoio objdetect)
    add_executable(camera_emergency_brake camera_emergency_brake.cpp)
    target_link_libraries(camera_emergency_brake PRIVATE ${OpenCV_LIBS})
    target_include_directories(camera_emergency_brake PRIVATE ${OpenCV_INCLUDE_DIRS})
    smartcar_apply_release_options(camera_emergency_brake)
endif()
