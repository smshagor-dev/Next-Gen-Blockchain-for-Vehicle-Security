#pragma once

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include "pqc_active_operations.h"
#include "pqc_hardware_provider.h"
#include "pqc_key_material.h"
#include "pqc_provider_policy.h"
#include "pqc_software_active_operations.h"

namespace omniguard {

struct PqcKeyStoreMetadata {
    std::string format;
    std::string provider;
    std::string key_id;
    std::string identity;
    std::string signature_algorithm;
    std::string kem_algorithm;
    bool hardware_backed = false;
    bool non_exportable = false;
};

class PqcKeyStore {
public:
    static constexpr const char* kFormat = "OMNIGUARD_PQC_KEYSTORE_V1";
    static constexpr const char* kProvider = "software_encrypted_file";
    static constexpr const char* kSignatureAlgorithm = "ML-DSA-44";
    static constexpr const char* kKemAlgorithm = "ML-KEM-512";

    PqcKeyStore(
        std::filesystem::path path,
        std::string wrapping_secret,
        std::string identity
    );
    ~PqcKeyStore();

    PqcKeyStore(const PqcKeyStore&) = delete;
    PqcKeyStore& operator=(const PqcKeyStore&) = delete;

    PqcKeyMaterial load_or_create() const;
    PqcKeyStoreMetadata inspect() const;

private:
    PqcProviderPolicyGuard provider_policy_guard_;
    std::filesystem::path path_;
    std::string wrapping_secret_;
    std::string identity_;
};

}  // namespace omniguard
