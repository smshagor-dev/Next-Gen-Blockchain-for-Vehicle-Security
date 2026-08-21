#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "pqc_provider_policy.h"

namespace omniguard {

struct PqcKeyMaterial {
    std::string key_id;
    std::string identity;
    std::vector<unsigned char> signature_public_key;
    std::vector<unsigned char> signature_secret_key;
    std::vector<unsigned char> kem_public_key;
    std::vector<unsigned char> kem_secret_key;

    PqcKeyMaterial() = default;
    PqcKeyMaterial(const PqcKeyMaterial&) = delete;
    PqcKeyMaterial& operator=(const PqcKeyMaterial&) = delete;
    PqcKeyMaterial(PqcKeyMaterial&& other) noexcept;
    PqcKeyMaterial& operator=(PqcKeyMaterial&& other) noexcept;
    ~PqcKeyMaterial();
};

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
