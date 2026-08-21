#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "pqc_key_store.h"

namespace omniguard {

struct PqcTrustedIdentity {
    std::uint64_t generation = 0;
    std::string key_id;
    std::string identity;
    std::vector<unsigned char> signature_public_key;
    std::vector<unsigned char> kem_public_key;
};

struct PqcTrustKeyringMetadata {
    std::string format;
    std::string identity;
    std::size_t generation_count = 0;
    std::size_t max_generations = 0;
    std::uint64_t active_generation = 0;
    std::string active_key_id;
    bool rollback_protected_by_active_key_binding = true;
    bool secret_key_material_stored = false;
};

class PqcTrustKeyring {
public:
    static constexpr const char* kFormat = "OMNIGUARD_PQC_TRUST_KEYRING_V1";
    static constexpr const char* kRootDomain = "OMNIGUARD_PQC_TRUST_ROOT_V1";
    static constexpr const char* kTransitionDomain = "OMNIGUARD_PQC_KEY_TRANSITION_V1";
    static constexpr std::size_t kDefaultMaxGenerations = 8;
    static constexpr std::size_t kAbsoluteMaxGenerations = 16;

    PqcTrustKeyring(
        std::filesystem::path path,
        std::string identity,
        std::size_t max_generations = kDefaultMaxGenerations
    );

    void initialize_root(const PqcKeyMaterial& root_material) const;
    void append_transition(
        const PqcKeyMaterial& previous_material,
        const PqcKeyMaterial& new_material,
        const std::string& reason
    ) const;

    PqcTrustKeyringMetadata inspect(const std::string& expected_active_key_id = {}) const;
    std::vector<PqcTrustedIdentity> trusted_identities(
        const std::string& expected_active_key_id = {}
    ) const;

    bool verify_detached_signature(
        const std::string& key_id,
        const std::string& message,
        const std::vector<unsigned char>& signature,
        const std::vector<unsigned char>& embedded_signature_public_key,
        const std::vector<unsigned char>& embedded_kem_public_key,
        const std::string& expected_active_key_id = {}
    ) const;

private:
    std::filesystem::path path_;
    std::string identity_;
    std::size_t max_generations_;
};

}  // namespace omniguard
