#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "pqc_kem_commitment.h"
#include "pqc_provider_policy.h"
#include "pqc_sensitive_bytes.h"

namespace omniguard {

struct PqcHardwareProbe {
    std::string provider;
    std::string device_identity;
    std::string evidence_reference;
    bool backend_loaded = false;
    bool token_present = false;
    bool hardware_mechanisms = false;
    bool private_keys_non_exportable = false;
    bool ml_dsa_44_key_generation = false;
    bool ml_dsa_44_sign = false;
    bool ml_kem_512_key_generation = false;
    bool ml_kem_512_decapsulate = false;
    bool ml_kem_512_derived_secret_non_exportable = false;
    bool ml_kem_512_sha3_256_raw_commitment = false;
    bool rotation_supported = false;
    std::size_t ml_dsa_44_signature_max_size = 0;
    std::size_t ml_kem_512_ciphertext_size = 0;
    std::size_t ml_kem_512_shared_secret_size = 0;
};

struct PqcHardwarePublicMaterial {
    std::string provider;
    std::string key_id;
    std::string identity;
    std::vector<unsigned char> signature_public_key;
    std::vector<unsigned char> kem_public_key;
    std::uint64_t generation = 0;
};

inline void validate_hardware_probe(const PqcHardwareProbe& probe) {
    if (!is_hardware_pqc_provider_name(probe.provider)) {
        throw std::runtime_error("PQC hardware probe returned a non-hardware provider name");
    }
    if (!probe.backend_loaded || !probe.token_present || !probe.hardware_mechanisms) {
        throw std::runtime_error("PQC hardware backend/token/mechanism probe failed");
    }
    if (!probe.private_keys_non_exportable) {
        throw std::runtime_error("PQC hardware provider did not prove non-exportable private-key policy");
    }
    if (!probe.ml_dsa_44_key_generation || !probe.ml_dsa_44_sign ||
        !probe.ml_kem_512_key_generation || !probe.ml_kem_512_decapsulate) {
        throw std::runtime_error("PQC hardware provider lacks required ML-DSA-44/ML-KEM-512 operations");
    }
    if (!probe.ml_kem_512_derived_secret_non_exportable || !probe.ml_kem_512_sha3_256_raw_commitment) {
        throw std::runtime_error(
            "PQC hardware provider cannot keep the ML-KEM derived secret non-exportable while producing the required commitment"
        );
    }
    if (!probe.rotation_supported) {
        throw std::runtime_error("PQC hardware provider does not support guarded key rotation");
    }
    if (probe.device_identity.empty() || probe.evidence_reference.empty()) {
        throw std::runtime_error("PQC hardware provider probe lacks device/evidence identity");
    }
    if (probe.ml_dsa_44_signature_max_size == 0 || probe.ml_kem_512_ciphertext_size == 0 ||
        probe.ml_kem_512_shared_secret_size == 0) {
        throw std::runtime_error("PQC hardware provider probe lacks required algorithm size metadata");
    }
}

inline void validate_hardware_public_material(
    const PqcHardwareProbe& probe,
    const PqcHardwarePublicMaterial& material,
    const std::string& expected_identity
) {
    validate_hardware_probe(probe);
    if (material.provider != probe.provider || !is_hardware_pqc_provider_name(material.provider)) {
        throw std::runtime_error("PQC hardware public material/provider binding is invalid");
    }
    if (expected_identity.empty() || material.identity != expected_identity) {
        throw std::runtime_error("PQC hardware public material/identity binding is invalid");
    }
    if (material.key_id.empty() || material.generation == 0 ||
        material.signature_public_key.empty() || material.kem_public_key.empty()) {
        throw std::runtime_error("PQC hardware public material is incomplete");
    }
}

inline PqcProviderCapabilities capabilities_from_verified_hardware_probe(const PqcHardwareProbe& probe) {
    validate_hardware_probe(probe);
    return {
        probe.provider,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
    };
}

class PqcHardwareProvider {
public:
    virtual ~PqcHardwareProvider() = default;

    virtual PqcHardwareProbe probe() const = 0;

    // Only public key material and opaque identifiers may cross this boundary.
    // Implementations must create or locate private keys inside the TPM/HSM/token.
    virtual PqcHardwarePublicMaterial load_or_create_public(const std::string& identity) = 0;

    virtual std::vector<unsigned char> sign_ml_dsa_44(
        const std::string& key_id,
        const std::vector<unsigned char>& message
    ) = 0;

    // Preferred hardware KEM boundary. The provider decapsulates inside the
    // device and returns only SHA3-256(prefix || raw_shared_secret). A PKCS#11
    // implementation can realize this with C_DecapsulateKey followed by
    // C_DigestInit/C_DigestUpdate/C_DigestKey/C_DigestFinal, without exporting
    // the derived shared-secret object.
    virtual PqcKemCommitment decapsulate_ml_kem_512_commitment(
        const std::string& key_id,
        const std::vector<unsigned char>& ciphertext,
        const std::string& commitment_prefix
    ) = 0;

    // Transitional legacy hook for the current V1 ledger commitment, which
    // hashes hex(shared_secret). A real non-exportable hardware provider is not
    // required to implement this method and should normally leave it rejected.
    virtual PqcSensitiveBytes decapsulate_ml_kem_512(
        const std::string&,
        const std::vector<unsigned char>&
    ) {
        throw std::runtime_error(
            "raw ML-KEM shared-secret export is unavailable for this hardware provider; use the V2 commitment path"
        );
    }

    virtual PqcHardwarePublicMaterial rotate(const std::string& identity) = 0;

    PqcProviderCapabilities verified_capabilities() const {
        return capabilities_from_verified_hardware_probe(probe());
    }
};

class UnavailablePqcHardwareProvider final : public PqcHardwareProvider {
public:
    explicit UnavailablePqcHardwareProvider(std::string provider) : provider_(std::move(provider)) {
        if (!is_hardware_pqc_provider_name(provider_)) {
            throw std::runtime_error("unavailable PQC hardware provider name is invalid");
        }
    }

    PqcHardwareProbe probe() const override {
        PqcHardwareProbe result;
        result.provider = provider_;
        return result;
    }

    PqcHardwarePublicMaterial load_or_create_public(const std::string&) override {
        fail();
    }

    std::vector<unsigned char> sign_ml_dsa_44(
        const std::string&,
        const std::vector<unsigned char>&
    ) override {
        fail();
    }

    PqcKemCommitment decapsulate_ml_kem_512_commitment(
        const std::string&,
        const std::vector<unsigned char>&,
        const std::string&
    ) override {
        fail();
    }

    PqcSensitiveBytes decapsulate_ml_kem_512(
        const std::string&,
        const std::vector<unsigned char>&
    ) override {
        fail();
    }

    PqcHardwarePublicMaterial rotate(const std::string&) override {
        fail();
    }

private:
    [[noreturn]] void fail() const {
        throw std::runtime_error(
            "requested PQC hardware provider '" + provider_ +
            "' has no runtime-verified adapter; software fallback is prohibited"
        );
    }

    std::string provider_;
};

}  // namespace omniguard
