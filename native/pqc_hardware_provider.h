#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "pqc_provider_policy.h"

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
    bool rotation_supported = false;
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
    if (!probe.rotation_supported) {
        throw std::runtime_error("PQC hardware provider does not support guarded key rotation");
    }
    if (probe.device_identity.empty() || probe.evidence_reference.empty()) {
        throw std::runtime_error("PQC hardware provider probe lacks device/evidence identity");
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

    // Sign and decapsulation are executed by the hardware backend. Private key
    // bytes must never be returned to the runtime or written to the filesystem.
    virtual std::vector<unsigned char> sign_ml_dsa_44(
        const std::string& key_id,
        const std::vector<unsigned char>& message
    ) = 0;

    virtual std::vector<unsigned char> decapsulate_ml_kem_512(
        const std::string& key_id,
        const std::vector<unsigned char>& ciphertext
    ) = 0;

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

    std::vector<unsigned char> decapsulate_ml_kem_512(
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
