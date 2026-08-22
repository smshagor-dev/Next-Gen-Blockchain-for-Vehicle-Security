#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "pqc_hardware_provider.h"
#include "pqc_provider_policy.h"
#include "pqc_sensitive_bytes.h"

namespace omniguard {

struct PqcActivePublicState {
    std::string provider;
    std::string key_id;
    std::string identity;
    std::vector<unsigned char> signature_public_key;
    std::vector<unsigned char> kem_public_key;
    std::uint64_t generation = 0;
    bool hardware_backed = false;
    bool non_exportable = false;
    bool runtime_probe_verified = false;
    std::size_t signature_max_size = 0;
    std::size_t kem_ciphertext_size = 0;
    std::size_t kem_shared_secret_size = 0;
};

inline void validate_active_public_state(const PqcActivePublicState& state) {
    if (state.provider.empty() || state.key_id.empty() || state.identity.empty() ||
        state.signature_public_key.empty() || state.kem_public_key.empty()) {
        throw std::runtime_error("active PQC public state is incomplete");
    }
    if (state.signature_max_size == 0 || state.kem_ciphertext_size == 0 ||
        state.kem_shared_secret_size == 0) {
        throw std::runtime_error("active PQC algorithm size metadata is incomplete");
    }

    if (is_hardware_pqc_provider_name(state.provider)) {
        if (!state.hardware_backed || !state.non_exportable || !state.runtime_probe_verified || state.generation == 0) {
            throw std::runtime_error("hardware PQC active state lacks verified non-exportable hardware evidence");
        }
    } else if (state.provider == kSoftwarePqcProvider) {
        if (state.hardware_backed || state.non_exportable) {
            throw std::runtime_error("software PQC active state cannot claim hardware-backed/non-exportable protection");
        }
    } else {
        throw std::runtime_error("active PQC state references an unknown provider");
    }
}

class PqcActivePrivateOperations {
public:
    virtual ~PqcActivePrivateOperations() = default;

    virtual const PqcActivePublicState& public_state() const = 0;

    virtual std::vector<unsigned char> sign_ml_dsa_44(
        const std::vector<unsigned char>& message
    ) = 0;

    virtual PqcSensitiveBytes decapsulate_ml_kem_512(
        const std::vector<unsigned char>& ciphertext
    ) = 0;
};

class HardwarePqcActivePrivateOperations final : public PqcActivePrivateOperations {
public:
    HardwarePqcActivePrivateOperations(
        std::shared_ptr<PqcHardwareProvider> provider,
        std::string identity
    ) : provider_(std::move(provider)) {
        if (!provider_) {
            throw std::runtime_error("hardware PQC active operations require a provider instance");
        }

        const PqcHardwareProbe probe = provider_->probe();
        const PqcProviderCapabilities capabilities = capabilities_from_verified_hardware_probe(probe);
        if (!capabilities.hardware_backed || !capabilities.non_exportable || !capabilities.runtime_probe_verified) {
            throw std::runtime_error("hardware PQC provider capability verification failed closed");
        }

        PqcHardwarePublicMaterial material = provider_->load_or_create_public(identity);
        validate_hardware_public_material(probe, material, identity);

        device_identity_ = probe.device_identity;
        state_ = {
            material.provider,
            material.key_id,
            material.identity,
            std::move(material.signature_public_key),
            std::move(material.kem_public_key),
            material.generation,
            true,
            true,
            true,
            probe.ml_dsa_44_signature_max_size,
            probe.ml_kem_512_ciphertext_size,
            probe.ml_kem_512_shared_secret_size,
        };
        validate_active_public_state(state_);
    }

    const PqcActivePublicState& public_state() const override {
        return state_;
    }

    std::vector<unsigned char> sign_ml_dsa_44(
        const std::vector<unsigned char>& message
    ) override {
        verify_live_provider_binding();
        std::vector<unsigned char> signature = provider_->sign_ml_dsa_44(state_.key_id, message);
        if (signature.empty() || signature.size() > state_.signature_max_size) {
            throw std::runtime_error("hardware ML-DSA-44 provider returned an invalid signature size");
        }
        return signature;
    }

    PqcSensitiveBytes decapsulate_ml_kem_512(
        const std::vector<unsigned char>& ciphertext
    ) override {
        verify_live_provider_binding();
        if (ciphertext.size() != state_.kem_ciphertext_size) {
            throw std::runtime_error("hardware ML-KEM-512 ciphertext size is invalid");
        }
        PqcSensitiveBytes secret = provider_->decapsulate_ml_kem_512(state_.key_id, ciphertext);
        if (secret.size() != state_.kem_shared_secret_size) {
            secret.clear();
            throw std::runtime_error("hardware ML-KEM-512 provider returned an invalid shared-secret size");
        }
        return secret;
    }

private:
    void verify_live_provider_binding() const {
        const PqcHardwareProbe probe = provider_->probe();
        (void)capabilities_from_verified_hardware_probe(probe);
        if (probe.provider != state_.provider || probe.device_identity != device_identity_ ||
            probe.ml_dsa_44_signature_max_size != state_.signature_max_size ||
            probe.ml_kem_512_ciphertext_size != state_.kem_ciphertext_size ||
            probe.ml_kem_512_shared_secret_size != state_.kem_shared_secret_size) {
            throw std::runtime_error("hardware PQC provider binding changed after activation");
        }
    }

    std::shared_ptr<PqcHardwareProvider> provider_;
    std::string device_identity_;
    PqcActivePublicState state_;
};

}  // namespace omniguard
