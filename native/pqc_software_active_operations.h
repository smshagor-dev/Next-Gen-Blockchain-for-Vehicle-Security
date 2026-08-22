#pragma once

#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

#include <oqs/oqs.h>

#include "pqc_active_operations.h"
#include "pqc_key_material.h"
#include "pqc_sensitive_bytes.h"

namespace omniguard {

struct SoftwareActiveSigDeleter {
    void operator()(OQS_SIG* value) const { OQS_SIG_free(value); }
};

struct SoftwareActiveKemDeleter {
    void operator()(OQS_KEM* value) const { OQS_KEM_free(value); }
};

using SoftwareActiveSigPtr = std::unique_ptr<OQS_SIG, SoftwareActiveSigDeleter>;
using SoftwareActiveKemPtr = std::unique_ptr<OQS_KEM, SoftwareActiveKemDeleter>;

class SoftwarePqcActivePrivateOperations final : public PqcActivePrivateOperations {
public:
    explicit SoftwarePqcActivePrivateOperations(PqcKeyMaterial material) {
        signature_.reset(OQS_SIG_new(OQS_SIG_alg_ml_dsa_44));
        kem_.reset(OQS_KEM_new(OQS_KEM_alg_ml_kem_512));
        if (!signature_ || !kem_) {
            throw std::runtime_error("required liboqs algorithms are unavailable for software PQC provider");
        }

        if (material.identity.empty() || material.key_id.empty() ||
            material.signature_public_key.size() != signature_->length_public_key ||
            material.signature_secret_key.size() != signature_->length_secret_key ||
            material.kem_public_key.size() != kem_->length_public_key ||
            material.kem_secret_key.size() != kem_->length_secret_key) {
            throw std::runtime_error("software PQC key material is incomplete or incompatible");
        }

        state_ = {
            kSoftwarePqcProvider,
            std::move(material.key_id),
            std::move(material.identity),
            std::move(material.signature_public_key),
            std::move(material.kem_public_key),
            0,
            false,
            false,
            true,
            signature_->length_signature,
            kem_->length_ciphertext,
            kem_->length_shared_secret,
        };
        signature_secret_key_ = PqcSensitiveBytes(std::move(material.signature_secret_key));
        kem_secret_key_ = PqcSensitiveBytes(std::move(material.kem_secret_key));
        validate_active_public_state(state_);
    }

    SoftwarePqcActivePrivateOperations(const SoftwarePqcActivePrivateOperations&) = delete;
    SoftwarePqcActivePrivateOperations& operator=(const SoftwarePqcActivePrivateOperations&) = delete;
    SoftwarePqcActivePrivateOperations(SoftwarePqcActivePrivateOperations&&) = delete;
    SoftwarePqcActivePrivateOperations& operator=(SoftwarePqcActivePrivateOperations&&) = delete;

    const PqcActivePublicState& public_state() const override {
        return state_;
    }

    std::vector<unsigned char> sign_ml_dsa_44(
        const std::vector<unsigned char>& message
    ) override {
        std::vector<unsigned char> signature(state_.signature_max_size);
        std::size_t signature_length = 0;
        if (OQS_SIG_sign(
                signature_.get(),
                signature.data(),
                &signature_length,
                message.data(),
                message.size(),
                signature_secret_key_.data()
            ) != OQS_SUCCESS) {
            throw std::runtime_error("software ML-DSA-44 signing failed");
        }
        if (signature_length == 0 || signature_length > signature.size()) {
            throw std::runtime_error("software ML-DSA-44 returned an invalid signature size");
        }
        signature.resize(signature_length);
        return signature;
    }

    PqcSensitiveBytes decapsulate_ml_kem_512(
        const std::vector<unsigned char>& ciphertext
    ) override {
        if (ciphertext.size() != state_.kem_ciphertext_size) {
            throw std::runtime_error("software ML-KEM-512 ciphertext size is invalid");
        }
        std::vector<unsigned char> shared_secret(state_.kem_shared_secret_size);
        if (OQS_KEM_decaps(
                kem_.get(),
                shared_secret.data(),
                ciphertext.data(),
                kem_secret_key_.data()
            ) != OQS_SUCCESS) {
            secure_zero_bytes(shared_secret.data(), shared_secret.size());
            throw std::runtime_error("software ML-KEM-512 decapsulation failed");
        }
        return PqcSensitiveBytes(std::move(shared_secret));
    }

private:
    SoftwareActiveSigPtr signature_;
    SoftwareActiveKemPtr kem_;
    PqcActivePublicState state_;
    PqcSensitiveBytes signature_secret_key_;
    PqcSensitiveBytes kem_secret_key_;
};

}  // namespace omniguard
