#pragma once

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <stdexcept>
#include <string>

namespace omniguard {

inline constexpr const char* kSoftwarePqcProvider = "software_encrypted_file";
inline constexpr const char* kTpm2PqcProvider = "tpm2";
inline constexpr const char* kPkcs11PqcProvider = "pkcs11";
inline constexpr const char* kHsmPqcProvider = "hsm";

struct PqcProviderCapabilities {
    std::string provider;
    bool hardware_backed = false;
    bool non_exportable = false;
    bool rotation_supported = false;
    bool implemented = false;
    bool available = false;
    bool supports_ml_dsa_44 = false;
    bool supports_ml_kem_512 = false;
    bool runtime_probe_verified = false;
};

inline bool parse_strict_env_bool(const char* name, bool default_value = false) {
    const char* raw = std::getenv(name);
    if (raw == nullptr || *raw == '\0') {
        return default_value;
    }
    const std::string value(raw);
    if (value == "1" || value == "true" || value == "TRUE") {
        return true;
    }
    if (value == "0" || value == "false" || value == "FALSE") {
        return false;
    }
    throw std::runtime_error(std::string("invalid boolean policy value for ") + name);
}

inline bool is_hardware_pqc_provider_name(const std::string& provider) {
    return provider == kTpm2PqcProvider || provider == kPkcs11PqcProvider || provider == kHsmPqcProvider;
}

inline std::string requested_pqc_provider_from_env() {
    const char* raw = std::getenv("SMARTCAR_CPP_PQC_PROVIDER");
    std::string provider = raw == nullptr || *raw == '\0' ? kSoftwarePqcProvider : std::string(raw);
    std::transform(provider.begin(), provider.end(), provider.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (provider != kSoftwarePqcProvider && !is_hardware_pqc_provider_name(provider)) {
        throw std::runtime_error("SMARTCAR_CPP_PQC_PROVIDER must be software_encrypted_file, tpm2, pkcs11, or hsm");
    }
    return provider;
}

inline PqcProviderCapabilities pqc_provider_capabilities(const std::string& provider) {
    if (provider == kSoftwarePqcProvider) {
        return {
            provider,
            false,
            false,
            true,
            true,
            true,
            true,
            true,
            true,
        };
    }
    if (!is_hardware_pqc_provider_name(provider)) {
        throw std::runtime_error("unknown PQC provider capability request");
    }

    // A configured hardware provider name is an intent, not evidence that a
    // hardware-backed key exists. Until a concrete adapter completes its
    // runtime probe and proves ML-DSA-44 + ML-KEM-512 non-exportable
    // operations, every positive hardware capability stays false.
    return {
        provider,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    };
}

inline PqcProviderCapabilities software_pqc_provider_capabilities() {
    return pqc_provider_capabilities(kSoftwarePqcProvider);
}

inline PqcProviderCapabilities enforce_pqc_provider_policy(bool hardware_required) {
    const std::string requested = requested_pqc_provider_from_env();
    const PqcProviderCapabilities capabilities = pqc_provider_capabilities(requested);
    if (!capabilities.implemented || !capabilities.available || !capabilities.runtime_probe_verified) {
        throw std::runtime_error(
            "requested PQC provider '" + requested +
            "' is not implemented/available/runtime-verified in this build; hardware provider fallback is never simulated"
        );
    }
    if (!capabilities.supports_ml_dsa_44 || !capabilities.supports_ml_kem_512) {
        throw std::runtime_error(
            "active PQC provider does not support the required ML-DSA-44 and ML-KEM-512 operations"
        );
    }
    if (hardware_required && (!capabilities.hardware_backed || !capabilities.non_exportable)) {
        throw std::runtime_error(
            "hardware-backed non-exportable PQC provider is required, but active provider '" + capabilities.provider +
            "' does not have runtime-verified hardware protection; software fallback is prohibited"
        );
    }
    return capabilities;
}

inline PqcProviderCapabilities enforce_pqc_provider_policy_from_env() {
    return enforce_pqc_provider_policy(
        parse_strict_env_bool("SMARTCAR_CPP_PQC_HARDWARE_REQUIRED", false)
    );
}

struct PqcProviderPolicyGuard {
    PqcProviderPolicyGuard() {
        (void)enforce_pqc_provider_policy_from_env();
    }
};

}  // namespace omniguard
