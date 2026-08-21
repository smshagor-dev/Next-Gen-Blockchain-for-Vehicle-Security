#pragma once

#include <cstdlib>
#include <stdexcept>
#include <string>

namespace omniguard {

inline constexpr const char* kSoftwarePqcProvider = "software_encrypted_file";

struct PqcProviderCapabilities {
    std::string provider;
    bool hardware_backed = false;
    bool non_exportable = false;
    bool rotation_supported = true;
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

inline PqcProviderCapabilities software_pqc_provider_capabilities() {
    return {
        kSoftwarePqcProvider,
        false,
        false,
        true,
    };
}

inline PqcProviderCapabilities enforce_pqc_provider_policy(bool hardware_required) {
    const PqcProviderCapabilities capabilities = software_pqc_provider_capabilities();
    if (hardware_required && !capabilities.hardware_backed) {
        throw std::runtime_error(
            "hardware-backed PQC provider is required, but only " + capabilities.provider +
            " is implemented; TPM2/PKCS11/HSM fallback is not simulated"
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
