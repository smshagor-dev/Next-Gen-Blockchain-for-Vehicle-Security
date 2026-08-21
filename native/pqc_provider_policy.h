#pragma once

#include <cstdlib>
#include <stdexcept>
#include <string>

#include "pqc_key_store.h"

namespace omniguard {

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
        PqcKeyStore::kProvider,
        false,
        false,
        true,
    };
}

inline PqcProviderCapabilities enforce_pqc_provider_policy_from_env() {
    const PqcProviderCapabilities capabilities = software_pqc_provider_capabilities();
    const bool hardware_required =
        parse_strict_env_bool("SMARTCAR_CPP_PQC_HARDWARE_REQUIRED", false);
    if (hardware_required && !capabilities.hardware_backed) {
        throw std::runtime_error(
            "hardware-backed PQC provider is required, but only " + capabilities.provider +
            " is implemented; TPM2/PKCS#11/HSM fallback is not simulated"
        );
    }
    return capabilities;
}

}  // namespace omniguard
