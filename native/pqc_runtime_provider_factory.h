#pragma once

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>

#include "pqc_active_operations.h"
#include "pqc_hardware_provider.h"
#include "pqc_key_store.h"
#include "pqc_provider_policy.h"
#include "pqc_software_active_operations.h"

#if defined(SMARTCAR_ENABLE_PKCS11_PROVIDER)
#include "pqc_pkcs11_provider.h"
#endif

namespace omniguard {

inline std::shared_ptr<PqcHardwareProvider> make_registered_hardware_pqc_provider(
    const std::string& provider
) {
    if (!is_hardware_pqc_provider_name(provider)) {
        throw std::runtime_error("runtime hardware PQC provider registry received a non-hardware provider name");
    }

#if defined(SMARTCAR_ENABLE_PKCS11_PROVIDER)
    if (provider == kPkcs11PqcProvider) {
        return make_pkcs11_hardware_provider_from_env();
    }
#endif

    // TPM2/HSM remain unavailable until concrete runtime adapters are compiled
    // and validated. A build without SMARTCAR_ENABLE_PKCS11_PROVIDER also keeps
    // PKCS#11 fail-closed. No hardware name ever falls back to software.
    return std::make_shared<UnavailablePqcHardwareProvider>(provider);
}

inline std::unique_ptr<PqcActivePrivateOperations> make_runtime_pqc_private_operations(
    const std::filesystem::path& software_keystore_path,
    const std::string& software_keystore_key,
    const std::string& identity
) {
    if (identity.empty()) {
        throw std::runtime_error("runtime PQC provider factory requires a non-empty identity");
    }

    const std::string requested = requested_pqc_provider_from_env();
    if (requested == kSoftwarePqcProvider) {
        // The software provider is permitted only when the policy explicitly
        // allows it. In particular SMARTCAR_CPP_PQC_HARDWARE_REQUIRED=1 must
        // reject this path before any keystore material is loaded or created.
        (void)enforce_pqc_provider_policy_from_env();
        PqcKeyMaterial material = PqcKeyStore(
            software_keystore_path,
            software_keystore_key,
            identity
        ).load_or_create();
        return std::make_unique<SoftwarePqcActivePrivateOperations>(std::move(material));
    }

    if (!is_hardware_pqc_provider_name(requested)) {
        throw std::runtime_error("runtime PQC provider factory resolved an unsupported provider");
    }

    // An explicit hardware provider request never falls back to the software
    // keystore, even when SMARTCAR_CPP_PQC_HARDWARE_REQUIRED=0. The selected
    // hardware adapter must independently pass its runtime capability probe
    // before any software keystore can be created or used.
    std::shared_ptr<PqcHardwareProvider> hardware = make_registered_hardware_pqc_provider(requested);
    return std::make_unique<HardwarePqcActivePrivateOperations>(std::move(hardware), identity);
}

}  // namespace omniguard
