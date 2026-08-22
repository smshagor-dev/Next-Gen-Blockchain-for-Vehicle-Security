#pragma once

#include <memory>

#include "pqc_hardware_provider.h"

namespace omniguard {

// Construct the runtime PKCS #11 v3.2 provider from process configuration.
// Construction performs module/interface/slot/session preflight only. Identity-
// specific keys are loaded or generated later by HardwarePqcActivePrivateOperations.
std::shared_ptr<PqcHardwareProvider> make_pkcs11_hardware_provider_from_env();

}  // namespace omniguard
