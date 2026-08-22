#pragma once

#include <string>
#include <vector>

namespace omniguard {

struct PqcKeyMaterial {
    std::string key_id;
    std::string identity;
    std::vector<unsigned char> signature_public_key;
    std::vector<unsigned char> signature_secret_key;
    std::vector<unsigned char> kem_public_key;
    std::vector<unsigned char> kem_secret_key;

    PqcKeyMaterial() = default;
    PqcKeyMaterial(const PqcKeyMaterial&) = delete;
    PqcKeyMaterial& operator=(const PqcKeyMaterial&) = delete;
    PqcKeyMaterial(PqcKeyMaterial&& other) noexcept;
    PqcKeyMaterial& operator=(PqcKeyMaterial&& other) noexcept;
    ~PqcKeyMaterial();
};

}  // namespace omniguard
