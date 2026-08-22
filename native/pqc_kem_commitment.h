#pragma once

#include <cstddef>
#include <stdexcept>
#include <string>

#include <openssl/evp.h>

#include "pqc_sensitive_bytes.h"

namespace omniguard {

inline constexpr const char* kKemCommitmentLegacyV1 =
    "OMNIGUARD_ML_KEM_SHARED_SECRET_COMMITMENT_V1_SHA3_256_HEX";
inline constexpr const char* kKemCommitmentRawV2 =
    "OMNIGUARD_ML_KEM_SHARED_SECRET_COMMITMENT_V2_SHA3_256_RAW";

struct PqcKemCommitment {
    std::string scheme;
    std::string digest_hex;
};

inline bool is_lower_hex_256(const std::string& value) {
    if (value.size() != 64) return false;
    for (const char ch : value) {
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
    }
    return true;
}

inline std::string commitment_bytes_to_hex(const unsigned char* data, std::size_t size) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string output(size * 2, '0');
    for (std::size_t i = 0; i < size; ++i) {
        output[i * 2] = kHex[(data[i] >> 4) & 0x0f];
        output[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return output;
}

inline std::string sha3_256_commitment_hex(
    const std::string& prefix,
    const unsigned char* secret,
    std::size_t secret_size,
    bool encode_secret_as_hex
) {
    if (prefix.empty() || secret == nullptr || secret_size == 0) {
        throw std::runtime_error("ML-KEM commitment input is incomplete");
    }

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("ML-KEM commitment digest context allocation failed");
    }

    unsigned char digest[32]{};
    unsigned int digest_size = 0;
    bool ok = EVP_DigestInit_ex(context, EVP_sha3_256(), nullptr) == 1 &&
              EVP_DigestUpdate(context, prefix.data(), prefix.size()) == 1;
    std::string secret_hex;
    if (ok && encode_secret_as_hex) {
        secret_hex = commitment_bytes_to_hex(secret, secret_size);
        ok = EVP_DigestUpdate(context, secret_hex.data(), secret_hex.size()) == 1;
    } else if (ok) {
        ok = EVP_DigestUpdate(context, secret, secret_size) == 1;
    }
    if (ok) {
        ok = EVP_DigestFinal_ex(context, digest, &digest_size) == 1 && digest_size == sizeof(digest);
    }
    EVP_MD_CTX_free(context);
    if (!secret_hex.empty()) {
        secure_zero_bytes(reinterpret_cast<unsigned char*>(secret_hex.data()), secret_hex.size());
    }
    if (!ok) {
        secure_zero_bytes(digest, sizeof(digest));
        throw std::runtime_error("ML-KEM commitment digest failed");
    }

    const std::string output = commitment_bytes_to_hex(digest, sizeof(digest));
    secure_zero_bytes(digest, sizeof(digest));
    return output;
}

inline PqcKemCommitment make_kem_commitment(
    const std::string& scheme,
    const std::string& prefix,
    const unsigned char* secret,
    std::size_t secret_size
) {
    if (scheme == kKemCommitmentLegacyV1) {
        return {scheme, sha3_256_commitment_hex(prefix, secret, secret_size, true)};
    }
    if (scheme == kKemCommitmentRawV2) {
        return {scheme, sha3_256_commitment_hex(prefix, secret, secret_size, false)};
    }
    throw std::runtime_error("unsupported ML-KEM shared-secret commitment scheme");
}

inline void validate_kem_commitment(const PqcKemCommitment& commitment) {
    if (commitment.scheme != kKemCommitmentLegacyV1 && commitment.scheme != kKemCommitmentRawV2) {
        throw std::runtime_error("ML-KEM commitment scheme is unsupported");
    }
    if (!is_lower_hex_256(commitment.digest_hex)) {
        throw std::runtime_error("ML-KEM commitment digest is malformed");
    }
}

}  // namespace omniguard
