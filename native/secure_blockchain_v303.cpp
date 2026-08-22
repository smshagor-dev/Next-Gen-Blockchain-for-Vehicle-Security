// OmniGuard V2X v3.0.3 native runtime.
// Persisted mixed-generation ledger verification with durable ML-DSA/ML-KEM identity,
// authenticated data-at-rest, explicit trust history, and optional rollback anchor.

#include "pqc_key_store.h"
#include "pqc_software_active_operations.h"
#include "pqc_state_guard.h"
#include "pqc_trust_keyring.h"

#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>

namespace {

using json = nlohmann::json;
using omniguard::PqcActivePrivateOperations;
using omniguard::PqcActivePublicState;
using omniguard::PqcKeyMaterial;
using omniguard::PqcKeyStore;
using omniguard::PqcRollbackAnchor;
using omniguard::PqcSensitiveBytes;
using omniguard::PqcTrustKeyring;
using omniguard::SoftwarePqcActivePrivateOperations;

constexpr const char* kBlockDomain = "OMNIGUARD_NATIVE_BLOCK_V3_2";
constexpr const char* kAeadDomain = "OMNIGUARD_CPP_DATA_KEY_V1";
constexpr const char* kPqcDomain = "OMNIGUARD_NATIVE_PQC_V1";
constexpr std::size_t kMinSecretLength = 32;
constexpr std::size_t kAesKeyBytes = 32;
constexpr std::size_t kGcmNonceBytes = 12;
constexpr std::size_t kGcmTagBytes = 16;
constexpr std::uintmax_t kMaxLedgerBytes = 64 * 1024 * 1024;
constexpr std::size_t kMaxBlocks = 100000;

std::string require_env_secret(const char* name) {
    const char* raw = std::getenv(name);
    if (raw == nullptr) {
        throw std::runtime_error(std::string("required credential is not configured: ") + name);
    }
    const std::string value(raw);
    if (value.size() < kMinSecretLength) {
        throw std::runtime_error(std::string("credential must contain at least 32 characters: ") + name);
    }
    return value;
}

std::string require_env_value(const char* name) {
    const char* raw = std::getenv(name);
    if (raw == nullptr || *raw == '\0') {
        throw std::runtime_error(std::string("required configuration is not set: ") + name);
    }
    return raw;
}

std::string optional_env_value(const char* name) {
    const char* raw = std::getenv(name);
    return raw == nullptr ? std::string() : std::string(raw);
}

std::size_t configured_max_generations() {
    const std::string raw = optional_env_value("SMARTCAR_CPP_PQC_TRUST_MAX_GENERATIONS");
    if (raw.empty()) {
        return PqcTrustKeyring::kDefaultMaxGenerations;
    }
    std::size_t consumed = 0;
    unsigned long parsed = 0;
    try {
        parsed = std::stoul(raw, &consumed, 10);
    } catch (const std::exception&) {
        throw std::runtime_error("SMARTCAR_CPP_PQC_TRUST_MAX_GENERATIONS must be an integer");
    }
    if (consumed != raw.size() || parsed < 2 || parsed > PqcTrustKeyring::kAbsoluteMaxGenerations) {
        throw std::runtime_error("SMARTCAR_CPP_PQC_TRUST_MAX_GENERATIONS must be between 2 and 16");
    }
    return static_cast<std::size_t>(parsed);
}

std::string now_iso() {
    const auto now = std::chrono::system_clock::now();
    const auto value = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &value);
#else
    gmtime_r(&value, &utc);
#endif
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

std::string to_hex(const unsigned char* data, std::size_t size) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string output(size * 2, '0');
    for (std::size_t i = 0; i < size; ++i) {
        output[i * 2] = kHex[(data[i] >> 4) & 0x0f];
        output[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return output;
}

unsigned char from_hex_char(char value) {
    if (value >= '0' && value <= '9') return static_cast<unsigned char>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<unsigned char>(value - 'a' + 10);
    if (value >= 'A' && value <= 'F') return static_cast<unsigned char>(value - 'A' + 10);
    throw std::runtime_error("native ledger contains invalid hexadecimal data");
}

std::vector<unsigned char> from_hex_exact(const std::string& value, std::size_t expected_size) {
    if (value.size() != expected_size * 2) {
        throw std::runtime_error("native ledger hexadecimal field has an unexpected length");
    }
    std::vector<unsigned char> output(expected_size);
    for (std::size_t i = 0; i < expected_size; ++i) {
        output[i] = static_cast<unsigned char>(
            (from_hex_char(value[i * 2]) << 4) | from_hex_char(value[i * 2 + 1])
        );
    }
    return output;
}

std::vector<unsigned char> from_hex_variable(const std::string& value, std::size_t max_bytes) {
    if (value.empty() || value.size() % 2 != 0 || value.size() / 2 > max_bytes) {
        throw std::runtime_error("native ledger hexadecimal field has an invalid length");
    }
    std::vector<unsigned char> output(value.size() / 2);
    for (std::size_t i = 0; i < output.size(); ++i) {
        output[i] = static_cast<unsigned char>(
            (from_hex_char(value[i * 2]) << 4) | from_hex_char(value[i * 2 + 1])
        );
    }
    return output;
}

std::vector<unsigned char> digest(const EVP_MD* md, const std::string& input) {
    const int size = EVP_MD_get_size(md);
    if (size <= 0) {
        throw std::runtime_error("digest size is invalid");
    }
    std::vector<unsigned char> output(static_cast<std::size_t>(size));
    unsigned int output_len = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("digest context allocation failed");
    }
    const bool ok = EVP_DigestInit_ex(context, md, nullptr) == 1 &&
                    EVP_DigestUpdate(context, input.data(), input.size()) == 1 &&
                    EVP_DigestFinal_ex(context, output.data(), &output_len) == 1;
    EVP_MD_CTX_free(context);
    if (!ok) {
        throw std::runtime_error("digest operation failed");
    }
    output.resize(output_len);
    return output;
}

std::string sha256_hex(const std::string& input) {
    const auto output = digest(EVP_sha256(), input);
    return to_hex(output.data(), output.size());
}

std::string sha3_256_hex(const std::string& input) {
    const auto output = digest(EVP_sha3_256(), input);
    return to_hex(output.data(), output.size());
}

bool is_sha3_hex(const std::string& value) {
    if (value.size() != 64) return false;
    for (const char ch : value) {
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
    }
    return true;
}

std::string require_string(const json& object, const char* key) {
    if (!object.contains(key) || !object.at(key).is_string()) {
        throw std::runtime_error(std::string("native ledger field missing or invalid: ") + key);
    }
    const std::string value = object.at(key).get<std::string>();
    if (value.empty()) {
        throw std::runtime_error(std::string("native ledger field is empty: ") + key);
    }
    return value;
}

std::size_t require_index(const json& object) {
    if (!object.contains("index") || !object.at("index").is_number_unsigned()) {
        throw std::runtime_error("native ledger index is missing or invalid");
    }
    return object.at("index").get<std::size_t>();
}

json read_bounded_json(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status)) {
        throw std::runtime_error("native ledger path must be a regular non-symlink file");
    }
    const auto size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > kMaxLedgerBytes) {
        throw std::runtime_error("native ledger file size is invalid");
    }
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("could not open native ledger");
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    try {
        json document = json::parse(buffer.str());
        if (!document.is_array() || document.empty() || document.size() > kMaxBlocks) {
            throw std::runtime_error("native ledger must contain a bounded non-empty block array");
        }
        return document;
    } catch (const json::exception&) {
        throw std::runtime_error("native ledger contains malformed JSON");
    }
}

void atomic_write_json(const std::filesystem::path& path, const json& document) {
    if (path.empty() || path.filename().empty()) throw std::runtime_error("native ledger path is invalid");
    if (path.has_parent_path()) {
        std::error_code error;
        std::filesystem::create_directories(path.parent_path(), error);
        if (error) throw std::runtime_error("could not create native ledger directory");
    }
    const std::filesystem::path temporary = path.string() + ".tmp";
    {
        std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
        if (!stream) throw std::runtime_error("could not create native ledger temporary file");
        stream << document.dump(2) << '\n';
        stream.flush();
        if (!stream) throw std::runtime_error("could not persist native ledger temporary file");
    }
    std::error_code permission_error;
    std::filesystem::permissions(
        temporary,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace,
        permission_error
    );
    if (permission_error) {
        std::filesystem::remove(temporary);
        throw std::runtime_error("could not restrict native ledger temporary file permissions");
    }
    std::error_code rename_error;
    std::filesystem::rename(temporary, path, rename_error);
    if (rename_error) {
        std::filesystem::remove(path, rename_error);
        rename_error.clear();
        std::filesystem::rename(temporary, path, rename_error);
    }
    if (rename_error) {
        std::filesystem::remove(temporary);
        throw std::runtime_error("could not atomically publish native ledger");
    }
}

class Aes256Gcm {
public:
    explicit Aes256Gcm(const std::string& data_key) {
        if (data_key.size() < kMinSecretLength) throw std::runtime_error("native data key is too short");
        const auto derived = digest(EVP_sha256(), std::string(kAeadDomain) + "\n" + data_key);
        if (derived.size() != key_.size()) throw std::runtime_error("native data key derivation failed");
        std::copy(derived.begin(), derived.end(), key_.begin());
    }

    ~Aes256Gcm() { OPENSSL_cleanse(key_.data(), key_.size()); }

    json seal(const std::string& plaintext, const std::string& aad) const {
        std::array<unsigned char, kGcmNonceBytes> nonce{};
        std::array<unsigned char, kGcmTagBytes> tag{};
        if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
            throw std::runtime_error("secure nonce generation failed");
        }
        std::vector<unsigned char> ciphertext(plaintext.size());
        EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
        if (context == nullptr) throw std::runtime_error("cipher context allocation failed");
        int len = 0;
        int total = 0;
        bool ok = EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                  EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
                  EVP_EncryptInit_ex(context, nullptr, nullptr, key_.data(), nonce.data()) == 1;
        if (ok) {
            ok = EVP_EncryptUpdate(
                context, nullptr, &len,
                reinterpret_cast<const unsigned char*>(aad.data()), static_cast<int>(aad.size())
            ) == 1;
        }
        if (ok && !plaintext.empty()) {
            ok = EVP_EncryptUpdate(
                context, ciphertext.data(), &len,
                reinterpret_cast<const unsigned char*>(plaintext.data()), static_cast<int>(plaintext.size())
            ) == 1;
            total = len;
        }
        if (ok) {
            ok = EVP_EncryptFinal_ex(context, ciphertext.data() + total, &len) == 1;
            total += len;
        }
        if (ok) {
            ok = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) == 1;
        }
        EVP_CIPHER_CTX_free(context);
        if (!ok) throw std::runtime_error("AES-256-GCM encryption failed");
        ciphertext.resize(static_cast<std::size_t>(total));
        return {
            {"scheme", "AES-256-GCM"},
            {"version", 1},
            {"nonce_hex", to_hex(nonce.data(), nonce.size())},
            {"tag_hex", to_hex(tag.data(), tag.size())},
            {"ciphertext_hex", to_hex(ciphertext.data(), ciphertext.size())},
        };
    }

    std::string open(const json& envelope, const std::string& aad) const {
        if (!envelope.is_object() || require_string(envelope, "scheme") != "AES-256-GCM" ||
            !envelope.contains("version") || !envelope.at("version").is_number_integer() ||
            envelope.at("version").get<int>() != 1) {
            throw std::runtime_error("native ledger AES-GCM envelope is invalid");
        }
        const auto nonce = from_hex_exact(require_string(envelope, "nonce_hex"), kGcmNonceBytes);
        const auto tag = from_hex_exact(require_string(envelope, "tag_hex"), kGcmTagBytes);
        const auto ciphertext = from_hex_variable(require_string(envelope, "ciphertext_hex"), 4096);
        std::vector<unsigned char> plaintext(ciphertext.size());
        EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
        if (context == nullptr) throw std::runtime_error("cipher context allocation failed");
        int len = 0;
        int total = 0;
        bool ok = EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                  EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
                  EVP_DecryptInit_ex(context, nullptr, nullptr, key_.data(), nonce.data()) == 1;
        if (ok) {
            ok = EVP_DecryptUpdate(
                context, nullptr, &len,
                reinterpret_cast<const unsigned char*>(aad.data()), static_cast<int>(aad.size())
            ) == 1;
        }
        if (ok && !ciphertext.empty()) {
            ok = EVP_DecryptUpdate(
                context, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())
            ) == 1;
            total = len;
        }
        if (ok) {
            ok = EVP_CIPHER_CTX_ctrl(
                context, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<unsigned char*>(tag.data())
            ) == 1;
        }
        if (ok) {
            ok = EVP_DecryptFinal_ex(context, plaintext.data() + total, &len) == 1;
            total += len;
        }
        EVP_CIPHER_CTX_free(context);
        if (!ok) {
            if (!plaintext.empty()) OPENSSL_cleanse(plaintext.data(), plaintext.size());
            throw std::runtime_error("native ledger AES-GCM authentication failed");
        }
        std::string output(reinterpret_cast<const char*>(plaintext.data()), static_cast<std::size_t>(total));
        if (!plaintext.empty()) OPENSSL_cleanse(plaintext.data(), plaintext.size());
        return output;
    }

private:
    std::array<unsigned char, kAesKeyBytes> key_{};
};

struct SigDeleter { void operator()(OQS_SIG* value) const { OQS_SIG_free(value); } };
struct KemDeleter { void operator()(OQS_KEM* value) const { OQS_KEM_free(value); } };
using SigPtr = std::unique_ptr<OQS_SIG, SigDeleter>;
using KemPtr = std::unique_ptr<OQS_KEM, KemDeleter>;

class ActivePqcEngine {
public:
    explicit ActivePqcEngine(PqcKeyMaterial material)
        : ActivePqcEngine(std::make_unique<SoftwarePqcActivePrivateOperations>(std::move(material))) {}

    explicit ActivePqcEngine(std::unique_ptr<PqcActivePrivateOperations> private_operations)
        : private_operations_(std::move(private_operations)) {
        if (!private_operations_) {
            throw std::runtime_error("active PQC engine requires a private-operation provider");
        }
        signature_.reset(OQS_SIG_new(OQS_SIG_alg_ml_dsa_44));
        kem_.reset(OQS_KEM_new(OQS_KEM_alg_ml_kem_512));
        if (!signature_ || !kem_) throw std::runtime_error("required liboqs algorithms are unavailable");

        public_state_ = private_operations_->public_state();
        omniguard::validate_active_public_state(public_state_);
        if (public_state_.signature_public_key.size() != signature_->length_public_key ||
            public_state_.kem_public_key.size() != kem_->length_public_key ||
            public_state_.signature_max_size != signature_->length_signature ||
            public_state_.kem_ciphertext_size != kem_->length_ciphertext ||
            public_state_.kem_shared_secret_size != kem_->length_shared_secret) {
            throw std::runtime_error("active PQC provider state is incompatible with ML-DSA-44/ML-KEM-512 runtime parameters");
        }
    }

    const std::string& identity() const { return public_state_.identity; }
    const std::string& key_id() const { return public_state_.key_id; }
    const std::string& provider() const { return public_state_.provider; }
    bool hardware_backed() const { return public_state_.hardware_backed; }
    bool non_exportable() const { return public_state_.non_exportable; }
    bool runtime_probe_verified() const { return public_state_.runtime_probe_verified; }
    const std::vector<unsigned char>& signature_public_key() const { return public_state_.signature_public_key; }
    const std::vector<unsigned char>& kem_public_key() const { return public_state_.kem_public_key; }
    std::size_t signature_size() const { return public_state_.signature_max_size; }
    std::size_t kem_ciphertext_size() const { return public_state_.kem_ciphertext_size; }

    json create_artifact(const std::string& message) const {
        const std::vector<unsigned char> message_bytes(message.begin(), message.end());
        std::vector<unsigned char> signature = private_operations_->sign_ml_dsa_44(message_bytes);
        if (signature.empty() || signature.size() > public_state_.signature_max_size) {
            throw std::runtime_error("active ML-DSA-44 provider returned an invalid signature size");
        }

        std::vector<unsigned char> ciphertext(kem_->length_ciphertext);
        std::vector<unsigned char> sender_secret(kem_->length_shared_secret);
        if (OQS_KEM_encaps(
                kem_.get(), ciphertext.data(), sender_secret.data(), public_state_.kem_public_key.data()
            ) != OQS_SUCCESS) {
            OPENSSL_cleanse(sender_secret.data(), sender_secret.size());
            throw std::runtime_error("ML-KEM encapsulation failed");
        }

        PqcSensitiveBytes receiver_secret;
        try {
            receiver_secret = private_operations_->decapsulate_ml_kem_512(ciphertext);
        } catch (...) {
            OPENSSL_cleanse(sender_secret.data(), sender_secret.size());
            throw;
        }
        const bool kem_ok = receiver_secret.size() == sender_secret.size() &&
                            receiver_secret.size() == public_state_.kem_shared_secret_size &&
                            CRYPTO_memcmp(sender_secret.data(), receiver_secret.data(), sender_secret.size()) == 0;
        if (!kem_ok) {
            OPENSSL_cleanse(sender_secret.data(), sender_secret.size());
            receiver_secret.clear();
            throw std::runtime_error("ML-KEM encapsulation/decapsulation provider round-trip failed");
        }

        const std::string shared_secret_hash = sha3_256_hex(
            std::string(kPqcDomain) + "\n" + public_state_.key_id + "\n" +
            to_hex(receiver_secret.data(), receiver_secret.size())
        );
        OPENSSL_cleanse(sender_secret.data(), sender_secret.size());
        receiver_secret.clear();

        const std::string signature_hex = to_hex(signature.data(), signature.size());
        const std::string ciphertext_hex = to_hex(ciphertext.data(), ciphertext.size());
        const std::string binding_hash = sha3_256_hex(
            std::string(kPqcDomain) + "\n" + public_state_.key_id + "\n" + message + "\n" +
            signature_hex + "\n" + ciphertext_hex + "\n" + shared_secret_hash
        );
        return {
            {"pqc_algorithm", "ML-DSA-44+ML-KEM-512"},
            {"pqc_key_id", public_state_.key_id},
            {"pqc_signature_hex", signature_hex},
            {"pqc_signature_public_key_hex", to_hex(public_state_.signature_public_key.data(), public_state_.signature_public_key.size())},
            {"pqc_kem_ciphertext_hex", ciphertext_hex},
            {"pqc_kem_public_key_hex", to_hex(public_state_.kem_public_key.data(), public_state_.kem_public_key.size())},
            {"pqc_shared_secret_hash", shared_secret_hash},
            {"pqc_binding_hash", binding_hash},
        };
    }

    bool verify_current(
        const std::string& message,
        const std::vector<unsigned char>& signature,
        const std::vector<unsigned char>& embedded_signature_public_key,
        const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& embedded_kem_public_key,
        const std::string& shared_secret_hash
    ) const {
        if (embedded_signature_public_key != public_state_.signature_public_key ||
            embedded_kem_public_key != public_state_.kem_public_key) {
            return false;
        }
        if (OQS_SIG_verify(
                signature_.get(),
                reinterpret_cast<const unsigned char*>(message.data()), message.size(),
                signature.data(), signature.size(), public_state_.signature_public_key.data()
            ) != OQS_SUCCESS) {
            return false;
        }
        if (ciphertext.size() != public_state_.kem_ciphertext_size) return false;

        PqcSensitiveBytes secret = private_operations_->decapsulate_ml_kem_512(ciphertext);
        if (secret.size() != public_state_.kem_shared_secret_size) {
            secret.clear();
            return false;
        }
        const std::string expected = sha3_256_hex(
            std::string(kPqcDomain) + "\n" + public_state_.key_id + "\n" + to_hex(secret.data(), secret.size())
        );
        secret.clear();
        return expected == shared_secret_hash;
    }

private:
    SigPtr signature_;
    KemPtr kem_;
    std::unique_ptr<PqcActivePrivateOperations> private_operations_;
    PqcActivePublicState public_state_;
};

std::string canonical_telemetry(const json& telemetry) {
    if (!telemetry.is_object()) throw std::runtime_error("native telemetry must be an object");
    const char* numeric_fields[] = {
        "speed", "acceleration", "fuel_level", "battery_voltage", "engine_temp",
        "gps_lat", "gps_lon", "obstacle_distance"
    };
    for (const char* field : numeric_fields) {
        if (!telemetry.contains(field) || !telemetry.at(field).is_number() ||
            !std::isfinite(telemetry.at(field).get<double>())) {
            throw std::runtime_error(std::string("native telemetry field invalid: ") + field);
        }
    }
    if (!telemetry.contains("emergency_brake_active") || !telemetry.at("emergency_brake_active").is_boolean()) {
        throw std::runtime_error("native emergency brake telemetry is invalid");
    }
    const std::string timestamp = require_string(telemetry, "timestamp");
    return json({
        {"speed", telemetry.at("speed")},
        {"acceleration", telemetry.at("acceleration")},
        {"fuel_level", telemetry.at("fuel_level")},
        {"battery_voltage", telemetry.at("battery_voltage")},
        {"engine_temp", telemetry.at("engine_temp")},
        {"gps_lat", telemetry.at("gps_lat")},
        {"gps_lon", telemetry.at("gps_lon")},
        {"obstacle_distance", telemetry.at("obstacle_distance")},
        {"emergency_brake_active", telemetry.at("emergency_brake_active")},
        {"timestamp", timestamp},
    }).dump();
}

std::string block_hash_for(
    std::size_t index,
    const std::string& timestamp,
    const std::string& vehicle_id,
    const std::string& telemetry_hash_sha3,
    const std::string& event_hash_sha3,
    const std::string& previous_hash
) {
    return sha3_256_hex(
        std::string(kBlockDomain) + "\n" + std::to_string(index) + "\n" + timestamp + "\n" +
        vehicle_id + "\n" + telemetry_hash_sha3 + "\n" + event_hash_sha3 + "\n" + previous_hash
    );
}

struct TrustHead {
    std::uint64_t generation = 0;
    std::string active_key_id;
    std::string head_hash;
};

TrustHead verified_trust_head(
    const std::filesystem::path& path,
    const PqcTrustKeyring& keyring,
    const std::string& active_key_id
) {
    const auto metadata = keyring.inspect(active_key_id);
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("could not open verified trust keyring metadata");
    json document;
    try {
        stream >> document;
    } catch (const json::exception&) {
        throw std::runtime_error("verified trust keyring metadata is malformed");
    }
    if (!document.contains("active_generation") || !document.at("active_generation").is_number_unsigned() ||
        !document.contains("active_key_id") || !document.at("active_key_id").is_string() ||
        !document.contains("head_hash") || !document.at("head_hash").is_string()) {
        throw std::runtime_error("verified trust keyring head fields are invalid");
    }
    TrustHead head{
        document.at("active_generation").get<std::uint64_t>(),
        document.at("active_key_id").get<std::string>(),
        document.at("head_hash").get<std::string>(),
    };
    if (head.generation != metadata.active_generation || head.active_key_id != metadata.active_key_id ||
        head.active_key_id != active_key_id || !is_sha3_hex(head.head_hash)) {
        throw std::runtime_error("verified trust keyring head is inconsistent");
    }
    return head;
}

class NativeRuntime {
public:
    NativeRuntime(
        std::string vehicle_id,
        const std::string& data_key,
        const std::filesystem::path& keystore_path,
        const std::string& keystore_key
    ) : vehicle_id_(std::move(vehicle_id)), cipher_(data_key),
        active_(PqcKeyStore(keystore_path, keystore_key, vehicle_id_).load_or_create()) {
        if (vehicle_id_.empty() || vehicle_id_.size() > 256 || active_.identity() != vehicle_id_) {
            throw std::runtime_error("native runtime vehicle/PQC identity binding is invalid");
        }
        const std::string keyring_value = optional_env_value("SMARTCAR_CPP_PQC_TRUST_KEYRING_PATH");
        if (!keyring_value.empty()) {
            keyring_path_ = keyring_value;
            if (!std::filesystem::exists(keyring_path_)) {
                throw std::runtime_error("configured PQC trust keyring does not exist");
            }
            keyring_ = std::make_unique<PqcTrustKeyring>(
                keyring_path_, vehicle_id_, configured_max_generations()
            );
            trust_head_ = verified_trust_head(keyring_path_, *keyring_, active_.key_id());
        }

        const bool anchor_required = omniguard::parse_strict_env_bool(
            "SMARTCAR_CPP_PQC_ROLLBACK_ANCHOR_REQUIRED", false
        );
        const std::string anchor_path = optional_env_value("SMARTCAR_CPP_PQC_ROLLBACK_ANCHOR_PATH");
        if (anchor_required && anchor_path.empty()) {
            throw std::runtime_error("rollback anchor is required but SMARTCAR_CPP_PQC_ROLLBACK_ANCHOR_PATH is unset");
        }
        if (!anchor_path.empty()) {
            if (!keyring_) throw std::runtime_error("rollback anchor requires a verified PQC trust keyring");
            const std::string anchor_secret = require_env_secret("SMARTCAR_CPP_PQC_ROLLBACK_KEY");
            PqcRollbackAnchor anchor(anchor_path, anchor_secret, vehicle_id_);
            anchor.verify_exact(
                trust_head_.generation,
                trust_head_.active_key_id,
                trust_head_.head_hash
            );
            anchor_verified_ = true;
        } else if (anchor_required) {
            throw std::runtime_error("required rollback anchor is unavailable");
        }
    }

    void create_new() {
        if (!ledger_.empty()) throw std::runtime_error("native runtime ledger is already initialized");
        ledger_.push_back(make_block(0, std::string(64, '0'), "GENESIS:VEHICLE_INITIALIZED"));
        (void)verify();
    }

    void load(const std::filesystem::path& path) {
        ledger_ = read_bounded_json(path);
        (void)verify();
    }

    void append(const std::string& event) {
        if (ledger_.empty()) throw std::runtime_error("cannot append before ledger initialization/load");
        (void)verify();
        const std::string previous_hash = require_string(ledger_.back(), "block_hash");
        ledger_.push_back(make_block(ledger_.size(), previous_hash, event.empty() ? "TELEMETRY:UPDATE" : event));
        (void)verify();
    }

    void save(const std::filesystem::path& path) const {
        (void)verify();
        atomic_write_json(path, ledger_);
    }

    json verify() const {
        if (ledger_.empty() || ledger_.size() > kMaxBlocks) throw std::runtime_error("native runtime ledger is empty/oversized");
        std::size_t historical_blocks = 0;
        std::size_t current_blocks = 0;
        std::string previous_block_hash(64, '0');
        for (std::size_t i = 0; i < ledger_.size(); ++i) {
            const json& block = ledger_.at(i);
            const std::size_t index = require_index(block);
            const std::string timestamp = require_string(block, "timestamp");
            const std::string block_vehicle_id = require_string(block, "vehicle_id");
            const std::string event_data = require_string(block, "event_data");
            const std::string previous_hash = require_string(block, "previous_hash");
            if (index != i || block_vehicle_id != vehicle_id_ || previous_hash != previous_block_hash) {
                throw std::runtime_error("native runtime index/vehicle/linkage validation failed");
            }
            if (!block.contains("telemetry")) throw std::runtime_error("native runtime telemetry is missing");
            const std::string telemetry = canonical_telemetry(block.at("telemetry"));
            const std::string telemetry_sha256 = require_string(block, "telemetry_hash_sha256");
            const std::string telemetry_sha3 = require_string(block, "telemetry_hash_sha3");
            const std::string event_sha256 = require_string(block, "event_hash_sha256");
            const std::string event_sha3 = require_string(block, "event_hash_sha3");
            if (telemetry_sha256 != sha256_hex(telemetry) || telemetry_sha3 != sha3_256_hex(telemetry) ||
                event_sha256 != sha256_hex(event_data) || event_sha3 != sha3_256_hex(event_data)) {
                throw std::runtime_error("native runtime telemetry/event digest validation failed");
            }
            const std::string block_hash = require_string(block, "block_hash");
            if (block_hash != block_hash_for(index, timestamp, vehicle_id_, telemetry_sha3, event_sha3, previous_hash)) {
                throw std::runtime_error("native runtime block hash validation failed");
            }
            if (!block.contains("dual_hash_encrypted") || !block.at("dual_hash_encrypted").is_object()) {
                throw std::runtime_error("native runtime encrypted dual hash is missing");
            }
            const std::string aad = "OMNIGUARD_DUAL_HASH_AAD_V1|" + vehicle_id_ + "|" +
                std::to_string(index) + "|" + block_hash;
            const std::string dual_hash = cipher_.open(block.at("dual_hash_encrypted"), aad);
            const std::string expected_dual = sha256_hex(block_hash) + ":" + sha3_256_hex(block_hash);
            if (dual_hash != expected_dual) throw std::runtime_error("native runtime dual hash validation failed");

            if (require_string(block, "pqc_algorithm") != "ML-DSA-44+ML-KEM-512") {
                throw std::runtime_error("native runtime PQC algorithm mismatch");
            }
            const std::string key_id = require_string(block, "pqc_key_id");
            const std::string signature_hex = require_string(block, "pqc_signature_hex");
            const std::string ciphertext_hex = require_string(block, "pqc_kem_ciphertext_hex");
            const std::string shared_secret_hash = require_string(block, "pqc_shared_secret_hash");
            const std::string binding_hash = require_string(block, "pqc_binding_hash");
            const std::string pqc_digest = require_string(block, "pqc_digest");
            if (!is_sha3_hex(shared_secret_hash) || !is_sha3_hex(binding_hash) || !is_sha3_hex(pqc_digest)) {
                throw std::runtime_error("native runtime PQC digest field is malformed");
            }
            const auto signature = from_hex_variable(signature_hex, active_.signature_size());
            const auto signature_public_key = from_hex_exact(
                require_string(block, "pqc_signature_public_key_hex"), active_.signature_public_key().size()
            );
            const auto kem_public_key = from_hex_exact(
                require_string(block, "pqc_kem_public_key_hex"), active_.kem_public_key().size()
            );
            const auto ciphertext = from_hex_exact(ciphertext_hex, active_.kem_ciphertext_size());
            const std::string message = std::string(kPqcDomain) + "\n" + key_id + "\n" + block_hash + "\n" +
                dual_hash + "\n" + previous_hash + "\n" + timestamp;

            if (key_id == active_.key_id()) {
                if (!active_.verify_current(
                        message, signature, signature_public_key, ciphertext, kem_public_key, shared_secret_hash
                    )) {
                    throw std::runtime_error("native runtime active-generation PQC verification failed");
                }
                ++current_blocks;
            } else {
                if (!keyring_) {
                    throw std::runtime_error("historical PQC generation encountered without configured trust keyring");
                }
                if (!keyring_->verify_detached_signature(
                        key_id,
                        message,
                        signature,
                        signature_public_key,
                        kem_public_key,
                        active_.key_id()
                    )) {
                    throw std::runtime_error("historical PQC generation is not admitted by verified trust history");
                }
                ++historical_blocks;
            }

            const std::string expected_binding = sha3_256_hex(
                std::string(kPqcDomain) + "\n" + key_id + "\n" + message + "\n" +
                signature_hex + "\n" + ciphertext_hex + "\n" + shared_secret_hash
            );
            if (binding_hash != expected_binding) throw std::runtime_error("native runtime PQC binding hash validation failed");
            const std::string expected_pqc_digest = sha3_256_hex(
                std::string(kPqcDomain) + "\n" + key_id + "\n" + binding_hash + "\n" + dual_hash
            );
            if (pqc_digest != expected_pqc_digest) throw std::runtime_error("native runtime PQC digest validation failed");
            previous_block_hash = block_hash;
        }

        return {
            {"format", "OMNIGUARD_NATIVE_RUNTIME_VERIFICATION_V3_0_3"},
            {"verified", true},
            {"vehicle_id", vehicle_id_},
            {"block_count", ledger_.size()},
            {"current_generation_blocks", current_blocks},
            {"historical_generation_blocks", historical_blocks},
            {"migration_state", historical_blocks > 0 ? "MIXED_GENERATION_VERIFIED" : "ACTIVE_ONLY"},
            {"active_key_id", active_.key_id()},
            {"active_pqc_provider", active_.provider()},
            {"active_pqc_hardware_backed", active_.hardware_backed()},
            {"active_pqc_non_exportable", active_.non_exportable()},
            {"active_pqc_runtime_probe_verified", active_.runtime_probe_verified()},
            {"active_pqc_private_operations_opaque", true},
            {"trust_keyring_verified", keyring_ != nullptr},
            {"rollback_anchor_verified", anchor_verified_},
            {"current_ml_kem_decapsulation_verified", current_blocks > 0},
            {"historical_ml_dsa_authenticity_verified", historical_blocks == 0 || keyring_ != nullptr},
            {"historical_ml_kem_decapsulation_verified", false},
            {"historical_kem_private_keys_retained", false},
            {"historical_kem_claim_is_authoritative", false},
            {"secret_values_exposed", false},
        };
    }

private:
    json make_block(std::size_t index, const std::string& previous_hash, const std::string& event) const {
        const std::string timestamp = now_iso();
        const json telemetry = {
            {"speed", 0.0},
            {"acceleration", 0.0},
            {"fuel_level", 100.0},
            {"battery_voltage", 12.6},
            {"engine_temp", 20.0},
            {"gps_lat", 0.0},
            {"gps_lon", 0.0},
            {"obstacle_distance", 999.0},
            {"emergency_brake_active", false},
            {"timestamp", timestamp},
        };
        const std::string telemetry_serialized = canonical_telemetry(telemetry);
        const std::string telemetry_sha256 = sha256_hex(telemetry_serialized);
        const std::string telemetry_sha3 = sha3_256_hex(telemetry_serialized);
        const std::string event_sha256 = sha256_hex(event);
        const std::string event_sha3 = sha3_256_hex(event);
        const std::string block_hash = block_hash_for(
            index, timestamp, vehicle_id_, telemetry_sha3, event_sha3, previous_hash
        );
        const std::string dual_hash = sha256_hex(block_hash) + ":" + sha3_256_hex(block_hash);
        const std::string aad = "OMNIGUARD_DUAL_HASH_AAD_V1|" + vehicle_id_ + "|" +
            std::to_string(index) + "|" + block_hash;
        const std::string message = std::string(kPqcDomain) + "\n" + active_.key_id() + "\n" + block_hash + "\n" +
            dual_hash + "\n" + previous_hash + "\n" + timestamp;
        json artifact = active_.create_artifact(message);
        const std::string pqc_digest = sha3_256_hex(
            std::string(kPqcDomain) + "\n" + active_.key_id() + "\n" +
            artifact.at("pqc_binding_hash").get<std::string>() + "\n" + dual_hash
        );
        json block = {
            {"index", index},
            {"timestamp", timestamp},
            {"vehicle_id", vehicle_id_},
            {"event_data", event},
            {"previous_hash", previous_hash},
            {"telemetry_hash_sha256", telemetry_sha256},
            {"telemetry_hash_sha3", telemetry_sha3},
            {"event_hash_sha256", event_sha256},
            {"event_hash_sha3", event_sha3},
            {"block_hash", block_hash},
            {"dual_hash_encrypted", cipher_.seal(dual_hash, aad)},
            {"pqc_digest", pqc_digest},
            {"telemetry", telemetry},
        };
        for (auto it = artifact.begin(); it != artifact.end(); ++it) block[it.key()] = it.value();
        return block;
    }

    std::string vehicle_id_;
    Aes256Gcm cipher_;
    ActivePqcEngine active_;
    std::filesystem::path keyring_path_;
    std::unique_ptr<PqcTrustKeyring> keyring_;
    TrustHead trust_head_;
    bool anchor_verified_ = false;
    json ledger_ = json::array();
};

std::string option_value(int argc, char** argv, const std::string& name, bool required) {
    for (int i = 2; i < argc; ++i) {
        if (std::string(argv[i]) == name && i + 1 < argc) return argv[i + 1];
    }
    if (required) throw std::runtime_error("missing required option: " + name);
    return {};
}

int run_self_test(
    const std::string& data_key,
    const std::string& keystore_key,
    const std::filesystem::path& keystore_path
) {
    const std::string identity = "SMARTCAR_CPP_SELFTEST";
    const std::filesystem::path ledger_path = keystore_path.string() + ".runtime-ledger.json";
    std::error_code ignored;
    std::filesystem::remove(ledger_path, ignored);
    {
        NativeRuntime runtime(identity, data_key, keystore_path, keystore_key);
        runtime.create_new();
        runtime.append("SELFTEST:TELEMETRY");
        runtime.save(ledger_path);
        const json report = runtime.verify();
        if (!report.at("verified").get<bool>() || report.at("block_count").get<std::size_t>() != 2 ||
            report.at("active_pqc_provider").get<std::string>() != omniguard::kSoftwarePqcProvider ||
            report.at("active_pqc_hardware_backed").get<bool>() ||
            report.at("active_pqc_non_exportable").get<bool>() ||
            !report.at("active_pqc_runtime_probe_verified").get<bool>() ||
            !report.at("active_pqc_private_operations_opaque").get<bool>()) {
            return 2;
        }
    }
    {
        NativeRuntime reloaded(identity, data_key, keystore_path, keystore_key);
        reloaded.load(ledger_path);
        const json report = reloaded.verify();
        if (!report.at("verified").get<bool>() || report.at("historical_generation_blocks").get<std::size_t>() != 0) return 3;
    }
    bool wrong_key_rejected = false;
    try {
        std::string wrong_key = keystore_key;
        wrong_key[0] = wrong_key[0] == 'X' ? 'Y' : 'X';
        NativeRuntime rejected(identity, data_key, keystore_path, wrong_key);
        (void)rejected;
    } catch (const std::exception&) {
        wrong_key_rejected = true;
    }
    if (!wrong_key_rejected) return 4;
    std::filesystem::remove(ledger_path, ignored);
    std::cout << "[SELF-TEST] PASS: v3.0.3 persisted runtime + opaque PQC private operations + durable ML-DSA-44/ML-KEM-512 + AES-256-GCM\n";
    return 0;
}

void print_usage() {
    std::cerr
        << "Usage:\n"
        << "  smartcar_blockchain --self-test\n"
        << "  smartcar_blockchain init --identity <vehicle-id> --ledger <ledger.json>\n"
        << "  smartcar_blockchain verify --identity <vehicle-id> --ledger <ledger.json>\n"
        << "  smartcar_blockchain append --identity <vehicle-id> --ledger <ledger.json> [--event <event>]\n"
        << "  smartcar_blockchain <vehicle-id> <ledger.json>   (compatibility init mode)\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const std::string data_key = require_env_secret("SMARTCAR_CPP_DATA_KEY");
        (void)require_env_secret("SMARTCAR_AUTH_TOKEN");
        const std::string keystore_key = require_env_secret("SMARTCAR_CPP_PQC_KEYSTORE_KEY");
        const std::filesystem::path keystore_path(require_env_value("SMARTCAR_CPP_PQC_KEYSTORE_PATH"));

        if (argc > 1 && std::string(argv[1]) == "--self-test") {
            return run_self_test(data_key, keystore_key, keystore_path);
        }

        if (argc >= 2 && (std::string(argv[1]) == "init" || std::string(argv[1]) == "verify" ||
                          std::string(argv[1]) == "append")) {
            const std::string command = argv[1];
            const std::string identity = option_value(argc, argv, "--identity", true);
            const std::filesystem::path ledger_path = option_value(argc, argv, "--ledger", true);
            NativeRuntime runtime(identity, data_key, keystore_path, keystore_key);
            if (command == "init") {
                if (std::filesystem::exists(ledger_path)) {
                    throw std::runtime_error("refusing to overwrite an existing native ledger during init");
                }
                runtime.create_new();
                runtime.save(ledger_path);
            } else if (command == "verify") {
                runtime.load(ledger_path);
            } else {
                runtime.load(ledger_path);
                runtime.append(option_value(argc, argv, "--event", false));
                runtime.save(ledger_path);
            }
            std::cout << runtime.verify().dump(2) << '\n';
            return 0;
        }

        if (argc >= 3) {
            const std::string identity = argv[1];
            const std::filesystem::path ledger_path = argv[2];
            if (std::filesystem::exists(ledger_path)) {
                throw std::runtime_error("compatibility init mode refuses to overwrite an existing ledger");
            }
            NativeRuntime runtime(identity, data_key, keystore_path, keystore_key);
            runtime.create_new();
            runtime.save(ledger_path);
            std::cout << runtime.verify().dump(2) << '\n';
            return 0;
        }

        print_usage();
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "[NATIVE] fail-closed: " << error.what() << '\n';
        return 1;
    }
}
