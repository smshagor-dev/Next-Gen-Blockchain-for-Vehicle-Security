#include "pqc_key_store.h"
#include "pqc_trust_keyring.h"

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <oqs/oqs.h>

namespace {

using json = nlohmann::json;
using omniguard::PqcKeyMaterial;
using omniguard::PqcKeyStore;
using omniguard::PqcTrustKeyring;

constexpr const char* kBlockDomain = "OMNIGUARD_NATIVE_BLOCK_V3_2";
constexpr const char* kAeadDomain = "OMNIGUARD_CPP_DATA_KEY_V1";
constexpr const char* kPqcDomain = "OMNIGUARD_NATIVE_PQC_V1";
constexpr std::size_t kMinSecretLength = 32;
constexpr std::size_t kAesKeyBytes = 32;
constexpr std::size_t kGcmNonceBytes = 12;
constexpr std::size_t kGcmTagBytes = 16;
constexpr std::uintmax_t kMaxLedgerBytes = 64 * 1024 * 1024;
constexpr std::size_t kMaxBlocks = 100000;

struct KemDeleter {
    void operator()(OQS_KEM* value) const { OQS_KEM_free(value); }
};

using KemPtr = std::unique_ptr<OQS_KEM, KemDeleter>;

std::string require_env(const char* name, std::size_t min_length = 1) {
    const char* raw = std::getenv(name);
    if (raw == nullptr) {
        throw std::runtime_error(std::string("required environment setting is missing: ") + name);
    }
    const std::string value(raw);
    if (value.size() < min_length) {
        throw std::runtime_error(std::string("environment setting is too short: ") + name);
    }
    return value;
}

std::size_t configured_max_generations() {
    const char* raw = std::getenv("SMARTCAR_CPP_PQC_TRUST_MAX_GENERATIONS");
    if (raw == nullptr || *raw == '\0') {
        return PqcTrustKeyring::kDefaultMaxGenerations;
    }
    const std::string text(raw);
    std::size_t consumed = 0;
    unsigned long parsed = 0;
    try {
        parsed = std::stoul(text, &consumed, 10);
    } catch (const std::exception&) {
        throw std::runtime_error("SMARTCAR_CPP_PQC_TRUST_MAX_GENERATIONS must be an integer");
    }
    if (consumed != text.size() || parsed < 2 || parsed > PqcTrustKeyring::kAbsoluteMaxGenerations) {
        throw std::runtime_error("SMARTCAR_CPP_PQC_TRUST_MAX_GENERATIONS must be between 2 and 16");
    }
    return static_cast<std::size_t>(parsed);
}

std::string option_value(int argc, char** argv, const std::string& name, bool required) {
    for (int i = 2; i < argc; ++i) {
        if (std::string(argv[i]) == name && i + 1 < argc) {
            return argv[i + 1];
        }
    }
    if (required) {
        throw std::runtime_error("missing required option: " + name);
    }
    return {};
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
    if (value >= '0' && value <= '9') {
        return static_cast<unsigned char>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<unsigned char>(value - 'a' + 10);
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<unsigned char>(value - 'A' + 10);
    }
    throw std::runtime_error("historical ledger contains invalid hexadecimal data");
}

std::vector<unsigned char> from_hex_exact(const std::string& value, std::size_t expected_size) {
    if (value.size() != expected_size * 2) {
        throw std::runtime_error("historical ledger hexadecimal field has an unexpected length");
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
        throw std::runtime_error("historical ledger hexadecimal field has an invalid length");
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
        throw std::runtime_error("historical verifier digest size is invalid");
    }
    std::vector<unsigned char> output(static_cast<std::size_t>(size));
    unsigned int output_len = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("historical verifier digest context allocation failed");
    }
    const bool ok = EVP_DigestInit_ex(context, md, nullptr) == 1 &&
                    EVP_DigestUpdate(context, input.data(), input.size()) == 1 &&
                    EVP_DigestFinal_ex(context, output.data(), &output_len) == 1;
    EVP_MD_CTX_free(context);
    if (!ok) {
        throw std::runtime_error("historical verifier digest operation failed");
    }
    output.resize(output_len);
    return output;
}

std::string sha256_hex(const std::string& input) {
    const auto value = digest(EVP_sha256(), input);
    return to_hex(value.data(), value.size());
}

std::string sha3_256_hex(const std::string& input) {
    const auto value = digest(EVP_sha3_256(), input);
    return to_hex(value.data(), value.size());
}

bool is_sha3_hex(const std::string& value) {
    if (value.size() != 64) {
        return false;
    }
    for (const char ch : value) {
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return false;
        }
    }
    return true;
}

std::string require_string(const json& object, const char* key) {
    if (!object.contains(key) || !object.at(key).is_string()) {
        throw std::runtime_error(std::string("historical ledger field is missing or invalid: ") + key);
    }
    const std::string value = object.at(key).get<std::string>();
    if (value.empty()) {
        throw std::runtime_error(std::string("historical ledger field is empty: ") + key);
    }
    return value;
}

std::size_t require_index(const json& object) {
    if (!object.contains("index") || !object.at("index").is_number_unsigned()) {
        throw std::runtime_error("historical ledger index is missing or invalid");
    }
    return object.at("index").get<std::size_t>();
}

json read_ledger(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status)) {
        throw std::runtime_error("historical ledger path must be a regular non-symlink file");
    }
    const auto size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > kMaxLedgerBytes) {
        throw std::runtime_error("historical ledger file size is invalid");
    }
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("could not open historical ledger");
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    try {
        json document = json::parse(buffer.str());
        if (!document.is_array() || document.empty() || document.size() > kMaxBlocks) {
            throw std::runtime_error("historical ledger must contain a bounded non-empty block array");
        }
        return document;
    } catch (const json::exception&) {
        throw std::runtime_error("historical ledger contains malformed JSON");
    }
}

class Aes256GcmReader {
public:
    explicit Aes256GcmReader(const std::string& data_key) {
        if (data_key.size() < kMinSecretLength) {
            throw std::runtime_error("native data key is too short");
        }
        const auto derived = digest(EVP_sha256(), std::string(kAeadDomain) + "\n" + data_key);
        if (derived.size() != key_.size()) {
            throw std::runtime_error("native data key derivation failed");
        }
        std::copy(derived.begin(), derived.end(), key_.begin());
    }

    ~Aes256GcmReader() { OPENSSL_cleanse(key_.data(), key_.size()); }

    std::string open(const json& envelope, const std::string& aad) const {
        if (!envelope.is_object() || require_string(envelope, "scheme") != "AES-256-GCM" ||
            !envelope.contains("version") || !envelope.at("version").is_number_integer() ||
            envelope.at("version").get<int>() != 1) {
            throw std::runtime_error("historical ledger AES-GCM envelope is invalid");
        }
        const auto nonce = from_hex_exact(require_string(envelope, "nonce_hex"), kGcmNonceBytes);
        const auto tag = from_hex_exact(require_string(envelope, "tag_hex"), kGcmTagBytes);
        const auto ciphertext = from_hex_variable(require_string(envelope, "ciphertext_hex"), 4096);
        std::vector<unsigned char> plaintext(ciphertext.size());

        EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
        if (context == nullptr) {
            throw std::runtime_error("historical ledger cipher context allocation failed");
        }
        int len = 0;
        int total = 0;
        bool ok = EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                  EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                                      static_cast<int>(nonce.size()), nullptr) == 1 &&
                  EVP_DecryptInit_ex(context, nullptr, nullptr, key_.data(), nonce.data()) == 1;
        if (ok) {
            ok = EVP_DecryptUpdate(
                     context,
                     nullptr,
                     &len,
                     reinterpret_cast<const unsigned char*>(aad.data()),
                     static_cast<int>(aad.size())
                 ) == 1;
        }
        if (ok && !ciphertext.empty()) {
            ok = EVP_DecryptUpdate(
                     context,
                     plaintext.data(),
                     &len,
                     ciphertext.data(),
                     static_cast<int>(ciphertext.size())
                 ) == 1;
            total = len;
        }
        if (ok) {
            ok = EVP_CIPHER_CTX_ctrl(
                     context,
                     EVP_CTRL_GCM_SET_TAG,
                     static_cast<int>(tag.size()),
                     const_cast<unsigned char*>(tag.data())
                 ) == 1;
        }
        if (ok) {
            ok = EVP_DecryptFinal_ex(context, plaintext.data() + total, &len) == 1;
            total += len;
        }
        EVP_CIPHER_CTX_free(context);
        if (!ok) {
            if (!plaintext.empty()) {
                OPENSSL_cleanse(plaintext.data(), plaintext.size());
            }
            throw std::runtime_error("historical ledger AES-GCM authentication failed");
        }
        std::string output(
            reinterpret_cast<const char*>(plaintext.data()),
            static_cast<std::size_t>(total)
        );
        if (!plaintext.empty()) {
            OPENSSL_cleanse(plaintext.data(), plaintext.size());
        }
        return output;
    }

private:
    std::array<unsigned char, kAesKeyBytes> key_{};
};

std::string canonical_telemetry(const json& telemetry) {
    if (!telemetry.is_object()) {
        throw std::runtime_error("historical ledger telemetry must be an object");
    }
    const char* numeric_fields[] = {
        "speed", "acceleration", "fuel_level", "battery_voltage", "engine_temp",
        "gps_lat", "gps_lon", "obstacle_distance"
    };
    for (const char* field : numeric_fields) {
        if (!telemetry.contains(field) || !telemetry.at(field).is_number()) {
            throw std::runtime_error(std::string("historical ledger telemetry field is invalid: ") + field);
        }
        if (!std::isfinite(telemetry.at(field).get<double>())) {
            throw std::runtime_error("historical ledger telemetry contains a non-finite value");
        }
    }
    if (!telemetry.contains("emergency_brake_active") ||
        !telemetry.at("emergency_brake_active").is_boolean()) {
        throw std::runtime_error("historical ledger emergency brake telemetry is invalid");
    }
    const std::string timestamp = require_string(telemetry, "timestamp");
    json canonical = {
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
    };
    return canonical.dump();
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
        std::string(kBlockDomain) + "\n" + std::to_string(index) + "\n" +
        timestamp + "\n" + vehicle_id + "\n" + telemetry_hash_sha3 + "\n" +
        event_hash_sha3 + "\n" + previous_hash
    );
}

bool verify_current_kem_claim(
    const PqcKeyMaterial& active_material,
    const std::vector<unsigned char>& ciphertext,
    const std::string& expected_shared_secret_hash
) {
    KemPtr kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_512));
    if (!kem || active_material.kem_secret_key.size() != kem->length_secret_key ||
        ciphertext.size() != kem->length_ciphertext) {
        return false;
    }
    std::vector<unsigned char> secret(kem->length_shared_secret);
    const bool decapsulated = OQS_KEM_decaps(
        kem.get(),
        secret.data(),
        ciphertext.data(),
        active_material.kem_secret_key.data()
    ) == OQS_SUCCESS;
    if (!decapsulated) {
        OPENSSL_cleanse(secret.data(), secret.size());
        return false;
    }
    const std::string actual = sha3_256_hex(
        std::string(kPqcDomain) + "\n" + active_material.key_id + "\n" +
        to_hex(secret.data(), secret.size())
    );
    OPENSSL_cleanse(secret.data(), secret.size());
    return actual == expected_shared_secret_hash;
}

json verify_ledger(
    const std::filesystem::path& ledger_path,
    const std::string& vehicle_id,
    const std::string& data_key,
    const PqcKeyMaterial& active_material,
    const PqcTrustKeyring& keyring
) {
    const json ledger = read_ledger(ledger_path);
    const auto trusted = keyring.trusted_identities(active_material.key_id);
    Aes256GcmReader cipher(data_key);

    std::size_t historical_blocks = 0;
    std::size_t current_blocks = 0;
    std::string previous_block_hash(64, '0');
    for (std::size_t i = 0; i < ledger.size(); ++i) {
        const json& block = ledger.at(i);
        const std::size_t index = require_index(block);
        const std::string timestamp = require_string(block, "timestamp");
        const std::string block_vehicle_id = require_string(block, "vehicle_id");
        const std::string event_data = require_string(block, "event_data");
        const std::string previous_hash = require_string(block, "previous_hash");
        if (index != i || block_vehicle_id != vehicle_id || previous_hash != previous_block_hash) {
            throw std::runtime_error("historical ledger index/vehicle/linkage validation failed");
        }
        const std::string telemetry = canonical_telemetry(block.at("telemetry"));
        const std::string telemetry_sha256 = require_string(block, "telemetry_hash_sha256");
        const std::string telemetry_sha3 = require_string(block, "telemetry_hash_sha3");
        const std::string event_sha256 = require_string(block, "event_hash_sha256");
        const std::string event_sha3 = require_string(block, "event_hash_sha3");
        if (telemetry_sha256 != sha256_hex(telemetry) || telemetry_sha3 != sha3_256_hex(telemetry) ||
            event_sha256 != sha256_hex(event_data) || event_sha3 != sha3_256_hex(event_data)) {
            throw std::runtime_error("historical ledger telemetry/event digest validation failed");
        }
        const std::string block_hash = require_string(block, "block_hash");
        const std::string expected_block_hash = block_hash_for(
            index, timestamp, vehicle_id, telemetry_sha3, event_sha3, previous_hash
        );
        if (block_hash != expected_block_hash) {
            throw std::runtime_error("historical ledger block hash validation failed");
        }
        if (!block.contains("dual_hash_encrypted") || !block.at("dual_hash_encrypted").is_object()) {
            throw std::runtime_error("historical ledger encrypted dual hash is missing");
        }
        const std::string aad =
            "OMNIGUARD_DUAL_HASH_AAD_V1|" + vehicle_id + "|" +
            std::to_string(index) + "|" + block_hash;
        const std::string dual_hash = cipher.open(block.at("dual_hash_encrypted"), aad);
        const std::string expected_dual = sha256_hex(block_hash) + ":" + sha3_256_hex(block_hash);
        if (dual_hash != expected_dual) {
            throw std::runtime_error("historical ledger dual-hash plaintext validation failed");
        }

        if (require_string(block, "pqc_algorithm") != "ML-DSA-44+ML-KEM-512") {
            throw std::runtime_error("historical ledger PQC algorithm is not supported");
        }
        const std::string key_id = require_string(block, "pqc_key_id");
        const std::string signature_hex = require_string(block, "pqc_signature_hex");
        const std::string kem_ciphertext_hex = require_string(block, "pqc_kem_ciphertext_hex");
        const std::string shared_secret_hash = require_string(block, "pqc_shared_secret_hash");
        const std::string binding_hash = require_string(block, "pqc_binding_hash");
        const std::string pqc_digest = require_string(block, "pqc_digest");
        if (!is_sha3_hex(shared_secret_hash) || !is_sha3_hex(binding_hash) || !is_sha3_hex(pqc_digest)) {
            throw std::runtime_error("historical ledger PQC digest field is malformed");
        }

        std::unique_ptr<OQS_SIG, void(*)(OQS_SIG*)> signature_algorithm(
            OQS_SIG_new(OQS_SIG_alg_ml_dsa_44), OQS_SIG_free
        );
        KemPtr kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_512));
        if (!signature_algorithm || !kem) {
            throw std::runtime_error("required liboqs historical verification algorithms are unavailable");
        }
        const auto signature = from_hex_variable(signature_hex, signature_algorithm->length_signature);
        const auto signature_public_key = from_hex_exact(
            require_string(block, "pqc_signature_public_key_hex"),
            signature_algorithm->length_public_key
        );
        const auto kem_public_key = from_hex_exact(
            require_string(block, "pqc_kem_public_key_hex"),
            kem->length_public_key
        );
        const auto kem_ciphertext = from_hex_exact(kem_ciphertext_hex, kem->length_ciphertext);
        const std::string message = std::string(kPqcDomain) + "\n" + key_id + "\n" +
            block_hash + "\n" + dual_hash + "\n" + previous_hash + "\n" + timestamp;
        if (!keyring.verify_detached_signature(
                key_id,
                message,
                signature,
                signature_public_key,
                kem_public_key,
                active_material.key_id
            )) {
            throw std::runtime_error("historical ledger ML-DSA signature is not admitted by the verified trust keyring");
        }
        const std::string expected_binding = sha3_256_hex(
            std::string(kPqcDomain) + "\n" + key_id + "\n" + message + "\n" +
            signature_hex + "\n" + kem_ciphertext_hex + "\n" + shared_secret_hash
        );
        if (binding_hash != expected_binding) {
            throw std::runtime_error("historical ledger PQC binding hash validation failed");
        }
        const std::string expected_pqc_digest = sha3_256_hex(
            std::string(kPqcDomain) + "\n" + key_id + "\n" + binding_hash + "\n" + dual_hash
        );
        if (pqc_digest != expected_pqc_digest) {
            throw std::runtime_error("historical ledger PQC digest validation failed");
        }

        if (key_id == active_material.key_id) {
            if (!verify_current_kem_claim(active_material, kem_ciphertext, shared_secret_hash)) {
                throw std::runtime_error("current-generation historical ledger ML-KEM claim failed verification");
            }
            ++current_blocks;
        } else {
            ++historical_blocks;
        }
        previous_block_hash = block_hash;
    }

    return {
        {"format", "OMNIGUARD_PQC_HISTORY_VERIFICATION_V1"},
        {"verified", true},
        {"vehicle_id", vehicle_id},
        {"block_count", ledger.size()},
        {"current_generation_blocks", current_blocks},
        {"historical_generation_blocks", historical_blocks},
        {"trusted_generation_count", trusted.size()},
        {"active_key_id", active_material.key_id},
        {"historical_ml_dsa_authenticity_verified", true},
        {"current_ml_kem_decapsulation_verified", current_blocks > 0},
        {"historical_ml_kem_decapsulation_verified", false},
        {"historical_kem_private_keys_retained", false},
        {"secret_values_exposed", false},
    };
}

void print_usage() {
    std::cerr
        << "Usage:\n"
        << "  smartcar_pqc_history_verify verify --identity <vehicle-id> --ledger <ledger.json>\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2 || std::string(argv[1]) != "verify") {
            print_usage();
            return 64;
        }
        const std::string identity = option_value(argc, argv, "--identity", true);
        const std::filesystem::path ledger_path = option_value(argc, argv, "--ledger", true);
        if (identity.empty() || identity.size() > 256 || ledger_path.empty()) {
            throw std::runtime_error("historical verification identity/ledger path is invalid");
        }

        const std::string data_key = require_env("SMARTCAR_CPP_DATA_KEY", kMinSecretLength);
        const std::string wrapping_secret =
            require_env("SMARTCAR_CPP_PQC_KEYSTORE_KEY", kMinSecretLength);
        const std::filesystem::path active_store_path =
            require_env("SMARTCAR_CPP_PQC_KEYSTORE_PATH");
        const std::filesystem::path keyring_path =
            require_env("SMARTCAR_CPP_PQC_TRUST_KEYRING_PATH");
        const std::size_t max_generations = configured_max_generations();

        PqcKeyStore active_store(active_store_path, wrapping_secret, identity);
        PqcKeyMaterial active_material = active_store.load_or_create();
        PqcTrustKeyring keyring(keyring_path, identity, max_generations);
        (void)keyring.inspect(active_material.key_id);

        std::cout << verify_ledger(
            ledger_path,
            identity,
            data_key,
            active_material,
            keyring
        ).dump(2) << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[PQC-HISTORY-VERIFY] fail-closed: " << error.what() << '\n';
        return 1;
    }
}
