// OmniGuard V2X: secure native C++ blockchain core (v3.2)
// Research hardening: AES-256-GCM data protection + real liboqs ML-DSA/ML-KEM only.

#include <array>
#include <chrono>
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
#include <vector>

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>

using json = nlohmann::json;

namespace {

constexpr const char* kBlockDomain = "OMNIGUARD_NATIVE_BLOCK_V3_2";
constexpr const char* kAeadDomain = "OMNIGUARD_CPP_DATA_KEY_V1";
constexpr const char* kPqcDomain = "OMNIGUARD_NATIVE_PQC_V1";
constexpr size_t kMinSecretLength = 32;
constexpr size_t kAesKeyBytes = 32;
constexpr size_t kGcmNonceBytes = 12;
constexpr size_t kGcmTagBytes = 16;

std::string require_env_secret(const char* name) {
    const char* raw = std::getenv(name);
    if (raw == nullptr) {
        throw std::runtime_error(std::string("required credential is not configured: ") + name);
    }
    std::string value(raw);
    if (value.size() < kMinSecretLength) {
        throw std::runtime_error(std::string("credential must contain at least 32 characters: ") + name);
    }
    return value;
}

std::string now_iso() {
    const auto now = std::chrono::system_clock::now();
    const auto t = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &t);
#else
    gmtime_r(&t, &utc);
#endif
    std::ostringstream out;
    out << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        out << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return out.str();
}

std::vector<uint8_t> digest(const EVP_MD* md, const std::string& input) {
    std::vector<uint8_t> out(static_cast<size_t>(EVP_MD_get_size(md)));
    unsigned int out_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("EVP_MD_CTX allocation failed");
    }
    const int ok = EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
                   EVP_DigestUpdate(ctx, input.data(), input.size()) == 1 &&
                   EVP_DigestFinal_ex(ctx, out.data(), &out_len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) {
        throw std::runtime_error("message digest operation failed");
    }
    out.resize(out_len);
    return out;
}

std::string sha256_hex(const std::string& input) {
    const auto value = digest(EVP_sha256(), input);
    return bytes_to_hex(value.data(), value.size());
}

std::string sha3_256_hex(const std::string& input) {
    const auto value = digest(EVP_sha3_256(), input);
    return bytes_to_hex(value.data(), value.size());
}

bool constant_time_equal(const std::vector<uint8_t>& lhs, const std::vector<uint8_t>& rhs) {
    return lhs.size() == rhs.size() &&
           (lhs.empty() || CRYPTO_memcmp(lhs.data(), rhs.data(), lhs.size()) == 0);
}

struct AeadEnvelope {
    std::array<uint8_t, kGcmNonceBytes> nonce{};
    std::array<uint8_t, kGcmTagBytes> tag{};
    std::vector<uint8_t> ciphertext;

    json to_json() const {
        return {
            {"scheme", "AES-256-GCM"},
            {"version", 1},
            {"nonce_hex", bytes_to_hex(nonce.data(), nonce.size())},
            {"tag_hex", bytes_to_hex(tag.data(), tag.size())},
            {"ciphertext_hex", bytes_to_hex(ciphertext.data(), ciphertext.size())},
        };
    }
};

class Aes256Gcm {
public:
    explicit Aes256Gcm(const std::string& high_entropy_secret) {
        if (high_entropy_secret.size() < kMinSecretLength) {
            throw std::runtime_error("native data key is too short");
        }
        const auto derived = digest(
            EVP_sha256(),
            std::string(kAeadDomain) + "\n" + high_entropy_secret
        );
        if (derived.size() != key_.size()) {
            throw std::runtime_error("native data key derivation failed");
        }
        std::memcpy(key_.data(), derived.data(), key_.size());
    }

    ~Aes256Gcm() {
        OPENSSL_cleanse(key_.data(), key_.size());
    }

    AeadEnvelope seal(const std::string& plaintext, const std::string& aad) const {
        AeadEnvelope envelope;
        if (RAND_bytes(envelope.nonce.data(), static_cast<int>(envelope.nonce.size())) != 1) {
            throw std::runtime_error("secure nonce generation failed");
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) {
            throw std::runtime_error("cipher context allocation failed");
        }

        envelope.ciphertext.resize(plaintext.size());
        int len = 0;
        int total = 0;
        bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                      static_cast<int>(envelope.nonce.size()), nullptr) == 1 &&
                  EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), envelope.nonce.data()) == 1;
        if (ok && !aad.empty()) {
            ok = EVP_EncryptUpdate(
                     ctx, nullptr, &len,
                     reinterpret_cast<const uint8_t*>(aad.data()),
                     static_cast<int>(aad.size())) == 1;
        }
        if (ok && !plaintext.empty()) {
            ok = EVP_EncryptUpdate(
                     ctx, envelope.ciphertext.data(), &len,
                     reinterpret_cast<const uint8_t*>(plaintext.data()),
                     static_cast<int>(plaintext.size())) == 1;
            total = len;
        }
        if (ok) {
            ok = EVP_EncryptFinal_ex(ctx, envelope.ciphertext.data() + total, &len) == 1;
            total += len;
        }
        if (ok) {
            ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                     static_cast<int>(envelope.tag.size()),
                                     envelope.tag.data()) == 1;
        }
        EVP_CIPHER_CTX_free(ctx);

        if (!ok) {
            throw std::runtime_error("AES-256-GCM encryption failed");
        }
        envelope.ciphertext.resize(static_cast<size_t>(total));
        return envelope;
    }

    bool open(
        const AeadEnvelope& envelope,
        const std::string& aad,
        std::string& plaintext
    ) const {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) {
            return false;
        }
        std::vector<uint8_t> output(envelope.ciphertext.size());
        int len = 0;
        int total = 0;
        bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                      static_cast<int>(envelope.nonce.size()), nullptr) == 1 &&
                  EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), envelope.nonce.data()) == 1;
        if (ok && !aad.empty()) {
            ok = EVP_DecryptUpdate(
                     ctx, nullptr, &len,
                     reinterpret_cast<const uint8_t*>(aad.data()),
                     static_cast<int>(aad.size())) == 1;
        }
        if (ok && !envelope.ciphertext.empty()) {
            ok = EVP_DecryptUpdate(
                     ctx, output.data(), &len,
                     envelope.ciphertext.data(),
                     static_cast<int>(envelope.ciphertext.size())) == 1;
            total = len;
        }
        if (ok) {
            ok = EVP_CIPHER_CTX_ctrl(
                     ctx, EVP_CTRL_GCM_SET_TAG,
                     static_cast<int>(envelope.tag.size()),
                     const_cast<uint8_t*>(envelope.tag.data())) == 1;
        }
        if (ok) {
            ok = EVP_DecryptFinal_ex(ctx, output.data() + total, &len) == 1;
            total += len;
        }
        EVP_CIPHER_CTX_free(ctx);
        if (!ok) {
            OPENSSL_cleanse(output.data(), output.size());
            return false;
        }
        plaintext.assign(reinterpret_cast<const char*>(output.data()), static_cast<size_t>(total));
        OPENSSL_cleanse(output.data(), output.size());
        return true;
    }

private:
    std::array<uint8_t, kAesKeyBytes> key_{};
};

struct PqcArtifact {
    std::string algorithm = "ML-DSA-44+ML-KEM-512";
    std::vector<uint8_t> signature;
    std::vector<uint8_t> signature_public_key;
    std::vector<uint8_t> kem_ciphertext;
    std::vector<uint8_t> kem_public_key;
    std::string shared_secret_hash;
    std::string binding_hash;
};

class RealPqcEngine {
public:
    RealPqcEngine() {
        sig_.reset(OQS_SIG_new(OQS_SIG_alg_ml_dsa_44));
        kem_.reset(OQS_KEM_new(OQS_KEM_alg_ml_kem_512));
        if (!sig_ || !kem_) {
            throw std::runtime_error("required liboqs ML-DSA-44/ML-KEM-512 algorithms are unavailable");
        }

        sig_pk_.resize(sig_->length_public_key);
        sig_sk_.resize(sig_->length_secret_key);
        kem_pk_.resize(kem_->length_public_key);
        kem_sk_.resize(kem_->length_secret_key);
        if (OQS_SIG_keypair(sig_.get(), sig_pk_.data(), sig_sk_.data()) != OQS_SUCCESS ||
            OQS_KEM_keypair(kem_.get(), kem_pk_.data(), kem_sk_.data()) != OQS_SUCCESS) {
            throw std::runtime_error("liboqs key generation failed");
        }
    }

    ~RealPqcEngine() {
        if (!sig_sk_.empty()) {
            OPENSSL_cleanse(sig_sk_.data(), sig_sk_.size());
        }
        if (!kem_sk_.empty()) {
            OPENSSL_cleanse(kem_sk_.data(), kem_sk_.size());
        }
    }

    PqcArtifact create(const std::string& message) const {
        PqcArtifact artifact;
        artifact.signature.resize(sig_->length_signature);
        size_t signature_len = 0;
        if (OQS_SIG_sign(
                sig_.get(), artifact.signature.data(), &signature_len,
                reinterpret_cast<const uint8_t*>(message.data()), message.size(),
                sig_sk_.data()) != OQS_SUCCESS) {
            throw std::runtime_error("ML-DSA signing failed");
        }
        artifact.signature.resize(signature_len);
        artifact.signature_public_key = sig_pk_;
        artifact.kem_public_key = kem_pk_;

        artifact.kem_ciphertext.resize(kem_->length_ciphertext);
        std::vector<uint8_t> sender_secret(kem_->length_shared_secret);
        std::vector<uint8_t> receiver_secret(kem_->length_shared_secret);
        const bool kem_ok = OQS_KEM_encaps(
                                kem_.get(), artifact.kem_ciphertext.data(), sender_secret.data(),
                                kem_pk_.data()) == OQS_SUCCESS &&
                            OQS_KEM_decaps(
                                kem_.get(), receiver_secret.data(), artifact.kem_ciphertext.data(),
                                kem_sk_.data()) == OQS_SUCCESS &&
                            constant_time_equal(sender_secret, receiver_secret);
        if (!kem_ok) {
            OPENSSL_cleanse(sender_secret.data(), sender_secret.size());
            OPENSSL_cleanse(receiver_secret.data(), receiver_secret.size());
            throw std::runtime_error("ML-KEM encapsulation/decapsulation failed");
        }

        artifact.shared_secret_hash = sha3_256_hex(
            std::string(kPqcDomain) + "\n" +
            bytes_to_hex(receiver_secret.data(), receiver_secret.size())
        );
        OPENSSL_cleanse(sender_secret.data(), sender_secret.size());
        OPENSSL_cleanse(receiver_secret.data(), receiver_secret.size());

        artifact.binding_hash = sha3_256_hex(
            std::string(kPqcDomain) + "\n" + message + "\n" +
            bytes_to_hex(artifact.signature.data(), artifact.signature.size()) + "\n" +
            bytes_to_hex(artifact.kem_ciphertext.data(), artifact.kem_ciphertext.size()) + "\n" +
            artifact.shared_secret_hash
        );
        return artifact;
    }

    bool verify(const std::string& message, const PqcArtifact& artifact) const {
        if (artifact.algorithm != "ML-DSA-44+ML-KEM-512" ||
            artifact.signature_public_key != sig_pk_ ||
            artifact.kem_public_key != kem_pk_) {
            return false;
        }
        if (OQS_SIG_verify(
                sig_.get(),
                reinterpret_cast<const uint8_t*>(message.data()), message.size(),
                artifact.signature.data(), artifact.signature.size(),
                artifact.signature_public_key.data()) != OQS_SUCCESS) {
            return false;
        }

        std::vector<uint8_t> receiver_secret(kem_->length_shared_secret);
        if (OQS_KEM_decaps(
                kem_.get(), receiver_secret.data(), artifact.kem_ciphertext.data(),
                kem_sk_.data()) != OQS_SUCCESS) {
            return false;
        }
        const std::string expected_secret_hash = sha3_256_hex(
            std::string(kPqcDomain) + "\n" +
            bytes_to_hex(receiver_secret.data(), receiver_secret.size())
        );
        OPENSSL_cleanse(receiver_secret.data(), receiver_secret.size());
        if (expected_secret_hash != artifact.shared_secret_hash) {
            return false;
        }
        const std::string expected_binding = sha3_256_hex(
            std::string(kPqcDomain) + "\n" + message + "\n" +
            bytes_to_hex(artifact.signature.data(), artifact.signature.size()) + "\n" +
            bytes_to_hex(artifact.kem_ciphertext.data(), artifact.kem_ciphertext.size()) + "\n" +
            artifact.shared_secret_hash
        );
        return expected_binding == artifact.binding_hash;
    }

private:
    struct SigDeleter {
        void operator()(OQS_SIG* ptr) const { OQS_SIG_free(ptr); }
    };
    struct KemDeleter {
        void operator()(OQS_KEM* ptr) const { OQS_KEM_free(ptr); }
    };

    std::unique_ptr<OQS_SIG, SigDeleter> sig_;
    std::unique_ptr<OQS_KEM, KemDeleter> kem_;
    std::vector<uint8_t> sig_pk_;
    std::vector<uint8_t> sig_sk_;
    std::vector<uint8_t> kem_pk_;
    std::vector<uint8_t> kem_sk_;
};

struct TelemetryData {
    double speed = 0.0;
    double acceleration = 0.0;
    double fuel_level = 100.0;
    double battery_voltage = 12.6;
    double engine_temp = 20.0;
    double gps_lat = 0.0;
    double gps_lon = 0.0;
    double obstacle_distance = 999.0;
    bool emergency_brake_active = false;
    std::string timestamp;
};

struct Block {
    size_t index = 0;
    std::string timestamp;
    std::string vehicle_id;
    TelemetryData telemetry;
    std::string event_data;
    std::string previous_hash;
    std::string telemetry_hash_sha256;
    std::string telemetry_hash_sha3;
    std::string event_hash_sha256;
    std::string event_hash_sha3;
    std::string block_hash;
    std::string dual_hash;
    PqcArtifact pqc;
    std::string pqc_digest;
};

class SecureBlockchain {
public:
    SecureBlockchain(
        std::string vehicle_id,
        const std::string& data_key,
        const std::string& auth_token
    ) : vehicle_id_(std::move(vehicle_id)),
        cipher_(data_key),
        auth_digest_(digest(EVP_sha3_256(), std::string("OMNIGUARD_AUTH_V1\n") + auth_token)) {
        if (vehicle_id_.empty() || auth_token.size() < kMinSecretLength) {
            throw std::runtime_error("vehicle identity/authentication configuration is invalid");
        }
        create_genesis();
    }

    bool authenticate(const std::string& token) {
        const auto candidate = digest(EVP_sha3_256(), std::string("OMNIGUARD_AUTH_V1\n") + token);
        if (!constant_time_equal(auth_digest_, candidate) || !verify_chain()) {
            return false;
        }
        unlocked_ = true;
        return true;
    }

    bool start_engine() {
        if (!unlocked_ || !verify_chain()) {
            return false;
        }
        engine_started_ = true;
        return true;
    }

    Block append(const TelemetryData& telemetry, std::string event) {
        if (!verify_chain()) {
            throw std::runtime_error("refusing append because native ledger verification failed");
        }
        Block block;
        block.index = chain_.size();
        block.timestamp = now_iso();
        block.vehicle_id = vehicle_id_;
        block.telemetry = telemetry;
        if (block.telemetry.timestamp.empty()) {
            block.telemetry.timestamp = block.timestamp;
        }
        block.event_data = event.empty() ? "TELEMETRY:UPDATE" : std::move(event);
        block.previous_hash = chain_.back().block_hash;
        finalize_block(block);
        chain_.push_back(block);
        if (!verify_chain()) {
            throw std::runtime_error("native ledger failed verification after append");
        }
        return block;
    }

    bool verify_chain() const {
        if (chain_.empty()) {
            return false;
        }
        for (size_t i = 0; i < chain_.size(); ++i) {
            const Block& block = chain_[i];
            if (block.index != i || block.vehicle_id != vehicle_id_) {
                return false;
            }
            const std::string expected_previous = i == 0 ? std::string(64, '0') : chain_[i - 1].block_hash;
            if (block.previous_hash != expected_previous) {
                return false;
            }
            const std::string telemetry = serialize_telemetry(block.telemetry);
            if (block.telemetry_hash_sha256 != sha256_hex(telemetry) ||
                block.telemetry_hash_sha3 != sha3_256_hex(telemetry) ||
                block.event_hash_sha256 != sha256_hex(block.event_data) ||
                block.event_hash_sha3 != sha3_256_hex(block.event_data)) {
                return false;
            }
            if (block.block_hash != compute_block_hash(block)) {
                return false;
            }
            const std::string expected_dual = sha256_hex(block.block_hash) + ":" + sha3_256_hex(block.block_hash);
            if (block.dual_hash != expected_dual) {
                return false;
            }
            const std::string message = pqc_message(block);
            if (!pqc_.verify(message, block.pqc)) {
                return false;
            }
            const std::string expected_pqc_digest = sha3_256_hex(
                std::string(kPqcDomain) + "\n" + block.pqc.binding_hash + "\n" + block.dual_hash
            );
            if (block.pqc_digest != expected_pqc_digest) {
                return false;
            }
        }
        return true;
    }

    void save(const std::filesystem::path& path) const {
        if (!verify_chain()) {
            throw std::runtime_error("refusing persistence because native ledger verification failed");
        }
        json output = json::array();
        for (const Block& block : chain_) {
            const std::string aad =
                "OMNIGUARD_DUAL_HASH_AAD_V1|" + vehicle_id_ + "|" +
                std::to_string(block.index) + "|" + block.block_hash;
            const AeadEnvelope encrypted_dual = cipher_.seal(block.dual_hash, aad);
            output.push_back({
                {"index", block.index},
                {"timestamp", block.timestamp},
                {"vehicle_id", block.vehicle_id},
                {"event_data", block.event_data},
                {"previous_hash", block.previous_hash},
                {"telemetry_hash_sha256", block.telemetry_hash_sha256},
                {"telemetry_hash_sha3", block.telemetry_hash_sha3},
                {"event_hash_sha256", block.event_hash_sha256},
                {"event_hash_sha3", block.event_hash_sha3},
                {"block_hash", block.block_hash},
                {"dual_hash_encrypted", encrypted_dual.to_json()},
                {"pqc_algorithm", block.pqc.algorithm},
                {"pqc_signature_hex", bytes_to_hex(block.pqc.signature.data(), block.pqc.signature.size())},
                {"pqc_signature_public_key_hex", bytes_to_hex(block.pqc.signature_public_key.data(), block.pqc.signature_public_key.size())},
                {"pqc_kem_ciphertext_hex", bytes_to_hex(block.pqc.kem_ciphertext.data(), block.pqc.kem_ciphertext.size())},
                {"pqc_kem_public_key_hex", bytes_to_hex(block.pqc.kem_public_key.data(), block.pqc.kem_public_key.size())},
                {"pqc_shared_secret_hash", block.pqc.shared_secret_hash},
                {"pqc_binding_hash", block.pqc.binding_hash},
                {"pqc_digest", block.pqc_digest},
                {"telemetry", {
                    {"speed", block.telemetry.speed},
                    {"acceleration", block.telemetry.acceleration},
                    {"fuel_level", block.telemetry.fuel_level},
                    {"battery_voltage", block.telemetry.battery_voltage},
                    {"engine_temp", block.telemetry.engine_temp},
                    {"gps_lat", block.telemetry.gps_lat},
                    {"gps_lon", block.telemetry.gps_lon},
                    {"obstacle_distance", block.telemetry.obstacle_distance},
                    {"emergency_brake_active", block.telemetry.emergency_brake_active},
                    {"timestamp", block.telemetry.timestamp},
                }},
            });
        }

        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path());
        }
        const std::filesystem::path temp = path.string() + ".tmp";
        {
            std::ofstream stream(temp, std::ios::binary | std::ios::trunc);
            if (!stream) {
                throw std::runtime_error("could not create native ledger temporary file");
            }
            stream << output.dump(2);
            stream.flush();
            if (!stream) {
                throw std::runtime_error("could not persist native ledger temporary file");
            }
        }
        std::error_code ec;
        std::filesystem::rename(temp, path, ec);
        if (ec) {
            std::filesystem::remove(path, ec);
            ec.clear();
            std::filesystem::rename(temp, path, ec);
        }
        if (ec) {
            std::filesystem::remove(temp);
            throw std::runtime_error("could not atomically publish native ledger file");
        }
    }

    bool aead_self_test() const {
        const std::string plaintext = "native-aead-self-test";
        const std::string aad = "OMNIGUARD_AEAD_SELF_TEST_V1";
        AeadEnvelope envelope = cipher_.seal(plaintext, aad);
        std::string recovered;
        if (!cipher_.open(envelope, aad, recovered) || recovered != plaintext) {
            return false;
        }
        envelope.tag[0] ^= 0x01;
        recovered.clear();
        return !cipher_.open(envelope, aad, recovered);
    }

    size_t size() const { return chain_.size(); }

private:
    std::string serialize_telemetry(const TelemetryData& value) const {
        json canonical = {
            {"speed", value.speed},
            {"acceleration", value.acceleration},
            {"fuel_level", value.fuel_level},
            {"battery_voltage", value.battery_voltage},
            {"engine_temp", value.engine_temp},
            {"gps_lat", value.gps_lat},
            {"gps_lon", value.gps_lon},
            {"obstacle_distance", value.obstacle_distance},
            {"emergency_brake_active", value.emergency_brake_active},
            {"timestamp", value.timestamp},
        };
        return canonical.dump();
    }

    std::string compute_block_hash(const Block& block) const {
        const std::string payload =
            std::string(kBlockDomain) + "\n" + std::to_string(block.index) + "\n" +
            block.timestamp + "\n" + block.vehicle_id + "\n" +
            block.telemetry_hash_sha3 + "\n" + block.event_hash_sha3 + "\n" +
            block.previous_hash;
        return sha3_256_hex(payload);
    }

    std::string pqc_message(const Block& block) const {
        return std::string(kPqcDomain) + "\n" + block.block_hash + "\n" +
               block.dual_hash + "\n" + block.previous_hash + "\n" + block.timestamp;
    }

    void finalize_block(Block& block) {
        const std::string telemetry = serialize_telemetry(block.telemetry);
        block.telemetry_hash_sha256 = sha256_hex(telemetry);
        block.telemetry_hash_sha3 = sha3_256_hex(telemetry);
        block.event_hash_sha256 = sha256_hex(block.event_data);
        block.event_hash_sha3 = sha3_256_hex(block.event_data);
        block.block_hash = compute_block_hash(block);
        block.dual_hash = sha256_hex(block.block_hash) + ":" + sha3_256_hex(block.block_hash);
        block.pqc = pqc_.create(pqc_message(block));
        block.pqc_digest = sha3_256_hex(
            std::string(kPqcDomain) + "\n" + block.pqc.binding_hash + "\n" + block.dual_hash
        );
    }

    void create_genesis() {
        Block genesis;
        genesis.index = 0;
        genesis.timestamp = now_iso();
        genesis.vehicle_id = vehicle_id_;
        genesis.telemetry.timestamp = genesis.timestamp;
        genesis.event_data = "GENESIS:VEHICLE_INITIALIZED";
        genesis.previous_hash = std::string(64, '0');
        finalize_block(genesis);
        chain_.push_back(std::move(genesis));
    }

    std::string vehicle_id_;
    Aes256Gcm cipher_;
    std::vector<uint8_t> auth_digest_;
    RealPqcEngine pqc_;
    std::vector<Block> chain_;
    bool unlocked_ = false;
    bool engine_started_ = false;
};

int run_self_test(const std::string& vehicle_id, const std::string& data_key, const std::string& auth_token) {
    SecureBlockchain blockchain(vehicle_id, data_key, auth_token);
    if (!blockchain.aead_self_test()) {
        std::cerr << "[SELF-TEST] AES-256-GCM tamper test failed\n";
        return 2;
    }
    if (blockchain.authenticate("definitely-wrong-token")) {
        std::cerr << "[SELF-TEST] invalid authentication token accepted\n";
        return 3;
    }
    if (!blockchain.authenticate(auth_token) || !blockchain.start_engine()) {
        std::cerr << "[SELF-TEST] valid authentication/engine gate failed\n";
        return 4;
    }

    TelemetryData telemetry;
    telemetry.speed = 64.5;
    telemetry.acceleration = 1.2;
    telemetry.engine_temp = 88.0;
    telemetry.gps_lat = 23.8103;
    telemetry.gps_lon = 90.4125;
    telemetry.obstacle_distance = 250.0;
    telemetry.timestamp = now_iso();
    blockchain.append(telemetry, "SELFTEST:TELEMETRY");
    if (!blockchain.verify_chain() || blockchain.size() != 2) {
        std::cerr << "[SELF-TEST] native ledger verification failed\n";
        return 5;
    }
    std::cout << "[SELF-TEST] PASS: AES-256-GCM + ML-DSA-44 + ML-KEM-512 + full-chain verification\n";
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const std::string data_key = require_env_secret("SMARTCAR_CPP_DATA_KEY");
        const std::string auth_token = require_env_secret("SMARTCAR_AUTH_TOKEN");
        const std::string vehicle_id = argc > 1 ? argv[1] : "SMARTCAR_CPP_VEHICLE_001";

        if (argc > 1 && std::string(argv[1]) == "--self-test") {
            return run_self_test("SMARTCAR_CPP_SELFTEST", data_key, auth_token);
        }

        SecureBlockchain blockchain(vehicle_id, data_key, auth_token);
        if (!blockchain.authenticate(auth_token)) {
            throw std::runtime_error("native authentication failed");
        }
        const std::filesystem::path output =
            argc > 2 ? std::filesystem::path(argv[2])
                     : std::filesystem::path("logs/blockchain_cpp_secure.json");
        blockchain.save(output);
        std::cout << "[NATIVE] Secure ledger initialized and persisted. blocks=" << blockchain.size() << "\n";
        std::cout << "[NATIVE] PQC=ML-DSA-44+ML-KEM-512, data-at-rest=AES-256-GCM\n";
        return 0;
    } catch (const std::exception& exc) {
        std::cerr << "[NATIVE] fail-closed: " << exc.what() << "\n";
        return 1;
    }
}
