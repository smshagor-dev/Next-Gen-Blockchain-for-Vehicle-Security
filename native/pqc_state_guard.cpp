#include "pqc_state_guard.h"

#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <system_error>

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#endif

namespace omniguard {
namespace {

using json = nlohmann::json;
constexpr std::size_t kMinSecretLength = 32;
constexpr std::uintmax_t kMaxAnchorBytes = 64 * 1024;
constexpr std::size_t kMaxIdentityLength = 256;
constexpr std::size_t kMaxKeyIdLength = 256;

std::string to_hex(const unsigned char* data, std::size_t size) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string output(size * 2, '0');
    for (std::size_t i = 0; i < size; ++i) {
        output[i * 2] = kHex[(data[i] >> 4) & 0x0f];
        output[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return output;
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

std::string sha3_256_hex(const std::string& input) {
    std::array<unsigned char, 32> output{};
    unsigned int output_len = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("rollback anchor SHA3 context allocation failed");
    }
    const bool ok = EVP_DigestInit_ex(context, EVP_sha3_256(), nullptr) == 1 &&
                    EVP_DigestUpdate(context, input.data(), input.size()) == 1 &&
                    EVP_DigestFinal_ex(context, output.data(), &output_len) == 1;
    EVP_MD_CTX_free(context);
    if (!ok || output_len != output.size()) {
        throw std::runtime_error("rollback anchor SHA3-256 operation failed");
    }
    return to_hex(output.data(), output.size());
}

std::string hmac_sha256_hex(const std::string& secret, const std::string& message) {
    unsigned char output[EVP_MAX_MD_SIZE]{};
    unsigned int output_len = 0;
    if (HMAC(
            EVP_sha256(),
            secret.data(),
            static_cast<int>(secret.size()),
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size(),
            output,
            &output_len
        ) == nullptr || output_len != 32) {
        throw std::runtime_error("rollback anchor HMAC operation failed");
    }
    return to_hex(output, output_len);
}

bool constant_time_hex_equal(const std::string& lhs, const std::string& rhs) {
    if (lhs.size() != rhs.size() || lhs.empty()) {
        return false;
    }
    return CRYPTO_memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
}

std::string require_string(const json& object, const char* key) {
    if (!object.contains(key) || !object.at(key).is_string()) {
        throw std::runtime_error(std::string("rollback anchor field missing or invalid: ") + key);
    }
    const std::string value = object.at(key).get<std::string>();
    if (value.empty()) {
        throw std::runtime_error(std::string("rollback anchor field is empty: ") + key);
    }
    return value;
}

std::uint64_t require_uint64(const json& object, const char* key) {
    if (!object.contains(key) || !object.at(key).is_number_unsigned()) {
        throw std::runtime_error(std::string("rollback anchor integer field missing or invalid: ") + key);
    }
    return object.at(key).get<std::uint64_t>();
}

void require_exact_keys(const json& object, const std::set<std::string>& expected) {
    if (!object.is_object()) {
        throw std::runtime_error("rollback anchor must be a JSON object");
    }
    std::set<std::string> actual;
    for (auto it = object.begin(); it != object.end(); ++it) {
        actual.insert(it.key());
    }
    if (actual != expected) {
        throw std::runtime_error("rollback anchor contains missing or unexpected fields");
    }
}

void ensure_regular_non_symlink(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status)) {
        throw std::runtime_error("rollback anchor path must be a regular non-symlink file");
    }
    const auto size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > kMaxAnchorBytes) {
        throw std::runtime_error("rollback anchor file size is invalid");
    }
}

void set_private_permissions(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace,
        error
    );
    if (error) {
        throw std::runtime_error("could not restrict rollback anchor permissions");
    }
}

std::string random_suffix() {
    std::array<unsigned char, 8> value{};
    if (RAND_bytes(value.data(), static_cast<int>(value.size())) != 1) {
        throw std::runtime_error("rollback anchor temporary-name generation failed");
    }
    return to_hex(value.data(), value.size());
}

json read_document(const std::filesystem::path& path) {
    ensure_regular_non_symlink(path);
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("could not open rollback anchor");
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    try {
        return json::parse(buffer.str());
    } catch (const json::exception&) {
        throw std::runtime_error("rollback anchor contains malformed JSON");
    }
}

void atomic_publish(const std::filesystem::path& path, const json& document, bool replace_existing) {
    if (path.empty() || path.filename().empty()) {
        throw std::runtime_error("rollback anchor path is invalid");
    }
    if (path.has_parent_path()) {
        std::error_code error;
        std::filesystem::create_directories(path.parent_path(), error);
        if (error) {
            throw std::runtime_error("could not create rollback anchor directory");
        }
    }
    if (!replace_existing && std::filesystem::exists(path)) {
        throw std::runtime_error("refusing to overwrite existing rollback anchor");
    }
    if (replace_existing) {
        if (!std::filesystem::exists(path)) {
            throw std::runtime_error("rollback anchor disappeared before update");
        }
        ensure_regular_non_symlink(path);
    }

    const std::filesystem::path temporary = path.string() + ".tmp." + random_suffix();
    try {
        {
            std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
            if (!stream) {
                throw std::runtime_error("could not create rollback anchor temporary file");
            }
            stream << document.dump(2) << '\n';
            stream.flush();
            if (!stream) {
                throw std::runtime_error("could not persist rollback anchor temporary file");
            }
        }
        set_private_permissions(temporary);
#if defined(_WIN32)
        const DWORD flags = replace_existing
            ? (MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
            : MOVEFILE_WRITE_THROUGH;
        if (!MoveFileExW(temporary.c_str(), path.c_str(), flags)) {
            throw std::runtime_error("could not atomically publish rollback anchor");
        }
#else
        std::error_code rename_error;
        std::filesystem::rename(temporary, path, rename_error);
        if (rename_error) {
            throw std::runtime_error("could not atomically publish rollback anchor");
        }
#endif
        set_private_permissions(path);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        throw;
    }
}

std::string canonical_message(
    const std::string& identity,
    std::uint64_t sequence,
    std::uint64_t generation,
    const std::string& active_key_id,
    const std::string& trust_head_hash,
    const std::string& previous_anchor_hash
) {
    return std::string(PqcRollbackAnchor::kDomain) + "\n" + identity + "\n" +
           std::to_string(sequence) + "\n" + std::to_string(generation) + "\n" +
           active_key_id + "\n" + trust_head_hash + "\n" + previous_anchor_hash;
}

json make_document(
    const std::string& secret,
    const std::string& identity,
    std::uint64_t sequence,
    std::uint64_t generation,
    const std::string& active_key_id,
    const std::string& trust_head_hash,
    const std::string& previous_anchor_hash
) {
    const std::string message = canonical_message(
        identity, sequence, generation, active_key_id, trust_head_hash, previous_anchor_hash
    );
    const std::string anchor_hash = sha3_256_hex(message);
    const std::string mac = hmac_sha256_hex(secret, message + "\n" + anchor_hash);
    return {
        {"format", PqcRollbackAnchor::kFormat},
        {"identity", identity},
        {"sequence", sequence},
        {"active_generation", generation},
        {"active_key_id", active_key_id},
        {"trust_head_hash", trust_head_hash},
        {"previous_anchor_hash", previous_anchor_hash},
        {"anchor_hash", anchor_hash},
        {"mac_hmac_sha256", mac},
        {"externally_protected", false},
        {"hardware_monotonic", false},
    };
}

PqcRollbackAnchorMetadata verify_document(
    const json& document,
    const std::string& secret,
    const std::string& identity
) {
    require_exact_keys(
        document,
        {
            "format",
            "identity",
            "sequence",
            "active_generation",
            "active_key_id",
            "trust_head_hash",
            "previous_anchor_hash",
            "anchor_hash",
            "mac_hmac_sha256",
            "externally_protected",
            "hardware_monotonic",
        }
    );
    if (require_string(document, "format") != PqcRollbackAnchor::kFormat ||
        require_string(document, "identity") != identity) {
        throw std::runtime_error("rollback anchor format or identity mismatch");
    }
    const std::uint64_t sequence = require_uint64(document, "sequence");
    const std::uint64_t generation = require_uint64(document, "active_generation");
    const std::string key_id = require_string(document, "active_key_id");
    const std::string trust_head_hash = require_string(document, "trust_head_hash");
    const std::string previous_hash = require_string(document, "previous_anchor_hash");
    const std::string anchor_hash = require_string(document, "anchor_hash");
    const std::string mac = require_string(document, "mac_hmac_sha256");
    if (sequence == 0 || generation == 0 || sequence != generation ||
        key_id.size() > kMaxKeyIdLength || !is_sha3_hex(trust_head_hash) ||
        !is_sha3_hex(previous_hash) || !is_sha3_hex(anchor_hash) || mac.size() != 64) {
        throw std::runtime_error("rollback anchor metadata is malformed");
    }
    if (!document.at("externally_protected").is_boolean() ||
        !document.at("hardware_monotonic").is_boolean() ||
        document.at("externally_protected").get<bool>() ||
        document.at("hardware_monotonic").get<bool>()) {
        throw std::runtime_error("rollback anchor capability metadata is invalid");
    }

    const std::string message = canonical_message(
        identity, sequence, generation, key_id, trust_head_hash, previous_hash
    );
    const std::string expected_hash = sha3_256_hex(message);
    const std::string expected_mac = hmac_sha256_hex(secret, message + "\n" + expected_hash);
    if (anchor_hash != expected_hash || !constant_time_hex_equal(mac, expected_mac)) {
        throw std::runtime_error("rollback anchor authentication failed");
    }
    return {
        PqcRollbackAnchor::kFormat,
        identity,
        sequence,
        generation,
        key_id,
        trust_head_hash,
        anchor_hash,
        false,
        false,
    };
}

}  // namespace

PqcRollbackAnchor::PqcRollbackAnchor(
    std::filesystem::path path,
    std::string secret,
    std::string identity
) : path_(std::move(path)), secret_(std::move(secret)), identity_(std::move(identity)) {
    if (path_.empty() || path_.filename().empty()) {
        throw std::runtime_error("rollback anchor path is invalid");
    }
    if (secret_.size() < kMinSecretLength) {
        throw std::runtime_error("rollback anchor secret must contain at least 32 characters");
    }
    if (identity_.empty() || identity_.size() > kMaxIdentityLength) {
        throw std::runtime_error("rollback anchor identity is invalid");
    }
}

void PqcRollbackAnchor::initialize(
    std::uint64_t generation,
    const std::string& active_key_id,
    const std::string& trust_head_hash
) const {
    if (generation == 0 || active_key_id.empty() || active_key_id.size() > kMaxKeyIdLength ||
        !is_sha3_hex(trust_head_hash)) {
        throw std::runtime_error("rollback anchor initialization metadata is invalid");
    }
    atomic_publish(
        path_,
        make_document(
            secret_,
            identity_,
            generation,
            generation,
            active_key_id,
            trust_head_hash,
            std::string(64, '0')
        ),
        false
    );
    verify_exact(generation, active_key_id, trust_head_hash);
}

void PqcRollbackAnchor::advance(
    std::uint64_t generation,
    const std::string& active_key_id,
    const std::string& trust_head_hash
) const {
    const PqcRollbackAnchorMetadata current = inspect();
    if (generation != current.active_generation + 1 || generation != current.sequence + 1 ||
        active_key_id.empty() || active_key_id == current.active_key_id ||
        active_key_id.size() > kMaxKeyIdLength || !is_sha3_hex(trust_head_hash)) {
        throw std::runtime_error("rollback anchor advance must be exactly one new trusted generation");
    }
    atomic_publish(
        path_,
        make_document(
            secret_,
            identity_,
            generation,
            generation,
            active_key_id,
            trust_head_hash,
            current.anchor_hash
        ),
        true
    );
    verify_exact(generation, active_key_id, trust_head_hash);
}

PqcRollbackAnchorMetadata PqcRollbackAnchor::inspect() const {
    if (!std::filesystem::exists(path_)) {
        throw std::runtime_error("rollback anchor does not exist");
    }
    return verify_document(read_document(path_), secret_, identity_);
}

void PqcRollbackAnchor::verify_exact(
    std::uint64_t generation,
    const std::string& active_key_id,
    const std::string& trust_head_hash
) const {
    const PqcRollbackAnchorMetadata metadata = inspect();
    if (metadata.active_generation != generation || metadata.active_key_id != active_key_id ||
        metadata.trust_head_hash != trust_head_hash) {
        throw std::runtime_error(
            "rollback anchor mismatch: copied/older trust state or unanchored rotation detected"
        );
    }
}

}  // namespace omniguard
