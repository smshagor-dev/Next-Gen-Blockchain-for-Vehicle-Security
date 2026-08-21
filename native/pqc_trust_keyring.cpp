#include "pqc_trust_keyring.h"

#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#endif

namespace omniguard {
namespace {

using json = nlohmann::json;

constexpr std::uintmax_t kMaxKeyringBytes = 2 * 1024 * 1024;
constexpr std::size_t kMinReasonLength = 8;
constexpr std::size_t kMaxReasonLength = 256;

struct SigDeleter {
    void operator()(OQS_SIG* value) const { OQS_SIG_free(value); }
};

struct KemDeleter {
    void operator()(OQS_KEM* value) const { OQS_KEM_free(value); }
};

using SigPtr = std::unique_ptr<OQS_SIG, SigDeleter>;
using KemPtr = std::unique_ptr<OQS_KEM, KemDeleter>;

struct VerifiedKeyring {
    json document;
    std::vector<PqcTrustedIdentity> identities;
    std::string head_hash;
};

std::pair<SigPtr, KemPtr> algorithms() {
    SigPtr signature(OQS_SIG_new(OQS_SIG_alg_ml_dsa_44));
    KemPtr kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_512));
    if (!signature || !kem) {
        throw std::runtime_error("required liboqs ML-DSA-44/ML-KEM-512 algorithms are unavailable");
    }
    return {std::move(signature), std::move(kem)};
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
    throw std::runtime_error("PQC trust keyring contains invalid hexadecimal data");
}

std::vector<unsigned char> from_hex(const std::string& value, std::size_t expected_size) {
    if (value.size() != expected_size * 2) {
        throw std::runtime_error("PQC trust keyring hexadecimal field has an unexpected length");
    }
    std::vector<unsigned char> output(expected_size);
    for (std::size_t i = 0; i < expected_size; ++i) {
        output[i] = static_cast<unsigned char>(
            (from_hex_char(value[i * 2]) << 4) | from_hex_char(value[i * 2 + 1])
        );
    }
    return output;
}

std::vector<unsigned char> from_variable_hex(const std::string& value, std::size_t max_bytes) {
    if (value.empty() || value.size() % 2 != 0 || value.size() / 2 > max_bytes) {
        throw std::runtime_error("PQC trust keyring signature field has an invalid length");
    }
    std::vector<unsigned char> output(value.size() / 2);
    for (std::size_t i = 0; i < output.size(); ++i) {
        output[i] = static_cast<unsigned char>(
            (from_hex_char(value[i * 2]) << 4) | from_hex_char(value[i * 2 + 1])
        );
    }
    return output;
}

std::string sha3_256_hex(const std::string& input) {
    std::array<unsigned char, 32> output{};
    unsigned int output_len = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("PQC trust keyring SHA3 context allocation failed");
    }
    const bool ok = EVP_DigestInit_ex(context, EVP_sha3_256(), nullptr) == 1 &&
                    EVP_DigestUpdate(context, input.data(), input.size()) == 1 &&
                    EVP_DigestFinal_ex(context, output.data(), &output_len) == 1;
    EVP_MD_CTX_free(context);
    if (!ok || output_len != output.size()) {
        throw std::runtime_error("PQC trust keyring SHA3-256 operation failed");
    }
    return to_hex(output.data(), output.size());
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
        throw std::runtime_error(std::string("PQC trust keyring field is missing or invalid: ") + key);
    }
    const std::string value = object.at(key).get<std::string>();
    if (value.empty()) {
        throw std::runtime_error(std::string("PQC trust keyring field is empty: ") + key);
    }
    return value;
}

std::uint64_t require_uint64(const json& object, const char* key) {
    if (!object.contains(key) || !object.at(key).is_number_unsigned()) {
        throw std::runtime_error(std::string("PQC trust keyring integer field is missing or invalid: ") + key);
    }
    return object.at(key).get<std::uint64_t>();
}

void require_exact_keys(const json& object, const std::set<std::string>& expected) {
    if (!object.is_object()) {
        throw std::runtime_error("PQC trust keyring schema element must be a JSON object");
    }
    std::set<std::string> actual;
    for (auto iterator = object.begin(); iterator != object.end(); ++iterator) {
        actual.insert(iterator.key());
    }
    if (actual != expected) {
        throw std::runtime_error("PQC trust keyring schema contains missing or unexpected fields");
    }
}

void ensure_regular_non_symlink(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status)) {
        throw std::runtime_error("PQC trust keyring path must be a regular non-symlink file");
    }
    const auto size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > kMaxKeyringBytes) {
        throw std::runtime_error("PQC trust keyring file size is invalid");
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
        throw std::runtime_error("could not restrict PQC trust keyring permissions");
    }
}

json read_document(const std::filesystem::path& path) {
    ensure_regular_non_symlink(path);
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("could not open PQC trust keyring");
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    if (!stream.good() && !stream.eof()) {
        throw std::runtime_error("could not read PQC trust keyring");
    }
    try {
        return json::parse(buffer.str());
    } catch (const json::exception&) {
        throw std::runtime_error("PQC trust keyring contains malformed JSON");
    }
}

std::string random_suffix() {
    std::array<unsigned char, 8> value{};
    if (RAND_bytes(value.data(), static_cast<int>(value.size())) != 1) {
        throw std::runtime_error("PQC trust keyring temporary name generation failed");
    }
    return to_hex(value.data(), value.size());
}

void atomic_publish_json(
    const std::filesystem::path& path,
    const json& document,
    bool replace_existing
) {
    if (path.empty() || path.filename().empty()) {
        throw std::runtime_error("PQC trust keyring path is invalid");
    }
    if (path.has_parent_path()) {
        std::error_code directory_error;
        std::filesystem::create_directories(path.parent_path(), directory_error);
        if (directory_error) {
            throw std::runtime_error("could not create PQC trust keyring directory");
        }
    }
    if (!replace_existing && std::filesystem::exists(path)) {
        throw std::runtime_error("refusing to overwrite existing PQC trust keyring root");
    }
    if (replace_existing && !std::filesystem::exists(path)) {
        throw std::runtime_error("PQC trust keyring disappeared before update");
    }
    if (replace_existing) {
        ensure_regular_non_symlink(path);
    }

    const std::filesystem::path temporary = path.string() + ".tmp." + random_suffix();
    try {
        {
            std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
            if (!stream) {
                throw std::runtime_error("could not create PQC trust keyring temporary file");
            }
            stream << document.dump(2) << '\n';
            stream.flush();
            if (!stream) {
                throw std::runtime_error("could not persist PQC trust keyring temporary file");
            }
        }
        set_private_permissions(temporary);
#if defined(_WIN32)
        const DWORD flags = replace_existing
            ? (MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
            : MOVEFILE_WRITE_THROUGH;
        if (!MoveFileExW(temporary.c_str(), path.c_str(), flags)) {
            throw std::runtime_error("could not atomically publish PQC trust keyring");
        }
#else
        std::error_code rename_error;
        std::filesystem::rename(temporary, path, rename_error);
        if (rename_error) {
            throw std::runtime_error("could not atomically publish PQC trust keyring");
        }
#endif
        set_private_permissions(path);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        throw;
    }
}

std::vector<unsigned char> sign_message(
    const OQS_SIG* signature,
    const std::vector<unsigned char>& secret_key,
    const std::string& message
) {
    if (secret_key.size() != signature->length_secret_key) {
        throw std::runtime_error("PQC trust transition signing secret key has an unexpected size");
    }
    std::vector<unsigned char> output(signature->length_signature);
    std::size_t output_len = 0;
    if (OQS_SIG_sign(
            signature,
            output.data(),
            &output_len,
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size(),
            secret_key.data()
        ) != OQS_SUCCESS) {
        throw std::runtime_error("PQC trust transition ML-DSA signing failed");
    }
    output.resize(output_len);
    return output;
}

bool verify_message(
    const OQS_SIG* signature,
    const std::vector<unsigned char>& public_key,
    const std::string& message,
    const std::vector<unsigned char>& signature_value
) {
    if (public_key.size() != signature->length_public_key || signature_value.empty() ||
        signature_value.size() > signature->length_signature) {
        return false;
    }
    return OQS_SIG_verify(
               signature,
               reinterpret_cast<const unsigned char*>(message.data()),
               message.size(),
               signature_value.data(),
               signature_value.size(),
               public_key.data()
           ) == OQS_SUCCESS;
}

void validate_material_shape(
    const PqcKeyMaterial& material,
    const std::string& expected_identity,
    const OQS_SIG* signature,
    const OQS_KEM* kem,
    bool require_private
) {
    if (material.identity != expected_identity || material.key_id.empty() || material.key_id.size() > 256 ||
        material.signature_public_key.size() != signature->length_public_key ||
        material.kem_public_key.size() != kem->length_public_key) {
        throw std::runtime_error("PQC trust key material is incomplete or bound to the wrong identity");
    }
    if (require_private &&
        (material.signature_secret_key.size() != signature->length_secret_key ||
         material.kem_secret_key.size() != kem->length_secret_key)) {
        throw std::runtime_error("PQC trust transition requires complete private key material");
    }
}

std::string root_statement(const PqcTrustedIdentity& root) {
    return std::string(PqcTrustKeyring::kRootDomain) + "\n" +
           root.identity + "\n" + std::to_string(root.generation) + "\n" + root.key_id + "\n" +
           PqcKeyStore::kSignatureAlgorithm + "\n" +
           to_hex(root.signature_public_key.data(), root.signature_public_key.size()) + "\n" +
           PqcKeyStore::kKemAlgorithm + "\n" +
           to_hex(root.kem_public_key.data(), root.kem_public_key.size());
}

std::string transition_statement(
    const std::string& identity,
    std::uint64_t from_generation,
    std::uint64_t to_generation,
    const std::string& from_key_id,
    const PqcTrustedIdentity& next,
    const std::string& reason_hash,
    const std::string& previous_transition_hash
) {
    return std::string(PqcTrustKeyring::kTransitionDomain) + "\n" +
           identity + "\n" + std::to_string(from_generation) + "\n" +
           std::to_string(to_generation) + "\n" + from_key_id + "\n" + next.key_id + "\n" +
           PqcKeyStore::kSignatureAlgorithm + "\n" +
           to_hex(next.signature_public_key.data(), next.signature_public_key.size()) + "\n" +
           PqcKeyStore::kKemAlgorithm + "\n" +
           to_hex(next.kem_public_key.data(), next.kem_public_key.size()) + "\n" +
           reason_hash + "\n" + previous_transition_hash;
}

json trusted_identity_json(const PqcTrustedIdentity& identity) {
    return {
        {"generation", identity.generation},
        {"key_id", identity.key_id},
        {"signature_algorithm", PqcKeyStore::kSignatureAlgorithm},
        {"kem_algorithm", PqcKeyStore::kKemAlgorithm},
        {"signature_public_key_hex", to_hex(
            identity.signature_public_key.data(), identity.signature_public_key.size())},
        {"kem_public_key_hex", to_hex(
            identity.kem_public_key.data(), identity.kem_public_key.size())},
    };
}

PqcTrustedIdentity parse_identity(
    const json& object,
    const std::string& identity,
    const OQS_SIG* signature,
    const OQS_KEM* kem
) {
    require_exact_keys(
        object,
        {
            "generation",
            "key_id",
            "signature_algorithm",
            "kem_algorithm",
            "signature_public_key_hex",
            "kem_public_key_hex",
        }
    );
    if (require_string(object, "signature_algorithm") != PqcKeyStore::kSignatureAlgorithm ||
        require_string(object, "kem_algorithm") != PqcKeyStore::kKemAlgorithm) {
        throw std::runtime_error("PQC trust keyring algorithm mismatch");
    }
    PqcTrustedIdentity output;
    output.generation = require_uint64(object, "generation");
    output.key_id = require_string(object, "key_id");
    output.identity = identity;
    if (output.key_id.size() > 256) {
        throw std::runtime_error("PQC trust key identifier is too long");
    }
    output.signature_public_key = from_hex(
        require_string(object, "signature_public_key_hex"),
        signature->length_public_key
    );
    output.kem_public_key = from_hex(
        require_string(object, "kem_public_key_hex"),
        kem->length_public_key
    );
    return output;
}

VerifiedKeyring verify_document(
    const json& document,
    const std::string& expected_identity,
    std::size_t expected_max_generations,
    const std::string& expected_active_key_id
) {
    require_exact_keys(
        document,
        {
            "format",
            "identity",
            "max_generations",
            "active_generation",
            "active_key_id",
            "root",
            "transitions",
            "head_hash",
            "secret_key_material_stored",
        }
    );
    if (require_string(document, "format") != PqcTrustKeyring::kFormat ||
        require_string(document, "identity") != expected_identity) {
        throw std::runtime_error("PQC trust keyring format or identity mismatch");
    }
    const std::uint64_t file_max_generations = require_uint64(document, "max_generations");
    if (file_max_generations != expected_max_generations || file_max_generations < 2 ||
        file_max_generations > PqcTrustKeyring::kAbsoluteMaxGenerations) {
        throw std::runtime_error("PQC trust keyring generation bound mismatch");
    }
    if (!document.at("secret_key_material_stored").is_boolean() ||
        document.at("secret_key_material_stored").get<bool>()) {
        throw std::runtime_error("PQC trust keyring must not store secret key material");
    }
    if (!document.at("root").is_object() || !document.at("transitions").is_array()) {
        throw std::runtime_error("PQC trust keyring root/transitions schema is invalid");
    }
    if (document.at("transitions").size() + 1 > expected_max_generations) {
        throw std::runtime_error("PQC trust keyring exceeds the configured generation bound");
    }

    auto [signature, kem] = algorithms();
    const json& root_object = document.at("root");
    require_exact_keys(root_object, {"identity", "root_record", "root_self_signature_hex", "root_record_hash"});
    if (require_string(root_object, "identity") != expected_identity ||
        !root_object.at("root_record").is_object()) {
        throw std::runtime_error("PQC trust root identity/schema mismatch");
    }

    PqcTrustedIdentity root = parse_identity(
        root_object.at("root_record"),
        expected_identity,
        signature.get(),
        kem.get()
    );
    if (root.generation != 1) {
        throw std::runtime_error("PQC trust root generation must be 1");
    }
    const std::vector<unsigned char> root_signature = from_variable_hex(
        require_string(root_object, "root_self_signature_hex"),
        signature->length_signature
    );
    const std::string root_message = root_statement(root);
    if (!verify_message(signature.get(), root.signature_public_key, root_message, root_signature)) {
        throw std::runtime_error("PQC trust root self-signature verification failed");
    }
    const std::string expected_root_hash = sha3_256_hex(
        root_message + "\n" + to_hex(root_signature.data(), root_signature.size())
    );
    if (require_string(root_object, "root_record_hash") != expected_root_hash) {
        throw std::runtime_error("PQC trust root record hash mismatch");
    }

    VerifiedKeyring verified;
    verified.document = document;
    verified.identities.push_back(root);
    verified.head_hash = expected_root_hash;
    std::set<std::string> seen_key_ids = {root.key_id};

    for (const auto& transition : document.at("transitions")) {
        require_exact_keys(
            transition,
            {
                "from_generation",
                "to_generation",
                "from_key_id",
                "new_key",
                "reason_sha3_256",
                "previous_transition_hash",
                "from_signature_hex",
                "to_signature_hex",
                "transition_hash",
            }
        );
        const PqcTrustedIdentity& previous = verified.identities.back();
        const std::uint64_t from_generation = require_uint64(transition, "from_generation");
        const std::uint64_t to_generation = require_uint64(transition, "to_generation");
        const std::string from_key_id = require_string(transition, "from_key_id");
        if (from_generation != previous.generation || to_generation != previous.generation + 1 ||
            from_key_id != previous.key_id) {
            throw std::runtime_error("PQC trust transition generation/key ordering mismatch");
        }
        if (!transition.at("new_key").is_object()) {
            throw std::runtime_error("PQC trust transition new key schema is invalid");
        }
        PqcTrustedIdentity next = parse_identity(
            transition.at("new_key"),
            expected_identity,
            signature.get(),
            kem.get()
        );
        if (next.generation != to_generation || seen_key_ids.count(next.key_id) != 0) {
            throw std::runtime_error("PQC trust transition reuses or misnumbers a key generation");
        }
        const std::string reason_hash = require_string(transition, "reason_sha3_256");
        const std::string previous_hash = require_string(transition, "previous_transition_hash");
        if (!is_sha3_hex(reason_hash) || previous_hash != verified.head_hash) {
            throw std::runtime_error("PQC trust transition reason/hash-chain validation failed");
        }
        const std::string statement = transition_statement(
            expected_identity,
            from_generation,
            to_generation,
            from_key_id,
            next,
            reason_hash,
            previous_hash
        );
        const std::vector<unsigned char> from_signature = from_variable_hex(
            require_string(transition, "from_signature_hex"),
            signature->length_signature
        );
        const std::vector<unsigned char> to_signature = from_variable_hex(
            require_string(transition, "to_signature_hex"),
            signature->length_signature
        );
        if (!verify_message(
                signature.get(), previous.signature_public_key, statement, from_signature) ||
            !verify_message(
                signature.get(), next.signature_public_key, statement, to_signature)) {
            throw std::runtime_error("PQC trust transition dual-signature verification failed");
        }
        const std::string expected_transition_hash = sha3_256_hex(
            statement + "\n" + to_hex(from_signature.data(), from_signature.size()) + "\n" +
            to_hex(to_signature.data(), to_signature.size())
        );
        if (require_string(transition, "transition_hash") != expected_transition_hash) {
            throw std::runtime_error("PQC trust transition hash mismatch");
        }
        verified.head_hash = expected_transition_hash;
        seen_key_ids.insert(next.key_id);
        verified.identities.push_back(std::move(next));
    }

    const std::uint64_t active_generation = require_uint64(document, "active_generation");
    const std::string active_key_id = require_string(document, "active_key_id");
    const PqcTrustedIdentity& active = verified.identities.back();
    if (active_generation != active.generation || active_key_id != active.key_id ||
        require_string(document, "head_hash") != verified.head_hash) {
        throw std::runtime_error("PQC trust keyring active head metadata mismatch");
    }
    if (!expected_active_key_id.empty() && active_key_id != expected_active_key_id) {
        throw std::runtime_error("PQC trust keyring rollback/downgrade detected: active key does not match durable keystore");
    }
    return verified;
}

}  // namespace

PqcTrustKeyring::PqcTrustKeyring(
    std::filesystem::path path,
    std::string identity,
    std::size_t max_generations
) : path_(std::move(path)),
    identity_(std::move(identity)),
    max_generations_(max_generations) {
    if (path_.empty() || path_.filename().empty()) {
        throw std::runtime_error("PQC trust keyring path is invalid");
    }
    if (identity_.empty() || identity_.size() > 256) {
        throw std::runtime_error("PQC trust keyring identity is invalid");
    }
    if (max_generations_ < 2 || max_generations_ > kAbsoluteMaxGenerations) {
        throw std::runtime_error("PQC trust keyring generation bound must be between 2 and 16");
    }
}

void PqcTrustKeyring::initialize_root(const PqcKeyMaterial& root_material) const {
    if (std::filesystem::exists(path_)) {
        throw std::runtime_error("PQC trust keyring already exists; root initialization is one-time only");
    }
    auto [signature, kem] = algorithms();
    validate_material_shape(root_material, identity_, signature.get(), kem.get(), true);

    PqcTrustedIdentity root;
    root.generation = 1;
    root.key_id = root_material.key_id;
    root.identity = identity_;
    root.signature_public_key = root_material.signature_public_key;
    root.kem_public_key = root_material.kem_public_key;
    const std::string statement = root_statement(root);
    std::vector<unsigned char> root_signature = sign_message(
        signature.get(), root_material.signature_secret_key, statement
    );
    const std::string root_hash = sha3_256_hex(
        statement + "\n" + to_hex(root_signature.data(), root_signature.size())
    );
    const json document = {
        {"format", kFormat},
        {"identity", identity_},
        {"max_generations", max_generations_},
        {"active_generation", 1},
        {"active_key_id", root.key_id},
        {"root", {
            {"identity", identity_},
            {"root_record", trusted_identity_json(root)},
            {"root_self_signature_hex", to_hex(root_signature.data(), root_signature.size())},
            {"root_record_hash", root_hash},
        }},
        {"transitions", json::array()},
        {"head_hash", root_hash},
        {"secret_key_material_stored", false},
    };
    atomic_publish_json(path_, document, false);
    (void)verify_document(document, identity_, max_generations_, root.key_id);
    if (!root_signature.empty()) {
        OPENSSL_cleanse(root_signature.data(), root_signature.size());
    }
}

void PqcTrustKeyring::append_transition(
    const PqcKeyMaterial& previous_material,
    const PqcKeyMaterial& new_material,
    const std::string& reason
) const {
    if (reason.size() < kMinReasonLength || reason.size() > kMaxReasonLength) {
        throw std::runtime_error("PQC trust transition reason must contain 8 to 256 characters");
    }
    if (!std::filesystem::exists(path_)) {
        throw std::runtime_error("PQC trust keyring is not initialized; run explicit keyring initialization before rotation");
    }
    auto [signature, kem] = algorithms();
    validate_material_shape(previous_material, identity_, signature.get(), kem.get(), true);
    validate_material_shape(new_material, identity_, signature.get(), kem.get(), true);
    if (previous_material.key_id == new_material.key_id) {
        throw std::runtime_error("PQC trust transition requires a new key identifier");
    }

    VerifiedKeyring verified = verify_document(
        read_document(path_),
        identity_,
        max_generations_,
        previous_material.key_id
    );
    if (verified.identities.size() >= max_generations_) {
        throw std::runtime_error("PQC trust keyring generation bound reached; refusing silent historical-key eviction");
    }
    const PqcTrustedIdentity& previous = verified.identities.back();
    if (previous.signature_public_key != previous_material.signature_public_key ||
        previous.kem_public_key != previous_material.kem_public_key) {
        throw std::runtime_error("active PQC keystore public keys do not match the trusted keyring head");
    }
    for (const auto& identity : verified.identities) {
        if (identity.key_id == new_material.key_id) {
            throw std::runtime_error("PQC trust transition would reuse a historical key identifier");
        }
    }

    PqcTrustedIdentity next;
    next.generation = previous.generation + 1;
    next.key_id = new_material.key_id;
    next.identity = identity_;
    next.signature_public_key = new_material.signature_public_key;
    next.kem_public_key = new_material.kem_public_key;
    const std::string reason_hash = sha3_256_hex(
        std::string(kTransitionDomain) + "\nreason\n" + identity_ + "\n" + reason
    );
    const std::string statement = transition_statement(
        identity_,
        previous.generation,
        next.generation,
        previous.key_id,
        next,
        reason_hash,
        verified.head_hash
    );
    std::vector<unsigned char> from_signature = sign_message(
        signature.get(), previous_material.signature_secret_key, statement
    );
    std::vector<unsigned char> to_signature = sign_message(
        signature.get(), new_material.signature_secret_key, statement
    );
    const std::string transition_hash = sha3_256_hex(
        statement + "\n" + to_hex(from_signature.data(), from_signature.size()) + "\n" +
        to_hex(to_signature.data(), to_signature.size())
    );

    json document = verified.document;
    document.at("transitions").push_back({
        {"from_generation", previous.generation},
        {"to_generation", next.generation},
        {"from_key_id", previous.key_id},
        {"new_key", trusted_identity_json(next)},
        {"reason_sha3_256", reason_hash},
        {"previous_transition_hash", verified.head_hash},
        {"from_signature_hex", to_hex(from_signature.data(), from_signature.size())},
        {"to_signature_hex", to_hex(to_signature.data(), to_signature.size())},
        {"transition_hash", transition_hash},
    });
    document["active_generation"] = next.generation;
    document["active_key_id"] = next.key_id;
    document["head_hash"] = transition_hash;

    (void)verify_document(document, identity_, max_generations_, next.key_id);
    atomic_publish_json(path_, document, true);
    (void)verify_document(read_document(path_), identity_, max_generations_, next.key_id);

    if (!from_signature.empty()) {
        OPENSSL_cleanse(from_signature.data(), from_signature.size());
    }
    if (!to_signature.empty()) {
        OPENSSL_cleanse(to_signature.data(), to_signature.size());
    }
}

PqcTrustKeyringMetadata PqcTrustKeyring::inspect(const std::string& expected_active_key_id) const {
    if (!std::filesystem::exists(path_)) {
        throw std::runtime_error("PQC trust keyring does not exist");
    }
    VerifiedKeyring verified = verify_document(
        read_document(path_), identity_, max_generations_, expected_active_key_id
    );
    const PqcTrustedIdentity& active = verified.identities.back();
    return {
        kFormat,
        identity_,
        verified.identities.size(),
        max_generations_,
        active.generation,
        active.key_id,
        true,
        false,
    };
}

std::vector<PqcTrustedIdentity> PqcTrustKeyring::trusted_identities(
    const std::string& expected_active_key_id
) const {
    if (!std::filesystem::exists(path_)) {
        throw std::runtime_error("PQC trust keyring does not exist");
    }
    return verify_document(
        read_document(path_), identity_, max_generations_, expected_active_key_id
    ).identities;
}

bool PqcTrustKeyring::verify_detached_signature(
    const std::string& key_id,
    const std::string& message,
    const std::vector<unsigned char>& signature_value,
    const std::vector<unsigned char>& embedded_signature_public_key,
    const std::vector<unsigned char>& embedded_kem_public_key,
    const std::string& expected_active_key_id
) const {
    try {
        const auto identities = trusted_identities(expected_active_key_id);
        const PqcTrustedIdentity* trusted = nullptr;
        for (const auto& candidate : identities) {
            if (candidate.key_id == key_id) {
                trusted = &candidate;
                break;
            }
        }
        if (trusted == nullptr || trusted->signature_public_key != embedded_signature_public_key ||
            trusted->kem_public_key != embedded_kem_public_key) {
            return false;
        }
        auto [signature, kem] = algorithms();
        (void)kem;
        return verify_message(
            signature.get(), trusted->signature_public_key, message, signature_value
        );
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace omniguard
