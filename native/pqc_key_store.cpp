#include "pqc_key_store.h"

#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
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

namespace omniguard {
namespace {

using json = nlohmann::json;

constexpr const char* kWrapDomain = "OMNIGUARD_CPP_PQC_KEYSTORE_KEY_V1";
constexpr const char* kKeyIdDomain = "OMNIGUARD_PQC_KEY_ID_V1";
constexpr const char* kPrivateRole = "native_pqc_private_material";
constexpr std::size_t kMinSecretLength = 32;
constexpr std::size_t kAesKeyBytes = 32;
constexpr std::size_t kNonceBytes = 12;
constexpr std::size_t kTagBytes = 16;
constexpr std::uintmax_t kMaxKeyStoreBytes = 1024 * 1024;

struct SigDeleter {
    void operator()(OQS_SIG* value) const { OQS_SIG_free(value); }
};

struct KemDeleter {
    void operator()(OQS_KEM* value) const { OQS_KEM_free(value); }
};

using SigPtr = std::unique_ptr<OQS_SIG, SigDeleter>;
using KemPtr = std::unique_ptr<OQS_KEM, KemDeleter>;

void cleanse(std::vector<unsigned char>& value) {
    if (!value.empty()) {
        OPENSSL_cleanse(value.data(), value.size());
    }
    value.clear();
    value.shrink_to_fit();
}

std::vector<unsigned char> digest(const EVP_MD* md, const std::string& input) {
    const int md_size = EVP_MD_get_size(md);
    if (md_size <= 0) {
        throw std::runtime_error("invalid digest size");
    }
    std::vector<unsigned char> output(static_cast<std::size_t>(md_size));
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

std::string to_hex(const unsigned char* data, std::size_t size) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string output;
    output.resize(size * 2);
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
    throw std::runtime_error("keystore contains invalid hexadecimal data");
}

std::vector<unsigned char> from_hex(const std::string& value, std::size_t expected_size) {
    if (value.size() != expected_size * 2) {
        throw std::runtime_error("keystore hexadecimal field has an unexpected length");
    }
    std::vector<unsigned char> output(expected_size);
    for (std::size_t i = 0; i < expected_size; ++i) {
        output[i] = static_cast<unsigned char>(
            (from_hex_char(value[i * 2]) << 4) | from_hex_char(value[i * 2 + 1])
        );
    }
    return output;
}

bool constant_time_equal(
    const std::vector<unsigned char>& left,
    const std::vector<unsigned char>& right
) {
    return left.size() == right.size() &&
           (left.empty() || CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0);
}

std::string require_string(const json& object, const char* key) {
    if (!object.contains(key) || !object.at(key).is_string()) {
        throw std::runtime_error(std::string("keystore field is missing or invalid: ") + key);
    }
    const std::string value = object.at(key).get<std::string>();
    if (value.empty()) {
        throw std::runtime_error(std::string("keystore field is empty: ") + key);
    }
    return value;
}

void require_exact_keys(const json& object, const std::set<std::string>& expected) {
    if (!object.is_object()) {
        throw std::runtime_error("keystore document must be a JSON object");
    }
    std::set<std::string> actual;
    for (auto iterator = object.begin(); iterator != object.end(); ++iterator) {
        actual.insert(iterator.key());
    }
    if (actual != expected) {
        throw std::runtime_error("keystore schema contains missing or unexpected fields");
    }
}

class WrappingCipher {
public:
    explicit WrappingCipher(const std::string& wrapping_secret) {
        if (wrapping_secret.size() < kMinSecretLength) {
            throw std::runtime_error("PQC keystore wrapping credential must contain at least 32 characters");
        }
        const auto derived = digest(
            EVP_sha256(),
            std::string(kWrapDomain) + "\n" + wrapping_secret
        );
        if (derived.size() != key_.size()) {
            throw std::runtime_error("PQC keystore key derivation failed");
        }
        std::memcpy(key_.data(), derived.data(), key_.size());
    }

    ~WrappingCipher() { OPENSSL_cleanse(key_.data(), key_.size()); }

    json seal(const std::string& plaintext, const std::string& aad) const {
        std::array<unsigned char, kNonceBytes> nonce{};
        std::array<unsigned char, kTagBytes> tag{};
        if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
            throw std::runtime_error("PQC keystore nonce generation failed");
        }

        std::vector<unsigned char> ciphertext(plaintext.size());
        EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
        if (context == nullptr) {
            throw std::runtime_error("PQC keystore cipher allocation failed");
        }

        int len = 0;
        int total = 0;
        bool ok = EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                  EVP_CIPHER_CTX_ctrl(
                      context,
                      EVP_CTRL_GCM_SET_IVLEN,
                      static_cast<int>(nonce.size()),
                      nullptr
                  ) == 1 &&
                  EVP_EncryptInit_ex(context, nullptr, nullptr, key_.data(), nonce.data()) == 1;
        if (ok && !aad.empty()) {
            ok = EVP_EncryptUpdate(
                     context,
                     nullptr,
                     &len,
                     reinterpret_cast<const unsigned char*>(aad.data()),
                     static_cast<int>(aad.size())
                 ) == 1;
        }
        if (ok && !plaintext.empty()) {
            ok = EVP_EncryptUpdate(
                     context,
                     ciphertext.data(),
                     &len,
                     reinterpret_cast<const unsigned char*>(plaintext.data()),
                     static_cast<int>(plaintext.size())
                 ) == 1;
            total = len;
        }
        if (ok) {
            ok = EVP_EncryptFinal_ex(context, ciphertext.data() + total, &len) == 1;
            total += len;
        }
        if (ok) {
            ok = EVP_CIPHER_CTX_ctrl(
                     context,
                     EVP_CTRL_GCM_GET_TAG,
                     static_cast<int>(tag.size()),
                     tag.data()
                 ) == 1;
        }
        EVP_CIPHER_CTX_free(context);

        if (!ok) {
            cleanse(ciphertext);
            throw std::runtime_error("PQC keystore AES-256-GCM encryption failed");
        }
        ciphertext.resize(static_cast<std::size_t>(total));
        json envelope = {
            {"scheme", "AES-256-GCM"},
            {"version", 1},
            {"nonce_hex", to_hex(nonce.data(), nonce.size())},
            {"tag_hex", to_hex(tag.data(), tag.size())},
            {"ciphertext_hex", to_hex(ciphertext.data(), ciphertext.size())},
        };
        cleanse(ciphertext);
        return envelope;
    }

    std::string open(const json& envelope, const std::string& aad) const {
        require_exact_keys(
            envelope,
            {"scheme", "version", "nonce_hex", "tag_hex", "ciphertext_hex"}
        );
        if (require_string(envelope, "scheme") != "AES-256-GCM" ||
            !envelope.at("version").is_number_integer() ||
            envelope.at("version").get<int>() != 1) {
            throw std::runtime_error("unsupported PQC keystore encryption envelope");
        }

        const auto nonce = from_hex(require_string(envelope, "nonce_hex"), kNonceBytes);
        const auto tag = from_hex(require_string(envelope, "tag_hex"), kTagBytes);
        const std::string ciphertext_hex = require_string(envelope, "ciphertext_hex");
        if (ciphertext_hex.size() % 2 != 0 || ciphertext_hex.size() > kMaxKeyStoreBytes * 2) {
            throw std::runtime_error("PQC keystore ciphertext size is invalid");
        }
        const auto ciphertext = from_hex(ciphertext_hex, ciphertext_hex.size() / 2);
        std::vector<unsigned char> plaintext(ciphertext.size());

        EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
        if (context == nullptr) {
            throw std::runtime_error("PQC keystore cipher allocation failed");
        }
        int len = 0;
        int total = 0;
        bool ok = EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                  EVP_CIPHER_CTX_ctrl(
                      context,
                      EVP_CTRL_GCM_SET_IVLEN,
                      static_cast<int>(nonce.size()),
                      nullptr
                  ) == 1 &&
                  EVP_DecryptInit_ex(context, nullptr, nullptr, key_.data(), nonce.data()) == 1;
        if (ok && !aad.empty()) {
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
            cleanse(plaintext);
            throw std::runtime_error("PQC keystore authentication failed");
        }
        std::string output(
            reinterpret_cast<const char*>(plaintext.data()),
            static_cast<std::size_t>(total)
        );
        cleanse(plaintext);
        return output;
    }

private:
    std::array<unsigned char, kAesKeyBytes> key_{};
};

std::string key_id_for(
    const std::string& identity,
    const std::vector<unsigned char>& sig_public,
    const std::vector<unsigned char>& kem_public
) {
    const auto value = digest(
        EVP_sha3_256(),
        std::string(kKeyIdDomain) + "\n" + identity + "\n" +
            PqcKeyStore::kSignatureAlgorithm + "\n" +
            to_hex(sig_public.data(), sig_public.size()) + "\n" +
            PqcKeyStore::kKemAlgorithm + "\n" +
            to_hex(kem_public.data(), kem_public.size())
    );
    return to_hex(value.data(), value.size());
}

std::string private_aad(const std::string& identity, const std::string& key_id) {
    return std::string(PqcKeyStore::kFormat) + "|" + identity + "|" + key_id + "|" +
           PqcKeyStore::kSignatureAlgorithm + "|" + PqcKeyStore::kKemAlgorithm + "|" +
           kPrivateRole;
}

void verify_key_material(
    const OQS_SIG* signature,
    const OQS_KEM* kem,
    const PqcKeyMaterial& material
) {
    static constexpr char kChallenge[] = "OMNIGUARD_PQC_KEYSTORE_SELF_CHECK_V1";
    std::vector<unsigned char> signature_value(signature->length_signature);
    std::size_t signature_length = 0;
    const bool sig_ok = OQS_SIG_sign(
                            signature,
                            signature_value.data(),
                            &signature_length,
                            reinterpret_cast<const unsigned char*>(kChallenge),
                            sizeof(kChallenge) - 1,
                            material.signature_secret_key.data()
                        ) == OQS_SUCCESS &&
                        OQS_SIG_verify(
                            signature,
                            reinterpret_cast<const unsigned char*>(kChallenge),
                            sizeof(kChallenge) - 1,
                            signature_value.data(),
                            signature_length,
                            material.signature_public_key.data()
                        ) == OQS_SUCCESS;
    cleanse(signature_value);
    if (!sig_ok) {
        throw std::runtime_error("PQC keystore ML-DSA key consistency check failed");
    }

    std::vector<unsigned char> ciphertext(kem->length_ciphertext);
    std::vector<unsigned char> sender(kem->length_shared_secret);
    std::vector<unsigned char> receiver(kem->length_shared_secret);
    const bool kem_ok = OQS_KEM_encaps(
                            kem,
                            ciphertext.data(),
                            sender.data(),
                            material.kem_public_key.data()
                        ) == OQS_SUCCESS &&
                        OQS_KEM_decaps(
                            kem,
                            receiver.data(),
                            ciphertext.data(),
                            material.kem_secret_key.data()
                        ) == OQS_SUCCESS &&
                        constant_time_equal(sender, receiver);
    cleanse(ciphertext);
    cleanse(sender);
    cleanse(receiver);
    if (!kem_ok) {
        throw std::runtime_error("PQC keystore ML-KEM key consistency check failed");
    }
}

void ensure_regular_non_symlink(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error) {
        throw std::runtime_error("could not inspect PQC keystore path");
    }
    if (std::filesystem::is_symlink(status)) {
        throw std::runtime_error("PQC keystore symlinks are not allowed");
    }
    if (!std::filesystem::is_regular_file(status)) {
        throw std::runtime_error("PQC keystore path is not a regular file");
    }
    const auto size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > kMaxKeyStoreBytes) {
        throw std::runtime_error("PQC keystore size is invalid");
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
        throw std::runtime_error("could not restrict PQC keystore file permissions");
    }
}

json read_document(const std::filesystem::path& path) {
    ensure_regular_non_symlink(path);
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("could not open PQC keystore");
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    if (!stream.good() && !stream.eof()) {
        throw std::runtime_error("could not read PQC keystore");
    }
    try {
        return json::parse(buffer.str());
    } catch (const json::exception&) {
        throw std::runtime_error("PQC keystore contains malformed JSON");
    }
}

void atomic_write(const std::filesystem::path& path, const json& document) {
    if (path.empty() || path.filename().empty()) {
        throw std::runtime_error("PQC keystore path is invalid");
    }
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }
    if (std::filesystem::exists(path)) {
        throw std::runtime_error("refusing to overwrite existing PQC keystore");
    }

    std::array<unsigned char, 8> suffix{};
    if (RAND_bytes(suffix.data(), static_cast<int>(suffix.size())) != 1) {
        throw std::runtime_error("PQC keystore temporary name generation failed");
    }
    const std::filesystem::path temporary =
        path.string() + ".tmp." + to_hex(suffix.data(), suffix.size());
    try {
        {
            std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
            if (!stream) {
                throw std::runtime_error("could not create PQC keystore temporary file");
            }
            stream << document.dump(2) << '\n';
            stream.flush();
            if (!stream) {
                throw std::runtime_error("could not persist PQC keystore temporary file");
            }
        }
        set_private_permissions(temporary);
        std::error_code error;
        std::filesystem::rename(temporary, path, error);
        if (error) {
            throw std::runtime_error("could not atomically publish PQC keystore");
        }
        set_private_permissions(path);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        throw;
    }
}

PqcKeyMaterial generate_material(
    const std::string& identity,
    const OQS_SIG* signature,
    const OQS_KEM* kem
) {
    PqcKeyMaterial material;
    material.identity = identity;
    material.signature_public_key.resize(signature->length_public_key);
    material.signature_secret_key.resize(signature->length_secret_key);
    material.kem_public_key.resize(kem->length_public_key);
    material.kem_secret_key.resize(kem->length_secret_key);
    if (OQS_SIG_keypair(
            signature,
            material.signature_public_key.data(),
            material.signature_secret_key.data()
        ) != OQS_SUCCESS ||
        OQS_KEM_keypair(
            kem,
            material.kem_public_key.data(),
            material.kem_secret_key.data()
        ) != OQS_SUCCESS) {
        throw std::runtime_error("liboqs PQC key generation failed");
    }
    material.key_id = key_id_for(
        identity,
        material.signature_public_key,
        material.kem_public_key
    );
    verify_key_material(signature, kem, material);
    return material;
}

json serialize_material(const PqcKeyMaterial& material, const WrappingCipher& cipher) {
    json private_payload = {
        {"signature_secret_key_hex", to_hex(
            material.signature_secret_key.data(), material.signature_secret_key.size())},
        {"kem_secret_key_hex", to_hex(
            material.kem_secret_key.data(), material.kem_secret_key.size())},
    };
    const json envelope = cipher.seal(
        private_payload.dump(),
        private_aad(material.identity, material.key_id)
    );
    return {
        {"format", PqcKeyStore::kFormat},
        {"provider", PqcKeyStore::kProvider},
        {"identity", material.identity},
        {"key_id", material.key_id},
        {"signature_algorithm", PqcKeyStore::kSignatureAlgorithm},
        {"kem_algorithm", PqcKeyStore::kKemAlgorithm},
        {"signature_public_key_hex", to_hex(
            material.signature_public_key.data(), material.signature_public_key.size())},
        {"kem_public_key_hex", to_hex(
            material.kem_public_key.data(), material.kem_public_key.size())},
        {"private_key_envelope", envelope},
    };
}

PqcKeyMaterial parse_material(
    const json& document,
    const std::string& expected_identity,
    const WrappingCipher& cipher,
    const OQS_SIG* signature,
    const OQS_KEM* kem
) {
    require_exact_keys(
        document,
        {
            "format",
            "provider",
            "identity",
            "key_id",
            "signature_algorithm",
            "kem_algorithm",
            "signature_public_key_hex",
            "kem_public_key_hex",
            "private_key_envelope",
        }
    );
    if (require_string(document, "format") != PqcKeyStore::kFormat ||
        require_string(document, "provider") != PqcKeyStore::kProvider ||
        require_string(document, "signature_algorithm") != PqcKeyStore::kSignatureAlgorithm ||
        require_string(document, "kem_algorithm") != PqcKeyStore::kKemAlgorithm) {
        throw std::runtime_error("PQC keystore format/provider/algorithm mismatch");
    }
    const std::string identity = require_string(document, "identity");
    if (identity != expected_identity) {
        throw std::runtime_error("PQC keystore identity mismatch");
    }

    PqcKeyMaterial material;
    material.identity = identity;
    material.key_id = require_string(document, "key_id");
    material.signature_public_key = from_hex(
        require_string(document, "signature_public_key_hex"),
        signature->length_public_key
    );
    material.kem_public_key = from_hex(
        require_string(document, "kem_public_key_hex"),
        kem->length_public_key
    );
    const std::string expected_key_id = key_id_for(
        identity,
        material.signature_public_key,
        material.kem_public_key
    );
    if (material.key_id != expected_key_id) {
        throw std::runtime_error("PQC keystore key identifier mismatch");
    }

    if (!document.at("private_key_envelope").is_object()) {
        throw std::runtime_error("PQC keystore private envelope is invalid");
    }
    const std::string plaintext = cipher.open(
        document.at("private_key_envelope"),
        private_aad(identity, material.key_id)
    );
    json private_payload;
    try {
        private_payload = json::parse(plaintext);
    } catch (const json::exception&) {
        throw std::runtime_error("PQC keystore private payload is malformed");
    }
    require_exact_keys(
        private_payload,
        {"signature_secret_key_hex", "kem_secret_key_hex"}
    );
    material.signature_secret_key = from_hex(
        require_string(private_payload, "signature_secret_key_hex"),
        signature->length_secret_key
    );
    material.kem_secret_key = from_hex(
        require_string(private_payload, "kem_secret_key_hex"),
        kem->length_secret_key
    );
    verify_key_material(signature, kem, material);
    return material;
}

std::pair<SigPtr, KemPtr> algorithms() {
    SigPtr signature(OQS_SIG_new(OQS_SIG_alg_ml_dsa_44));
    KemPtr kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_512));
    if (!signature || !kem) {
        throw std::runtime_error("required liboqs ML-DSA-44/ML-KEM-512 algorithms are unavailable");
    }
    return {std::move(signature), std::move(kem)};
}

}  // namespace

PqcKeyMaterial::PqcKeyMaterial(PqcKeyMaterial&& other) noexcept
    : key_id(std::move(other.key_id)),
      identity(std::move(other.identity)),
      signature_public_key(std::move(other.signature_public_key)),
      signature_secret_key(std::move(other.signature_secret_key)),
      kem_public_key(std::move(other.kem_public_key)),
      kem_secret_key(std::move(other.kem_secret_key)) {}

PqcKeyMaterial& PqcKeyMaterial::operator=(PqcKeyMaterial&& other) noexcept {
    if (this != &other) {
        cleanse(signature_secret_key);
        cleanse(kem_secret_key);
        key_id = std::move(other.key_id);
        identity = std::move(other.identity);
        signature_public_key = std::move(other.signature_public_key);
        signature_secret_key = std::move(other.signature_secret_key);
        kem_public_key = std::move(other.kem_public_key);
        kem_secret_key = std::move(other.kem_secret_key);
    }
    return *this;
}

PqcKeyMaterial::~PqcKeyMaterial() {
    cleanse(signature_secret_key);
    cleanse(kem_secret_key);
}

PqcKeyStore::PqcKeyStore(
    std::filesystem::path path,
    std::string wrapping_secret,
    std::string identity
) : path_(std::move(path)),
    wrapping_secret_(std::move(wrapping_secret)),
    identity_(std::move(identity)) {
    if (path_.empty() || path_.filename().empty()) {
        throw std::runtime_error("PQC keystore path is invalid");
    }
    if (wrapping_secret_.size() < kMinSecretLength) {
        throw std::runtime_error("PQC keystore wrapping credential must contain at least 32 characters");
    }
    if (identity_.empty() || identity_.size() > 256) {
        throw std::runtime_error("PQC keystore identity is invalid");
    }
}

PqcKeyStore::~PqcKeyStore() {
    if (!wrapping_secret_.empty()) {
        OPENSSL_cleanse(wrapping_secret_.data(), wrapping_secret_.size());
    }
}

PqcKeyMaterial PqcKeyStore::load_or_create() const {
    auto [signature, kem] = algorithms();
    WrappingCipher cipher(wrapping_secret_);
    if (std::filesystem::exists(path_)) {
        return parse_material(
            read_document(path_),
            identity_,
            cipher,
            signature.get(),
            kem.get()
        );
    }

    PqcKeyMaterial material = generate_material(identity_, signature.get(), kem.get());
    const json document = serialize_material(material, cipher);
    atomic_write(path_, document);
    return material;
}

PqcKeyStoreMetadata PqcKeyStore::inspect() const {
    if (!std::filesystem::exists(path_)) {
        throw std::runtime_error("PQC keystore does not exist");
    }
    auto [signature, kem] = algorithms();
    WrappingCipher cipher(wrapping_secret_);
    PqcKeyMaterial material = parse_material(
        read_document(path_),
        identity_,
        cipher,
        signature.get(),
        kem.get()
    );
    return {
        kFormat,
        kProvider,
        material.key_id,
        material.identity,
        kSignatureAlgorithm,
        kKemAlgorithm,
        false,
        false,
    };
}

}  // namespace omniguard
