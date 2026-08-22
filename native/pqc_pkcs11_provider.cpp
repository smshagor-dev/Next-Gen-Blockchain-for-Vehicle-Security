#include "pqc_pkcs11_provider.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <pkcs11.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#if !defined(CKM_ML_DSA_KEY_PAIR_GEN) || !defined(CKM_ML_DSA) || \
    !defined(CKM_ML_KEM_KEY_PAIR_GEN) || !defined(CKM_ML_KEM) || \
    !defined(CKP_ML_DSA_44) || !defined(CKP_ML_KEM_512) || \
    !defined(CKA_PARAMETER_SET) || !defined(CKA_ENCAPSULATE) || \
    !defined(CKA_DECAPSULATE) || !defined(CKF_ENCAPSULATE) || \
    !defined(CKF_DECAPSULATE)
#error "SMARTCAR PKCS#11 provider requires a PKCS#11 v3.2 header with ML-DSA and ML-KEM definitions"
#endif

namespace omniguard {
namespace {

constexpr std::size_t kMlDsa44PublicKeyBytes = 1312;
constexpr std::size_t kMlDsa44SignatureBytes = 2420;
constexpr std::size_t kMlKem512PublicKeyBytes = 800;
constexpr std::size_t kMlKem512CiphertextBytes = 768;
constexpr std::size_t kMlKem512SharedSecretBytes = 32;
constexpr std::size_t kMaxAttributeBytes = 64 * 1024;
constexpr std::uint64_t kMaxGeneration = 1000000;
constexpr const char* kPkcs11ProviderEvidenceVersion = "OMNIGUARD_PKCS11_PROVIDER_EVIDENCE_V1";

[[noreturn]] void fail_ck(const std::string& operation, CK_RV rv) {
    std::ostringstream message;
    message << operation << " failed with PKCS#11 status 0x" << std::hex
            << static_cast<unsigned long long>(rv);
    throw std::runtime_error(message.str());
}

void require_ck(const std::string& operation, CK_RV rv) {
    if (rv != CKR_OK) {
        fail_ck(operation, rv);
    }
}

std::string optional_env(const char* name) {
    const char* raw = std::getenv(name);
    return raw == nullptr ? std::string() : std::string(raw);
}

std::string required_env(const char* name) {
    const std::string value = optional_env(name);
    if (value.empty()) {
        throw std::runtime_error(std::string("required PKCS#11 configuration is missing: ") + name);
    }
    return value;
}

std::string trim_ascii(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
        value.pop_back();
    }
    std::size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }
    return value.substr(start);
}

template <typename T, std::size_t N>
std::string fixed_text(const T (&value)[N]) {
    return trim_ascii(std::string(reinterpret_cast<const char*>(value), N));
}

std::string read_pin_file(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status)) {
        throw std::runtime_error("SMARTCAR_CPP_PKCS11_PIN_FILE must be a regular non-symlink file");
    }
    const auto size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > 4096) {
        throw std::runtime_error("SMARTCAR_CPP_PKCS11_PIN_FILE has an invalid size");
    }
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("could not open SMARTCAR_CPP_PKCS11_PIN_FILE");
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    std::string value = buffer.str();
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) {
        value.pop_back();
    }
    if (value.empty()) {
        throw std::runtime_error("SMARTCAR_CPP_PKCS11_PIN_FILE is empty");
    }
    return value;
}

std::string load_pin(bool protected_authentication_path) {
    const std::string env_pin = optional_env("SMARTCAR_CPP_PKCS11_PIN");
    const std::string pin_file = optional_env("SMARTCAR_CPP_PKCS11_PIN_FILE");
    if (!env_pin.empty() && !pin_file.empty()) {
        throw std::runtime_error("configure only one of SMARTCAR_CPP_PKCS11_PIN or SMARTCAR_CPP_PKCS11_PIN_FILE");
    }
    if (!pin_file.empty()) {
        return read_pin_file(pin_file);
    }
    if (!env_pin.empty()) {
        return env_pin;
    }
    if (protected_authentication_path) {
        return {};
    }
    throw std::runtime_error(
        "PKCS#11 token login requires SMARTCAR_CPP_PKCS11_PIN or SMARTCAR_CPP_PKCS11_PIN_FILE"
    );
}

std::filesystem::path canonical_module_path() {
    const std::filesystem::path configured = required_env("SMARTCAR_CPP_PKCS11_MODULE");
    std::error_code error;
    const std::filesystem::path canonical = std::filesystem::canonical(configured, error);
    if (error || canonical.empty()) {
        throw std::runtime_error("SMARTCAR_CPP_PKCS11_MODULE cannot be resolved to a canonical path");
    }
    const auto status = std::filesystem::status(canonical, error);
    if (error || !std::filesystem::is_regular_file(status)) {
        throw std::runtime_error("SMARTCAR_CPP_PKCS11_MODULE must resolve to a regular module file");
    }
    return canonical;
}

class NativeModule {
public:
    explicit NativeModule(const std::filesystem::path& path) : path_(path) {
#if defined(_WIN32)
        handle_ = LoadLibraryW(path_.wstring().c_str());
        if (handle_ == nullptr) {
            throw std::runtime_error("failed to load configured PKCS#11 module");
        }
#else
        handle_ = dlopen(path_.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (handle_ == nullptr) {
            throw std::runtime_error("failed to load configured PKCS#11 module");
        }
#endif
    }

    NativeModule(const NativeModule&) = delete;
    NativeModule& operator=(const NativeModule&) = delete;

    ~NativeModule() {
#if defined(_WIN32)
        if (handle_ != nullptr) FreeLibrary(handle_);
#else
        if (handle_ != nullptr) dlclose(handle_);
#endif
    }

    void* symbol(const char* name) const {
#if defined(_WIN32)
        void* result = reinterpret_cast<void*>(GetProcAddress(handle_, name));
#else
        void* result = dlsym(handle_, name);
#endif
        if (result == nullptr) {
            throw std::runtime_error(std::string("PKCS#11 module is missing required entry point: ") + name);
        }
        return result;
    }

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
#if defined(_WIN32)
    HMODULE handle_ = nullptr;
#else
    void* handle_ = nullptr;
#endif
};

std::vector<unsigned char> digest_bytes(const EVP_MD* md, const std::string& input) {
    const int expected = EVP_MD_get_size(md);
    if (expected <= 0) {
        throw std::runtime_error("PKCS#11 provider digest size is invalid");
    }
    std::vector<unsigned char> output(static_cast<std::size_t>(expected));
    unsigned int output_length = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("PKCS#11 provider digest context allocation failed");
    }
    const bool ok = EVP_DigestInit_ex(context, md, nullptr) == 1 &&
                    EVP_DigestUpdate(context, input.data(), input.size()) == 1 &&
                    EVP_DigestFinal_ex(context, output.data(), &output_length) == 1;
    EVP_MD_CTX_free(context);
    if (!ok) {
        throw std::runtime_error("PKCS#11 provider digest operation failed");
    }
    output.resize(output_length);
    return output;
}

std::string bytes_to_hex(const unsigned char* data, std::size_t size) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string output(size * 2, '0');
    for (std::size_t i = 0; i < size; ++i) {
        output[i * 2] = kHex[(data[i] >> 4) & 0x0f];
        output[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return output;
}

std::string sha256_hex(const std::string& input) {
    const auto value = digest_bytes(EVP_sha256(), input);
    return bytes_to_hex(value.data(), value.size());
}

std::string sha3_256_hex(const std::string& input) {
    const auto value = digest_bytes(EVP_sha3_256(), input);
    return bytes_to_hex(value.data(), value.size());
}

std::vector<unsigned char> object_id_for(
    const std::string& identity,
    std::uint64_t generation,
    const std::string& purpose
) {
    return digest_bytes(
        EVP_sha256(),
        "OMNIGUARD_PKCS11_OBJECT_ID_V1\n" + identity + "\n" +
        std::to_string(generation) + "\n" + purpose
    );
}

std::string identity_tag(const std::string& identity) {
    return sha256_hex("OMNIGUARD_PKCS11_IDENTITY_V1\n" + identity).substr(0, 16);
}

std::string key_label(
    const std::string& algorithm,
    const std::string& tag,
    std::uint64_t generation
) {
    return "OMNIGUARD_" + algorithm + "_" + tag + "_G" + std::to_string(generation);
}

struct ObjectHandles {
    CK_OBJECT_HANDLE signature_public = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE signature_private = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE kem_public = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE kem_private = CK_INVALID_HANDLE;
};

class Pkcs11PqcHardwareProvider final : public PqcHardwareProvider {
public:
    Pkcs11PqcHardwareProvider()
        : module_(canonical_module_path()) {
        load_interface();
        initialize();
        select_slot();
        open_session_and_login();
        inspect_backend();
    }

    Pkcs11PqcHardwareProvider(const Pkcs11PqcHardwareProvider&) = delete;
    Pkcs11PqcHardwareProvider& operator=(const Pkcs11PqcHardwareProvider&) = delete;

    ~Pkcs11PqcHardwareProvider() override {
        if (!pin_.empty()) {
            OPENSSL_cleanse(pin_.data(), pin_.size());
        }
        if (functions_ != nullptr && session_ != CK_INVALID_HANDLE) {
            if (owns_login_) {
                (void)functions_->C_Logout(session_);
            }
            (void)functions_->C_CloseSession(session_);
        }
        if (functions_ != nullptr && owns_initialize_) {
            (void)functions_->C_Finalize(nullptr);
        }
    }

    PqcHardwareProbe probe() const override {
        PqcHardwareProbe result;
        result.provider = kPkcs11PqcProvider;
        result.device_identity = device_identity_;
        result.evidence_reference = evidence_reference_;
        result.backend_loaded = interface_v32_ && session_ != CK_INVALID_HANDLE;
        result.token_present = token_present_;
        result.hardware_mechanisms = hardware_slot_ && required_mechanisms_;
        result.private_keys_non_exportable = private_keys_verified_;
        result.ml_dsa_44_key_generation = ml_dsa_generation_;
        result.ml_dsa_44_sign = ml_dsa_sign_;
        result.ml_kem_512_key_generation = ml_kem_generation_;
        result.ml_kem_512_decapsulate = ml_kem_decapsulate_;
        result.ml_kem_512_derived_secret_non_exportable = derived_secret_verified_;
        result.ml_kem_512_sha3_256_raw_commitment = sha3_commitment_available_;
        result.rotation_supported = rw_session_ && ml_dsa_generation_ && ml_kem_generation_;
        result.ml_dsa_44_signature_max_size = kMlDsa44SignatureBytes;
        result.ml_kem_512_ciphertext_size = kMlKem512CiphertextBytes;
        result.ml_kem_512_shared_secret_size = kMlKem512SharedSecretBytes;
        return result;
    }

    PqcHardwarePublicMaterial load_or_create_public(const std::string& identity) override {
        validate_identity(identity);
        const std::set<std::uint64_t> generations = discover_generations(identity);
        if (generations.empty()) {
            generate_generation(identity, 1);
        } else {
            const std::uint64_t generation = *generations.rbegin();
            activate_generation(identity, generation);
        }
        prove_active_operations();
        return active_public_material();
    }

    std::vector<unsigned char> sign_ml_dsa_44(
        const std::string& key_id,
        const std::vector<unsigned char>& message
    ) override {
        require_active_key(key_id);
        return sign_with_handle(active_handles_.signature_private, message);
    }

    PqcKemCommitment decapsulate_ml_kem_512_commitment(
        const std::string& key_id,
        const std::vector<unsigned char>& ciphertext,
        const std::string& commitment_prefix
    ) override {
        require_active_key(key_id);
        if (ciphertext.size() != kMlKem512CiphertextBytes) {
            throw std::runtime_error("PKCS#11 ML-KEM-512 ciphertext size is invalid");
        }

        CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
        try {
            secret = decapsulate_to_nonexportable_secret(active_handles_.kem_private, ciphertext);
            verify_derived_secret_policy(secret);
            const std::string digest = digest_key_with_prefix(secret, commitment_prefix);
            require_ck("C_DestroyObject(decapsulated secret)", functions_->C_DestroyObject(session_, secret));
            secret = CK_INVALID_HANDLE;
            derived_secret_verified_ = true;
            return {kKemCommitmentRawV2, digest};
        } catch (...) {
            if (secret != CK_INVALID_HANDLE) {
                (void)functions_->C_DestroyObject(session_, secret);
            }
            throw;
        }
    }

    PqcHardwarePublicMaterial rotate(const std::string& identity) override {
        validate_identity(identity);
        if (active_identity_.empty()) {
            (void)load_or_create_public(identity);
        }
        if (identity != active_identity_) {
            throw std::runtime_error("PKCS#11 rotation identity does not match the active hardware identity");
        }
        if (active_generation_ >= kMaxGeneration) {
            throw std::runtime_error("PKCS#11 hardware generation limit reached");
        }
        generate_generation(identity, active_generation_ + 1);
        prove_active_operations();
        return active_public_material();
    }

private:
    using GetInterfaceFn = CK_RV (*)(
        CK_UTF8CHAR_PTR,
        CK_VERSION_PTR,
        CK_INTERFACE_PTR_PTR,
        CK_FLAGS
    );

    void load_interface() {
        auto get_interface = reinterpret_cast<GetInterfaceFn>(module_.symbol("C_GetInterface"));
        CK_VERSION requested{3, 2};
        CK_INTERFACE_PTR interface = nullptr;
        CK_UTF8CHAR name[] = {'P', 'K', 'C', 'S', ' ', '1', '1', '\0'};
        require_ck("C_GetInterface(PKCS 11 v3.2)", get_interface(name, &requested, &interface, 0));
        if (interface == nullptr || interface->pFunctionList == nullptr) {
            throw std::runtime_error("PKCS#11 v3.2 interface returned no function list");
        }
        functions_ = static_cast<CK_FUNCTION_LIST_3_2_PTR>(interface->pFunctionList);
        if (functions_->version.major != 3 || functions_->version.minor < 2 ||
            functions_->C_EncapsulateKey == nullptr || functions_->C_DecapsulateKey == nullptr ||
            functions_->C_DigestKey == nullptr) {
            throw std::runtime_error("PKCS#11 module does not expose the required v3.2 KEM/digest interface");
        }
        interface_v32_ = true;
    }

    void initialize() {
        const CK_RV rv = functions_->C_Initialize(nullptr);
        if (rv == CKR_OK) {
            owns_initialize_ = true;
        } else if (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
            fail_ck("C_Initialize", rv);
        }
    }

    std::vector<CK_SLOT_ID> token_slots() const {
        CK_ULONG count = 0;
        require_ck("C_GetSlotList(count)", functions_->C_GetSlotList(CK_TRUE, nullptr, &count));
        if (count == 0 || count > 4096) {
            throw std::runtime_error("PKCS#11 module exposes no bounded token-present slot list");
        }
        std::vector<CK_SLOT_ID> slots(count);
        require_ck("C_GetSlotList(values)", functions_->C_GetSlotList(CK_TRUE, slots.data(), &count));
        slots.resize(count);
        return slots;
    }

    CK_SLOT_ID parse_slot_id(const std::string& text) const {
        std::size_t consumed = 0;
        unsigned long long value = 0;
        try {
            value = std::stoull(text, &consumed, 10);
        } catch (const std::exception&) {
            throw std::runtime_error("SMARTCAR_CPP_PKCS11_SLOT_ID must be an unsigned integer");
        }
        if (consumed != text.size() || value > std::numeric_limits<CK_SLOT_ID>::max()) {
            throw std::runtime_error("SMARTCAR_CPP_PKCS11_SLOT_ID is out of range");
        }
        return static_cast<CK_SLOT_ID>(value);
    }

    void select_slot() {
        const std::vector<CK_SLOT_ID> slots = token_slots();
        const std::string configured_slot = optional_env("SMARTCAR_CPP_PKCS11_SLOT_ID");
        const std::string configured_label = optional_env("SMARTCAR_CPP_PKCS11_TOKEN_LABEL");

        bool selected = false;
        if (!configured_slot.empty()) {
            const CK_SLOT_ID requested = parse_slot_id(configured_slot);
            if (std::find(slots.begin(), slots.end(), requested) == slots.end()) {
                throw std::runtime_error("configured PKCS#11 slot does not contain a present token");
            }
            slot_ = requested;
            selected = true;
        } else if (configured_label.empty() && slots.size() == 1) {
            slot_ = slots.front();
            selected = true;
        }

        if (!selected && !configured_label.empty()) {
            for (const CK_SLOT_ID slot : slots) {
                CK_TOKEN_INFO info{};
                require_ck("C_GetTokenInfo", functions_->C_GetTokenInfo(slot, &info));
                if (fixed_text(info.label) == configured_label) {
                    if (selected) {
                        throw std::runtime_error("PKCS#11 token label is ambiguous across multiple slots");
                    }
                    slot_ = slot;
                    selected = true;
                }
            }
        }

        if (!selected) {
            throw std::runtime_error(
                "select a PKCS#11 token with SMARTCAR_CPP_PKCS11_SLOT_ID or SMARTCAR_CPP_PKCS11_TOKEN_LABEL"
            );
        }

        require_ck("C_GetTokenInfo(selected)", functions_->C_GetTokenInfo(slot_, &token_info_));
        token_present_ = true;
        if (!configured_label.empty() && fixed_text(token_info_.label) != configured_label) {
            throw std::runtime_error("configured PKCS#11 slot/token-label binding does not match");
        }

        CK_SLOT_INFO slot_info{};
        require_ck("C_GetSlotInfo(selected)", functions_->C_GetSlotInfo(slot_, &slot_info));
        hardware_slot_ = (slot_info.flags & CKF_HW_SLOT) != 0;

        const std::string manufacturer = fixed_text(token_info_.manufacturerID);
        const std::string model = fixed_text(token_info_.model);
        const std::string serial = fixed_text(token_info_.serialNumber);
        const std::string label = fixed_text(token_info_.label);
        if (serial.empty() || label.empty()) {
            throw std::runtime_error("PKCS#11 token lacks stable label/serial identity");
        }
        device_identity_ = manufacturer + "|" + model + "|" + serial + "|slot=" + std::to_string(slot_);
        evidence_reference_ = std::string(kPkcs11ProviderEvidenceVersion) + "|module=" +
            module_.path().string() + "|token=" + label + "|serial=" + serial +
            "|slot=" + std::to_string(slot_) + "|hw_slot=" + (hardware_slot_ ? "1" : "0");
    }

    void open_session_and_login() {
        CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
        const CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        require_ck("C_OpenSession(RW)", functions_->C_OpenSession(slot_, flags, nullptr, nullptr, &session));
        session_ = session;
        rw_session_ = true;

        const bool protected_path = (token_info_.flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0;
        pin_ = load_pin(protected_path);
        CK_UTF8CHAR_PTR pin_ptr = pin_.empty()
            ? nullptr
            : reinterpret_cast<CK_UTF8CHAR_PTR>(pin_.data());
        const CK_RV rv = functions_->C_Login(
            session_,
            CKU_USER,
            pin_ptr,
            static_cast<CK_ULONG>(pin_.size())
        );
        if (rv == CKR_OK) {
            owns_login_ = true;
        } else if (rv != CKR_USER_ALREADY_LOGGED_IN) {
            fail_ck("C_Login(CKU_USER)", rv);
        }
    }

    bool mechanism_has(CK_MECHANISM_TYPE mechanism, CK_FLAGS required_flags) const {
        CK_MECHANISM_INFO info{};
        const CK_RV rv = functions_->C_GetMechanismInfo(slot_, mechanism, &info);
        return rv == CKR_OK && (info.flags & required_flags) == required_flags;
    }

    void inspect_backend() {
        ml_dsa_generation_ = mechanism_has(CKM_ML_DSA_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR);
        ml_dsa_sign_ = mechanism_has(CKM_ML_DSA, CKF_SIGN);
        ml_kem_generation_ = mechanism_has(CKM_ML_KEM_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR);
        ml_kem_decapsulate_ = mechanism_has(CKM_ML_KEM, CKF_DECAPSULATE);
        const bool ml_kem_encapsulate = mechanism_has(CKM_ML_KEM, CKF_ENCAPSULATE);
        const bool sha3_digest = mechanism_has(CKM_SHA3_256, CKF_DIGEST);
        sha3_commitment_available_ = sha3_digest && functions_->C_DigestInit != nullptr &&
            functions_->C_DigestUpdate != nullptr && functions_->C_DigestKey != nullptr &&
            functions_->C_DigestFinal != nullptr && functions_->C_DecapsulateKey != nullptr;
        required_mechanisms_ = ml_dsa_generation_ && ml_dsa_sign_ && ml_kem_generation_ &&
            ml_kem_decapsulate_ && ml_kem_encapsulate && sha3_commitment_available_;
    }

    void validate_identity(const std::string& identity) const {
        if (identity.empty() || identity.size() > 256) {
            throw std::runtime_error("PKCS#11 hardware identity must contain 1..256 bytes");
        }
    }

    std::vector<unsigned char> get_attribute_bytes(CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type) const {
        CK_ATTRIBUTE attribute{type, nullptr, 0};
        require_ck("C_GetAttributeValue(size)", functions_->C_GetAttributeValue(session_, object, &attribute, 1));
        if (attribute.ulValueLen == CK_UNAVAILABLE_INFORMATION || attribute.ulValueLen > kMaxAttributeBytes) {
            throw std::runtime_error("PKCS#11 object attribute is unavailable or oversized");
        }
        std::vector<unsigned char> value(static_cast<std::size_t>(attribute.ulValueLen));
        attribute.pValue = value.empty() ? nullptr : value.data();
        require_ck("C_GetAttributeValue(value)", functions_->C_GetAttributeValue(session_, object, &attribute, 1));
        return value;
    }

    std::string get_attribute_string(CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type) const {
        const auto value = get_attribute_bytes(object, type);
        return std::string(reinterpret_cast<const char*>(value.data()), value.size());
    }

    CK_BBOOL get_attribute_bool(CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type) const {
        CK_BBOOL value = CK_FALSE;
        CK_ATTRIBUTE attribute{type, &value, sizeof(value)};
        require_ck("C_GetAttributeValue(bool)", functions_->C_GetAttributeValue(session_, object, &attribute, 1));
        return value;
    }

    CK_ULONG get_attribute_ulong(CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type) const {
        CK_ULONG value = 0;
        CK_ATTRIBUTE attribute{type, &value, sizeof(value)};
        require_ck("C_GetAttributeValue(ulong)", functions_->C_GetAttributeValue(session_, object, &attribute, 1));
        return value;
    }

    CK_OBJECT_HANDLE find_exact_object(
        CK_OBJECT_CLASS object_class,
        CK_KEY_TYPE key_type,
        const std::string& label,
        const std::vector<unsigned char>& id
    ) const {
        CK_ATTRIBUTE search[] = {
            {CKA_CLASS, &object_class, sizeof(object_class)},
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
            {CKA_LABEL, const_cast<char*>(label.data()), static_cast<CK_ULONG>(label.size())},
            {CKA_ID, const_cast<unsigned char*>(id.data()), static_cast<CK_ULONG>(id.size())},
        };
        require_ck("C_FindObjectsInit(exact)", functions_->C_FindObjectsInit(session_, search, 4));
        std::array<CK_OBJECT_HANDLE, 2> found{};
        CK_ULONG count = 0;
        CK_RV rv = functions_->C_FindObjects(session_, found.data(), static_cast<CK_ULONG>(found.size()), &count);
        const CK_RV final_rv = functions_->C_FindObjectsFinal(session_);
        require_ck("C_FindObjects(exact)", rv);
        require_ck("C_FindObjectsFinal(exact)", final_rv);
        if (count == 0) {
            return CK_INVALID_HANDLE;
        }
        if (count != 1) {
            throw std::runtime_error("PKCS#11 object identity is ambiguous; refusing duplicate key objects");
        }
        return found[0];
    }

    std::set<std::uint64_t> discover_generations(const std::string& identity) const {
        const std::string prefix = "OMNIGUARD_MLDSA_" + identity_tag(identity) + "_G";
        CK_OBJECT_CLASS object_class = CKO_PUBLIC_KEY;
        CK_KEY_TYPE key_type = CKK_ML_DSA;
        CK_ATTRIBUTE search[] = {
            {CKA_CLASS, &object_class, sizeof(object_class)},
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        };
        require_ck("C_FindObjectsInit(generations)", functions_->C_FindObjectsInit(session_, search, 2));
        std::set<std::uint64_t> generations;
        try {
            while (true) {
                std::array<CK_OBJECT_HANDLE, 32> found{};
                CK_ULONG count = 0;
                require_ck(
                    "C_FindObjects(generations)",
                    functions_->C_FindObjects(session_, found.data(), static_cast<CK_ULONG>(found.size()), &count)
                );
                if (count == 0) break;
                for (CK_ULONG i = 0; i < count; ++i) {
                    const std::string label = get_attribute_string(found[i], CKA_LABEL);
                    if (label.rfind(prefix, 0) != 0) continue;
                    const std::string suffix = label.substr(prefix.size());
                    std::size_t consumed = 0;
                    unsigned long long parsed = 0;
                    try {
                        parsed = std::stoull(suffix, &consumed, 10);
                    } catch (const std::exception&) {
                        throw std::runtime_error("PKCS#11 OmniGuard key label has an invalid generation");
                    }
                    if (consumed != suffix.size() || parsed == 0 || parsed > kMaxGeneration) {
                        throw std::runtime_error("PKCS#11 OmniGuard key generation is out of range");
                    }
                    generations.insert(static_cast<std::uint64_t>(parsed));
                }
            }
        } catch (...) {
            (void)functions_->C_FindObjectsFinal(session_);
            throw;
        }
        require_ck("C_FindObjectsFinal(generations)", functions_->C_FindObjectsFinal(session_));
        return generations;
    }

    void verify_private_key_policy(CK_OBJECT_HANDLE object) const {
        if (get_attribute_bool(object, CKA_SENSITIVE) != CK_TRUE ||
            get_attribute_bool(object, CKA_EXTRACTABLE) != CK_FALSE ||
            get_attribute_bool(object, CKA_ALWAYS_SENSITIVE) != CK_TRUE ||
            get_attribute_bool(object, CKA_NEVER_EXTRACTABLE) != CK_TRUE) {
            throw std::runtime_error("PKCS#11 private key is not proven sensitive and non-exportable");
        }
    }

    void verify_parameter_set(CK_OBJECT_HANDLE object, CK_ULONG expected) const {
        if (get_attribute_ulong(object, CKA_PARAMETER_SET) != expected) {
            throw std::runtime_error("PKCS#11 key object uses an unexpected PQC parameter set");
        }
    }

    ObjectHandles find_generation_handles(const std::string& identity, std::uint64_t generation) const {
        const std::string tag = identity_tag(identity);
        const std::string dsa_label = key_label("MLDSA", tag, generation);
        const std::string kem_label = key_label("MLKEM", tag, generation);
        const auto dsa_id = object_id_for(identity, generation, "MLDSA");
        const auto kem_id = object_id_for(identity, generation, "MLKEM");
        ObjectHandles handles;
        handles.signature_public = find_exact_object(CKO_PUBLIC_KEY, CKK_ML_DSA, dsa_label, dsa_id);
        handles.signature_private = find_exact_object(CKO_PRIVATE_KEY, CKK_ML_DSA, dsa_label, dsa_id);
        handles.kem_public = find_exact_object(CKO_PUBLIC_KEY, CKK_ML_KEM, kem_label, kem_id);
        handles.kem_private = find_exact_object(CKO_PRIVATE_KEY, CKK_ML_KEM, kem_label, kem_id);
        if (handles.signature_public == CK_INVALID_HANDLE || handles.signature_private == CK_INVALID_HANDLE ||
            handles.kem_public == CK_INVALID_HANDLE || handles.kem_private == CK_INVALID_HANDLE) {
            throw std::runtime_error("PKCS#11 latest OmniGuard generation is incomplete; refusing rollback to an older generation");
        }
        return handles;
    }

    PqcHardwarePublicMaterial material_from_handles(
        const std::string& identity,
        std::uint64_t generation,
        const ObjectHandles& handles
    ) const {
        verify_parameter_set(handles.signature_public, CKP_ML_DSA_44);
        verify_parameter_set(handles.signature_private, CKP_ML_DSA_44);
        verify_parameter_set(handles.kem_public, CKP_ML_KEM_512);
        verify_parameter_set(handles.kem_private, CKP_ML_KEM_512);
        verify_private_key_policy(handles.signature_private);
        verify_private_key_policy(handles.kem_private);

        std::vector<unsigned char> signature_public = get_attribute_bytes(handles.signature_public, CKA_VALUE);
        std::vector<unsigned char> kem_public = get_attribute_bytes(handles.kem_public, CKA_VALUE);
        if (signature_public.size() != kMlDsa44PublicKeyBytes || kem_public.size() != kMlKem512PublicKeyBytes) {
            throw std::runtime_error("PKCS#11 public-key size does not match ML-DSA-44/ML-KEM-512");
        }
        const std::string key_id = sha3_256_hex(
            "OMNIGUARD_PKCS11_KEY_ID_V1\n" + device_identity_ + "\n" + identity + "\n" +
            std::to_string(generation) + "\n" +
            bytes_to_hex(signature_public.data(), signature_public.size()) + "\n" +
            bytes_to_hex(kem_public.data(), kem_public.size())
        );
        return {
            kPkcs11PqcProvider,
            key_id,
            identity,
            std::move(signature_public),
            std::move(kem_public),
            generation,
        };
    }

    void activate_generation(const std::string& identity, std::uint64_t generation) {
        const ObjectHandles handles = find_generation_handles(identity, generation);
        PqcHardwarePublicMaterial material = material_from_handles(identity, generation, handles);
        active_identity_ = identity;
        active_generation_ = generation;
        active_key_id_ = material.key_id;
        active_signature_public_ = material.signature_public_key;
        active_kem_public_ = material.kem_public_key;
        active_handles_ = handles;
        private_keys_verified_ = true;
        derived_secret_verified_ = false;
    }

    void destroy_if_valid(CK_OBJECT_HANDLE handle) const noexcept {
        if (handle != CK_INVALID_HANDLE) {
            (void)functions_->C_DestroyObject(session_, handle);
        }
    }

    void generate_generation(const std::string& identity, std::uint64_t generation) {
        if (!rw_session_ || generation == 0 || generation > kMaxGeneration) {
            throw std::runtime_error("PKCS#11 generation request is invalid or token session is not writable");
        }
        const std::string tag = identity_tag(identity);
        const std::string dsa_label = key_label("MLDSA", tag, generation);
        const std::string kem_label = key_label("MLKEM", tag, generation);
        const auto dsa_id = object_id_for(identity, generation, "MLDSA");
        const auto kem_id = object_id_for(identity, generation, "MLKEM");
        if (find_exact_object(CKO_PUBLIC_KEY, CKK_ML_DSA, dsa_label, dsa_id) != CK_INVALID_HANDLE ||
            find_exact_object(CKO_PUBLIC_KEY, CKK_ML_KEM, kem_label, kem_id) != CK_INVALID_HANDLE) {
            throw std::runtime_error("PKCS#11 target hardware generation already exists");
        }

        CK_BBOOL true_value = CK_TRUE;
        CK_BBOOL false_value = CK_FALSE;
        CK_ML_DSA_PARAMETER_SET_TYPE dsa_parameter_set = CKP_ML_DSA_44;
        CK_ML_KEM_PARAMETER_SET_TYPE kem_parameter_set = CKP_ML_KEM_512;
        CK_OBJECT_HANDLE dsa_public = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE dsa_private = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE kem_public = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE kem_private = CK_INVALID_HANDLE;

        CK_ATTRIBUTE dsa_public_template[] = {
            {CKA_TOKEN, &true_value, sizeof(true_value)},
            {CKA_LABEL, const_cast<char*>(dsa_label.data()), static_cast<CK_ULONG>(dsa_label.size())},
            {CKA_ID, const_cast<unsigned char*>(dsa_id.data()), static_cast<CK_ULONG>(dsa_id.size())},
            {CKA_VERIFY, &true_value, sizeof(true_value)},
            {CKA_PARAMETER_SET, &dsa_parameter_set, sizeof(dsa_parameter_set)},
        };
        CK_ATTRIBUTE dsa_private_template[] = {
            {CKA_TOKEN, &true_value, sizeof(true_value)},
            {CKA_PRIVATE, &true_value, sizeof(true_value)},
            {CKA_LABEL, const_cast<char*>(dsa_label.data()), static_cast<CK_ULONG>(dsa_label.size())},
            {CKA_ID, const_cast<unsigned char*>(dsa_id.data()), static_cast<CK_ULONG>(dsa_id.size())},
            {CKA_SENSITIVE, &true_value, sizeof(true_value)},
            {CKA_EXTRACTABLE, &false_value, sizeof(false_value)},
            {CKA_SIGN, &true_value, sizeof(true_value)},
        };
        CK_MECHANISM dsa_mechanism{CKM_ML_DSA_KEY_PAIR_GEN, nullptr, 0};

        try {
            require_ck(
                "C_GenerateKeyPair(ML-DSA-44)",
                functions_->C_GenerateKeyPair(
                    session_, &dsa_mechanism,
                    dsa_public_template, sizeof(dsa_public_template) / sizeof(dsa_public_template[0]),
                    dsa_private_template, sizeof(dsa_private_template) / sizeof(dsa_private_template[0]),
                    &dsa_public, &dsa_private
                )
            );

            CK_ATTRIBUTE kem_public_template[] = {
                {CKA_TOKEN, &true_value, sizeof(true_value)},
                {CKA_LABEL, const_cast<char*>(kem_label.data()), static_cast<CK_ULONG>(kem_label.size())},
                {CKA_ID, const_cast<unsigned char*>(kem_id.data()), static_cast<CK_ULONG>(kem_id.size())},
                {CKA_ENCAPSULATE, &true_value, sizeof(true_value)},
                {CKA_PARAMETER_SET, &kem_parameter_set, sizeof(kem_parameter_set)},
            };
            CK_ATTRIBUTE kem_private_template[] = {
                {CKA_TOKEN, &true_value, sizeof(true_value)},
                {CKA_PRIVATE, &true_value, sizeof(true_value)},
                {CKA_LABEL, const_cast<char*>(kem_label.data()), static_cast<CK_ULONG>(kem_label.size())},
                {CKA_ID, const_cast<unsigned char*>(kem_id.data()), static_cast<CK_ULONG>(kem_id.size())},
                {CKA_SENSITIVE, &true_value, sizeof(true_value)},
                {CKA_EXTRACTABLE, &false_value, sizeof(false_value)},
                {CKA_DECAPSULATE, &true_value, sizeof(true_value)},
            };
            CK_MECHANISM kem_mechanism{CKM_ML_KEM_KEY_PAIR_GEN, nullptr, 0};
            require_ck(
                "C_GenerateKeyPair(ML-KEM-512)",
                functions_->C_GenerateKeyPair(
                    session_, &kem_mechanism,
                    kem_public_template, sizeof(kem_public_template) / sizeof(kem_public_template[0]),
                    kem_private_template, sizeof(kem_private_template) / sizeof(kem_private_template[0]),
                    &kem_public, &kem_private
                )
            );
        } catch (...) {
            destroy_if_valid(kem_private);
            destroy_if_valid(kem_public);
            destroy_if_valid(dsa_private);
            destroy_if_valid(dsa_public);
            throw;
        }

        activate_generation(identity, generation);
    }

    std::vector<unsigned char> sign_with_handle(
        CK_OBJECT_HANDLE private_key,
        const std::vector<unsigned char>& message
    ) const {
        CK_MECHANISM mechanism{CKM_ML_DSA, nullptr, 0};
        require_ck("C_SignInit(ML-DSA-44)", functions_->C_SignInit(session_, &mechanism, private_key));
        std::vector<unsigned char> signature(kMlDsa44SignatureBytes);
        CK_ULONG length = static_cast<CK_ULONG>(signature.size());
        require_ck(
            "C_Sign(ML-DSA-44)",
            functions_->C_Sign(
                session_,
                const_cast<unsigned char*>(message.data()),
                static_cast<CK_ULONG>(message.size()),
                signature.data(),
                &length
            )
        );
        if (length == 0 || length > signature.size()) {
            throw std::runtime_error("PKCS#11 ML-DSA-44 signature length is invalid");
        }
        signature.resize(static_cast<std::size_t>(length));
        return signature;
    }

    void prove_signature_pair() const {
        const std::string challenge = "OMNIGUARD_PKCS11_ML_DSA_PAIR_PROBE_V1|" + active_key_id_;
        const std::vector<unsigned char> message(challenge.begin(), challenge.end());
        const std::vector<unsigned char> signature = sign_with_handle(active_handles_.signature_private, message);
        CK_MECHANISM mechanism{CKM_ML_DSA, nullptr, 0};
        require_ck("C_VerifyInit(ML-DSA-44)", functions_->C_VerifyInit(session_, &mechanism, active_handles_.signature_public));
        require_ck(
            "C_Verify(ML-DSA-44 pair proof)",
            functions_->C_Verify(
                session_,
                const_cast<unsigned char*>(message.data()),
                static_cast<CK_ULONG>(message.size()),
                const_cast<unsigned char*>(signature.data()),
                static_cast<CK_ULONG>(signature.size())
            )
        );
    }

    CK_OBJECT_HANDLE decapsulate_to_nonexportable_secret(
        CK_OBJECT_HANDLE private_key,
        const std::vector<unsigned char>& ciphertext
    ) const {
        CK_OBJECT_CLASS secret_class = CKO_SECRET_KEY;
        CK_KEY_TYPE secret_type = CKK_GENERIC_SECRET;
        CK_BBOOL false_value = CK_FALSE;
        CK_BBOOL true_value = CK_TRUE;
        CK_ULONG value_length = kMlKem512SharedSecretBytes;
        CK_ATTRIBUTE secret_template[] = {
            {CKA_CLASS, &secret_class, sizeof(secret_class)},
            {CKA_KEY_TYPE, &secret_type, sizeof(secret_type)},
            {CKA_TOKEN, &false_value, sizeof(false_value)},
            {CKA_SENSITIVE, &true_value, sizeof(true_value)},
            {CKA_EXTRACTABLE, &false_value, sizeof(false_value)},
            {CKA_VALUE_LEN, &value_length, sizeof(value_length)},
        };
        CK_MECHANISM mechanism{CKM_ML_KEM, nullptr, 0};
        CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
        require_ck(
            "C_DecapsulateKey(ML-KEM-512)",
            functions_->C_DecapsulateKey(
                session_, &mechanism, private_key,
                secret_template, sizeof(secret_template) / sizeof(secret_template[0]),
                const_cast<unsigned char*>(ciphertext.data()),
                static_cast<CK_ULONG>(ciphertext.size()),
                &secret
            )
        );
        if (secret == CK_INVALID_HANDLE) {
            throw std::runtime_error("PKCS#11 ML-KEM decapsulation returned no derived secret object");
        }
        return secret;
    }

    void verify_derived_secret_policy(CK_OBJECT_HANDLE secret) const {
        if (get_attribute_bool(secret, CKA_SENSITIVE) != CK_TRUE ||
            get_attribute_bool(secret, CKA_EXTRACTABLE) != CK_FALSE) {
            throw std::runtime_error("PKCS#11 derived ML-KEM secret is not sensitive/non-exportable");
        }
    }

    std::string digest_key_with_prefix(CK_OBJECT_HANDLE secret, const std::string& prefix) const {
        CK_MECHANISM mechanism{CKM_SHA3_256, nullptr, 0};
        require_ck("C_DigestInit(SHA3-256)", functions_->C_DigestInit(session_, &mechanism));
        if (!prefix.empty()) {
            require_ck(
                "C_DigestUpdate(commitment prefix)",
                functions_->C_DigestUpdate(
                    session_,
                    reinterpret_cast<CK_BYTE_PTR>(const_cast<char*>(prefix.data())),
                    static_cast<CK_ULONG>(prefix.size())
                )
            );
        }
        require_ck("C_DigestKey(derived secret)", functions_->C_DigestKey(session_, secret));
        std::array<unsigned char, 32> digest{};
        CK_ULONG digest_length = static_cast<CK_ULONG>(digest.size());
        require_ck("C_DigestFinal(SHA3-256)", functions_->C_DigestFinal(session_, digest.data(), &digest_length));
        if (digest_length != digest.size()) {
            throw std::runtime_error("PKCS#11 SHA3-256 commitment length is invalid");
        }
        return bytes_to_hex(digest.data(), digest.size());
    }

    void prove_kem_commitment_path() {
        CK_OBJECT_CLASS secret_class = CKO_SECRET_KEY;
        CK_KEY_TYPE secret_type = CKK_GENERIC_SECRET;
        CK_BBOOL false_value = CK_FALSE;
        CK_BBOOL true_value = CK_TRUE;
        CK_ULONG value_length = kMlKem512SharedSecretBytes;
        CK_ATTRIBUTE secret_template[] = {
            {CKA_CLASS, &secret_class, sizeof(secret_class)},
            {CKA_KEY_TYPE, &secret_type, sizeof(secret_type)},
            {CKA_TOKEN, &false_value, sizeof(false_value)},
            {CKA_SENSITIVE, &true_value, sizeof(true_value)},
            {CKA_EXTRACTABLE, &false_value, sizeof(false_value)},
            {CKA_VALUE_LEN, &value_length, sizeof(value_length)},
        };
        CK_MECHANISM mechanism{CKM_ML_KEM, nullptr, 0};
        std::vector<unsigned char> ciphertext(kMlKem512CiphertextBytes);
        CK_ULONG ciphertext_length = static_cast<CK_ULONG>(ciphertext.size());
        CK_OBJECT_HANDLE sender_secret = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE receiver_secret = CK_INVALID_HANDLE;
        try {
            require_ck(
                "C_EncapsulateKey(ML-KEM-512 proof)",
                functions_->C_EncapsulateKey(
                    session_, &mechanism, active_handles_.kem_public,
                    secret_template, sizeof(secret_template) / sizeof(secret_template[0]),
                    ciphertext.data(), &ciphertext_length, &sender_secret
                )
            );
            if (ciphertext_length != kMlKem512CiphertextBytes || sender_secret == CK_INVALID_HANDLE) {
                throw std::runtime_error("PKCS#11 ML-KEM encapsulation proof returned invalid output");
            }
            ciphertext.resize(static_cast<std::size_t>(ciphertext_length));
            receiver_secret = decapsulate_to_nonexportable_secret(active_handles_.kem_private, ciphertext);
            verify_derived_secret_policy(sender_secret);
            verify_derived_secret_policy(receiver_secret);
            const std::string prefix = "OMNIGUARD_PKCS11_ML_KEM_PAIR_PROBE_V1|" + active_key_id_ + "|";
            const std::string sender_digest = digest_key_with_prefix(sender_secret, prefix);
            const std::string receiver_digest = digest_key_with_prefix(receiver_secret, prefix);
            if (sender_digest.size() != receiver_digest.size() ||
                CRYPTO_memcmp(sender_digest.data(), receiver_digest.data(), sender_digest.size()) != 0) {
                throw std::runtime_error("PKCS#11 ML-KEM encapsulation/decapsulation pair proof failed");
            }
            require_ck("C_DestroyObject(sender proof secret)", functions_->C_DestroyObject(session_, sender_secret));
            sender_secret = CK_INVALID_HANDLE;
            require_ck("C_DestroyObject(receiver proof secret)", functions_->C_DestroyObject(session_, receiver_secret));
            receiver_secret = CK_INVALID_HANDLE;
            derived_secret_verified_ = true;
        } catch (...) {
            destroy_if_valid(receiver_secret);
            destroy_if_valid(sender_secret);
            throw;
        }
    }

    void prove_active_operations() {
        prove_signature_pair();
        prove_kem_commitment_path();
        (void)capabilities_from_verified_hardware_probe(probe());
    }

    void require_active_key(const std::string& key_id) const {
        if (active_key_id_.empty() || key_id != active_key_id_ || active_generation_ == 0 ||
            !private_keys_verified_ || !derived_secret_verified_) {
            throw std::runtime_error("PKCS#11 operation does not match a fully verified active hardware key");
        }
    }

    PqcHardwarePublicMaterial active_public_material() const {
        if (active_key_id_.empty() || active_identity_.empty() || active_generation_ == 0 ||
            active_signature_public_.empty() || active_kem_public_.empty()) {
            throw std::runtime_error("PKCS#11 active public material is incomplete");
        }
        return {
            kPkcs11PqcProvider,
            active_key_id_,
            active_identity_,
            active_signature_public_,
            active_kem_public_,
            active_generation_,
        };
    }

    NativeModule module_;
    CK_FUNCTION_LIST_3_2_PTR functions_ = nullptr;
    CK_SLOT_ID slot_ = 0;
    CK_SESSION_HANDLE session_ = CK_INVALID_HANDLE;
    CK_TOKEN_INFO token_info_{};
    std::string pin_;
    std::string device_identity_;
    std::string evidence_reference_;
    bool interface_v32_ = false;
    bool owns_initialize_ = false;
    bool owns_login_ = false;
    bool token_present_ = false;
    bool hardware_slot_ = false;
    bool rw_session_ = false;
    bool ml_dsa_generation_ = false;
    bool ml_dsa_sign_ = false;
    bool ml_kem_generation_ = false;
    bool ml_kem_decapsulate_ = false;
    bool sha3_commitment_available_ = false;
    bool required_mechanisms_ = false;
    bool private_keys_verified_ = false;
    bool derived_secret_verified_ = false;
    std::string active_identity_;
    std::string active_key_id_;
    std::uint64_t active_generation_ = 0;
    ObjectHandles active_handles_;
    std::vector<unsigned char> active_signature_public_;
    std::vector<unsigned char> active_kem_public_;
};

}  // namespace

std::shared_ptr<PqcHardwareProvider> make_pkcs11_hardware_provider_from_env() {
    return std::make_shared<Pkcs11PqcHardwareProvider>();
}

}  // namespace omniguard
