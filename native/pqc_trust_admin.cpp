#include "pqc_key_store.h"
#include "pqc_provider_policy.h"
#include "pqc_trust_keyring.h"

#include <array>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>

namespace {

using json = nlohmann::json;
using omniguard::PqcKeyMaterial;
using omniguard::PqcKeyStore;
using omniguard::PqcTrustKeyring;

constexpr std::size_t kMinSecretLength = 32;
constexpr std::size_t kMinReasonLength = 8;
constexpr std::size_t kMaxReasonLength = 256;

struct SigDeleter {
    void operator()(OQS_SIG* value) const { OQS_SIG_free(value); }
};

using SigPtr = std::unique_ptr<OQS_SIG, SigDeleter>;

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

std::string random_hex(std::size_t bytes) {
    std::vector<unsigned char> value(bytes);
    if (RAND_bytes(value.data(), static_cast<int>(value.size())) != 1) {
        throw std::runtime_error("secure random generation failed");
    }
    static constexpr char kHex[] = "0123456789abcdef";
    std::string output(value.size() * 2, '0');
    for (std::size_t i = 0; i < value.size(); ++i) {
        output[i * 2] = kHex[(value[i] >> 4) & 0x0f];
        output[i * 2 + 1] = kHex[value[i] & 0x0f];
    }
    return output;
}

std::vector<unsigned char> sign_for_selftest(
    const PqcKeyMaterial& material,
    const std::string& message
) {
    SigPtr signature(OQS_SIG_new(OQS_SIG_alg_ml_dsa_44));
    if (!signature || material.signature_secret_key.size() != signature->length_secret_key) {
        throw std::runtime_error("self-test ML-DSA-44 signing material is invalid");
    }
    std::vector<unsigned char> output(signature->length_signature);
    std::size_t output_len = 0;
    if (OQS_SIG_sign(
            signature.get(),
            output.data(),
            &output_len,
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size(),
            material.signature_secret_key.data()
        ) != OQS_SUCCESS) {
        throw std::runtime_error("self-test ML-DSA-44 signing failed");
    }
    output.resize(output_len);
    return output;
}

json metadata_json(const omniguard::PqcTrustKeyringMetadata& metadata) {
    return {
        {"format", metadata.format},
        {"identity", metadata.identity},
        {"generation_count", metadata.generation_count},
        {"max_generations", metadata.max_generations},
        {"active_generation", metadata.active_generation},
        {"active_key_id", metadata.active_key_id},
        {"rollback_protected_by_active_key_binding", metadata.rollback_protected_by_active_key_binding},
        {"secret_key_material_stored", metadata.secret_key_material_stored},
        {"remote_admission", false},
    };
}

int self_test() {
    const std::filesystem::path root =
        std::filesystem::temp_directory_path() /
        ("omniguard-pqc-trust-selftest-" + random_hex(8));
    const std::filesystem::path first_store_path = root / "generation-1.json";
    const std::filesystem::path second_store_path = root / "generation-2.json";
    const std::filesystem::path third_store_path = root / "generation-3.json";
    const std::filesystem::path keyring_path = root / "trust-keyring.json";
    const std::filesystem::path rollback_copy_path = root / "rollback-copy.json";
    const std::string wrapping_secret = random_hex(48);
    const std::string identity = "SMARTCAR_PQC_TRUST_SELFTEST";

    try {
        std::filesystem::create_directories(root);
        PqcKeyStore first_store(first_store_path, wrapping_secret, identity);
        PqcKeyMaterial first = first_store.load_or_create();
        PqcTrustKeyring keyring(keyring_path, identity, 2);
        keyring.initialize_root(first);
        const auto root_metadata = keyring.inspect(first.key_id);
        if (root_metadata.generation_count != 1 || root_metadata.active_generation != 1 ||
            root_metadata.secret_key_material_stored) {
            throw std::runtime_error("PQC trust root metadata is invalid");
        }
        std::filesystem::copy_file(keyring_path, rollback_copy_path);

        const std::string historical_message = "OMNIGUARD_PQC_TRUST_SELFTEST_MESSAGE_V1";
        std::vector<unsigned char> historical_signature = sign_for_selftest(first, historical_message);

        PqcKeyStore second_store(second_store_path, wrapping_secret, identity);
        PqcKeyMaterial second = second_store.load_or_create();
        keyring.append_transition(first, second, "hosted deterministic trust transition");
        const auto transitioned = keyring.inspect(second.key_id);
        if (transitioned.generation_count != 2 || transitioned.active_generation != 2 ||
            transitioned.active_key_id != second.key_id) {
            throw std::runtime_error("PQC trust transition did not advance the active generation");
        }
        if (!keyring.verify_detached_signature(
                first.key_id,
                historical_message,
                historical_signature,
                first.signature_public_key,
                first.kem_public_key,
                second.key_id
            )) {
            throw std::runtime_error("trusted historical ML-DSA signature did not verify after rotation");
        }

        std::vector<unsigned char> substituted_signature_key = first.signature_public_key;
        substituted_signature_key[0] ^= 0x01;
        if (keyring.verify_detached_signature(
                first.key_id,
                historical_message,
                historical_signature,
                substituted_signature_key,
                first.kem_public_key,
                second.key_id
            )) {
            throw std::runtime_error("arbitrary embedded historical public key was trusted");
        }

        bool rollback_rejected = false;
        try {
            PqcTrustKeyring rollback(rollback_copy_path, identity, 2);
            (void)rollback.inspect(second.key_id);
        } catch (const std::exception&) {
            rollback_rejected = true;
        }
        if (!rollback_rejected) {
            throw std::runtime_error("rolled-back PQC trust keyring was accepted against the active durable key");
        }

        PqcKeyStore third_store(third_store_path, wrapping_secret, identity);
        PqcKeyMaterial third = third_store.load_or_create();
        bool bound_rejected = false;
        try {
            keyring.append_transition(second, third, "generation bound must reject this transition");
        } catch (const std::exception&) {
            bound_rejected = true;
        }
        if (!bound_rejected || keyring.inspect(second.key_id).generation_count != 2) {
            throw std::runtime_error("PQC trust generation bound silently evicted historical trust");
        }

        if (!historical_signature.empty()) {
            OPENSSL_cleanse(historical_signature.data(), historical_signature.size());
        }
        std::filesystem::remove_all(root);
        std::cout << "[PQC-TRUST-SELF-TEST] PASS: self-signed root + dual-signed transition + historical signature + rollback/substitution/bound rejection\n";
        return 0;
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
        throw;
    }
}

void print_usage() {
    std::cerr
        << "Usage:\n"
        << "  smartcar_pqc_trust_admin init --identity <vehicle-id>\n"
        << "  smartcar_pqc_trust_admin inspect --identity <vehicle-id>\n"
        << "  smartcar_pqc_trust_admin admit --identity <vehicle-id> --previous-keystore <backup-path> --reason <text> --confirm ADMIT:<active-key-id>\n"
        << "  smartcar_pqc_trust_admin --self-test\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            print_usage();
            return 64;
        }
        const std::string command = argv[1];
        if (command == "--self-test") {
            return self_test();
        }
        (void)omniguard::enforce_pqc_provider_policy_from_env();

        const std::string identity = option_value(argc, argv, "--identity", true);
        if (identity.empty() || identity.size() > 256) {
            throw std::runtime_error("PQC trust operator identity is invalid");
        }
        const std::string wrapping_secret =
            require_env("SMARTCAR_CPP_PQC_KEYSTORE_KEY", kMinSecretLength);
        const std::filesystem::path active_store_path =
            require_env("SMARTCAR_CPP_PQC_KEYSTORE_PATH");
        const std::filesystem::path keyring_path =
            require_env("SMARTCAR_CPP_PQC_TRUST_KEYRING_PATH");
        const std::size_t max_generations = configured_max_generations();

        PqcKeyStore active_store(active_store_path, wrapping_secret, identity);
        if (command == "init") {
            PqcKeyMaterial active = active_store.load_or_create();
            PqcTrustKeyring keyring(keyring_path, identity, max_generations);
            keyring.initialize_root(active);
            std::cout << metadata_json(keyring.inspect(active.key_id)).dump(2) << '\n';
            return 0;
        }
        if (command == "inspect") {
            const auto active = active_store.inspect();
            PqcTrustKeyring keyring(keyring_path, identity, max_generations);
            std::cout << metadata_json(keyring.inspect(active.key_id)).dump(2) << '\n';
            return 0;
        }
        if (command == "admit") {
            const std::filesystem::path previous_path =
                option_value(argc, argv, "--previous-keystore", true);
            const std::string reason = option_value(argc, argv, "--reason", true);
            const std::string confirmation = option_value(argc, argv, "--confirm", true);
            if (reason.size() < kMinReasonLength || reason.size() > kMaxReasonLength) {
                throw std::runtime_error("PQC trust admission reason must contain 8 to 256 characters");
            }
            if (previous_path.empty() || previous_path == active_store_path) {
                throw std::runtime_error("previous PQC keystore backup path is invalid");
            }

            PqcKeyMaterial current = active_store.load_or_create();
            if (confirmation != "ADMIT:" + current.key_id) {
                throw std::runtime_error("PQC trust admission confirmation does not match the active key identifier");
            }
            PqcKeyStore previous_store(previous_path, wrapping_secret, identity);
            PqcKeyMaterial previous = previous_store.load_or_create();
            if (previous.key_id == current.key_id) {
                throw std::runtime_error("PQC trust admission requires distinct previous and active key identifiers");
            }
            PqcTrustKeyring keyring(keyring_path, identity, max_generations);
            keyring.append_transition(previous, current, reason);
            std::cout << metadata_json(keyring.inspect(current.key_id)).dump(2) << '\n';
            return 0;
        }

        print_usage();
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "[PQC-TRUST-ADMIN] fail-closed: " << error.what() << '\n';
        return 1;
    }
}
