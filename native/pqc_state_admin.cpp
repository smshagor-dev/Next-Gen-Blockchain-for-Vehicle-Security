#include "pqc_key_store.h"
#include "pqc_state_guard.h"
#include "pqc_trust_keyring.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

namespace {

using json = nlohmann::json;
using omniguard::PqcKeyMaterial;
using omniguard::PqcKeyStore;
using omniguard::PqcRollbackAnchor;
using omniguard::PqcTrustKeyring;

constexpr std::size_t kMinSecretLength = 32;

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

json read_json(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status)) {
        throw std::runtime_error("state metadata path must be a regular non-symlink file");
    }
    const auto size = std::filesystem::file_size(path, error);
    if (error || size == 0 || size > 2 * 1024 * 1024) {
        throw std::runtime_error("state metadata file size is invalid");
    }
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("could not open state metadata file");
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    try {
        return json::parse(buffer.str());
    } catch (const json::exception&) {
        throw std::runtime_error("state metadata contains malformed JSON");
    }
}

struct TrustHead {
    std::uint64_t generation = 0;
    std::string active_key_id;
    std::string head_hash;
};

TrustHead verified_trust_head(
    const std::filesystem::path& keyring_path,
    const std::string& identity,
    std::size_t max_generations,
    const std::string& active_key_id
) {
    PqcTrustKeyring keyring(keyring_path, identity, max_generations);
    const auto metadata = keyring.inspect(active_key_id);
    const json document = read_json(keyring_path);
    if (!document.contains("active_generation") || !document.at("active_generation").is_number_unsigned() ||
        !document.contains("active_key_id") || !document.at("active_key_id").is_string() ||
        !document.contains("head_hash") || !document.at("head_hash").is_string()) {
        throw std::runtime_error("verified trust keyring head metadata is malformed");
    }
    TrustHead head{
        document.at("active_generation").get<std::uint64_t>(),
        document.at("active_key_id").get<std::string>(),
        document.at("head_hash").get<std::string>(),
    };
    if (head.generation != metadata.active_generation || head.active_key_id != metadata.active_key_id ||
        head.active_key_id != active_key_id) {
        throw std::runtime_error("trust keyring head metadata is inconsistent");
    }
    return head;
}

struct StateContext {
    std::string identity;
    std::string wrapping_secret;
    std::filesystem::path active_store_path;
    std::filesystem::path keyring_path;
    std::filesystem::path anchor_path;
    std::string anchor_secret;
    std::size_t max_generations = PqcTrustKeyring::kDefaultMaxGenerations;
    PqcKeyMaterial active_material;
    TrustHead trust_head;
};

StateContext load_context(const std::string& identity) {
    if (identity.empty() || identity.size() > 256) {
        throw std::runtime_error("PQC state identity is invalid");
    }
    StateContext context;
    context.identity = identity;
    context.wrapping_secret = require_env("SMARTCAR_CPP_PQC_KEYSTORE_KEY", kMinSecretLength);
    context.active_store_path = require_env("SMARTCAR_CPP_PQC_KEYSTORE_PATH");
    context.keyring_path = require_env("SMARTCAR_CPP_PQC_TRUST_KEYRING_PATH");
    context.anchor_path = require_env("SMARTCAR_CPP_PQC_ROLLBACK_ANCHOR_PATH");
    context.anchor_secret = require_env("SMARTCAR_CPP_PQC_ROLLBACK_KEY", kMinSecretLength);
    context.max_generations = configured_max_generations();

    if (!std::filesystem::exists(context.active_store_path) || !std::filesystem::exists(context.keyring_path)) {
        throw std::runtime_error("active keystore and trust keyring must already exist for state administration");
    }
    PqcKeyStore active_store(context.active_store_path, context.wrapping_secret, identity);
    context.active_material = active_store.load_or_create();
    context.trust_head = verified_trust_head(
        context.keyring_path,
        identity,
        context.max_generations,
        context.active_material.key_id
    );
    return context;
}

json state_status(const StateContext& context, bool require_anchor) {
    json output = {
        {"format", "OMNIGUARD_PQC_STATE_STATUS_V1"},
        {"identity", context.identity},
        {"active_key_id", context.active_material.key_id},
        {"active_generation", context.trust_head.generation},
        {"trust_head_hash", context.trust_head.head_hash},
        {"keystore_keyring_consistent", true},
        {"rollback_anchor_configured", std::filesystem::exists(context.anchor_path)},
        {"hardware_monotonic_counter", false},
        {"automatic_recovery_allowed", false},
        {"secret_values_exposed", false},
    };
    if (std::filesystem::exists(context.anchor_path)) {
        PqcRollbackAnchor anchor(context.anchor_path, context.anchor_secret, context.identity);
        anchor.verify_exact(
            context.trust_head.generation,
            context.trust_head.active_key_id,
            context.trust_head.head_hash
        );
        output["rollback_anchor_valid"] = true;
    } else {
        output["rollback_anchor_valid"] = false;
        if (require_anchor) {
            throw std::runtime_error("rollback anchor is required but not initialized");
        }
    }
    output["healthy"] = output["rollback_anchor_valid"].get<bool>() || !require_anchor;
    return output;
}

void print_usage() {
    std::cerr
        << "Usage:\n"
        << "  smartcar_pqc_state_admin status --identity <vehicle-id>\n"
        << "  smartcar_pqc_state_admin anchor-init --identity <vehicle-id> --confirm ANCHOR:<active-key-id>\n"
        << "  smartcar_pqc_state_admin anchor-advance --identity <vehicle-id> --confirm ADVANCE:<active-key-id>\n"
        << "  smartcar_pqc_state_admin recovery-check --identity <vehicle-id> --previous-keystore <backup.json>\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            print_usage();
            return 64;
        }
        const std::string command = argv[1];
        const std::string identity = option_value(argc, argv, "--identity", true);
        StateContext context = load_context(identity);

        if (command == "status") {
            std::cout << state_status(context, false).dump(2) << '\n';
            return 0;
        }

        if (command == "anchor-init") {
            const std::string confirm = option_value(argc, argv, "--confirm", true);
            if (confirm != "ANCHOR:" + context.active_material.key_id) {
                throw std::runtime_error("rollback anchor initialization confirmation does not match active key");
            }
            PqcRollbackAnchor anchor(context.anchor_path, context.anchor_secret, identity);
            anchor.initialize(
                context.trust_head.generation,
                context.trust_head.active_key_id,
                context.trust_head.head_hash
            );
            std::cout << state_status(context, true).dump(2) << '\n';
            return 0;
        }

        if (command == "anchor-advance") {
            const std::string confirm = option_value(argc, argv, "--confirm", true);
            if (confirm != "ADVANCE:" + context.active_material.key_id) {
                throw std::runtime_error("rollback anchor advance confirmation does not match active key");
            }
            PqcRollbackAnchor anchor(context.anchor_path, context.anchor_secret, identity);
            anchor.advance(
                context.trust_head.generation,
                context.trust_head.active_key_id,
                context.trust_head.head_hash
            );
            std::cout << state_status(context, true).dump(2) << '\n';
            return 0;
        }

        if (command == "recovery-check") {
            const std::filesystem::path backup = option_value(argc, argv, "--previous-keystore", true);
            if (!std::filesystem::exists(backup)) {
                throw std::runtime_error("recovery candidate keystore does not exist");
            }
            PqcKeyStore candidate_store(backup, context.wrapping_secret, identity);
            PqcKeyMaterial candidate = candidate_store.load_or_create();
            if (candidate.key_id == context.active_material.key_id) {
                throw std::runtime_error("recovery candidate is the current active identity, not a historical backup");
            }
            PqcTrustKeyring keyring(context.keyring_path, identity, context.max_generations);
            const auto trusted = keyring.trusted_identities(context.active_material.key_id);
            bool admitted = false;
            std::uint64_t generation = 0;
            for (const auto& item : trusted) {
                if (item.key_id == candidate.key_id &&
                    item.signature_public_key == candidate.signature_public_key &&
                    item.kem_public_key == candidate.kem_public_key) {
                    admitted = true;
                    generation = item.generation;
                    break;
                }
            }
            if (!admitted) {
                throw std::runtime_error("recovery candidate is not an admitted historical PQC identity");
            }
            std::cout << json({
                {"format", "OMNIGUARD_PQC_RECOVERY_CHECK_V1"},
                {"identity", identity},
                {"candidate_key_id", candidate.key_id},
                {"candidate_generation", generation},
                {"candidate_admitted_historical", true},
                {"active_key_id", context.active_material.key_id},
                {"automatic_restore_allowed", false},
                {"requires_explicit_operator_recovery_procedure", true},
                {"rollback_anchor_must_not_be_decremented", true},
                {"secret_values_exposed", false},
            }).dump(2) << '\n';
            return 0;
        }

        print_usage();
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "[PQC-STATE-ADMIN] fail-closed: " << error.what() << '\n';
        return 1;
    }
}
