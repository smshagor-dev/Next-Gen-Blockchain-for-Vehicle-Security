#include "pqc_key_store.h"
#include "pqc_provider_policy.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#endif

namespace {

using json = nlohmann::json;
using omniguard::PqcKeyStore;
using omniguard::PqcKeyStoreMetadata;
using omniguard::PqcProviderCapabilities;

constexpr const char* kPreparedFormat = "OMNIGUARD_PQC_ROTATION_PREPARED_V1";
constexpr const char* kCompletedFormat = "OMNIGUARD_PQC_ROTATION_COMPLETED_V1";
constexpr std::size_t kMinSecretLength = 32;
constexpr std::size_t kMinReasonLength = 8;
constexpr std::size_t kMaxReasonLength = 256;

struct RotationResult {
    std::string previous_key_id;
    std::string new_key_id;
    std::filesystem::path backup_path;
    std::filesystem::path prepared_receipt_path;
    std::filesystem::path completed_receipt_path;
};

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

std::string to_hex(const unsigned char* data, std::size_t size) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string output(size * 2, '0');
    for (std::size_t i = 0; i < size; ++i) {
        output[i * 2] = kHex[(data[i] >> 4) & 0x0f];
        output[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return output;
}

std::string random_hex(std::size_t bytes) {
    std::vector<unsigned char> value(bytes);
    if (RAND_bytes(value.data(), static_cast<int>(value.size())) != 1) {
        throw std::runtime_error("secure random generation failed");
    }
    return to_hex(value.data(), value.size());
}

std::string sha3_256_hex(const std::string& input) {
    std::array<unsigned char, 32> output{};
    unsigned int output_len = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("SHA3 context allocation failed");
    }
    const bool ok = EVP_DigestInit_ex(context, EVP_sha3_256(), nullptr) == 1 &&
                    EVP_DigestUpdate(context, input.data(), input.size()) == 1 &&
                    EVP_DigestFinal_ex(context, output.data(), &output_len) == 1;
    EVP_MD_CTX_free(context);
    if (!ok || output_len != output.size()) {
        throw std::runtime_error("SHA3-256 operation failed");
    }
    return to_hex(output.data(), output.size());
}

std::string now_epoch_string() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::to_string(std::chrono::duration_cast<std::chrono::seconds>(now).count());
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
        throw std::runtime_error("could not restrict local PQC administration file permissions");
    }
}

void ensure_safe_directory(const std::filesystem::path& directory) {
    if (directory.empty()) {
        throw std::runtime_error("rotation directory is invalid");
    }
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    if (error) {
        throw std::runtime_error("could not create rotation directory");
    }
    const auto status = std::filesystem::symlink_status(directory, error);
    if (error || std::filesystem::is_symlink(status) || !std::filesystem::is_directory(status)) {
        throw std::runtime_error("rotation directory must be a real local directory, not a symlink");
    }
}

void write_new_json(const std::filesystem::path& path, const json& document) {
    if (path.empty() || path.filename().empty() || std::filesystem::exists(path)) {
        throw std::runtime_error("refusing to overwrite PQC rotation evidence");
    }
    if (path.has_parent_path()) {
        ensure_safe_directory(path.parent_path());
    }
    const std::filesystem::path temporary = path.string() + ".tmp." + random_hex(8);
    try {
        {
            std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
            if (!stream) {
                throw std::runtime_error("could not create PQC rotation evidence temporary file");
            }
            stream << document.dump(2) << '\n';
            stream.flush();
            if (!stream) {
                throw std::runtime_error("could not persist PQC rotation evidence");
            }
        }
        set_private_permissions(temporary);
        std::error_code error;
        std::filesystem::rename(temporary, path, error);
        if (error) {
            throw std::runtime_error("could not atomically publish PQC rotation evidence");
        }
        set_private_permissions(path);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        throw;
    }
}

void atomic_replace_file(
    const std::filesystem::path& staging,
    const std::filesystem::path& active
) {
#if defined(_WIN32)
    if (!MoveFileExW(
            staging.c_str(),
            active.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("could not atomically activate rotated PQC keystore");
    }
#else
    std::error_code error;
    std::filesystem::rename(staging, active, error);
    if (error) {
        throw std::runtime_error("could not atomically activate rotated PQC keystore");
    }
#endif
    set_private_permissions(active);
}

json metadata_json(const PqcKeyStoreMetadata& metadata) {
    return {
        {"format", metadata.format},
        {"provider", metadata.provider},
        {"key_id", metadata.key_id},
        {"identity", metadata.identity},
        {"signature_algorithm", metadata.signature_algorithm},
        {"kem_algorithm", metadata.kem_algorithm},
        {"hardware_backed", metadata.hardware_backed},
        {"non_exportable", metadata.non_exportable},
    };
}

json capabilities_json(const PqcProviderCapabilities& capabilities) {
    return {
        {"provider", capabilities.provider},
        {"hardware_backed", capabilities.hardware_backed},
        {"non_exportable", capabilities.non_exportable},
        {"rotation_supported", capabilities.rotation_supported},
    };
}

RotationResult rotate_local(
    const std::filesystem::path& active_path,
    const std::string& wrapping_secret,
    const std::string& identity,
    const std::filesystem::path& rotation_directory,
    const std::string& reason,
    const std::string& confirmation,
    bool rotation_enabled
) {
    if (!rotation_enabled) {
        throw std::runtime_error(
            "local PQC rotation is disabled; set SMARTCAR_CPP_PQC_ROTATION_ENABLED=1 for an explicit maintenance window"
        );
    }
    if (reason.size() < kMinReasonLength || reason.size() > kMaxReasonLength) {
        throw std::runtime_error("PQC rotation reason must contain 8 to 256 characters");
    }

    omniguard::enforce_pqc_provider_policy_from_env();
    PqcKeyStore active_store(active_path, wrapping_secret, identity);
    const PqcKeyStoreMetadata previous = active_store.inspect();
    const std::string expected_confirmation = "ROTATE:" + previous.key_id;
    if (confirmation != expected_confirmation) {
        throw std::runtime_error("PQC rotation confirmation does not match the active key identifier");
    }

    ensure_safe_directory(rotation_directory);
    const std::string rotation_id = now_epoch_string() + "-" + random_hex(6);
    const std::string previous_prefix = previous.key_id.substr(0, 16);
    const std::filesystem::path backup_path =
        rotation_directory / ("backup-" + previous_prefix + "-" + rotation_id + ".json");
    const std::filesystem::path prepared_path =
        rotation_directory / ("rotation-" + rotation_id + ".prepared.json");
    const std::filesystem::path completed_path =
        rotation_directory / ("rotation-" + rotation_id + ".completed.json");
    const std::filesystem::path staging_path =
        active_path.parent_path() /
        (active_path.filename().string() + ".rotate." + rotation_id + ".new");

    if (std::filesystem::exists(backup_path) || std::filesystem::exists(prepared_path) ||
        std::filesystem::exists(completed_path) || std::filesystem::exists(staging_path)) {
        throw std::runtime_error("PQC rotation output path collision");
    }

    std::error_code copy_error;
    std::filesystem::copy_file(active_path, backup_path, std::filesystem::copy_options::none, copy_error);
    if (copy_error) {
        throw std::runtime_error("could not create encrypted PQC keystore rotation backup");
    }
    set_private_permissions(backup_path);

    bool activated = false;
    try {
        PqcKeyStore staging_store(staging_path, wrapping_secret, identity);
        (void)staging_store.load_or_create();
        const PqcKeyStoreMetadata replacement = staging_store.inspect();
        if (replacement.key_id == previous.key_id) {
            throw std::runtime_error("PQC rotation did not produce a new key identifier");
        }

        const json prepared = {
            {"format", kPreparedFormat},
            {"rotation_id", rotation_id},
            {"identity", identity},
            {"provider", previous.provider},
            {"signature_algorithm", previous.signature_algorithm},
            {"kem_algorithm", previous.kem_algorithm},
            {"previous_key_id", previous.key_id},
            {"new_key_id", replacement.key_id},
            {"reason", reason},
            {"backup_filename", backup_path.filename().string()},
            {"prepared_at_epoch", now_epoch_string()},
            {"private_key_material_exposed", false},
            {"remote_rotation", false},
        };
        write_new_json(prepared_path, prepared);
        const std::string prepared_digest = sha3_256_hex(prepared.dump());

        atomic_replace_file(staging_path, active_path);
        activated = true;
        PqcKeyStore verified_store(active_path, wrapping_secret, identity);
        const PqcKeyStoreMetadata verified = verified_store.inspect();
        if (verified.key_id != replacement.key_id) {
            throw std::runtime_error("rotated PQC keystore verification failed after activation");
        }

        const json completed = {
            {"format", kCompletedFormat},
            {"rotation_id", rotation_id},
            {"identity", identity},
            {"provider", verified.provider},
            {"previous_key_id", previous.key_id},
            {"new_key_id", verified.key_id},
            {"prepared_receipt_sha3_256", prepared_digest},
            {"backup_filename", backup_path.filename().string()},
            {"completed_at_epoch", now_epoch_string()},
            {"private_key_material_exposed", false},
            {"remote_rotation", false},
        };
        try {
            write_new_json(completed_path, completed);
        } catch (...) {
            throw std::runtime_error(
                "PQC rotation activated but completion receipt could not be written; inspect the active key and prepared receipt before further operation"
            );
        }

        return {
            previous.key_id,
            verified.key_id,
            backup_path,
            prepared_path,
            completed_path,
        };
    } catch (...) {
        std::error_code ignored;
        if (!activated) {
            std::filesystem::remove(staging_path, ignored);
        }
        throw;
    }
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

std::filesystem::path default_rotation_directory(const std::filesystem::path& active_path) {
    return active_path.parent_path() / (active_path.filename().string() + ".rotations");
}

int self_test() {
    const std::filesystem::path root =
        std::filesystem::temp_directory_path() /
        ("omniguard-pqc-rotation-selftest-" + random_hex(8));
    const std::filesystem::path store_path = root / "native-pqc-keystore.json";
    const std::filesystem::path rotation_directory = root / "rotation-evidence";
    const std::string wrapping_secret = random_hex(48);
    const std::string identity = "SMARTCAR_PQC_ROTATION_SELFTEST";

    try {
        std::filesystem::create_directories(root);
        PqcKeyStore initial_store(store_path, wrapping_secret, identity);
        (void)initial_store.load_or_create();
        const auto initial = initial_store.inspect();

        bool wrong_confirmation_rejected = false;
        try {
            (void)rotate_local(
                store_path,
                wrapping_secret,
                identity,
                rotation_directory,
                "self-test wrong confirmation",
                "ROTATE:not-the-active-key",
                true
            );
        } catch (const std::exception&) {
            wrong_confirmation_rejected = true;
        }
        if (!wrong_confirmation_rejected || initial_store.inspect().key_id != initial.key_id) {
            throw std::runtime_error("wrong rotation confirmation changed active PQC identity");
        }

        const RotationResult result = rotate_local(
            store_path,
            wrapping_secret,
            identity,
            rotation_directory,
            "deterministic hosted rotation validation",
            "ROTATE:" + initial.key_id,
            true
        );
        PqcKeyStore rotated_store(store_path, wrapping_secret, identity);
        const auto rotated = rotated_store.inspect();
        if (rotated.key_id != result.new_key_id || rotated.key_id == initial.key_id) {
            throw std::runtime_error("rotated PQC identity was not activated");
        }

        PqcKeyStore backup_store(result.backup_path, wrapping_secret, identity);
        if (backup_store.inspect().key_id != initial.key_id) {
            throw std::runtime_error("encrypted PQC rotation backup does not contain previous identity");
        }
        if (!std::filesystem::exists(result.prepared_receipt_path) ||
            !std::filesystem::exists(result.completed_receipt_path)) {
            throw std::runtime_error("PQC rotation evidence receipts are missing");
        }

        const json prepared = json::parse(std::ifstream(result.prepared_receipt_path));
        const json completed = json::parse(std::ifstream(result.completed_receipt_path));
        if (prepared.at("format") != kPreparedFormat || completed.at("format") != kCompletedFormat ||
            prepared.at("previous_key_id") != initial.key_id ||
            completed.at("new_key_id") != rotated.key_id ||
            prepared.at("private_key_material_exposed") != false ||
            completed.at("remote_rotation") != false) {
            throw std::runtime_error("PQC rotation receipt content is invalid");
        }

        bool disabled_rejected = false;
        try {
            (void)rotate_local(
                store_path,
                wrapping_secret,
                identity,
                rotation_directory,
                "self-test disabled rotation",
                "ROTATE:" + rotated.key_id,
                false
            );
        } catch (const std::exception&) {
            disabled_rejected = true;
        }
        if (!disabled_rejected || rotated_store.inspect().key_id != rotated.key_id) {
            throw std::runtime_error("disabled rotation changed active PQC identity");
        }

        bool hardware_required_rejected = false;
        try {
            (void)omniguard::enforce_pqc_provider_policy(true);
        } catch (const std::exception&) {
            hardware_required_rejected = true;
        }
        if (!hardware_required_rejected) {
            throw std::runtime_error("software PQC provider satisfied hardware-required policy");
        }
        const auto capabilities = omniguard::enforce_pqc_provider_policy(false);
        if (capabilities.hardware_backed || capabilities.non_exportable ||
            capabilities.provider != PqcKeyStore::kProvider) {
            throw std::runtime_error("PQC provider capabilities are not conservative");
        }

        std::filesystem::remove_all(root);
        std::cout << "[PQC-KEY-ADMIN-SELF-TEST] PASS: guarded local rotation + encrypted backup + linked receipts + hardware-required fail-closed\n";
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
        << "  smartcar_pqc_key_admin provider-status\n"
        << "  smartcar_pqc_key_admin inspect --identity <vehicle-id>\n"
        << "  smartcar_pqc_key_admin rotate --identity <vehicle-id> --reason <text> --confirm ROTATE:<key-id> [--rotation-dir <path>]\n"
        << "  smartcar_pqc_key_admin --self-test\n";
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
        if (command == "provider-status") {
            const auto capabilities = omniguard::enforce_pqc_provider_policy_from_env();
            std::cout << capabilities_json(capabilities).dump(2) << '\n';
            return 0;
        }

        const auto capabilities = omniguard::enforce_pqc_provider_policy_from_env();
        (void)capabilities;
        const std::string identity = option_value(argc, argv, "--identity", true);
        if (identity.empty() || identity.size() > 256) {
            throw std::runtime_error("PQC operator identity is invalid");
        }
        const std::string wrapping_secret =
            require_env("SMARTCAR_CPP_PQC_KEYSTORE_KEY", kMinSecretLength);
        const std::filesystem::path active_path =
            require_env("SMARTCAR_CPP_PQC_KEYSTORE_PATH");

        if (command == "inspect") {
            PqcKeyStore store(active_path, wrapping_secret, identity);
            std::cout << metadata_json(store.inspect()).dump(2) << '\n';
            return 0;
        }
        if (command == "rotate") {
            const std::string reason = option_value(argc, argv, "--reason", true);
            const std::string confirmation = option_value(argc, argv, "--confirm", true);
            const std::string rotation_dir_option =
                option_value(argc, argv, "--rotation-dir", false);
            const std::filesystem::path rotation_directory = rotation_dir_option.empty()
                ? default_rotation_directory(active_path)
                : std::filesystem::path(rotation_dir_option);
            const bool enabled = omniguard::parse_strict_env_bool(
                "SMARTCAR_CPP_PQC_ROTATION_ENABLED",
                false
            );
            const RotationResult result = rotate_local(
                active_path,
                wrapping_secret,
                identity,
                rotation_directory,
                reason,
                confirmation,
                enabled
            );
            std::cout << json({
                {"status", "rotated"},
                {"provider", PqcKeyStore::kProvider},
                {"identity", identity},
                {"previous_key_id", result.previous_key_id},
                {"new_key_id", result.new_key_id},
                {"backup_path", result.backup_path.string()},
                {"prepared_receipt_path", result.prepared_receipt_path.string()},
                {"completed_receipt_path", result.completed_receipt_path.string()},
                {"private_key_material_exposed", false},
                {"remote_rotation", false},
            }).dump(2) << '\n';
            return 0;
        }

        print_usage();
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "[PQC-KEY-ADMIN] fail-closed: " << error.what() << '\n';
        return 1;
    }
}
