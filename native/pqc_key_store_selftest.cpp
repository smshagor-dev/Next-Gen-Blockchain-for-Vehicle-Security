#include "pqc_key_store.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

namespace {

using json = nlohmann::json;

std::string require_secret() {
    const char* value = std::getenv("SMARTCAR_CPP_PQC_KEYSTORE_KEY");
    if (value == nullptr || std::string(value).size() < 32) {
        throw std::runtime_error(
            "SMARTCAR_CPP_PQC_KEYSTORE_KEY must contain at least 32 characters"
        );
    }
    return value;
}

std::string read_all(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("could not read self-test keystore");
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
}

void write_all(const std::filesystem::path& path, const std::string& value) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        throw std::runtime_error("could not write self-test keystore");
    }
    stream << value;
    stream.flush();
    if (!stream) {
        throw std::runtime_error("could not persist self-test keystore");
    }
}

template <typename Function>
bool throws(Function&& function) {
    try {
        function();
        return false;
    } catch (const std::exception&) {
        return true;
    }
}

}  // namespace

int main() {
    std::filesystem::path root;
    try {
        const std::string secret = require_secret();
        root = std::filesystem::temp_directory_path() /
               ("omniguard-pqc-keystore-selftest-" + std::to_string(std::rand()));
        std::filesystem::create_directories(root);
        const std::filesystem::path path = root / "native-pqc-keystore.json";
        const std::string identity = "OMNIGUARD_SELFTEST_VEHICLE_001";

        omniguard::PqcKeyStore first(path, secret, identity);
        auto created = first.load_or_create();
        if (created.key_id.empty() || created.identity != identity) {
            throw std::runtime_error("new keystore identity was not established");
        }
        const std::string first_key_id = created.key_id;
        const auto first_sig_public = created.signature_public_key;
        const auto first_kem_public = created.kem_public_key;

        omniguard::PqcKeyStore second(path, secret, identity);
        auto loaded = second.load_or_create();
        if (loaded.key_id != first_key_id ||
            loaded.signature_public_key != first_sig_public ||
            loaded.kem_public_key != first_kem_public) {
            throw std::runtime_error("PQC identity changed across keystore reload");
        }

        const auto metadata = second.inspect();
        if (metadata.format != omniguard::PqcKeyStore::kFormat ||
            metadata.provider != "software_encrypted_file" ||
            metadata.key_id != first_key_id ||
            metadata.hardware_backed || metadata.non_exportable) {
            throw std::runtime_error("PQC keystore provider metadata is inconsistent");
        }

        const std::string original = read_all(path);
        json document = json::parse(original);
        std::string tag = document.at("private_key_envelope").at("tag_hex").get<std::string>();
        tag[0] = tag[0] == '0' ? '1' : '0';
        document["private_key_envelope"]["tag_hex"] = tag;
        write_all(path, document.dump(2));
        if (!throws([&]() {
                omniguard::PqcKeyStore tampered(path, secret, identity);
                (void)tampered.load_or_create();
            })) {
            throw std::runtime_error("tampered PQC keystore was accepted");
        }

        write_all(path, original);
        if (!throws([&]() {
                omniguard::PqcKeyStore wrong_key(
                    path,
                    "wrong-key-material-for-pqc-keystore-selftest-000000000000",
                    identity
                );
                (void)wrong_key.load_or_create();
            })) {
            throw std::runtime_error("PQC keystore opened with the wrong wrapping key");
        }

        write_all(path, "{");
        if (!throws([&]() {
                omniguard::PqcKeyStore truncated(path, secret, identity);
                (void)truncated.load_or_create();
            })) {
            throw std::runtime_error("truncated PQC keystore was silently regenerated");
        }

        write_all(path, original);
        auto recovered = second.load_or_create();
        if (recovered.key_id != first_key_id) {
            throw std::runtime_error("restored keystore did not recover the original identity");
        }

        std::filesystem::remove_all(root);
        std::cout
            << "[PQC-KEYSTORE-SELFTEST] PASS: persistent ML-DSA-44/ML-KEM-512 identity, "
               "AES-256-GCM private-key protection, tamper/wrong-key/truncation fail-closed\n";
        return 0;
    } catch (const std::exception& exception) {
        if (!root.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(root, ignored);
        }
        std::cerr << "[PQC-KEYSTORE-SELFTEST] FAIL: " << exception.what() << '\n';
        return 1;
    }
}
