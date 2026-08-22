#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace omniguard {

struct PqcRollbackAnchorMetadata {
    std::string format;
    std::string identity;
    std::uint64_t sequence = 0;
    std::uint64_t active_generation = 0;
    std::string active_key_id;
    std::string trust_head_hash;
    std::string anchor_hash;
    bool externally_protected = false;
    bool hardware_monotonic = false;
};

class PqcRollbackAnchor {
public:
    static constexpr const char* kFormat = "OMNIGUARD_PQC_ROLLBACK_ANCHOR_V1";
    static constexpr const char* kDomain = "OMNIGUARD_PQC_ROLLBACK_ANCHOR_HMAC_V1";

    PqcRollbackAnchor(
        std::filesystem::path path,
        std::string secret,
        std::string identity
    );

    void initialize(
        std::uint64_t generation,
        const std::string& active_key_id,
        const std::string& trust_head_hash
    ) const;

    void advance(
        std::uint64_t generation,
        const std::string& active_key_id,
        const std::string& trust_head_hash
    ) const;

    PqcRollbackAnchorMetadata inspect() const;

    void verify_exact(
        std::uint64_t generation,
        const std::string& active_key_id,
        const std::string& trust_head_hash
    ) const;

private:
    std::filesystem::path path_;
    std::string secret_;
    std::string identity_;
};

}  // namespace omniguard
