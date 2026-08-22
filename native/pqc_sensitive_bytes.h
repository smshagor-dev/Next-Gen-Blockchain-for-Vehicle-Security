#pragma once

#include <cstddef>
#include <utility>
#include <vector>

namespace omniguard {

inline void secure_zero_bytes(unsigned char* data, std::size_t size) noexcept {
    volatile unsigned char* cursor = data;
    while (cursor != nullptr && size-- > 0) {
        *cursor++ = 0;
    }
}

class PqcSensitiveBytes {
public:
    PqcSensitiveBytes() = default;

    explicit PqcSensitiveBytes(std::vector<unsigned char> bytes) : bytes_(std::move(bytes)) {}

    PqcSensitiveBytes(const PqcSensitiveBytes&) = delete;
    PqcSensitiveBytes& operator=(const PqcSensitiveBytes&) = delete;

    PqcSensitiveBytes(PqcSensitiveBytes&& other) noexcept : bytes_(std::move(other.bytes_)) {}

    PqcSensitiveBytes& operator=(PqcSensitiveBytes&& other) noexcept {
        if (this != &other) {
            clear();
            bytes_ = std::move(other.bytes_);
        }
        return *this;
    }

    ~PqcSensitiveBytes() {
        clear();
    }

    const unsigned char* data() const noexcept { return bytes_.data(); }
    unsigned char* data() noexcept { return bytes_.data(); }
    std::size_t size() const noexcept { return bytes_.size(); }
    bool empty() const noexcept { return bytes_.empty(); }

    void clear() noexcept {
        if (!bytes_.empty()) {
            secure_zero_bytes(bytes_.data(), bytes_.size());
            bytes_.clear();
        }
    }

private:
    std::vector<unsigned char> bytes_;
};

}  // namespace omniguard
