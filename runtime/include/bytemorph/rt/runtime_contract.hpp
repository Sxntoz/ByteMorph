#pragma once

#include <cstdint>
#include <string_view>

namespace bytemorph::rt {

/// Future contract (v0.3+) for embedded runtime integrity verification
/// (cryptographic section/image hashing without disabling OS security features).
struct IntegrityManifest {
    std::uint32_t algorithm_id{0}; // e.g., SHA-256 / BLAKE3
    std::uint64_t covered_va_start{0};
    std::uint64_t covered_size{0};
    std::uint8_t digest[32]{};
};

/// Future contract (v0.4+) for GUI/CLI telemetry events.
class IProtectionObserver {
public:
    virtual ~IProtectionObserver() = default;
    virtual void on_stage_started(std::string_view stage) = 0;
    virtual void on_stage_completed(std::string_view stage) = 0;
};

} // namespace bytemorph::rt
