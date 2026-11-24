#pragma once

#include "bytemorph/core/diagnostics/error.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace bytemorph::prot {

struct AeadKey {
    std::array<std::uint8_t, 32> bytes{};
};

struct AeadNonce {
    std::array<std::uint8_t, 24> bytes{}; // XChaCha20-Poly1305 192-bit nonce
};

struct AeadSealedBox {
    AeadNonce nonce;
    std::array<std::uint8_t, 16> mac{};
    std::vector<std::uint8_t> ciphertext;
};

/// Authenticated encryption (XChaCha20-Poly1305) and cryptographic hashing (BLAKE2b-256)
/// backed by Monocypher 4.0.2.
class CryptoAead {
public:
    [[nodiscard]] static AeadKey derive_key_from_seed(std::uint64_t seed, std::string_view domain);
    [[nodiscard]] static AeadNonce generate_nonce(std::uint64_t seed, std::uint64_t counter);
    [[nodiscard]] static std::array<std::uint8_t, 32> blake2b_256(std::span<const std::uint8_t> data);

    [[nodiscard]] static core::diagnostics::Result<AeadSealedBox>
    seal(std::span<const std::uint8_t> plaintext,
         std::span<const std::uint8_t> associated_data,
         const AeadKey& key,
         const AeadNonce& nonce);

    [[nodiscard]] static core::diagnostics::Result<std::vector<std::uint8_t>>
    open(const AeadSealedBox& box,
         std::span<const std::uint8_t> associated_data,
         const AeadKey& key);

    static void secure_wipe(std::span<std::uint8_t> buffer) noexcept;
};

} // namespace bytemorph::prot
