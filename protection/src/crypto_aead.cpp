#include "bytemorph/prot/crypto_aead.hpp"

#include "monocypher.h"

#include <cstring>

namespace bytemorph::prot {

AeadKey CryptoAead::derive_key_from_seed(std::uint64_t seed, std::string_view domain) {
    AeadKey key;
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, key.bytes.size());
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(&seed), sizeof(seed));
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(domain.data()), domain.size());
    crypto_blake2b_final(&ctx, key.bytes.data());
    crypto_wipe(&ctx, sizeof(ctx));
    return key;
}

AeadNonce CryptoAead::generate_nonce(std::uint64_t seed, std::uint64_t counter) {
    AeadNonce nonce;
    std::array<std::uint8_t, 32> digest{};
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, digest.size());
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(&seed), sizeof(seed));
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(&counter), sizeof(counter));
    const char tag[] = "ByteMorph-v0.4-Nonce";
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(tag), sizeof(tag) - 1);
    crypto_blake2b_final(&ctx, digest.data());
    std::memcpy(nonce.bytes.data(), digest.data(), nonce.bytes.size());
    crypto_wipe(digest.data(), digest.size());
    crypto_wipe(&ctx, sizeof(ctx));
    return nonce;
}

std::array<std::uint8_t, 32> CryptoAead::blake2b_256(std::span<const std::uint8_t> data) {
    std::array<std::uint8_t, 32> out{};
    crypto_blake2b(out.data(), out.size(), data.data(), data.size());
    return out;
}

core::diagnostics::Result<AeadSealedBox>
CryptoAead::seal(std::span<const std::uint8_t> plaintext,
                 std::span<const std::uint8_t> associated_data,
                 const AeadKey& key,
                 const AeadNonce& nonce) {
    AeadSealedBox box;
    box.nonce = nonce;
    box.ciphertext.resize(plaintext.size());

    crypto_aead_lock(
        box.ciphertext.data(),
        box.mac.data(),
        key.bytes.data(),
        nonce.bytes.data(),
        associated_data.data(),
        associated_data.size(),
        plaintext.data(),
        plaintext.size());

    return box;
}

core::diagnostics::Result<std::vector<std::uint8_t>>
CryptoAead::open(const AeadSealedBox& box,
                 std::span<const std::uint8_t> associated_data,
                 const AeadKey& key) {
    std::vector<std::uint8_t> plaintext(box.ciphertext.size());
    const int rc = crypto_aead_unlock(
        plaintext.data(),
        box.mac.data(),
        key.bytes.data(),
        box.nonce.bytes.data(),
        associated_data.data(),
        associated_data.size(),
        box.ciphertext.data(),
        box.ciphertext.size());

    if (rc != 0) {
        crypto_wipe(plaintext.data(), plaintext.size());
        return core::diagnostics::Result<std::vector<std::uint8_t>>::err(
            core::diagnostics::ErrorCode::ParseError,
            "AEAD authentication tag verification failed (tampered or wrong key)",
            "CryptoAead::open");
    }
    return plaintext;
}

void CryptoAead::secure_wipe(std::span<std::uint8_t> buffer) noexcept {
    if (!buffer.empty()) {
        crypto_wipe(buffer.data(), buffer.size());
    }
}

} // namespace bytemorph::prot
