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

AeadKey CryptoAead::derive_block_key(const AeadKey& master_key,
                                     std::uint32_t fn_index,
                                     std::uint32_t block_id,
                                     std::string_view domain) {
    AeadKey subkey;
    crypto_blake2b_ctx ctx;
    crypto_blake2b_keyed_init(&ctx, subkey.bytes.size(), master_key.bytes.data(), master_key.bytes.size());
    const char kdf_tag[] = "BM_BLK_KDF_v1";
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(kdf_tag), sizeof(kdf_tag) - 1);
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(domain.data()), domain.size());
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(&fn_index), sizeof(fn_index));
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(&block_id), sizeof(block_id));
    crypto_blake2b_final(&ctx, subkey.bytes.data());
    crypto_wipe(&ctx, sizeof(ctx));
    return subkey;
}

AeadNonce CryptoAead::generate_block_nonce(std::uint64_t seed,
                                           std::uint32_t fn_index,
                                           std::uint32_t block_id) {
    AeadNonce nonce;
    std::array<std::uint8_t, 32> digest{};
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, digest.size());
    const char tag[] = "BM_BLK_NONCE_v1";
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(tag), sizeof(tag) - 1);
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(&seed), sizeof(seed));
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(&fn_index), sizeof(fn_index));
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(&block_id), sizeof(block_id));
    crypto_blake2b_final(&ctx, digest.data());
    std::memcpy(nonce.bytes.data(), digest.data(), nonce.bytes.size());
    crypto_wipe(digest.data(), digest.size());
    crypto_wipe(&ctx, sizeof(ctx));
    return nonce;
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

core::diagnostics::Result<void>
CryptoAead::open_into(std::span<const std::uint8_t> ciphertext,
                      const AeadNonce& nonce,
                      const std::array<std::uint8_t, 16>& mac,
                      std::span<const std::uint8_t> associated_data,
                      const AeadKey& key,
                      std::span<std::uint8_t> out_plaintext) {
    if (out_plaintext.size() < ciphertext.size()) {
        return core::diagnostics::Result<void>::err(
            core::diagnostics::ErrorCode::OutOfBounds,
            "Output plaintext buffer smaller than ciphertext",
            "CryptoAead::open_into");
    }
    const int rc = crypto_aead_unlock(
        out_plaintext.data(),
        mac.data(),
        key.bytes.data(),
        nonce.bytes.data(),
        associated_data.data(),
        associated_data.size(),
        ciphertext.data(),
        ciphertext.size());

    if (rc != 0) {
        if (!ciphertext.empty()) {
            crypto_wipe(out_plaintext.data(), ciphertext.size());
        }
        return core::diagnostics::Result<void>::err(
            core::diagnostics::ErrorCode::ParseError,
            "AEAD authentication tag verification failed (tampered or wrong key)",
            "CryptoAead::open_into");
    }
    return core::diagnostics::Result<void>::ok();
}

core::diagnostics::Result<std::vector<std::uint8_t>>
CryptoAead::open(const AeadSealedBox& box,
                 std::span<const std::uint8_t> associated_data,
                 const AeadKey& key) {
    std::vector<std::uint8_t> plaintext(box.ciphertext.size());
    auto res = open_into(box.ciphertext, box.nonce, box.mac, associated_data, key, plaintext);
    if (!res) {
        return core::diagnostics::Result<std::vector<std::uint8_t>>::err(
            res.error().code, res.error().message, "CryptoAead::open");
    }
    return plaintext;
}

void CryptoAead::secure_wipe(std::span<std::uint8_t> buffer) noexcept {
    if (!buffer.empty()) {
        crypto_wipe(buffer.data(), buffer.size());
    }
}

} // namespace bytemorph::prot
