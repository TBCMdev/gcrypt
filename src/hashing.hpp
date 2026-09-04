#pragma once
#include <sodium.h>

#include <protocol.hpp>
#include <array>

namespace gcrypt::hashing
{
    using sha256_digest = std::array<unsigned char, crypto_hash_sha256_BYTES>;
    using sha512_digest = std::array<unsigned char, crypto_hash_sha512_BYTES>;

    #if GCRYPT_HASH_SIZE == 256
        using dhash = sha256_digest;
    #elif GCRYPT_HASH_SIZE == 512
        using dhash = sha512_digest;
    #else
        #error Unsupported SHA hashing method.
    #endif

    /// @brief Computes SHA hash of contiguous data container (e.g., std::array, std::vector)
    template<typename Container>
    dhash SHA(const Container& data)
    {
        dhash digest{};
        #if GCRYPT_HASH_SIZE == 256
            crypto_hash_sha256(digest.data(), data.data(), data.size());
        #else
            crypto_hash_sha512(digest.data(), data.data(), data.size());
        #endif
        return digest;
    }

    /// @brief Implements XedDSA hash_i(M) = SHA-512( (2^256 - 1 - i) || M )
    /// @note XedDSA specification strictly requires SHA-512
    template<typename Container>
    sha512_digest hash255_i(uint8_t i, const Container& message)
    {
        // 1. Construct 32-byte prefix: (2^256 - 1 - i) in Little-Endian
        // 2^256 - 1 = 32 bytes of 0xFF
        std::array<unsigned char, 32> prefix;
        prefix.fill(0xFF);
        prefix[0] -= i; // Subtract i from LSB

        // 2. Stream prefix + message using Libsodium SHA-512 API
        sha512_digest digest{};
        crypto_hash_sha512_state state;

        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, prefix.data(), prefix.size());
        crypto_hash_sha512_update(&state, message.data(), message.size());
        crypto_hash_sha512_final(&state, digest.data());

        return digest;
    }
}