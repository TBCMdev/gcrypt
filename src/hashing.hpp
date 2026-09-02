#pragma once
#include <openssl/sha.h>

#include <protocol.hpp>
#include <array>

#if GCRYPT_HASH_SIZE == 256
#define GCRYPT_HASH SHA256
#elif GCRYPT_HASH_SIZE == 512
#define GCRYPT_HASH SHA512
#else
#define GCRYPT_HASH SHA
#endif
namespace gcrypt::hashing
{
    typedef struct hash_t
    {
        unsigned char* Hash;
        std::array<unsigned char, SHA512_DIGEST_LENGTH> Digest;
    } dhash;
    
    /// @brief Computes the SHA of the given data. the sha mode (size: 256/512) is controlled by protocol.GCRYPT_HASH_SIZE
    /// @tparam _Size the size of the data array to be hashed
    /// @param data the data array
    /// @return a hash object with digest
    template<std::size_t _Size>
    dhash SHA(const std::array<unsigned char, _Size> data)
    {
        dhash h{};
        h.Hash = GCRYPT_HASH(data.data(), _Size, h.Digest.data());
        return h;
    }

    /// @brief hash_i for implementation of the XedDSA/VXEdDSA algorithms, with b = 255.
    template<std::size_t _MSize>
    dhash hash255_i(unsigned char i, const std::array<unsigned char, _MSize> message)
    {
        std::array<unsigned char, GCRYPT_X25519_KEY_SIZE + _MSize> buffer{};

        std::fill_n(buffer.data(), GCRYPT_X25519_KEY_SIZE, 0xFF);
        buffer[GCRYPT_X25519_KEY_SIZE - 1] = 0x7F; // MSB = MAX - 1
        buffer[0] -= i; // LSB -= i

        return SHA(buffer);
    }
}