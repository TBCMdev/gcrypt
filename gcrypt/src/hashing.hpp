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
        std::array<unsigned char, SHA_DIGEST_LENGTH> Digest;
    } dhash;
    
    /// @brief Computes the SHA of the given data. the sha mode (size: 256/512) is controlled by protocol.GCRYPT_HASH_SIZE
    /// @tparam _Size the size of the data array to be hashed
    /// @param data the data array
    /// @return a hash object with digest
    template<std::size_t _Size>
    dhash SHA(const std::array<unsigned char, _Size> data);
}