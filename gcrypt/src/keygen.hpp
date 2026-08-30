#pragma once
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <expected>

#include "protocol.hpp"

namespace gcrypt::keygen
{


    enum class KeyGenError
    {
        LIBRARY_ERROR,
        UNKNOWN
    };

    namespace X25519
    {
        using key = gcrypt::key<GCRYPT_X25519_KEY_SIZE>;
        std::expected<
            keypair<GCRYPT_X25519_KEY_SIZE>,
            KeyGenError
                     > make_pair();
    }
}