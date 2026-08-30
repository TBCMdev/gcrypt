#include "keygen.hpp"

namespace gcrypt::keygen
{
    std::expected
                <
                keypair<GCRYPT_X25519_KEY_SIZE>,
                KeyGenError
                > X25519::make_pair()
    {
        EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
        if (!pkey)
            return std::unexpected(KeyGenError::LIBRARY_ERROR);
        
        keypair<GCRYPT_X25519_KEY_SIZE> kp{};
        
        size_t klenpub  = GCRYPT_X25519_KEY_SIZE;
        size_t klenpriv = GCRYPT_X25519_KEY_SIZE;

        if (EVP_PKEY_get_raw_public_key(pkey, kp.Public.data(), &klenpub) != 1 || klenpub != GCRYPT_X25519_KEY_SIZE)
        {
            EVP_PKEY_free(pkey);
            return std::unexpected(KeyGenError::LIBRARY_ERROR);
        }

        if (EVP_PKEY_get_raw_private_key(pkey, kp.Private.data(), &klenpriv) != 1 || klenpriv != GCRYPT_X25519_KEY_SIZE)
        {
            EVP_PKEY_free(pkey);
            return std::unexpected(KeyGenError::LIBRARY_ERROR);
        }

        EVP_PKEY_free(pkey);
        return kp;
    }
}