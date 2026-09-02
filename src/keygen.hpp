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
        UNKNOWN_ALGORITHM,
        UNKNOWN
    };

    constexpr const char* descriptive_error(const KeyGenError err)
    {
        switch(err)
        {
            case KeyGenError::LIBRARY_ERROR:
                return "Key Generation failed due to a library error.";
            case KeyGenError::UNKNOWN_ALGORITHM:
                return "Key Generation failed due to lack of an algorithm implementation.";
            default:
                return "Key Generation failed with an unknown error.";    
        }
    }

    /// @brief Creates a key, setting a number of bytes starting with the first byte in little endian form.
    /// @tparam _Size The size of the key to create
    /// @tparam ..._Bytes the bytes to set
    template<std::size_t _Size, std::convertible_to<uint8_t>... _Bytes>
    key<_Size> from_lebytes(_Bytes... bytes)
    {
        key<_Size> out{};

        std::size_t offset = 0;

        ((out[offset++] = static_cast<uint8_t>(bytes)), ...);

        return out;
    }

    /// @brief Generates a cryptographically secure random key of _Size bytes.
    template<std::size_t _Size>
    key<_Size> random()
    {
        key<_Size> out{};
        if (RAND_bytes(out.data(), _Size) != 1)
            throw std::runtime_error("OpenSSL RAND_bytes failed");
        return out;
    }
    
    /// @brief Generates keyCount keypair refills to use to replenish one time prekeys.
    /// @param privIdentityKey The private identity key of the user
    /// @param Count the amount of keys to generate
    /// @return The list of generated keys, both for private and public use.
    refill_payload refill(const xckey& privIdentityKey, uint32_t Count);

    namespace _impl::openssl
    {
        enum class KeyGenAlgorithm
        {
            X25519,
            Ed25519
        };
        /// @brief Invokes the given algorithm. Note: Remember to call ENV_FREE on the associated object.
        /// @return The generated key object
        EVP_PKEY* _invoke_alg(KeyGenAlgorithm _alg);

        /// @brief Calls the openssl implementation for generating a cryptographically secure key.
        /// @tparam _Bytes The byte size of the keypair's keys
        /// @tparam _PublicKeyType the type of the public key
        /// @tparam _PrivateKeyType the type of the privat key
        /// @param _alg The algorithm to use
        /// @return 
        template
            <
             std::size_t _Bytes,
             template<std::size_t> typename _PublicKeyType = key,
             template<std::size_t> typename _PrivateKeyType = _PublicKeyType
            >
        std::expected<keypair<_Bytes, _PublicKeyType, _PrivateKeyType>, KeyGenError> make_pair(KeyGenAlgorithm _alg)
        {
            EVP_PKEY* pkey = _invoke_alg(_alg);
            
            if (!pkey)
                return std::unexpected(KeyGenError::LIBRARY_ERROR);

            keypair<_Bytes, _PublicKeyType, _PrivateKeyType> kp{};
        
            size_t klenpub  = _Bytes;
            size_t klenpriv = _Bytes;

            if (EVP_PKEY_get_raw_public_key(pkey, kp.Public.data(), &klenpub) != 1 || klenpub != _Bytes)
            {
                EVP_PKEY_free(pkey);
                return std::unexpected(KeyGenError::LIBRARY_ERROR);
            }

            if (EVP_PKEY_get_raw_private_key(pkey, kp.Private.data(), &klenpriv) != 1 || klenpriv != _Bytes)
            {
                EVP_PKEY_free(pkey);
                return std::unexpected(KeyGenError::LIBRARY_ERROR);
            }

            EVP_PKEY_free(pkey);
            return kp;
        }
        /// @brief Calls the openssl implementation for generating a cryptographically secure key with a uint identifier for both keys, contained in the public key structure.
        /// @tparam _Bytes The byte size of the keypair's keys
        /// @tparam _PublicKeyType the type of the public key
        /// @tparam _PrivateKeyType the type of the privat key
        /// @param _alg The algorithm to use
        /// @return 
        template
            <
             std::size_t _Bytes,
             template<std::size_t> typename _PrivateKeyType = key
            >
        std::expected<keypair<_Bytes, idkey, _PrivateKeyType>, KeyGenError> make_id_pair(KeyGenAlgorithm _alg)
        {
            EVP_PKEY* pkey = _invoke_alg(_alg);
            
            if (!pkey)
                return std::unexpected(KeyGenError::LIBRARY_ERROR);

            keypair<_Bytes, idkey, _PrivateKeyType> kp{};
        
            size_t klenpub  = _Bytes;
            size_t klenpriv = _Bytes;

            if (EVP_PKEY_get_raw_public_key(pkey, kp.Public.key.data(), &klenpub) != 1 || klenpub != _Bytes)
            {
                EVP_PKEY_free(pkey);
                return std::unexpected(KeyGenError::LIBRARY_ERROR);
            }

            if (EVP_PKEY_get_raw_private_key(pkey, kp.Private.data(), &klenpriv) != 1 || klenpriv != _Bytes)
            {
                EVP_PKEY_free(pkey);
                return std::unexpected(KeyGenError::LIBRARY_ERROR);
            }

            kp.Public.identifier = util::keyid(kp.Public.key);

            EVP_PKEY_free(pkey);
            return kp;
        }
    }

    namespace X25519
    {
        std::expected<xckeypair,KeyGenError> make_pair();
        std::expected<xcikeypair,KeyGenError> make_id_pair();
    }
    namespace Ed25519
    {
        std::expected<edkeypair,KeyGenError> make_pair();
        std::expected<edikeypair,KeyGenError> make_id_pair();
    }
    namespace MLKEM_32
    {
        std::expected<qkeypair, KeyGenError> make_pair();
        std::expected<qikeypair, KeyGenError> make_id_pair();
    }
    
}