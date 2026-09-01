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
    key<_Size> from_lebytes(_Bytes... bytes);

    /// @brief Generates a cryptographically secure random key of _Size bytes.
    template<std::size_t _Size>
    key<_Size> random();
    
    namespace _impl::openssl
    {
        enum class KeyGenAlgorithm
        {
            X25519,
            Ed25519
        };
        /// @brief Calls the openssl implementation for generating a cryptographically secure key.
        /// @tparam _Bytes The byte size of the keypair's keys
        /// @tparam _PublicKeyType the type of the public key
        /// @tparam _PrivateKeyType the type of the privat key
        /// @param _alg The algorithm to use
        /// @return 
        template
            <
             std::size_t _Bytes,
             template<std::size_t> class _PublicKeyType = key,
             template<std::size_t> class _PrivateKeyType = _PublicKeyType
            >
        std::expected<keypair<_Bytes, _PublicKeyType, _PrivateKeyType>, KeyGenError> make_pair(KeyGenAlgorithm _alg);
    }

    namespace X25519
    {
        std::expected<
            xckeypair,
            KeyGenError
                     > make_pair();
    }
    namespace Ed25519
    {
        std::expected<edkeypair,KeyGenError> make_pair();
    }
    namespace MLKEM_32
    {
        std::expected<qkeypair, KeyGenError> make_pair();
    }
    
}