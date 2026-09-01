#include "keygen.hpp"

#include <openssl/rand.h>


namespace gcrypt::keygen
{

    template<std::size_t _Size, std::convertible_to<uint8_t>... _Bytes>
    key<_Size> from_lebytes(_Bytes... bytes)
    {
        key<_Size> out{};

        std::size_t offset = 0;

        ((out[offset++] = static_cast<uint8_t>(bytes)), ...);

        return out;
    }

    template<int _Size>
    key<_Size> random()
    {
        key<_Size> out{};
        RAND_bytes(out.data(), _Size);
        return out;
    }
    

    namespace _impl::openssl
    {
        template
            <
             std::size_t _Bytes,
             template<std::size_t> class _PublicKeyType,
             template<std::size_t> class _PrivateKeyType
            >
        std::expected<keypair<_Bytes, _PublicKeyType, _PrivateKeyType>, KeyGenError> make_pair(KeyGenAlgorithm _alg)
        {
            EVP_PKEY* pkey;
            switch(_alg)
            {
                case KeyGenAlgorithm::X25519:
                    pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
                    break;
                case KeyGenAlgorithm::Ed25519:
                    pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "Ed25519");
                    break;
                default:
                    return std::unexpected(KeyGenError::UNKNOWN_ALGORITHM);
            }
            
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
    }

    std::expected
                <
                xckeypair,
                KeyGenError
                > X25519::make_pair()
    {
        return _impl::openssl::make_pair<GCRYPT_X25519_KEY_SIZE>(_impl::openssl::KeyGenAlgorithm::X25519);
    }
    std::expected
                <
                edkeypair,
                KeyGenError
                > Ed25519::make_pair()
    {
        return _impl::openssl::make_pair<GCRYPT_X25519_KEY_SIZE>(_impl::openssl::KeyGenAlgorithm::Ed25519);
    }
    std::expected
                <
                qkeypair,
                KeyGenError
                > MLKEM_32::make_pair()
    {

        qkeypair out{};

        if (mlkimpl_keypair(out.Public.data(), out.Private.data()) == 0)
            return std::unexpected(KeyGenError::LIBRARY_ERROR);
        
        return out;
    }
}