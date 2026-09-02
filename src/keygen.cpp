#include "protocol.hpp"
#include "keygen.hpp"
#include "util.hpp"
#include "algorithms.hpp"

#include <openssl/rand.h>
#include <stdexcept>

namespace gcrypt::keygen
{
    refill_payload refill(const xckey& privIdentityKey, uint32_t Count)
    {
        refill_payload payload{};

        payload.oneTimePreKeys.reserve(Count);
        payload.signedOneTimeQuantumPreKeys.reserve(Count);

        for (std::size_t i = 0; i < Count; i++)
        {
            auto x_res = keygen::X25519::make_pair();
            if (!x_res.has_value()) 
                throw keygen::descriptive_error(x_res.error());

            xckeypair x_pair = x_res.value();
            uint32_t  x_id   = util::keyid(x_pair.Public);

            payload.oneTimePreKeys.push_back(xcikey
            {
                .key        = x_pair.Public,
                .identifier = x_id
            });

            auto q_res = keygen::MLKEM_32::make_pair();
            if (!q_res.has_value()) 
                throw keygen::descriptive_error(q_res.error());

            qkeypair q_pair = q_res.value();
            uint32_t q_id   = util::keyid(q_pair.Public);

            const key<64> Z_N = keygen::random<64>();

            qsidkey _qsidkey{};
            _qsidkey.key        = q_pair.Public;
            _qsidkey.identifier = q_id;
            _qsidkey.signature  = XedDSA::sign32(privIdentityKey, q_pair.Public, Z_N);

            payload.signedOneTimeQuantumPreKeys.push_back(_qsidkey);
        }

        return payload;
    }

    namespace _impl::openssl
    {
        EVP_PKEY* _invoke_alg(KeyGenAlgorithm _alg)
        {
            switch(_alg)
            {
                case KeyGenAlgorithm::X25519:
                    return EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
                case KeyGenAlgorithm::Ed25519:
                    return EVP_PKEY_Q_keygen(nullptr, nullptr, "Ed25519");
                default:
                    return nullptr;
            }
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
                xcikeypair,
                KeyGenError
                > X25519::make_id_pair()
    {
        return _impl::openssl::make_id_pair<GCRYPT_X25519_KEY_SIZE>(_impl::openssl::KeyGenAlgorithm::X25519);
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
                edikeypair,
                KeyGenError
                > Ed25519::make_id_pair()
    {
        return _impl::openssl::make_id_pair<GCRYPT_X25519_KEY_SIZE>(_impl::openssl::KeyGenAlgorithm::Ed25519);
    }
    std::expected
                <
                qkeypair,
                KeyGenError
                > MLKEM_32::make_pair()
    {

        qkeypair out{};

        if (mlkimpl_keypair(out.Public.data(), out.Private.data()) != 0)
            return std::unexpected(KeyGenError::LIBRARY_ERROR);
        
        return out;
    }
    std::expected
                <
                qikeypair,
                KeyGenError
                > MLKEM_32::make_id_pair()
    {
        qikeypair out{};

        if (mlkimpl_keypair(out.Public.key.data(), out.Private.data()) != 0)
            return std::unexpected(KeyGenError::LIBRARY_ERROR);
        return out;
    }
}