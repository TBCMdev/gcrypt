#include "protocol.hpp"
#include "keygen.hpp"
#include "util.hpp"
#include "algorithms.hpp"

#include <stdexcept>

namespace gcrypt::keygen
{
    std::expected
                <
                xckeypair,
                KeyGenError
                > X25519::make_pair()
    {
        xckeypair out{};
        crypto_box_keypair(out.Public.data(), out.Private.data());

        return out;
    }
    std::expected
                <
                xcikeypair,
                KeyGenError
                > X25519::make_id_pair()
    {
        xcikeypair out{};
        crypto_box_keypair(out.Public.key.data(), out.Private.data());
        out.Public.identifier = util::keyid(out.Public.key);
        return out;
    }
    std::expected
                <
                edkeypair,
                KeyGenError
                > Ed25519::make_pair()
    {
        edkeypair out{};
        crypto_box_keypair(out.Public.data(), out.Private.data());

        return out;
    }
    std::expected
                <
                edikeypair,
                KeyGenError
                > Ed25519::make_id_pair()
    {
        edikeypair out{};
        crypto_box_keypair(out.Public.key.data(), out.Private.data());
        out.Public.identifier = util::keyid(out.Public.key);

        return out;
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