#pragma once
#include <string>
#include <cstdint>
#include <array>
#include <vector>


#define GCRYPT_VERSION_STRING "0.0.1"
#define GCRYPT_X25519_KEY_SIZE crypto_core_ed25519_BYTES
#define GCRYPT_HASH_SIZE 512
#define GCRYPT_SIGNATURE_SIZE 64
#define GCRYPT_INFO "gecko-protocol-" GCRYPT_VERSION_STRING

namespace gcrypt
{

    template<std::size_t _Bytes>
    using key = std::array<uint8_t, _Bytes>;

    template<std::size_t _Bytes>
    struct keypair
    {
        key<_Bytes> Public;
        key<_Bytes> Private;
    };

    // Unique key pair
    template<std::size_t _BytesPublic, std::size_t _BytesPrivate>
    struct ukeypair
    {
        key<_BytesPublic>  Public;
        key<_BytesPrivate> Private;
    };


    typedef struct prebundle_t
    {
        uint32_t registration;

    } prebundle;

    /// @brief One time prekey
    struct otprekey
    {
        uint32_t id;
        key<GCRYPT_X25519_KEY_SIZE> Public;
    };

    /// @brief A payload sent to the server to register a devices keys.
    /// @tparam _OneTimePreKeyCount the amount of one time pre keys you want to give to the server.
    template<std::size_t _OneTimePreKeyCount>
    struct server_payload
    {
        using payload_key = key<GCRYPT_X25519_KEY_SIZE>;
        uint32_t registration;
        payload_key identityKey;
        payload_key signedPreKey;
        key<GCRYPT_SIGNATURE_SIZE> preKeySignature;

        std::array<payload_key, _OneTimePreKeyCount> oneTimePreKeys;
    };

    struct local_bundle
    {

        keypair<GCRYPT_X25519_KEY_SIZE>          Identity;
        keypair<GCRYPT_X25519_KEY_SIZE>          SignedPreKey;
        std::vector<key<GCRYPT_X25519_KEY_SIZE>> OneTimePreKeys;
    };

}