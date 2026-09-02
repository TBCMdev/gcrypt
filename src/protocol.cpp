#include "protocol.hpp"
#include "keygen.hpp"
#include "algorithms.hpp"
#include "util.hpp"
#include <sodium.h>

namespace gcrypt
{
    local_key_bundle make_lkb(uint32_t deviceId)
    {
        local_key_bundle out{};

        auto IdentityKeyResult   = keygen::Ed25519 ::make_pair();
        if (!IdentityKeyResult.has_value())   throw keygen::descriptive_error(IdentityKeyResult.error());
        auto SignedPreKeyResult  = keygen::X25519  ::make_id_pair();
        if (!SignedPreKeyResult.has_value())  throw keygen::descriptive_error(SignedPreKeyResult.error());
        auto QuantumPreKeyResult = keygen::MLKEM_32::make_id_pair();
        if (!QuantumPreKeyResult.has_value()) throw keygen::descriptive_error(QuantumPreKeyResult.error());

        std::unordered_map<uint32_t, xckeypair> OneTimePreKeys;
        OneTimePreKeys.reserve(GCRYPT_INITIAL_PREKEY_BUNDLE_COUNT);

        for(int i = 0; i < GCRYPT_INITIAL_PREKEY_BUNDLE_COUNT; i++)
        {
            auto KeyPairResult = keygen::X25519::make_pair();
            if (!KeyPairResult.has_value()) throw keygen::descriptive_error(KeyPairResult.error());

            auto val = KeyPairResult.value();

            OneTimePreKeys.insert({util::keyid(val.Public), val});
        }

        std::unordered_map<uint32_t, qkeypair> OneTimeQuantumKeys;
        OneTimeQuantumKeys.reserve(GCRYPT_INITIAL_PREKEY_BUNDLE_COUNT);

        for(int i = 0; i < GCRYPT_INITIAL_PREKEY_BUNDLE_COUNT; i++)
        {
            auto KeyPairResult = keygen::MLKEM_32::make_pair();
            if (!KeyPairResult.has_value()) throw keygen::descriptive_error(KeyPairResult.error());

            auto val = KeyPairResult.value();
            OneTimeQuantumKeys.insert({util::keyid(val.Public), val});
        }

        return local_key_bundle
        {
            .IdentityKey        = IdentityKeyResult.value(),
            .SignedPreKey       = SignedPreKeyResult.value(),
            .QuantumPreKey      = QuantumPreKeyResult.value(),
            .OneTimePreKeys     = std::move(OneTimePreKeys),
            .OneTimeQuantumKeys = std::move(OneTimeQuantumKeys)
        };
    }
    template<std::size_t _OneTimePreKeyCount>
    public_server_payload<_OneTimePreKeyCount> make_server_payload(uint32_t deviceId, const local_key_bundle& keys)
    {
        const key<64> Z_SPK   = keygen::random<64>();
        const key<64> Z_PQSPK = keygen::random<64>();
    
        uint32_t registration = randombytes_uniform(GCRYPT_MAX_REGISTRATION_VALUE) + 1;

        std::array<xcikey, _OneTimePreKeyCount> pOtpk;
        std::array<qsidkey, _OneTimePreKeyCount> pOtQpk;
        
        for (std::size_t i = 0; i < _OneTimePreKeyCount; i++)
        {
            const auto& okey = keys.OneTimePreKeys[i];
            pOtpk[i] = xcikey
            {
                .key        = okey.Public,
                .identifier = okey.identifier
            };

            const auto& qkey = keys.OneTimeQuantumKeys[i];
            const key<64> Z_N   = keygen::random<64>();

            pOtQpk[i] = qsidkey
            {
                .key        = qkey.Public,
                .identifier = qkey.identifier,
                .signature  = XedDSA::sign32(keys.IdentityKey.Private, qkey.Public, Z_N)
            };
        }

        return public_server_payload<_OneTimePreKeyCount>
        {
            .registration = registration,
            .deviceId     = deviceId,

            .identityKey    = keys.IdentityKey.Public,
            .signedPreKey   = xcsikey 
                            {
                                .key         = keys.SignedPreKey.Public,
                                .identifier  = keys.SignedPreKey.Public.identifier,
                                .signature   = XedDSA::sign32(keys.IdentityKey.Private, keys.SignedPreKey.Public, Z_SPK)
                            }
            .quantumPreKey  = qpubsidkey 
                            {
                                .key         = keys.SignedPreKey.Public,
                                .identifier  = keys.SignedPreKey.Public.identifier,
                                .signature   = XedDSA::sign32(keys.IdentityKey.Private, keys.QuantumPreKey.Public, Z_PQSPK)
                            }
            .oneTimePreKeys              = pOtpk
            .signedOneTimeQuantumPreKeys = pOtQpk
        };

    }
}