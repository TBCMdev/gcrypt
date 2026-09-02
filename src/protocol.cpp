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
}