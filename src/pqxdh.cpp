#include "pqxdh.hpp"

#include "util.hpp"
#include "keygen.hpp"
namespace gcrypt::pqxdh
{
    local_key_bundle make_lkb(uint32_t deviceId)
    {
        GCRYPT_ASSERT_STORE();
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

    #ifndef GCRYPT_NOSTORE
        // Public || Private
        auto bytes = util::key_bytes(IdentityKeyResult->Public, IdentityKeyResult->Private);
        if (!GCRYPT_ISTORE->store_identity_key_pair(bytes))
            throw std::runtime_error("Gcrypt::store_identity_key_pair failed.");

    #endif

        return local_key_bundle
        {
            .IdentityKey        = IdentityKeyResult.value(),
            .SignedPreKey       = SignedPreKeyResult.value(),
            .QuantumPreKey      = QuantumPreKeyResult.value(),
            .OneTimePreKeys     = std::move(OneTimePreKeys),
            .OneTimeQuantumKeys = std::move(OneTimeQuantumKeys)
        };
    }
    refill_payload refill(const xckey& privIdentityKey, uint32_t Count)
    {
        GCRYPT_ASSERT_STORE();
        
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

        #ifndef GCRYPT_NOSTORE
            {
                auto bytes = util::key_bytes(x_pair.Public, x_pair.Private);
                if (!GCRYPT_ISTORE->store_one_time_prekey(x_id, store::key_type::PREKEY, bytes))
                    throw std::runtime_error("Gcrypt::store_one_time_prekey failed.");
            }
        #endif

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
        #ifndef GCRYPT_NOSTORE
            {
                auto bytes = util::key_bytes(q_pair.Public, q_pair.Private);
                if (!GCRYPT_ISTORE->store_one_time_prekey(q_id, store::key_type::QUANTUM, bytes))
                    throw std::runtime_error("Gcrypt::store_one_time_prekey failed.");
            }
        #endif
            const key<64> Z_N = keygen::random<64>();

            qsidkey _qsidkey{};
            _qsidkey.key        = q_pair.Public;
            _qsidkey.identifier = q_id;
            _qsidkey.signature  = XedDSA::sign32(privIdentityKey, q_pair.Public, Z_N);

            payload.signedOneTimeQuantumPreKeys.push_back(_qsidkey);
        }

        return payload;
    }
    bool verify_foreign_bundle(const xckey& userIdentityKey, const foreign_prekey_bundle& bundle)
    {
        if (!util::kmatch(userIdentityKey, bundle.identityKey))
            return false;

        if (!XedDSA::verify32(userIdentityKey, bundle.signedPreKey.key, bundle.signedPreKey.signature))
            return false;

        // only check signature if it is qsidkey
        if (const auto* signedQKey = std::get_if<qsidkey>(&bundle.qpubsidkey))
            if (!XedDSA::verify32(userIdentityKey, signedQKey->key, signedQKey->signature))
                return false;
                
        return true;
    }
    std::optional<session_init_result> create_outbound_session(
                                            const xckeypair& localIdentityKey,
                                            const xckey& identityToVerifyAgainst,
                                            const foreign_prekey_bundle& keys
                                                              )
    {
        if (!verify_foreign_bundle(identityToVerifyAgainst, keys))
            return std::nullopt;

        const auto _EK = keygen::X25519::make_pair();

        if (!_EK.has_value())
            return std::nullopt;

        const auto EK = _EK.value();

        const MLKEM_32::kem_keypair PQPK = MLKEM_32::encapsulate(
            keys.qpubsidkey.index() == 0 ?
                std::get<0>(keys.qpubsidkey).key :
                std::get<1>(keys.qpubsidkey).key
            );
        
        const xckey DH_1 = X25519::ssecret(localIdentityKey.Private, keys.signedPreKey.key),
                    DH_2 = X25519::ssecret(EK.Private, keys.identityKey),
                    DH_3 = X25519::ssecret(EK.Private, keys.signedPreKey.key);
        key<32> SK;
        try{
            // use pre key in signing
            if (keys.oneTimePreKey.has_value())
            {
                const xckey DH_4 = X25519::ssecret(EK.Private, keys.oneTimePreKey->key);
                auto input = util::kconcat(DH_1, DH_2, DH_3, DH_4, PQPK.sharedSecret);
                SK = HKDF::KDF<32>(input);
            }
            else
            {
                auto input = util::kconcat(DH_1, DH_2, DH_3, PQPK.sharedSecret);

                SK = HKDF::KDF<32>(input);
            }
        }catch(const std::runtime_error& HKDF_extract_error)
        { return std::nullopt; }

        // continue execution
        // @note: Could be a risk to call this function ? could be called and returned a valid session regardless of bundle verification.
        return _internal::finalize_outbound_session(
                                                localIdentityKey.Public,
                                                EK.Public,
                                                PQPK.cipherText,
                                                SK, keys);
    }

    std::optional<store::messaging_session> create_inbound_session(
                        const xckeypair&                     localIdentityKey,
                        const xckey&                         usedPrivateSignedPreKey,
                        const std::optional<xckey>&          usedPrivateOneTimePreKey,
                        const key<MLKEM_SKB>&                usedPrivateQuantumPreKey,
                        const initial_message_handshake&     handshake
                        )
    {
        const xckey PQSS = MLKEM_32::decapsulate(handshake.cipherText, usedPrivateQuantumPreKey);

        const xckey DH_1 = X25519::ssecret(usedPrivateSignedPreKey, handshake.identityKey);
        const xckey DH_2 = X25519::ssecret(localIdentityKey.Private, handshake.ephermoralKey);
        const xckey DH_3 = X25519::ssecret(usedPrivateSignedPreKey, handshake.ephermoralKey);

        key<32> extract;
        try{
            if (usedPrivateOneTimePreKey.has_value())
            {
                const xckey DH_4 = X25519::ssecret(usedPrivateOneTimePreKey.value(), handshake.ephermoralKey);
                auto input = util::kconcat(DH_1, DH_2, DH_3, DH_4, PQSS);
                extract = HKDF::KDF<32>(input);
            }
            else
            {
                auto input = util::kconcat(DH_1, DH_2, DH_3, PQSS);
                extract = HKDF::KDF<32>(input);
            }
        }catch(const std::runtime_error& HKDF_extract_error)
        { return std::nullopt; }

        // 4. Initialize Bob's Double Ratchet session
        store::messaging_session session{};
        session.remoteIdentityKey = handshake.identityKey;
        session.remoteRatchetKey  = handshake.ephermoralKey; // Initial receiving ratchet key
        session.rootKey           = extract;                 // Derived Master Root Key

        return session;
    }
    std::optional<store::messaging_session> create_inbound_session(const initial_message_handshake& handshake)
    {
        GCRYPT_ASSERT_STORE();
    #ifndef GCRYPT_NOSTORE

        if (handshake.usedPreKeys.size() < 1)
            return std::nullopt;

        xckeypair                     localIdentityKey;
        if (
            auto pik = GCRYPT_ISTORE->load_identity_key_pair();
            !pik.has_value()                                                ||
            util::load_keyb_s(*pik, localIdentityKey.Public)                  ||
            util::load_keyb_s(*pik, localIdentityKey.Private, sizeof(xckey))
            )
            return std::nullopt;
        
        xckey                         usedPrivateSignedPreKey;
        if (
            auto spk = GCRYPT_ISTORE->load_one_time_prekey(handshake.usedPreKeys[0], store::key_type::PREKEY);
            !spk.has_value()                                                ||
            util::load_keyb_s(*spk, usedPrivateSignedPreKey, sizeof(xckey))
            )
            return std::nullopt;

        bool has_usedPrivateOneTimePreKey = handshake.usedPreKeys.size() > 1;
        xckey                         usedPrivateOneTimePreKey;

        if (has_usedPrivateOneTimePreKey)
        {
            if (
                auto opk = GCRYPT_ISTORE->load_one_time_prekey(handshake.usedPreKeys[1], store::key_type::PREKEY);
                !opk.has_value()                                                ||
                util::load_keyb_s(*opk, usedPrivateOneTimePreKey, sizeof(xckey))
                )
                return std::nullopt;
        }
        key<MLKEM_SKB>                usedPrivateQuantumPreKey;
        if (
                auto qpk = GCRYPT_ISTORE->load_one_time_prekey(handshake.usedPreKeys[1], store::key_type::QUANTUM);
                !qpk.has_value()                                                ||
                util::load_keyb_s(*qpk, usedPrivateQuantumPreKey, MLKEM_SKB)
                )
                return std::nullopt;

        
        return create_inbound_session(localIdentityKey,
                                      usedPrivateSignedPreKey,
                                      has_usedPrivateOneTimePreKey ? (std::optional<xckey>)usedPrivateOneTimePreKey : std::nullopt,
                                      usedPrivateQuantumPreKey,
                                      handshake);
    #else
        return std::nullopt;
    #endif
    }
}