#pragma once

#include "algorithms.hpp"
#include "store.hpp"

namespace gcrypt::pqxdh
{

    /// @brief Represents a generated pair of curve and quantum keys.
    ///        The maps are to be private, and merged with local key storage,
    ///        and the arrays are used for public external (server-side) use if required.
    struct refill_payload
    {
        std::vector<xcikey>  oneTimePreKeys;
        std::vector<qsidkey> signedOneTimeQuantumPreKeys;
    };

    /// @brief A payload sent to the server to register a devices keys. Note that all keys below are PUBLIC.
    /// @tparam _OneTimePreKeyCount the amount of one time pre keys you want to give to the server.
    template<std::size_t _OneTimePreKeyCount>
    struct public_server_payload
    {
        #define GCRYPT_MAX_REGISTRATION_VALUE 16380
        uint32_t                  registration,
                                  deviceId;
        xckey      identityKey; // x curve key
        xcsikey    signedPreKey; // x curve sig+id key
        qpubsidkey quantumPreKey; // quantum public sig+id key

        std::array<xcikey, _OneTimePreKeyCount>
                                  oneTimePreKeys;
        std::array<qsidkey, _OneTimePreKeyCount>
                                  signedOneTimeQuantumPreKeys;
    };
    
    /// @brief All keys stored locally.
    struct local_key_bundle
    {
        xckeypair              IdentityKey;
        xcikeypair             SignedPreKey;
        qikeypair              QuantumPreKey;

        std::unordered_map<uint32_t, xckeypair> OneTimePreKeys;
        std::unordered_map<uint32_t, qkeypair>  OneTimeQuantumKeys;
    };

    /// @brief Represents all information that is retrieved from a foreign source about a recipient
    ///        of which a user would like to establish a session with.
    struct foreign_prekey_bundle
    {
        xckey identityKey;
        xcsikey signedPreKey;
        /// @brief Either a qsidkey one-time qkey, or the last resort pre key.
        std::variant<qsidkey, qpubikey> qpubsidkey; 
        std::optional<xcikey> oneTimePreKey;
    };

    /// @brief Represents the payload a user must send as an initial handshake message, containing all
    ///        keys needed to establish a session.
    struct initial_message_handshake
    {
        xckey identityKey;
        xckey ephermoralKey;
        qpubkey cipherText;

        std::vector<uint32_t> usedPreKeys;
        std::vector<uint32_t> usedQuantumPreKeys;

        // TODO: Initial AEAD CypherText
    };

    struct session_init_result
    {
        store::messaging_session session;
        initial_message_handshake handshakeMessage;
    };

    /// @brief For internal implementation only. Do not call.
    namespace _internal
    {
        /// @brief An extention to create_outbound_session,
        ///        which takes the size of the secret key and finalizes the
        ///        session creation. Not to be used externally.
        template<std::size_t _SecretKeyBytes>
        std::optional<session_init_result> finalize_outbound_session(
                                    const xckey&                 localPublicIdentityKey,
                                    const xckey&                 publicEphemeralKey,
                                    const key<MLKEM_CTB>&        cipherText,
                                    const key<_SecretKeyBytes>&  KDFSecretKey,
                                    const foreign_prekey_bundle& keys
                                            )
        {

            std::vector<uint32_t> usedPreKeys;
            std::vector<uint32_t> usedQuantumPreKeys;

            usedPreKeys.reserve(2);
            usedPreKeys.push_back(keys.signedPreKey.identifier);

            if (keys.oneTimePreKey.has_value())
                usedPreKeys.push_back(keys.oneTimePreKey->identifier);

            // Todo : multiple qkey support
            const uint32_t qKeyId = std::visit([](const auto& k) { return k.identifier; }, keys.qpubsidkey);
            usedQuantumPreKeys.push_back(qKeyId);

            initial_message_handshake handshake 
            {
                .identityKey    = localPublicIdentityKey,
                .ephermoralKey  = publicEphemeralKey,   
                .cipherText     = cipherText,
                .usedPreKeys    = std::move(usedPreKeys),
                .usedQuantumPreKeys = std::move(usedQuantumPreKeys)
            };

            store::messaging_session session
            {
                // TODO

                .remoteIdentityKey = keys.identityKey,
                .rootKey = KDFSecretKey,
                .sequenceNumber = 0
            };

            return session_init_result
            {
                .session = std::move(session),
                .handshakeMessage = std::move(handshake)
            };
        }

    }

    /// @brief Initializes this device's local key bundle.
    /// @tparam _OneTimePreKeyCount 
    /// @param deviceId 
    /// @return The created bundle
    local_key_bundle make_lkb(uint32_t deviceId);

    /// @brief Generates keyCount keypair refills to use to replenish one time prekeys.
    /// @param privIdentityKey The private identity key of the user
    /// @param Count the amount of keys to generate
    /// @return The list of generated keys, both for private and public use.
    refill_payload refill(const xckey& privIdentityKey, uint32_t Count);

    /// @brief Creates a server welcome payload with everything it needs to setup encryption.
    /// @tparam _OneTimePreKeyCount 
    /// @param keys 
    /// @return The created payload
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
                .identifier = okey.identifier,
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

    /// @brief Verifies the signatures found within the foreign pre key bundle.
    /// @param bundle The provided bundle from an external user.
    /// @param userIdentityKey The provided identity key from the user.
    /// @return true if all signatures matched.
    bool verify_foreign_bundle(const xckey& userIdentityKey, const foreign_prekey_bundle& bundle);

    /// @brief Attempts to create an outbound session, by verifying the foreign bundle
    ///        and initializing the keys needed to complete the pqxdh handshake.
    std::optional<session_init_result> create_outbound_session(
                                                const xckeypair& localIdentityKey,
                                                const xckey& identityToVerifyAgainst,
                                                const foreign_prekey_bundle& keys
                                                                );

    /// @brief Attempts to create a session from an inbound initial_message_handshake object.
    /// @note This function queries storage to find the corresponding private keys for the public prekeys the handshake
    ///       used. If you do not want to use storage, invoke the sub implementation and overload for this function create_inbound_session.
    /// @param handshake The incoming handshake
    /// @return The session if it was created.
GCRYPT_FUNC_USES_STORAGE
    std::optional<store::messaging_session> create_inbound_session(const initial_message_handshake& handshake);
    /// @brief Attempts to create a session from an inbound initial_message_handshake object.
    /// @note This function does not query storage to fetch the used private keys, as they are passed as arguments.
    /// @param usedPrivatePreKey the corresponding private key of the public one time pre key that the handshake used.
    /// @param usedPrivateQuantumPreKey the corresponding private key of the public one time quantum pre key that the handshake used.
    /// @param handshake The incoming handshake
    /// @return The session if it was created.
    std::optional<store::messaging_session> create_inbound_session(
                                    const xckey&                     usedPrivatePreKey,
                                    const key<MLKEM_SKB>             usedPrivateQuantumPreKey,
                                    const initial_message_handshake& handshake
                                                                );
}
