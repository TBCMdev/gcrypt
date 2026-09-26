#pragma once
#include "protocol.hpp"
#include <memory>
#include <tuple>

#ifndef GCRYPT_FUNC_USES_STORAGE
    #define GCRYPT_FUNC_USES_STORAGE
#endif

namespace gcrypt::session
{
    struct skipped_message_key
    {
        xckey ratchetPublicKey;  // The remote ratchet key for this chain
        uint32_t sequenceNumber; // Sequence number within that chain
        key<32> messageKey;      // Unused derived message key
    };

    struct message_header
    {
        xckey ratchet;
        uint32_t cmn; // chain message number
        uint32_t cpn; // chain's previous number
    };

    struct message
    {
        message_header header;
        bytespan data;
    };

    /// @brief Active Double Ratchet session state for a specific peer
    struct messaging_session
    {
        xckey remoteIdentityKey;             // Remote verified long-term Public Identity Key
        
        key<32> rootKey;                     // Root Key (RK) - updated on every DH ratchet turn
        key<32> sendingChainKey;             // Sending Chain Key (CKs) - ratchets on every sent msg
        key<32> receivingChainKey;           // Receiving Chain Key (CKr) - ratchets on every rcvd msg

        xckeypair localRatchetKey;           // Our current active DH key pair (DHs)
        xckey remoteRatchetKey;              // Remote current active DH public key (DHr)

        uint32_t sendSequence{0};            // Ns: Messages sent in current sending chain
        uint32_t receiveSequence{0};         // Nr: Messages received in current receiving chain
        uint32_t previousChainLength{0};     // PN: Message count of previous sending chain

        std::vector<skipped_message_key> skippedKeys; // Cache for out-of-order arrivals


        /// @brief Constructs a payload in byte form that can be sent to the recipient
        ///        of this messaging session.
        /// @param msg the un encrypted message content in byte form.
        /// @throws An error if the encryption was not successful
        /// @return The list of encrypted bytes
        bytedata ratchet_encrypt(const bytespan& msg);


         /// @brief Handles the new message from the given session. If the provided message bytes have
        ///        already been handled, calling this again will cause undefined behaviour.
        /// @param data the data to decrypt
        /// @return the list of unencrypted bytes representing the sent message, or std::nullopt if the decryption failed.
        std::optional<bytedata> ratchet_decrypt(const bytespan& data);

        /// @brief Constructs a new messaging session given the secret key, and the recipients
        ///        Diffie hellman public key.
        /// @param SK Secret Key
        /// @param PeerDHPublicKey DH Public Key
        /// @param masterSecretKey The secret key
        messaging_session(const xckey& SK, const xckey& PeerDHPublicKey, const key<32>& masterSecretKey);
        /// @brief Constructs a new messaging session given the local users' Local Ratchet Keys(LKR).
        /// @param SK The agreed upon secret key. 
        /// @param LRK The Local Ratchet Keypair
        messaging_session(const xckey& SK, const xckeypair& LRK, const key<32>& masterSecretKey);
#ifndef GCRYPT_EXPOSE
    protected:
#else
    public:
#endif
        /*
            ============ IMPL ============
        
            Below you can find definitions for a majority of the methods needed
            to perform the signal protocol ratchet encryption/decryption steps.

            These methods are protected by default, however can be exposed by compiling 
            the library with the definition of GCRYPT_EXPOSE (see above macro usage).

            README contains more information about why this macro exists.

           ============ IMPL ============
        */

    #define GCRYPT_HEADER_LEN 40
    #define GCRYPT_SESSION_MAX_KEY_SKIP 5
        std::optional<xckey> try_skipped_msg_keys(const message_header& header);
        void                 skip_msg_keys       (int until);
        // converts the current state of the session into a byte header.
        bytedata header();
        // decodes the given span of bytes into a message header. If data contains extra bytes, they are not
        // used in this function (> GCRYPT_HEADER_LEN)
        message_header get_header(const bytespan& data);

        std::tuple<key<32>, uint32_t> ratchet_send_key();
        key<32> ratchet_receive_key(const message_header& header);
        // Performs the ratchet decrypt step.

        // Performs the diffie hellman ratchet step for the given received message header.
        void dh_ratchet(const message_header& header);
        void dhstep();
    };

    using msessionref = std::shared_ptr<messaging_session>;
}   