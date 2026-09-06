#pragma once
#include "protocol.hpp"
#include <memory>

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

    struct message
    {
        xckey ratchet;
        bytespan data;
    };

    /// @brief Active Double Ratchet session state for a specific peer
    struct messaging_session
    {

        xckey remoteIdentityKey;            // Bob's verified long-term Public Identity Key
        
        key<32> rootKey;                     // Root Key (RK) - updated on every DH ratchet turn
        key<32> sendingChainKey;             // Sending Chain Key (CKs) - ratchets on every sent msg
        key<32> receivingChainKey;           // Receiving Chain Key (CKr) - ratchets on every rcvd msg

        xckeypair localRatchetKey;           // Our current active DH key pair (DHs)
        xckey remoteRatchetKey;              // Bob's current active DH public key (DHr)

        uint32_t sendSequence{0};            // Ns: Messages sent in current sending chain
        uint32_t receiveSequence{0};         // Nr: Messages received in current receiving chain
        uint32_t previousChainLength{0};    // PN: Message count of previous sending chain

        std::vector<skipped_message_key> skippedKeys; // Cache for out-of-order arrivals


        /// @brief Constructs a payload in byte form that can be sent to the recipient
        ///        of this messaging session.
        /// @param ue_message the un encrypted message content in byte form.
        /// @return The list of encrypted bytes
        bytedata construct_byte_message(const bytespan& data);

         /// @brief Handles the new message from the given session. If the provided message bytes have
        ///        already been handled, calling this again will cause undefined behaviour.
        /// @param message the array of bytes representing the message. The format for this is defined in
        ///                messaging_session::construct_byte_message.
        /// @return the list of unencrypted bytes representing the sent message.data field.
        bytedata receive(const bytespan& data);
    };

    using msessionref = std::shared_ptr<messaging_session>;
}   