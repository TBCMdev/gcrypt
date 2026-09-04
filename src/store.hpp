#pragma once

#include "protocol.hpp"
#include "errors.hpp"
#include <vector>

#define GCRYPT_SESSION_MANAGER_WARNING "A storage manager function was called yet attains no implementation." \
                                     " This is likely due to an implementation of gcrypt without implementing store::storage_manager"

#define GCRYPT_STORE_NOT_IMPLEMENTED GCRYPT_NOT_IMPLEMENTED(GCRYPT_SESSION_MANAGER_WARNING)

#ifndef GCRYPT_KEY_MANAGER_INDEX_TYPE
#define GCRYPT_KEY_MANAGER_INDEX_TYPE uint64_t
#endif

/// @brief Used to denote functions that query the gcrypt storage api. These functions throw
///        a not_implemented exception if not already handled by the preprocessor or no implementation exists
///        for the sub functions that this function invokes in order to query storage.
#define GCRYPT_FUNC_USES_STORAGE

namespace gcrypt::store
{
    struct skipped_message_key
    {
        xckey ratchetPublicKey;  // The remote ratchet key for this chain
        uint32_t sequenceNumber; // Sequence number within that chain
        key<32> messageKey;      // Unused derived message key
    };

    /// @brief Active Double Ratchet session state for a specific peer
    struct messaging_session
    {
        // =========================================================================
        // 1. Peer Identification
        // =========================================================================
        xckey remoteIdentityKey;            // Bob's verified long-term Public Identity Key
        
        // =========================================================================
        // 2. Symmetric Chain Keys (Root & Chain HKDF state)
        // =========================================================================
        key<32> rootKey;                     // Root Key (RK) - updated on every DH ratchet turn
        key<32> sendingChainKey;             // Sending Chain Key (CKs) - ratchets on every sent msg
        key<32> receivingChainKey;           // Receiving Chain Key (CKr) - ratchets on every rcvd msg

        // =========================================================================
        // 3. Asymmetric DH Ratchet State
        // =========================================================================
        xckeypair localRatchetKey;           // Our current active DH key pair (DHs)
        xckey remoteRatchetKey;              // Bob's current active DH public key (DHr)

        // =========================================================================
        // 4. Sequence Counters & Message Tracking
        // =========================================================================
        uint32_t sendSequence{0};            // Ns: Messages sent in current sending chain
        uint32_t receiveSequence{0};         // Nr: Messages received in current receiving chain
        uint32_t previousChainLength{0};    // PN: Message count of previous sending chain

        // =========================================================================
        // 5. Out-of-Order Message Handling
        // =========================================================================
        std::vector<skipped_message_key> skippedKeys; // Cache for out-of-order arrivals
    };

    class storage_manager
    {
    public:
        virtual ~storage_manager() = default;
        /// @brief Attempts to store the given session_blob, by invoking the implementers body for this function and querying their storage.
        /// @param recipient_id The identifier used to store this session. Something like "Alice:1".
        /// @param session_blob The blob (array of bytes) of the provided session. This is a direct encoding of gcrypt::store::messaging_session.
        /// @throws not_implemented - if no implementation for this function exists. This is default behavior.
        /// @return true if it was successfully stored, false otherwise.
        inline virtual bool store_session(const std::string& recipient_id, const vbytearray& session_blob)
            #ifdef GCRYPT_NOSTORE
                    { GCRYPT_STORE_NOT_IMPLEMENTED; }
            #else
                    = 0;
            #endif
        /// @brief Attempts to load the given session_blob from the implementers storage with the given recipient_id as a mapped key.
        /// @param recipient_id The identifier used to store this session. Something like "Alice:1".
        /// @throws not_implemented - if no implementation for this function exists. This is default behavior.
        /// @return The array of bytes directly representing a gcrypt::store::messaging_session.
        inline virtual std::optional<vbytearray> load_session(const std::string& recipient_id)
            #ifdef GCRYPT_NOSTTORE
                    { GCRYPT_STORE_NOT_IMPLEMENTED; }
            #else
                    = 0;
            #endif
        /// @brief Returns the generated prekey for the given mapped id, if it exists.
        /// @note Uses GCRYPT_KEY_MANAGER_INDEX_TYPE to determine the numeric data type used to index the key storage implementation.
        ///       This is defaulted to long.
        /// @throws not_implemented - if no implementation for this function exists. This is default behavior.
        /// @return The prekey from the implementation. This should contain the private bytes of the key.
        inline virtual vkey get_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id)
            #ifdef GCRYPT_NOSTORE
                    { GCRYPT_STORE_NOT_IMPLEMENTED; }
            #else
                    = 0;
            #endif
        /// @brief Attempts to delete the prekey record associated with the mapped id.
        /// @note Uses GCRYPT_KEY_MANAGER_INDEX_TYPE to determine the numeric data type used to index the key storage implementation.
        ///       This is defaulted to long.
        /// @throws not_implemented - if no implementation for this function exists. This is default behavior.
        /// @return Whether or not the key was deleted.
        inline virtual bool delete_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id)
            #ifdef GCRYPT_NOSTORE
                    { GCRYPT_STORE_NOT_IMPLEMENTED; }
            #else
                    = 0;
            #endif
    };

#define GCRYPT_ISTORE_NAME _StorageManagerHwnd
/// @brief Store instance (instance of storage_manager)
#define GCRYPT_ISTORE gcrypt::store::GCRYPT_ISTORE_NAME

    inline std::shared_ptr<storage_manager> GCRYPT_ISTORE_NAME = nullptr;


    /// @brief Registers the given storage_manager instance as the primary storage communicator (found under)
    ///        the macro GCRYPT_ISTORE.
    void Init(storage_manager* managerInstance);

}   