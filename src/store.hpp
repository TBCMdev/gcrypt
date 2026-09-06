#pragma once
#include "session.hpp"
#include "protocol.hpp"
#include "errors.hpp"
#include <vector>

#define GCRYPT_SESSION_MANAGER_WARNING "A storage manager function was called yet attains no implementation." \
                                     " This is likely due to an implementation of gcrypt without implementing store::storage_manager"

#define GCRYPT_STORE_NOT_IMPLEMENTED GCRYPT_NOT_IMPLEMENTED(GCRYPT_SESSION_MANAGER_WARNING)

#ifndef GCRYPT_KEY_MANAGER_INDEX_TYPE
#define GCRYPT_KEY_MANAGER_INDEX_TYPE uint32_t
#endif

#ifndef GCRYPT_NOSTORE
    #define GCRYPT_ASSERT_STORE() \
        do { \
            if (!GCRYPT_ISTORE) GCRYPT_STORE_NOT_IMPLEMENTED; \
        } while(0)
#else
    #define GCRYPT_ASSERT_STORE() ((void)0)
#endif

/// @brief Used to denote functions that query the gcrypt storage api. These functions throw
///        a not_implemented exception if not already handled by the preprocessor or no implementation exists
///        for the sub functions that this function invokes in order to query storage.
#define GCRYPT_FUNC_USES_STORAGE


namespace gcrypt::store
{
    /// @brief Used to distinguish between keys and their sizes.
    enum class key_type
    {
        IDENTITY,
        EPHEMERAL,
        SIGNED,
        PREKEY,

        // Needs big storage regardless of quantum key type.
        QUANTUM
    };


    class storage_manager
    {
    private:
        std::unordered_map<std::string, session::msessionref> _LocalSessions;
    public:
        virtual ~storage_manager() = default;
        
        

        /// @brief Attempts to store the given session_blob, by invoking the implementers body for this function and querying their storage.
        /// @param recipient_id The identifier used to store this session. Something like "Alice:1".
        /// @param session_blob The blob (array of bytes) of the provided session. This is a direct encoding of gcrypt::store::messaging_session.
        /// @throws not_implemented - if no implementation for this function exists. This is default behavior.
        /// @return true if it was successfully stored, false otherwise.
        inline virtual bool store_session(const std::string& recipient_id, const bytespan& session_blob)
            #ifdef GCRYPT_NOSTORE
                { GCRYPT_STORE_NOT_IMPLEMENTED; }
            #else
                = 0;
            #endif
        /// @brief Attempts to load the given session_blob from the implementers storage with the given recipient_id as a mapped key.
        /// @param recipient_id The identifier used to store this session. Something like "Alice:1".
        /// @throws not_implemented - if no implementation for this function exists. This is default behavior.
        /// @return The array of bytes directly representing a gcrypt::store::messaging_session.
        inline virtual std::optional<session::messaging_session> load_session(const std::string& recipient_id)
            #ifdef GCRYPT_NOSTORE
                { GCRYPT_STORE_NOT_IMPLEMENTED; }
            #else
                = 0;
            #endif
        

        /// @brief Attempts to store the given prekey bytes to the implementers storage with the given id to map it.
        /// @note Uses GCRYPT_KEY_MANAGER_INDEX_TYPE to determine the numeric data type used to index the key storage implementation.
        ///       This is defaulted to uint32_t.
        /// @param key_type The type of the key. If the type is Quantum, it should be stored in a LARGE BLOB format, otherwise
        ///                 It can be stored in a SMALL BLOB format.
        /// @throws not_implemented - if no implementation for this function exists. This is default behavior.
        /// @return Whether or not the key was stored successfully.
        inline virtual bool store_one_time_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id, const key_type& key_type, const bytespan& key_blob)
            #ifdef GCRYPT_NOSTORE
                { GCRYPT_STORE_NOT_IMPLEMENTED; }
            #else
                = 0;
            #endif
        /// @brief Attempts to store the given identity key pair to the implementers storage.
        /// @note This method should choose wisely how the identity key pair is stored. For mobile, this should
        ///       be stored in a special place seperate from database implementations, something like the local encrypted key store.
        /// @note This function is called once for storing the generate identity keys of the local_key_bundle.
        ///       The Identity key is special, yet the other keys are all stored in small or large storage.        
        /// @param ik_pair_blob The pair of keys denoted as Public || Private (public<sizeof(xckeypair)> followed by private<sizeof(xckeypair)>).
        /// @return 
        inline virtual bool store_identity_key_pair(const bytespan& ik_pair_blob)
            #ifdef GCRYPT_NOSTORE
                { GCRYPT_STORE_NOT_IMPLEMENTED; }
            #else
                = 0;
            #endif

        /// @brief Attempts to load the given identity key pair from the implementers storage.
        /// @return The keys public and private bytes (Public || Private).
        inline virtual std::optional<vkey> load_identity_key_pair()
            #ifdef GCRYPT_NOSTORE
                { GCRYPT_STORE_NOT_IMPLEMENTED; }
            #else
                = 0;
            #endif
        
        /// @brief Returns the generated prekey for the given mapped id, if it exists.
        /// @note Uses GCRYPT_KEY_MANAGER_INDEX_TYPE to determine the numeric data type used to index the key storage implementation.
        ///       This is defaulted to uint32_t.
        /// @param key_type The type of the key trying to be queried. Only use this parameter to determine the overall size of the key.
        /// @throws not_implemented - if no implementation for this function exists. This is default behavior.
        /// @return The prekey from the implementation. This should contain the private bytes of the key.
        inline virtual std::optional<vkey> load_one_time_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id, const key_type& key_type)
            #ifdef GCRYPT_NOSTORE
                { GCRYPT_STORE_NOT_IMPLEMENTED; }
            #else
                = 0;
            #endif
        /// @brief Attempts to delete the prekey record associated with the mapped id.
        /// @note Uses GCRYPT_KEY_MANAGER_INDEX_TYPE to determine the numeric data type used to index the key storage implementation.
        ///       This is defaulted to uint32_t.
        /// @throws not_implemented - if no implementation for this function exists. This is default behavior.
        /// @return Whether or not the key was deleted.
        inline virtual bool delete_one_time_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id)
            #ifdef GCRYPT_NOSTORE
                { GCRYPT_STORE_NOT_IMPLEMENTED; }
            #else
                = 0;
            #endif


        /// @brief Returns the cached session if an entry exists.
        /// @param recipient_id the key for this session
        /// @return The session reference (a shared ptr to the session), if a mapping exists
        inline std::optional<session::msessionref> get_cached_session(const std::string& recipient_id) const
        {
            auto i = _LocalSessions.find(recipient_id);
            return i != _LocalSessions.end() ? (std::optional<session::msessionref>)i->second : std::nullopt;
        }
        /// @brief Stores the given session in memory for faster access. This is called internally.
        /// @param recipient_id The key for this session
        /// @param session the session reference (a shared ptr to the session object).
        inline void store_cached_session(const std::string& recipient_id, const session::msessionref& session)
        {
            _LocalSessions.insert_or_assign(recipient_id, session);
        }

        /// @brief Attempts to retrieve the session mapped to the given recipient id string.
        ///        If not present in memory, this function invokes load_session to try to load it
        ///        into memory. Then this session is stored in memory for faster access.
        inline std::optional<session::msessionref> get_session(const std::string& recipient_id)
        {
            auto cache = get_cached_session(recipient_id);
            if (cache.has_value())
                return *cache;
            
            auto loaded = load_session(recipient_id);
            if (!loaded.has_value())
                return std::nullopt;
            
            session::msessionref ref (&loaded.value());

            store_cached_session(recipient_id, ref);
            return ref;
        }
    };

#define GCRYPT_ISTORE_NAME _StorageManagerHwnd
/// @brief Store instance (instance of storage_manager)
#define GCRYPT_ISTORE gcrypt::store::GCRYPT_ISTORE_NAME

    inline std::shared_ptr<storage_manager> GCRYPT_ISTORE_NAME = nullptr;

    /// @brief Registers the given storage_manager instance as the primary storage communicator (found under)
    ///        the macro GCRYPT_ISTORE.
    void Init(storage_manager* managerInstance);

}   