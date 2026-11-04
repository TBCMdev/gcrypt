#pragma once
#include "store.hpp"

class StorageManager : public gcrypt::store::storage_manager
{
public:
    bool store_session(const std::string& recipient_id, const gcrypt::bytespan& session_blob) override;
    std::optional<gcrypt::session::messaging_session> load_session(const std::string& recipient_id) override;
    void close_session(const std::string& recipient_id) override;

    bool store_one_time_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id, const gcrypt::store::key_type& type, const gcrypt::bytespan& key_blob) override;
    std::optional<gcrypt::vkey> load_one_time_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id, const gcrypt::store::key_type& type) override;
    bool delete_one_time_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id) override;

    bool store_identity_key_pair(const gcrypt::bytespan& ik_pair_blob) override;
    std::optional<gcrypt::vkey> load_identity_key_pair() override;
};