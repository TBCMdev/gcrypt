#ifdef __EMSCRIPTEN__
#include "StorageManager.hpp"
#include <emscripten.h>

// get: stashes the bytes JS side and returns the length ( or -1 if missing / error)
EM_ASYNC_JS(int, gcko_idb_get, (const char* store, const char* key), {
    try {
        const bytes = await globalThis.gckoDb.get(UTF8ToString(store), UTF8ToString(key));
        globalThis.__gckoPending = bytes ?? null;
        return bytes ? bytes.length : -1;
    } catch (e) { console.error("idb get failed", e); return -1; }
});

// synchronous copy of the stashed bytes into WASM memory
EM_JS(void, gcko_idb_take, (uint8_t* dest), {
    if (globalThis.__gckoPending) HEAPU8.set(globalThis.__gckoPending, dest);
    globalThis.__gckoPending = null;
});

EM_ASYNC_JS(int, gcko_idb_put, (const char* store, const char* key, const uint8_t* data, int len), {
    try {
        // copy before awaiting: WASM memory can change while suspended
        const bytes = HEAPU8.slice(data, data + len);
        await globalThis.gckoDb.put(UTF8ToString(store), UTF8ToString(key), bytes);
        return 1;
    } catch (e) { console.error("idb put failed", e); return 0; }
});

EM_ASYNC_JS(int, gcko_idb_delete, (const char* store, const char* key), {
    try {
        await globalThis.gckoDb.del(UTF8ToString(store), UTF8ToString(key));
        return 1;
    } catch (e) { console.error("idb delete failed", e); return 0; }
});

namespace
{
    constexpr const char* SESSIONS = "sessions";
    constexpr const char* PREKEYS  = "prekeys";
    constexpr const char* IDENTITY = "identity";
    constexpr const char* IDENTITY_ID = "local";

    std::optional<gcrypt::bytedata> load_blob(const char* store, const std::string& key)
    {
        const int len = gcko_idb_get(store, key.c_str());
        if (len < 0) return std::nullopt;

        gcrypt::bytedata out(static_cast<std::size_t>(len));
        gcko_idb_take(out.data());
        return out;
    }

    bool store_blob(const char* store, const std::string& key, const gcrypt::bytespan& blob)
    {
        return gcko_idb_put(store, key.c_str(), blob.data(), static_cast<int>(blob.size())) == 1;
    }
}

bool StorageManager::store_session(const std::string& recipient_id, const gcrypt::bytespan& session_blob)
{
    return store_blob(SESSIONS, recipient_id, session_blob);
}

std::optional<gcrypt::session::messaging_session> StorageManager::load_session(const std::string& recipient_id)
{
    auto blob = load_blob(SESSIONS, recipient_id);
    if (!blob) return std::nullopt;

    auto session = gcrypt::session::messaging_session::from_bytes(recipient_id, gcrypt::fixed_bytespan{*blob});
    if (!session) return std::nullopt;   // corrupt / unreadable blobb
    return std::move(*session);
}

void StorageManager::close_session(const std::string&)
{
    // only evicts from the in-memory cache, which is PRIVATE to the base class
    // (_LocalSessions). nothing to do here until that's exposed?
}

bool StorageManager::store_one_time_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id, const gcrypt::store::key_type&, const gcrypt::bytespan& key_blob)
{
    return store_blob(PREKEYS, std::to_string(id), key_blob);
}

std::optional<gcrypt::vkey> StorageManager::load_one_time_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id, const gcrypt::store::key_type&)
{
    return load_blob(PREKEYS, std::to_string(id));
}

bool StorageManager::delete_one_time_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id)
{
    return gcko_idb_delete(PREKEYS, std::to_string(id).c_str()) == 1;
}

bool StorageManager::store_identity_key_pair(const gcrypt::bytespan& ik_pair_blob)
{
    return store_blob(IDENTITY, IDENTITY_ID, ik_pair_blob);
}

std::optional<gcrypt::vkey> StorageManager::load_identity_key_pair()
{
    return load_blob(IDENTITY, IDENTITY_ID);
}
#endif