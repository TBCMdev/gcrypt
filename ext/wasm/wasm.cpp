#include <emscripten/bind.h>
#include <emscripten/val.h>
#include "protocol.hpp"
#include "session.hpp" 
#include "keygen.hpp"
#include "algorithms.hpp"
#include "pqxdh.hpp"
#include "store.hpp"
#include <stdexcept>

using namespace emscripten;
using namespace gcrypt::pqxdh;
using namespace gcrypt::session; 

namespace gcrypt::wasmOM::from
{
    template<std::size_t _Bytes>
    val key(const gcrypt::key<_Bytes>& k)
    {
        return val(typed_memory_view(_Bytes, k.data()));
    }

    template<std::size_t _BytesPublic, std::size_t _BytesPrivate,
             template<std::size_t> typename _PublicKeyType = gcrypt::key,
             template<std::size_t> typename _PrivateKeyType = _PublicKeyType>
    val key_pair(const gcrypt::_keypair_impl<_PublicKeyType, _PrivateKeyType, _BytesPublic, _BytesPrivate>& k)
    {
        val obj = val::object();
        obj.set("public", key(k.Public).call<val>("slice"));
        obj.set("private", key(k.Private).call<val>("slice"));
        return obj;
    }

    template<std::size_t _Bytes>
    val id_key(const gcrypt::idkey<_Bytes>& k)
    {
        val obj = val::object();
        obj.set("key", key(k.data).call<val>("slice"));
        obj.set("identifier", k.identifier);
        return obj;
    }

    template<std::size_t _Bytes, std::size_t _SigBytes>
    val sid_key(const gcrypt::sidkey<_Bytes, _SigBytes>& k)
    {
        val obj = val::object();
        obj.set("key", key(k.data).call<val>("slice"));
        obj.set("identifier", k.identifier);
        obj.set("signature", key(k.signature).call<val>("slice"));
        return obj;
    }

    val local_key_bundle(const gcrypt::pqxdh::local_key_bundle& bundle)
    {
        val obj = val::object();
        obj.set("identityKey", key_pair(bundle.IdentityKey));
        obj.set("signedPreKey", key_pair(bundle.SignedPreKey));
        obj.set("quantumPreKey", key_pair(bundle.QuantumPreKey));
        return obj;
    }

    val session_init_result(const gcrypt::pqxdh::session_init_result& result)
    {
        val obj = val::object();
        val handshake = val::object();
        handshake.set("identityKey", key(result.handshakeMessage.identityKey).call<val>("slice"));
        handshake.set("ephemeralKey", key(result.handshakeMessage.ephermoralKey).call<val>("slice"));
        handshake.set("cipherText", key(result.handshakeMessage.cipherText).call<val>("slice"));
        
        obj.set("handshakeMessage", handshake);
        return obj;
    }
}

namespace gcrypt::wasmOM::to
{
    template<std::size_t _Bytes>
    std::optional<gcrypt::key<_Bytes>> to_key(val v)
    {
        if (v.isUndefined() || v.isNull()) return std::nullopt;
        auto vec = vecFromJSArray<uint8_t>(v);
        if (vec.size() != _Bytes) return std::nullopt;
        gcrypt::key<_Bytes> k;
        std::copy(vec.begin(), vec.end(), k.data());
        return k;
    }

    std::optional<foreign_prekey_bundle> foreignpk_bundle(val foreignBundle)
    {
        if (foreignBundle.isUndefined() || foreignBundle.isNull()) return std::nullopt;

        foreign_prekey_bundle bundle{};

        auto idKeyOpt = to_key<sizeof(gcrypt::xckey)>(foreignBundle["identityKey"]);
        if (!idKeyOpt) return std::nullopt;
        bundle.identityKey = *idKeyOpt;

        return bundle;
    }
}

class JSStorageManagerWrap : public wrapper<gcrypt::store::storage_manager>
{
public:
    EMSCRIPTEN_WRAPPER(JSStorageManagerWrap);

    bool store_session(const std::string& recipient_id, const gcrypt::bytespan& session_blob) override 
    {
        val view = val(typed_memory_view(session_blob.size(), session_blob.data()));
        return call<bool>("storeSession", recipient_id, view);
    }

    std::optional<messaging_session> load_session(const std::string& recipient_id) override 
    {
        val result = call<val>("loadSession", recipient_id);
        if (result.isUndefined() || result.isNull()) return std::nullopt;
        
        throw std::runtime_error("Implement session deserialization from blob!");
    }

    void close_session(const std::string& recipient_id) override 
    {
        call<void>("closeSession", recipient_id);
    }

    bool store_one_time_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id, const gcrypt::store::key_type& key_type, const gcrypt::bytespan& key_blob) override 
    {
        val view = val(typed_memory_view(key_blob.size(), key_blob.data()));
        return call<bool>("storeOneTimePreKey", static_cast<uint32_t>(id), static_cast<uint32_t>(key_type), view);
    }

    bool store_identity_key_pair(const gcrypt::bytespan& ik_pair_blob) override 
    {
        val view = val(typed_memory_view(ik_pair_blob.size(), ik_pair_blob.data()));
        return call<bool>("storeIdentityKeyPair", view);
    }

    std::optional<gcrypt::vkey> load_identity_key_pair() override 
    {
        val result = call<val>("loadIdentityKeyPair");
        if (result.isUndefined() || result.isNull()) return std::nullopt;
        
        auto vec = vecFromJSArray<uint8_t>(result);
        gcrypt::vkey key(vec.size());
        std::copy(vec.begin(), vec.end(), key.begin());
        return key;
    }

    std::optional<gcrypt::vkey> load_one_time_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id, const gcrypt::store::key_type& key_type) override 
    {
        val result = call<val>("loadOneTimePreKey", static_cast<uint32_t>(id), static_cast<uint32_t>(key_type));
        if (result.isUndefined() || result.isNull()) return std::nullopt;
        
        auto vec = vecFromJSArray<uint8_t>(result);
        gcrypt::vkey key(vec.size());
        std::copy(vec.begin(), vec.end(), key.begin());
        return key;
    }

    bool delete_one_time_prekey(GCRYPT_KEY_MANAGER_INDEX_TYPE id) override 
    {
        return call<bool>("deleteOneTimePreKey", static_cast<uint32_t>(id));
    }
};

void initStorage(JSStorageManagerWrap* storageImpl)
{
    if (!storageImpl) return;
    gcrypt::store::Init(storageImpl);
}

val makeLocalKeyBundle(int deviceId)
{
    uint32_t udId = static_cast<uint32_t>(deviceId);
    local_key_bundle kbundle = make_lkb(udId);

    return gcrypt::wasmOM::from::local_key_bundle(kbundle);
}

val initializeNewSession(val foreignBundle)
{
    if (!GCRYPT_ISTORE) return val::null();

    auto localIdKeyOpt = GCRYPT_ISTORE->load_identity_key_pair();
    if (!localIdKeyOpt.has_value()) return val::null();

    gcrypt::xckeypair localIdentityKeyPair;
    std::copy(localIdKeyOpt->begin(), localIdKeyOpt->begin() + sizeof(gcrypt::xckey), localIdentityKeyPair.Public.begin());
    std::copy(localIdKeyOpt->begin() + sizeof(gcrypt::xckey), localIdKeyOpt->end(), localIdentityKeyPair.Private.begin());

    auto bundle = gcrypt::wasmOM::to::foreignpk_bundle(foreignBundle);
    if (!bundle.has_value()) return val::null();

    auto result = create_outbound_session(localIdentityKeyPair, bundle->identityKey, *bundle);
    if (!result.has_value()) return val::null();

    return gcrypt::wasmOM::from::session_init_result(*result);
}

val initializeExistingSession(val longTermIdentityKey, val foreignBundle)
{
    if (!GCRYPT_ISTORE) return val::null();

    auto localIdKeyOpt = GCRYPT_ISTORE->load_identity_key_pair();
    if (!localIdKeyOpt.has_value()) return val::null();

    gcrypt::xckeypair localIdentityKeyPair;
    std::copy(localIdKeyOpt->begin(), localIdKeyOpt->begin() + sizeof(gcrypt::xckey), localIdentityKeyPair.Public.begin());
    std::copy(localIdKeyOpt->begin() + sizeof(gcrypt::xckey), localIdKeyOpt->end(), localIdentityKeyPair.Private.begin());

    auto bundle = gcrypt::wasmOM::to::foreignpk_bundle(foreignBundle);
    auto remoteIdentityKey = gcrypt::wasmOM::to::to_key<sizeof(gcrypt::xckey)>(longTermIdentityKey);
    
    if (!bundle.has_value() || !remoteIdentityKey.has_value()) return val::null();

    auto result = create_outbound_session(localIdentityKeyPair, *remoteIdentityKey, *bundle);
    if (!result.has_value()) return val::null();

    return gcrypt::wasmOM::from::session_init_result(*result);
}

val encryptTo(std::string whoId, val message)
{
    if (!GCRYPT_ISTORE) return val::null();

    std::optional<msessionref> session = GCRYPT_ISTORE->get_session(whoId);
    if (!session.has_value()) return val::null();

    auto msgVec = vecFromJSArray<uint8_t>(message);
    gcrypt::bytespan msgSpan(msgVec.data(), msgVec.size());

    gcrypt::bytedata encrypted = session.value()->ratchet_encrypt(msgSpan);
    
    return val(typed_memory_view(encrypted.size(), encrypted.data())).call<val>("slice");
}

val decryptFrom(std::string whoId, val message)
{
    if (!GCRYPT_ISTORE) return val::null();

    std::optional<msessionref> session = GCRYPT_ISTORE->get_session(whoId);
    if (!session.has_value()) return val::null();

    auto msgVec = vecFromJSArray<uint8_t>(message);
    gcrypt::bytespan msgSpan(msgVec.data(), msgVec.size());

    std::optional<gcrypt::bytedata> decrypted = session.value()->ratchet_decrypt(msgSpan);
    if (!decrypted.has_value()) return val::null();

    return val(typed_memory_view(decrypted->size(), decrypted->data())).call<val>("slice");
}

EMSCRIPTEN_BINDINGS(gcrypt_wasm_module) 
{
    class_<gcrypt::store::storage_manager>("StorageManager")
        .allow_subclass<JSStorageManagerWrap>("JSStorageManagerWrap");

    function("initStorage", &initStorage, allow_raw_pointers());
    function("makeLocalKeyBundle", &makeLocalKeyBundle);
    function("initializeNewSession", &initializeNewSession);
    function("initializeExistingSession", &initializeExistingSession);
    function("encryptTo", &encryptTo);
    function("decryptFrom", &decryptFrom);
}