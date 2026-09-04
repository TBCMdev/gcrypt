#include "jnib.hpp"

#include "keygen.hpp"
#include "algorithms.hpp"
#include "pqxdh.hpp"

#include <sodium.h>

using namespace gcrypt::pqxdh;
#pragma region JNI_NonTemplateConversions
namespace gcrypt::jniOM::from
{
    jobject initial_handshake(JNI_PCONTEXT, const initial_message_handshake& handshake)
    {
        const jclass clazz = env->FindClass(JNI_initial_message_handshake_CLASSNAME_MAPPING);
        if (!clazz) return nullptr;

        jmethodID constructor = env->GetMethodID(clazz, JNI_CONSTRUCTOR_NAME, JNI_EMPTY_CONSTRUCTOR_SIG);
        if (!constructor) {
            env->DeleteLocalRef(clazz);
            return nullptr;
        }

        jobject obj = env->NewObject(clazz, constructor);
        if (!obj) {
            env->DeleteLocalRef(clazz);
            return nullptr;
        }

        jfieldID fid_identityKey        = env->GetFieldID(clazz, "identityKey", "[B");
        jfieldID fid_ephemeralKey       = env->GetFieldID(clazz, "ephemeralKey", "[B");
        jfieldID fid_cipherText         = env->GetFieldID(clazz, "cipherText", "[B");
        jfieldID fid_usedPreKeys        = env->GetFieldID(clazz, "usedPreKeys", "[I");
        jfieldID fid_usedQuantumPreKeys = env->GetFieldID(clazz, "usedQuantumPreKeys", "[I");

        // 1. Keys & CipherText
        jbyteArray identityArr = key(JNI_CONTEXT, handshake.identityKey);
        env->SetObjectField(obj, fid_identityKey, identityArr);
        env->DeleteLocalRef(identityArr);

        jbyteArray ephemeralArr = key(JNI_CONTEXT, handshake.ephermoralKey);
        env->SetObjectField(obj, fid_ephemeralKey, ephemeralArr);
        env->DeleteLocalRef(ephemeralArr);

        jbyteArray cipherTextArr = key(JNI_CONTEXT, handshake.cipherText);
        env->SetObjectField(obj, fid_cipherText, cipherTextArr);
        env->DeleteLocalRef(cipherTextArr);

        // 2. Used PreKey IDs (std::vector<uint32_t> -> jintArray)
        jintArray preKeysArr = env->NewIntArray(static_cast<jsize>(handshake.usedPreKeys.size()));
        env->SetIntArrayRegion(
            preKeysArr, 0, 
            static_cast<jsize>(handshake.usedPreKeys.size()), 
            reinterpret_cast<const jint*>(handshake.usedPreKeys.data())
        );
        env->SetObjectField(obj, fid_usedPreKeys, preKeysArr);
        env->DeleteLocalRef(preKeysArr);

        jintArray qPreKeysArr = env->NewIntArray(static_cast<jsize>(handshake.usedQuantumPreKeys.size()));
        env->SetIntArrayRegion(
            qPreKeysArr, 0, 
            static_cast<jsize>(handshake.usedQuantumPreKeys.size()), 
            reinterpret_cast<const jint*>(handshake.usedQuantumPreKeys.data())
        );
        env->SetObjectField(obj, fid_usedQuantumPreKeys, qPreKeysArr);
        env->DeleteLocalRef(qPreKeysArr);

        env->DeleteLocalRef(clazz);
        return obj;
    }
    jobject messaging_session(
            JNI_PCONTEXT, 
            const store::messaging_session& session)
    {
        return nullptr;

        // TODO

        // jclass clazz = env->FindClass(JNI_messaging_session_CLASSNAME_MAPPING);
        // if (!clazz) return nullptr;

        // jmethodID constructor = env->GetMethodID(clazz, JNI_CONSTRUCTOR_NAME, JNI_EMPTY_CONSTRUCTOR_SIG);
        // if (!constructor) {
        //     env->DeleteLocalRef(clazz);
        //     return nullptr;
        // }

        // jobject jSession = env->NewObject(clazz, constructor);
        // if (!jSession) {
        //     env->DeleteLocalRef(clazz);
        //     return nullptr;
        // }

        // jfieldID fid_remoteIdentityKey = env->GetFieldID(clazz, "remoteIdentityKey", "[B");
        // jfieldID fid_rootKey           = env->GetFieldID(clazz, "rootKey", "[B");
        // jfieldID fid_sequenceNumber    = env->GetFieldID(clazz, "sequenceNumber", "I");

        // // Populate Remote Identity Key
        // jbyteArray remoteIdArr = from::key(JNI_CONTEXT, session.remoteIdentityKey);
        // env->SetObjectField(jSession, fid_remoteIdentityKey, remoteIdArr);
        // if (remoteIdArr) env->DeleteLocalRef(remoteIdArr);

        // // Populate Root Key
        // jbyteArray rootKeyArr = from::key(JNI_CONTEXT, session.rootKey);
        // env->SetObjectField(jSession, fid_rootKey, rootKeyArr);
        // if (rootKeyArr) env->DeleteLocalRef(rootKeyArr);

        // // Populate Sequence Number / Counter
        // env->SetIntField(jSession, fid_sequenceNumber, static_cast<jint>(session.sequenceNumber));

        // env->DeleteLocalRef(clazz);
        // return jSession;
    }
    jobject session_init_result(
        JNI_PCONTEXT, 
        const gcrypt::pqxdh::session_init_result& result)
    {
        jclass clazz = env->FindClass(JNI_session_init_result_CLASSNAME_MAPPING);
        if (!clazz) return nullptr;

        jmethodID constructor = env->GetMethodID(clazz, JNI_CONSTRUCTOR_NAME, JNI_EMPTY_CONSTRUCTOR_SIG);
        if (!constructor) {
            env->DeleteLocalRef(clazz);
            return nullptr;
        }

        jobject jResult = env->NewObject(clazz, constructor);
        if (!jResult) {
            env->DeleteLocalRef(clazz);
            return nullptr;
        }

        jfieldID fid_session          = env->GetFieldID(clazz, "session", "L" JNI_messaging_session_CLASSNAME_MAPPING ";");
        jfieldID fid_handshakeMessage = env->GetFieldID(clazz, "handshakeMessage", "L" JNI_initial_message_handshake_CLASSNAME_MAPPING ";");

        // Convert and set session object
        jobject jSessionObj = from::messaging_session(JNI_CONTEXT, result.session);
        env->SetObjectField(jResult, fid_session, jSessionObj);
        if (jSessionObj) env->DeleteLocalRef(jSessionObj);

        // Convert and set initial message handshake object
        jobject jHandshakeObj = initial_handshake(JNI_CONTEXT, result.handshakeMessage);
        env->SetObjectField(jResult, fid_handshakeMessage, jHandshakeObj);
        if (jHandshakeObj) env->DeleteLocalRef(jHandshakeObj);

        env->DeleteLocalRef(clazz);
        return jResult;
    }
    
}
namespace gcrypt::jniOM::to
{
    std::optional<foreign_prekey_bundle> foreignpk_bundle(JNI_PCONTEXT, jobject foreignBundle)
    {
        if (!foreignBundle) return std::nullopt;

        jclass clazz = env->GetObjectClass(foreignBundle);
        if (!clazz) return std::nullopt;

        jfieldID fid_identityKey   = env->GetFieldID(clazz, "identityKey", "[B");
        jfieldID fid_signedPreKey  = env->GetFieldID(clazz, "signedPreKey", "L" JNI_sid_key_CLASSNAME_MAPPING ";");
        // Either (GcryptSidKey) or non-signed key (GcryptIdKey)
        jfieldID fid_quantumPreKey = env->GetFieldID(clazz, "quantumPreKey", "Ljava/lang/Object;");
        jfieldID fid_oneTimePreKey = env->GetFieldID(clazz, "oneTimePreKey", "L" JNI_id_key_CLASSNAME_MAPPING ";");

        // 1. Identity Key (xckey = key<32>)
        jbyteArray jIdKey = static_cast<jbyteArray>(env->GetObjectField(foreignBundle, fid_identityKey));
        auto identityKeyOpt = to_key<sizeof(gcrypt::xckey)>(JNI_CONTEXT, jIdKey);
        if (jIdKey) env->DeleteLocalRef(jIdKey);

        if (!identityKeyOpt) {
            env->DeleteLocalRef(clazz);
            return std::nullopt;
        }

        // 2. Signed PreKey (xcsikey = sidkey<32, 64>)
        jobject jSignedPreKey = env->GetObjectField(foreignBundle, fid_signedPreKey);
        auto signedPreKeyOpt  = to_sid_key<
            sizeof(decltype(gcrypt::xcsikey::key)), 
            sizeof(decltype(gcrypt::xcsikey::signature))
        >(JNI_CONTEXT, jSignedPreKey);

        if (jSignedPreKey) env->DeleteLocalRef(jSignedPreKey);

        if (!signedPreKeyOpt) {
            env->DeleteLocalRef(clazz);
            return std::nullopt;
        }

        // 3. Quantum PreKey Variant (qsidkey or qpubsidkey)
        jobject jQuantumKey = env->GetObjectField(foreignBundle, fid_quantumPreKey);
        if (!jQuantumKey) {
            env->DeleteLocalRef(clazz);
            return std::nullopt;
        }

        std::variant<gcrypt::qsidkey, gcrypt::qpubikey> quantumPreKey;

        // Check if quantumKey is a signed key (GcryptSidKey) vs non-signed key (GcryptIdKey)
        jclass sidClazz = env->FindClass(JNI_sid_key_CLASSNAME_MAPPING);
        bool isSidKey = (sidClazz && env->IsInstanceOf(jQuantumKey, sidClazz));
        if (sidClazz) env->DeleteLocalRef(sidClazz);

        if (isSidKey) {
            auto qSidOpt = to_sid_key<
                sizeof(decltype(gcrypt::qsidkey::key)), 
                sizeof(decltype(gcrypt::qsidkey::signature))
            >(JNI_CONTEXT, jQuantumKey);

            if (!qSidOpt) {
                env->DeleteLocalRef(jQuantumKey);
                env->DeleteLocalRef(clazz);
                return std::nullopt;
            }
            quantumPreKey = *qSidOpt;
        } 
        else {
            auto qIdOpt = to_id_key<sizeof(decltype(gcrypt::qpubikey::key))>(JNI_CONTEXT, jQuantumKey);

            if (!qIdOpt) {
                env->DeleteLocalRef(jQuantumKey);
                env->DeleteLocalRef(clazz);
                return std::nullopt;
            }
            quantumPreKey = *qIdOpt;
        }
        env->DeleteLocalRef(jQuantumKey);

        // 4. Optional One-Time PreKey
        jobject jOneTimePreKey = env->GetObjectField(foreignBundle, fid_oneTimePreKey);
        std::optional<gcrypt::xcikey> oneTimePreKeyOpt;

        if (jOneTimePreKey) {
            oneTimePreKeyOpt = to_id_key<sizeof(decltype(gcrypt::xcikey::key))>(JNI_CONTEXT, jOneTimePreKey);
            env->DeleteLocalRef(jOneTimePreKey);
        }

        env->DeleteLocalRef(clazz);

        return gcrypt::pqxdh::foreign_prekey_bundle{
            .identityKey   = *identityKeyOpt,
            .signedPreKey  = *signedPreKeyOpt,
            .qpubsidkey    = quantumPreKey,
            .oneTimePreKey = oneTimePreKeyOpt
        };
    }
    std::optional<initial_message_handshake> initial_handshake(
            JNI_PCONTEXT, 
            jobject jHandshake)
    {
        if (!jHandshake) return std::nullopt;

        jclass clazz = env->GetObjectClass(jHandshake);
        if (!clazz) return std::nullopt;

        jfieldID fid_identityKey        = env->GetFieldID(clazz, "identityKey", "[B");
        jfieldID fid_ephemeralKey       = env->GetFieldID(clazz, "ephemeralKey", "[B");
        jfieldID fid_cipherText         = env->GetFieldID(clazz, "cipherText", "[B");
        jfieldID fid_usedPreKeys        = env->GetFieldID(clazz, "usedPreKeys", "[I");
        jfieldID fid_usedQuantumPreKeys = env->GetFieldID(clazz, "usedQuantumPreKeys", "[I");

        initial_message_handshake handshake{};

        // 1. Identity Key (32 bytes)
        jbyteArray jIdKey = static_cast<jbyteArray>(env->GetObjectField(jHandshake, fid_identityKey));
        auto idOpt = to_key<sizeof(gcrypt::xckey)>(JNI_CONTEXT, jIdKey);
        if (jIdKey) env->DeleteLocalRef(jIdKey);
        if (!idOpt) { env->DeleteLocalRef(clazz); return std::nullopt; }
        handshake.identityKey = *idOpt;

        // 2. Ephemeral Key (32 bytes)
        jbyteArray jEphKey = static_cast<jbyteArray>(env->GetObjectField(jHandshake, fid_ephemeralKey));
        auto ephOpt = to_key<sizeof(gcrypt::xckey)>(JNI_CONTEXT, jEphKey);
        if (jEphKey) env->DeleteLocalRef(jEphKey);
        if (!ephOpt) { env->DeleteLocalRef(clazz); return std::nullopt; }
        handshake.ephermoralKey = *ephOpt;

        // 3. CipherText / Quantum Encapsulation (qpubkey bytes)
        jbyteArray jCipher = static_cast<jbyteArray>(env->GetObjectField(jHandshake, fid_cipherText));
        auto cipherOpt = to_key<sizeof(gcrypt::qpubkey)>(JNI_CONTEXT, jCipher);
        if (jCipher) env->DeleteLocalRef(jCipher);
        if (!cipherOpt) { env->DeleteLocalRef(clazz); return std::nullopt; }
        handshake.cipherText = *cipherOpt;

        // 4. Used PreKey IDs (jintArray -> std::vector<uint32_t>)
        jintArray jPreKeys = static_cast<jintArray>(env->GetObjectField(jHandshake, fid_usedPreKeys));
        if (jPreKeys) {
            jsize len = env->GetArrayLength(jPreKeys);
            handshake.usedPreKeys.resize(static_cast<size_t>(len));
            env->GetIntArrayRegion(jPreKeys, 0, len, reinterpret_cast<jint*>(handshake.usedPreKeys.data()));
            env->DeleteLocalRef(jPreKeys);
        }

        // 5. Used Quantum PreKey IDs (jintArray -> std::vector<uint32_t>)
        jintArray jQPreKeys = static_cast<jintArray>(env->GetObjectField(jHandshake, fid_usedQuantumPreKeys));
        if (jQPreKeys) {
            jsize len = env->GetArrayLength(jQPreKeys);
            handshake.usedQuantumPreKeys.resize(static_cast<size_t>(len));
            env->GetIntArrayRegion(jQPreKeys, 0, len, reinterpret_cast<jint*>(handshake.usedQuantumPreKeys.data()));
            env->DeleteLocalRef(jQPreKeys);
        }

        env->DeleteLocalRef(clazz);
        return handshake;
    }
    
}
#pragma endregion 

// below are implementation wrappers for the pqxdh handshake protocol and X3DH E2EE protocol.

GCRYPT_JNI_FUNC_SIG(jint, int) JNI_OnLoad(JavaVM* vm, void* reserved) {
    if (sodium_init() < 0) {
        return JNI_ERR; // Libsodium failed to initialize CSPRNG
    }
    return JNI_VERSION_1_6;
}

/// @brief Makes a local encryption key bundle with the given device ID.
GCRYPT_JNI_FUNC_SIG(jobject, gcrypt::local_key_bundle)
GCRYPT_LIB_JNI_FUNC(makeLocalKeyBundle)(JNI_ENTRY_PCONTEXT, jint deviceId)
{
    uint32_t udId = static_cast<uint32_t>(deviceId);
    local_key_bundle kbundle = make_lkb(udId);

    gcrypt::jni::_GlobalSession = std::make_unique<gcrypt::jni::jni_session>(kbundle);

    return gcrypt::jniOM::from::local_key_bundle(JNI_CONTEXT, kbundle);
}

GCRYPT_JNI_FUNC_SIG(jobject, gcrypt::refill_payload)
GCRYPT_LIB_JNI_FUNC(refill)(JNI_ENTRY_PCONTEXT, jint numKeys)
{
    if (!JNI_SESSION)
        return nullptr;

    uint32_t count = static_cast<uint32_t>(numKeys);

    auto payload = refill(JNI_SESSION->IdentityKey.Private, count);

    return gcrypt::jniOM::from::refill_payload(JNI_CONTEXT, payload);
}


// =============================================================================
// 1. New Session (TOFU / First-time contact)
// =============================================================================
/// @brief Attempts to make a new session message handshake 
///        given the foreign bundle received by the server.
/// @note  This endpoint should only be used for establishing connection
///        with someone who you do not already have a previous connection with,
///        i.e. You do not have their long term identity key to verify that it is them.
///        If you do have this key, invoke @see{initializeExistingSession(longTermIdentityKey, foreignBundle)} instead for security reasons.
/// @return Returns null if something went wrong, or if the signatures were invalid.
GCRYPT_JNI_FUNC_SIG(jobject, gcrypt::session_init_result)
GCRYPT_LIB_JNI_FUNC(initializeNewSession)(
    JNI_ENTRY_PCONTEXT, 
    JNI_OBJREF(gcrypt::foreign_prekey_bundle) foreignBundle)
{
    if (!JNI_SESSION)
        return nullptr;

    auto bundle = gcrypt::jniOM::to::foreignpk_bundle(JNI_CONTEXT, foreignBundle);
    if (!bundle.has_value()) {
        return nullptr;
    }

    // New contact: Verify signatures directly against the bundle's identity key (TOFU)
    auto result = create_outbound_session(JNI_SESSION->IdentityKey, bundle->identityKey, *bundle);
    if (!result.has_value()) {
        return nullptr;
    }

    return gcrypt::jniOM::from::session_init_result(JNI_CONTEXT, *result);
}

// =============================================================================
// 2. Existing Session (Known contact / Stored Identity Key)
// =============================================================================
/// @brief Attempts to make a new session message handshake 
///        given the foreign bundle received by the server, from an existing user (i.e. you have established conections with them before).
/// @note  This endpoint should only be used for establishing connection
///        with someone who you do already have a previous connection with,
///        i.e. You have their long term identity key to verify that it is them.
///        If you do not have this key, invoke @see{initializeNewSession(foreignBundle)} instead for
///        new user session establishment.
/// @return Returns null if something went wrong, or if the signatures were invalid.
GCRYPT_JNI_FUNC_SIG(jobject, gcrypt::session_init_result)
GCRYPT_LIB_JNI_FUNC(initializeExistingSession)(
    JNI_ENTRY_PCONTEXT, 
    jbyteArray _longTermIdentityKey,
    JNI_OBJREF(gcrypt::foreign_prekey_bundle) foreignBundle)
{
    if (!JNI_SESSION)
        return nullptr;
        
    auto bundle = gcrypt::jniOM::to::foreignpk_bundle(JNI_CONTEXT, foreignBundle);
    if (!bundle.has_value()) {
        return nullptr;
    }

    auto longTermIdentityKey = gcrypt::jniOM::to::to_key<sizeof(gcrypt::xckey)>(JNI_CONTEXT, _longTermIdentityKey);
    if (!longTermIdentityKey.has_value()) {
        return nullptr;
    }

    // Existing contact: Verify signatures against our locally trusted identity key
    auto result = create_outbound_session(JNI_SESSION->IdentityKey, *longTermIdentityKey, *bundle);
    if (!result.has_value()) {
        return nullptr;
    }

    return gcrypt::jniOM::from::session_init_result(JNI_CONTEXT, *result);
}

// =============================================================================
// 3. Processing Incoming Handshake (Bob / Recipient side)
// =============================================================================
GCRYPT_JNI_FUNC_SIG(jobject, gcrypt::gcrypt_messaging_session)
GCRYPT_LIB_JNI_FUNC(handleInitialHandshake)(
    JNI_ENTRY_PCONTEXT,
    JNI_OBJREF(gcrypt::initial_message_handshake) message)
{
    if (!JNI_SESSION)
        return nullptr;

    auto handshakeMsg = gcrypt::jniOM::to::initial_handshake(JNI_CONTEXT, message);
    if (!handshakeMsg.has_value()) {
        return nullptr;
    }

    // 1. Look up Bob's matching private keys using handshakeMsg->usedPreKeys / usedQuantumPreKeys
    // 2. Perform DH decapsulation using Alice's EKA and IK_A
    // 3. Derive Bob's matching Master Secret
    
    // messaging_session bobSession = ...;
    return nullptr;
    // return gcrypt::jniOM::from::messaging_session(JNI_CONTEXT, bobSession);
}