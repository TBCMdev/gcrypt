#pragma once
#include "jni.h"
#include "protocol.hpp"

/*
    Contains the wrapper definitions for integrating gcrypt with java/kotlin.
*/

#define GCRYPT_JAVA Java_
#define GCRYPT_PACKAGE_NAME io_github_gckoltys_gecko_gcrypt_
#define GCRYPT_JNI_FUNC_SIG(ret, cpp_structure_equivalent) JNIEXPORT ret JNICALL

#define GCRYPT_LIB_JNI_FUNC(name) GCRYPT_JAVA##GCRYPT_PACKAGE_NAME ##_name

#define JNI_ENV_NAME env
#define JNI_INSTANCE_NAME instance

#define JNI_ENTRY_PCONTEXT JNIEnv* JNI_ENV_NAME, jobject JNI_INSTANCE_NAME
#define JNI_PCONTEXT JNIEnv* JNI_ENV_NAME
#define JNI_CONTEXT JNI_ENV_NAME
#define JNI_SESSION_NAME _GlobalSession

#define JNI_SESSION gcrypt::jni::JNI_SESSION_NAME

// Jni Object parameter
#define JNI_POBJ(x) "L" x ";"

// Package path prefix required by FindClass (using slashes)
#define GCRYPT_PKG_PATH "io/github/gckoltys/gecko/gcrypt/"

#pragma region JNI_InbuildMappings
    #define JNI_CONSTRUCTOR_NAME "<init>"
    #define JAVA_UTIL_PACKAGE    "java/util/"

    #define JAVA_OBJECT_NAME     "Object"
    #define JAVA_OBJECT_PATH     JAVA_UTIL_PACKAGE JAVA_OBJECT_NAME
    #define JAVA_MAP_PATH        JAVA_UTIL_PACKAGE "Map"
#pragma endregion

#pragma region JNI_StructureMappings
    #define JNI_INBUILT_hashmap_CLASSNAME_MAPPING       JAVA_UTIL_PACKAGE "HashMap"
    #define JNI_local_key_bundle_CLASSNAME_MAPPING      GCRYPT_PKG_PATH "GcryptLocalKeyBundle"
    #define JNI_key_pair_CLASSNAME_MAPPING              GCRYPT_PKG_PATH "GcryptKeyPair"
    #define JNI_id_key_CLASSNAME_MAPPING                GCRYPT_PKG_PATH "GcryptIdKey"
    #define JNI_sid_key_CLASSNAME_MAPPING               GCRYPT_PKG_PATH "GcryptSidKey"
    #define JNI_public_server_payload_CLASSNAME_MAPPING GCRYPT_PKG_PATH "GcryptPublicServerPayload"
    #define JNI_refill_payload_CLASSNAME_MAPPING        GCRYPT_PKG_PATH "GcryptKeyRefillPayload"
#pragma endregion

#pragma region JNI_ObjectMethodSignatures
    #define JNI_INBUILD_hashmap_put_METHOD_SIG "(" JNI_POBJ(JAVA_OBJECT_PATH) JNI_POBJ(JAVA_OBJECT_PATH) ")" JNI_POBJ(JAVA_OBJECT_PATH)
#pragma endregion

#pragma region JNI_ObjectConstructorSignatures
    #define JNI_EMPTY_CONSTRUCTOR_SIG                 "()V"
    #define JNI_local_key_bundle_CONSTRUCTOR_SIG      "()V"
    #define JNI_key_pair_CONSTRUCTOR_SIG              "([B[B)V"
    #define JNI_id_key_CONSTRUCTOR_SIG                "([BI)V"
    #define JNI_sid_key_CONSTRUCTOR_SIG               "([BI[B)V"
    #define JNI_public_server_payload_CONSTRUCTOR_SIG "()V"
    #define JNI_refill_payload_CONSTRUCTOR_SIG        "()V"
#pragma endregion

namespace gcrypt::jni
{
    /// @brief All important keys, used for endpoints to avoid passing in keys each time.
    struct jni_session
    {
        xckeypair  IdentityKey;
        xcikeypair SignedPreKey;

    public:
        jni_session(local_key_bundle& ref)
        {
            IdentityKey = ref.IdentityKey;
            SignedPreKey = ref.SignedPreKey;
        }
    };

    /// @brief A Global reference to important key storage
    inline std::unique_ptr<jni_session> JNI_SESSION_NAME = nullptr;
}

/// @brief JNI Object Mapping
namespace gcrypt::jniOM
{
    template<std::size_t _Bytes>
    jbyteArray key(JNI_PCONTEXT, const gcrypt::key<_Bytes>& k)
    {
        jbyteArray array = env->NewByteArray(_Bytes);
        env->SetByteArrayRegion(array, 0, _Bytes, reinterpret_cast<const jbyte*>(k.data()));
        return array;
    }

    template<std::size_t _BytesPublic,
             std::size_t _BytesPrivate,
             template<std::size_t> typename _PublicKeyType = gcrypt::key,
             template<std::size_t> typename _PrivateKeyType = _PublicKeyType
            >
    jobject key_pair(JNI_PCONTEXT, const gcrypt::_keypair_impl<_PublicKeyType, _PrivateKeyType, _BytesPublic, _BytesPrivate>& k)
    {
        const jclass clazz = env->FindClass(JNI_key_pair_CLASSNAME_MAPPING);
        if (!clazz) return nullptr;

        jmethodID constructor = env->GetMethodID(clazz, JNI_CONSTRUCTOR_NAME, JNI_key_pair_CONSTRUCTOR_SIG);

        jbyteArray pubArray = key(JNI_CONTEXT, k.Public);
        jbyteArray privArray = key(JNI_CONTEXT, k.Private);

        jobject keyPairObj = env->NewObject(clazz, constructor, pubArray, privArray);

        env->DeleteLocalRef(pubArray);
        env->DeleteLocalRef(privArray);
        env->DeleteLocalRef(clazz);

        return keyPairObj;
    }

    template<std::size_t _Bytes>
    jobject id_key(JNI_PCONTEXT, const gcrypt::idkey<_Bytes>& k)
    {
        const jclass clazz = env->FindClass(JNI_id_key_CLASSNAME_MAPPING);
        if (!clazz) return nullptr;

        jmethodID constructor = env->GetMethodID(clazz, JNI_CONSTRUCTOR_NAME, JNI_id_key_CONSTRUCTOR_SIG);

        jbyteArray keyArray = key(JNI_CONTEXT, k.key);
        jint id = static_cast<jint>(k.identifier);

        jobject idKeyObj = env->NewObject(clazz, constructor, keyArray, id);

        env->DeleteLocalRef(keyArray);
        env->DeleteLocalRef(clazz);

        return idKeyObj;
    }

    template<std::size_t _Bytes, std::size_t _SigBytes>
    jobject sid_key(JNI_PCONTEXT, const gcrypt::sidkey<_Bytes, _SigBytes>& k)
    {
        const jclass clazz = env->FindClass(JNI_sid_key_CLASSNAME_MAPPING);
        if (!clazz) return nullptr;

        jmethodID constructor = env->GetMethodID(clazz, JNI_CONSTRUCTOR_NAME, JNI_sid_key_CONSTRUCTOR_SIG);

        jbyteArray keyArray = key(JNI_CONTEXT, k.key);
        jint id = static_cast<jint>(k.identifier);
        jbyteArray sigArray = key(JNI_CONTEXT, k.signature);

        jobject sidKeyObj = env->NewObject(clazz, constructor, keyArray, id, sigArray);

        env->DeleteLocalRef(keyArray);
        env->DeleteLocalRef(sigArray);
        env->DeleteLocalRef(clazz);

        return sidKeyObj;
    }

    // =========================================================================
    // 2. Container (Vector / Array) Mappers
    // =========================================================================

    /// @brief Converts any container (std::vector or std::array) of idkey into a Java GcryptIdKey[] array.
    template<typename Container>
    jobjectArray id_key_vector(JNI_PCONTEXT, const Container& vec)
    {
        jclass elemClazz = env->FindClass(JNI_id_key_CLASSNAME_MAPPING);
        if (!elemClazz) return nullptr;

        jobjectArray array = env->NewObjectArray(vec.size(), elemClazz, nullptr);

        for (size_t i = 0; i < vec.size(); ++i) {
            jobject elem = id_key(JNI_CONTEXT, vec[i]);
            env->SetObjectArrayElement(array, i, elem);
            env->DeleteLocalRef(elem);
        }

        env->DeleteLocalRef(elemClazz);
        return array;
    }

    /// @brief Converts any container (std::vector or std::array) of sidkey into a Java GcryptSidKey[] array.
    template<typename Container>
    jobjectArray sid_key_vector(JNI_PCONTEXT, const Container& vec)
    {
        jclass elemClazz = env->FindClass(JNI_sid_key_CLASSNAME_MAPPING);
        if (!elemClazz) return nullptr;

        jobjectArray array = env->NewObjectArray(vec.size(), elemClazz, nullptr);

        for (size_t i = 0; i < vec.size(); ++i) {
            jobject elem = sid_key(JNI_CONTEXT, vec[i]);
            env->SetObjectArrayElement(array, i, elem);
            env->DeleteLocalRef(elem);
        }

        env->DeleteLocalRef(elemClazz);
        return array;
    }

    template<template<std::size_t> typename _KeyType = gcrypt::key, std::size_t _Bytes>
    jobjectArray key_vector(JNI_PCONTEXT, const std::vector<_KeyType<_Bytes>>& vec)
    {
        jclass elemClazz = env->FindClass("[B");
        if (!elemClazz) return nullptr;

        jobjectArray array = env->NewObjectArray(vec.size(), elemClazz, nullptr);

        for (size_t i = 0; i < vec.size(); ++i) {
            jobject elem = key(JNI_CONTEXT, vec[i]);
            env->SetObjectArrayElement(array, i, elem);
            env->DeleteLocalRef(elem);
        }

        env->DeleteLocalRef(elemClazz);
        return array;
    }

    template<std::size_t _BytesPublic, std::size_t _BytesPrivate>
    jobjectArray key_pair_vector(JNI_PCONTEXT, const std::vector<gcrypt::ukeypair<_BytesPublic, _BytesPrivate>>& vec)
    {
        jclass elemClazz = env->FindClass(JNI_key_pair_CLASSNAME_MAPPING);
        if (!elemClazz) return nullptr;

        jobjectArray array = env->NewObjectArray(vec.size(), elemClazz, nullptr);

        for (size_t i = 0; i < vec.size(); ++i) {
            jobject elem = key_pair(JNI_CONTEXT, vec[i]);
            env->SetObjectArrayElement(array, i, elem);
            env->DeleteLocalRef(elem);
        }

        env->DeleteLocalRef(elemClazz);
        return array;
    }

    template<std::size_t _BytesPublic, std::size_t _BytesPrivate>
    jobject key_pair_map(JNI_PCONTEXT, const std::unordered_map<uint32_t, gcrypt::ukeypair<_BytesPublic, _BytesPrivate>>& _map)
    {
        jclass hashMapClass = env->FindClass(JNI_INBUILT_hashmap_CLASSNAME_MAPPING);
        if (!hashMapClass) return nullptr;

        jmethodID constructor = env->GetMethodID(hashMapClass, JNI_CONSTRUCTOR_NAME, JNI_EMPTY_CONSTRUCTOR_SIG);
        jobject hashmap       = env->NewObject(hashMapClass, constructor);

        jmethodID putMethod   = env->GetMethodID(hashMapClass, "put", JNI_INBUILD_hashmap_put_METHOD_SIG);

        for (const auto& [k, val] : _map)
        {
            const jint ckey    = static_cast<jint>(k);
            const jobject cval = key_pair(JNI_CONTEXT, val);

            env->CallObjectMethod(hashmap, putMethod, ckey, cval);

            env->DeleteLocalRef(cval);
        }

        env->DeleteLocalRef(hashMapClass);
        return hashmap;
    }

    // =========================================================================
    // Structure Mappers
    // =========================================================================

    jobject local_key_bundle(JNI_PCONTEXT, const gcrypt::local_key_bundle& bundle)
    {
        const jclass clazz = env->FindClass(JNI_local_key_bundle_CLASSNAME_MAPPING);
        if (!clazz) return nullptr;

        jmethodID constructor = env->GetMethodID(clazz, JNI_CONSTRUCTOR_NAME, JNI_local_key_bundle_CONSTRUCTOR_SIG);
        jobject obj = env->NewObject(clazz, constructor);
        if (!obj) {
            env->DeleteLocalRef(clazz);
            return nullptr;
        }

        jfieldID fid_identityKey    = env->GetFieldID(clazz, "identityKey", "L" JNI_key_pair_CLASSNAME_MAPPING ";");
        jfieldID fid_signedPreKey   = env->GetFieldID(clazz, "signedPreKey", "L" JNI_key_pair_CLASSNAME_MAPPING ";");
        jfieldID fid_quantumPreKey  = env->GetFieldID(clazz, "quantumPreKey", "L" JNI_key_pair_CLASSNAME_MAPPING ";");
        jfieldID fid_oneTimePreKeys = env->GetFieldID(clazz, "oneTimePreKeys", "L" JAVA_MAP_PATH ";");
        jfieldID fid_oneTimeQuantum = env->GetFieldID(clazz, "oneTimeQuantumKeys", "L" JAVA_MAP_PATH ";");

        jobject identityObj = key_pair(JNI_CONTEXT, bundle.IdentityKey);
        env->SetObjectField(obj, fid_identityKey, identityObj);
        env->DeleteLocalRef(identityObj);

        jobject signedObj = key_pair(JNI_CONTEXT, bundle.SignedPreKey);
        env->SetObjectField(obj, fid_signedPreKey, signedObj);
        env->DeleteLocalRef(signedObj);

        jobject quantumObj = key_pair(JNI_CONTEXT, bundle.QuantumPreKey);
        env->SetObjectField(obj, fid_quantumPreKey, quantumObj);
        env->DeleteLocalRef(quantumObj);

        jobject otPreKeysMap = key_pair_map(JNI_CONTEXT, bundle.OneTimePreKeys);
        env->SetObjectField(obj, fid_oneTimePreKeys, otPreKeysMap);
        env->DeleteLocalRef(otPreKeysMap);

        jobject otQuantumMap = key_pair_map(JNI_CONTEXT, bundle.OneTimeQuantumKeys);
        env->SetObjectField(obj, fid_oneTimeQuantum, otQuantumMap);
        env->DeleteLocalRef(otQuantumMap);

        env->DeleteLocalRef(clazz);
        return obj;
    }

    jobject refill_payload(JNI_PCONTEXT, const gcrypt::refill_payload& payload)
    {
        const jclass clazz = env->FindClass(JNI_refill_payload_CLASSNAME_MAPPING);
        if (!clazz) return nullptr;

        jmethodID constructor = env->GetMethodID(clazz, JNI_CONSTRUCTOR_NAME, JNI_refill_payload_CONSTRUCTOR_SIG);
        if (!constructor) {
            env->DeleteLocalRef(clazz);
            return nullptr;
        }

        jobject obj = env->NewObject(clazz, constructor);
        if (!obj) {
            env->DeleteLocalRef(clazz);
            return nullptr;
        }

        jfieldID fid_oneTimePreKeys = env->GetFieldID(
            clazz, 
            "oneTimePreKeys", 
            "[L" JNI_id_key_CLASSNAME_MAPPING ";"
        );

        jfieldID fid_signedOneTimeQuantumPreKeys = env->GetFieldID(
            clazz, 
            "signedOneTimeQuantumPreKeys", 
            "[L" JNI_sid_key_CLASSNAME_MAPPING ";"
        );

        // Uses id_key_vector and sid_key_vector for std::vector
        jobject otPreKeysArray = id_key_vector(JNI_CONTEXT, payload.oneTimePreKeys);
        env->SetObjectField(obj, fid_oneTimePreKeys, otPreKeysArray);
        env->DeleteLocalRef(otPreKeysArray);

        jobject otQuantumArray = sid_key_vector(JNI_CONTEXT, payload.signedOneTimeQuantumPreKeys);
        env->SetObjectField(obj, fid_signedOneTimeQuantumPreKeys, otQuantumArray);
        env->DeleteLocalRef(otQuantumArray);

        env->DeleteLocalRef(clazz);
        return obj;
    }

    template<std::size_t _OneTimePreKeyCount>
    jobject public_server_payload(JNI_PCONTEXT, const gcrypt::public_server_payload<_OneTimePreKeyCount>& payload)
    {
        const jclass clazz = env->FindClass(JNI_public_server_payload_CLASSNAME_MAPPING);
        if (!clazz) return nullptr;

        jmethodID constructor = env->GetMethodID(clazz, JNI_CONSTRUCTOR_NAME, JNI_public_server_payload_CONSTRUCTOR_SIG);
        if (!constructor) {
            env->DeleteLocalRef(clazz);
            return nullptr;
        }

        jobject obj = env->NewObject(clazz, constructor);
        if (!obj) {
            env->DeleteLocalRef(clazz);
            return nullptr;
        }

        jfieldID fid_registration  = env->GetFieldID(clazz, "registration", "I");
        jfieldID fid_deviceId      = env->GetFieldID(clazz, "deviceId", "I");
        jfieldID fid_identityKey   = env->GetFieldID(clazz, "identityKey", "[B");
        jfieldID fid_signedPreKey  = env->GetFieldID(clazz, "signedPreKey", "L" JNI_sid_key_CLASSNAME_MAPPING ";");
        jfieldID fid_quantumPreKey = env->GetFieldID(clazz, "quantumPreKey", "L" JNI_sid_key_CLASSNAME_MAPPING ";");
        
        jfieldID fid_oneTimePreKeys = env->GetFieldID(
            clazz, 
            "oneTimePreKeys", 
            "[L" JNI_id_key_CLASSNAME_MAPPING ";"
        );
        jfieldID fid_signedOneTimeQuantumPreKeys = env->GetFieldID(
            clazz, 
            "signedOneTimeQuantumPreKeys", 
            "[L" JNI_sid_key_CLASSNAME_MAPPING ";"
        );

        env->SetIntField(obj, fid_registration, static_cast<jint>(payload.registration));
        env->SetIntField(obj, fid_deviceId, static_cast<jint>(payload.deviceId));

        jbyteArray identityKeyObj = key(JNI_CONTEXT, payload.identityKey);
        env->SetObjectField(obj, fid_identityKey, identityKeyObj);
        env->DeleteLocalRef(identityKeyObj);

        jobject signedPreKeyObj = sid_key(JNI_CONTEXT, payload.signedPreKey);
        env->SetObjectField(obj, fid_signedPreKey, signedPreKeyObj);
        env->DeleteLocalRef(signedPreKeyObj);

        jobject quantumPreKeyObj = sid_key(JNI_CONTEXT, payload.quantumPreKey);
        env->SetObjectField(obj, fid_quantumPreKey, quantumPreKeyObj);
        env->DeleteLocalRef(quantumPreKeyObj);

        // Uses id_key_vector and sid_key_vector for std::array
        jobject otPreKeysArray = id_key_vector(JNI_CONTEXT, payload.oneTimePreKeys);
        env->SetObjectField(obj, fid_oneTimePreKeys, otPreKeysArray);
        env->DeleteLocalRef(otPreKeysArray);

        jobject otQuantumArray = sid_key_vector(JNI_CONTEXT, payload.signedOneTimeQuantumPreKeys);
        env->SetObjectField(obj, fid_signedOneTimeQuantumPreKeys, otQuantumArray);
        env->DeleteLocalRef(otQuantumArray);

        env->DeleteLocalRef(clazz);
        return obj;
    }
}