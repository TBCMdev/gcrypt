#include "jni.h"
#include "protocol.hpp"

#define GCRYPT_JAVA Java_
#define GCRYPT_PACKAGE_NAME io_github_gckoltys_gecko_gcrypt_
#define GCRYPT_JNI_FUNC_SIG(ret) JNIEXPORT ret JNICALL

#define GCRYPT_LIB_JNI_FUNC(name) GCRYPT_JAVA##GCRYPT_PACKAGE_NAME ##_name

#define JNI_ENV_NAME env
#define JNI_INSTANCE_NAME instance
#define JNI_PCONTEXT JNIEnv* JNI_ENV_NAME, jobject JNI_INSTANCE_NAME
#define JNI_CONTEXT JNI_ENV_NAME, JNI_INSTANCE_NAME

// Package path prefix required by FindClass (using slashes)
#define GCRYPT_PKG_PATH "io/github/gckoltys/gecko/gcrypt/"

#pragma region JNI_InbuildMappings
    #define JNI_CONSTRUCTOR_NAME "<init>"
#pragma endregion

#pragma region JNI_StructureMappings
    #define JNI_local_key_bundle_CLASSNAME_MAPPING      GCRYPT_PKG_PATH "GcryptLocalKeyBundle"
    #define JNI_key_pair_CLASSNAME_MAPPING              GCRYPT_PKG_PATH "GcryptKeyPair"
    #define JNI_id_key_CLASSNAME_MAPPING                GCRYPT_PKG_PATH "GcryptIdKey"
    #define JNI_sid_key_CLASSNAME_MAPPING               GCRYPT_PKG_PATH "GcryptSidKey"
    #define JNI_public_server_payload_CLASSNAME_MAPPING GCRYPT_PKG_PATH "GcryptPublicServerPayload"
#pragma endregion

#pragma region JNI_ObjectConstructorSignatures
    #define JNI_local_key_bundle_CONSTRUCTOR_SIG      "()V"
    #define JNI_key_pair_CONSTRUCTOR_SIG              "([B[B)V"
    #define JNI_id_key_CONSTRUCTOR_SIG                "([BI)V"
    #define JNI_sid_key_CONSTRUCTOR_SIG               "([BI[B)V"
    #define JNI_public_server_payload_CONSTRUCTOR_SIG "()V"
#pragma endregion

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
             template<std::size_t> class _PublicKeyType = gcrypt::key,
             template<std::size_t> class _PrivateKeyType = _PublicKeyType
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
    jobject local_key_bundle(JNI_PCONTEXT, const gcrypt::local_key_bundle& bundle)
    {
        const jclass clazz = env->FindClass(JNI_local_key_bundle_CLASSNAME_MAPPING);
        if (!clazz) return nullptr;

        jmethodID constructor = env->GetMethodID(clazz, JNI_CONSTRUCTOR_NAME, JNI_local_key_bundle_CONSTRUCTOR_SIG);
        jobject obj = env->NewObject(clazz, constructor);
        if (!obj) return nullptr;

        jfieldID fid_identityKey    = env->GetFieldID(clazz, "identityKey", "L" JNI_key_pair_CLASSNAME_MAPPING ";");
        jfieldID fid_signedPreKey   = env->GetFieldID(clazz, "signedPreKey", "L" JNI_key_pair_CLASSNAME_MAPPING ";");
        jfieldID fid_quantumPreKey  = env->GetFieldID(clazz, "quantumPreKey", "L" JNI_key_pair_CLASSNAME_MAPPING ";");
        jfieldID fid_oneTimePreKeys = env->GetFieldID(clazz, "oneTimePreKeys", "[L" JNI_key_pair_CLASSNAME_MAPPING ";");
        jfieldID fid_oneTimeQuantum = env->GetFieldID(clazz, "oneTimeQuantumKeys", "[L" JNI_key_pair_CLASSNAME_MAPPING ";");

        jobject identityObj = key_pair(JNI_CONTEXT, bundle.IdentityKey);
        env->SetObjectField(obj, fid_identityKey, identityObj);
        env->DeleteLocalRef(identityObj);

        jobject signedObj = key_pair(JNI_CONTEXT, bundle.SignedPreKey);
        env->SetObjectField(obj, fid_signedPreKey, signedObj);
        env->DeleteLocalRef(signedObj);

        jobject quantumObj = key_pair(JNI_CONTEXT, bundle.QuantumPreKey);
        env->SetObjectField(obj, fid_quantumPreKey, quantumObj);
        env->DeleteLocalRef(quantumObj);

        jobjectArray otPreKeysArr = key_pair_vector(JNI_CONTEXT, bundle.OneTimePreKeys);
        env->SetObjectField(obj, fid_oneTimePreKeys, otPreKeysArr);
        env->DeleteLocalRef(otPreKeysArr);

        jobjectArray otQuantumArr = key_pair_vector(JNI_CONTEXT, bundle.OneTimeQuantumKeys);
        env->SetObjectField(obj, fid_oneTimeQuantum, otQuantumArr);
        env->DeleteLocalRef(otQuantumArr);

        env->DeleteLocalRef(clazz);
        return obj;
    }
}

/// @brief JNI Export Entry Point
GCRYPT_JNI_FUNC_SIG(jobject)
GCRYPT_LIB_JNI_FUNC(MakeLocalKeyBundle)(JNI_PCONTEXT, jint deviceId)
{
    uint32_t udId = static_cast<uint32_t>(deviceId);
    gcrypt::local_key_bundle kbundle = gcrypt::make_lkb(udId);

    return gcrypt::jniOM::local_key_bundle(JNI_CONTEXT, kbundle);
}