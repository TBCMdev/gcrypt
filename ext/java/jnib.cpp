#include "jnib.hpp"

#include "keygen.hpp"



/// @brief Makes a local encryption key bundle with the given device ID.
GCRYPT_JNI_FUNC_SIG(jobject, gcrypt::local_key_bundle)
GCRYPT_LIB_JNI_FUNC(makeLocalKeyBundle)(JNI_ENTRY_PCONTEXT, jint deviceId)
{
    uint32_t udId = static_cast<uint32_t>(deviceId);
    gcrypt::local_key_bundle kbundle = gcrypt::make_lkb(udId);

    gcrypt::jni::_GlobalSession = std::make_unique<gcrypt::jni::jni_session>(kbundle);

    return gcrypt::jniOM::local_key_bundle(JNI_CONTEXT, kbundle);
}

GCRYPT_JNI_FUNC_SIG(jobject, gcrypt::refill_payload)
GCRYPT_LIB_JNI_FUNC(refill)(JNI_ENTRY_PCONTEXT, jint numKeys)
{
    if (!JNI_SESSION)
        return nullptr;

    uint32_t count = static_cast<uint32_t>(numKeys);

    auto payload = gcrypt::keygen::refill(JNI_SESSION->IdentityKey.Private, count);

    return gcrypt::jniOM::refill_payload(JNI_CONTEXT, payload);
}