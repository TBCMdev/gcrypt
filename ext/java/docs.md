# JNI Gcrypt Protocol

To compile, include the jni files in the compilation, and define the constants:

```
GCRYPT_PACKAGE_NAME=myname
GCRYPT_PKG_PATH=com.example.stuff
```

## Notation

- `GCRYPT_JNI_FUNC_SIG(x, y)`: defines a JNI function that returns a jni type of x (converted from a c++ type y). This is for readability only.
- `JNI_ENTRY_PCONTEXT`: The env and object caller context of a java invocation. Pass this into any endpoint you make.

### Wrapper notation (below)

A wrapper example would be: `c++_function_name(params):ret -> JNI_function_sig(params):ret`

## Wrapperse

### Keys & Key Util

#### `refill(int numKeys): GcryptKeyRefillPayload`
- Maps to : `keygen::refill(uint32_t numKeys): refill_payload `

#### `makeLocalKeyBundle(int deviceId): GcryptLocalKeyBundle`
- Maps to : `pqxdh::make_lkb(uint32_t deviceId): local_key_bundle `
### Session Initializing

#### `initializeNewSession(GcryptForeignPreKeyBundle): GcryptSessionInitResult`
- Maps to : `pqxdh::make_lkb(uint32_t deviceId): local_key_bundle `

#### `initializeExistingSession(GcryptForeignPreKeyBundle): GcryptSessionInitResult`
- Maps to : `pqxdh::create_outbound_session(const xkey&, const foreign_prekey_bundle&): session_init_result `

