#pragma once
#include <string>
#include <cstdint>
#include <array>
#include <vector>
#include <memory>
#include <unordered_map>
#include <variant>
#include <optional>
#include <span>
#include <sodium.h>

#define GCRYPT_VERSION_STRING "0.0.1"
#define GCRYPT_X25519_KEY_SIZE 32
#define GCRYPT_HASH_SIZE 512
#define GCRYPT_SIGNATURE_SIZE 64
#define GCRYPT_INFO "gecko-protocol-" GCRYPT_VERSION_STRING

extern "C"
{
    
    #ifndef MLK_CONFIG_PARAMETER_SET
        #define MLK_CONFIG_PARAMETER_SET 1024
    #endif
    #ifndef MLK_CONFIG_NAMESPACE_PREFIX
        #define MLK_CONFIG_NAMESPACE_PREFIX mlkimpl
    #endif
    #include <mlkem_native.h>
}

// quantum byte size (CipherTextBytes)
#define MLKEM_PKB MLKEM_PUBLICKEYBYTES(MLK_CONFIG_PARAMETER_SET)  // 1568 bytes
#define MLKEM_SKB MLKEM_SECRETKEYBYTES(MLK_CONFIG_PARAMETER_SET)  // 3168 bytes
#define MLKEM_CTB MLKEM_CIPHERTEXTBYTES(MLK_CONFIG_PARAMETER_SET) // 1568 bytes

#define GCRYPT_INITIAL_PREKEY_BUNDLE_COUNT 100

namespace gcrypt
{

    template<std::size_t _Size>
    using bytekey = std::array<uint8_t, _Size>;

    /// @brief (just a varying array of bytes).
    using bytespan = std::span<uint8_t>;
    /// @brief A key of varying size
    using vkey = std::vector<uint8_t>;


    template<std::size_t _Bytes>
    class key
    {
    private:
        std::array<uint8_t, _Bytes> impl_storage{};
    public:
        key() = default;
        key(const key& other) = default;
        key(key&& other) noexcept : impl_storage(other.impl_storage)
        { other.kill(); }

        ~key() { kill(); }

        key& operator=(key&& other) noexcept
        {
            if (this != &other)
            {
                kill(); // Clear old secret first
                impl_storage = other.impl_storage;
                other.kill(); // Clear source
            }
            return *this;
        }
        key& operator=(const key& other)
        {
            if (this != &other)
            {
                kill(); // Erase current secret first
                impl_storage = other.impl_storage;
            }
            return *this;
        }

        /// @brief Sets the memory region of this key to all zeros.
        void kill() noexcept { sodium_memzero(data(), _Bytes); }

        constexpr uint8_t* data() noexcept { return impl_storage.data(); }
        std::array<uint8_t, _Bytes>& bytes() noexcept { return impl_storage; }
        const std::array<uint8_t, _Bytes>& bytes() const noexcept { return impl_storage; }
        constexpr const uint8_t* data() const noexcept { return impl_storage.data(); }
        constexpr std::size_t size() const noexcept { return _Bytes; }

        uint8_t& operator[](std::size_t idx) { return impl_storage[idx]; }
        const uint8_t& operator[](std::size_t idx) const { return impl_storage[idx]; }
        
        operator bytekey<_Bytes>&() noexcept { return impl_storage; }
        operator const bytekey<_Bytes>&() const noexcept { return impl_storage; }

        auto begin() noexcept { return impl_storage.begin(); }
        auto end() noexcept { return impl_storage.end(); }
        auto begin() const noexcept { return impl_storage.begin(); }
        auto end() const noexcept { return impl_storage.end(); }
    };

    /// @brief The implementation of a generic keypair.
    /// @tparam _BytesPublic the public key's bytes
    /// @tparam _BytesPrivate the private key's bytes
    /// @tparam _PublicKeyType the public key's type
    /// @tparam _PrivateKeyType the private key's type
    template<
        template<std::size_t> class _PublicKeyType,
        template<std::size_t> class _PrivateKeyType,
        std::size_t _PublicBytes,
        std::size_t _PrivateBytes
            >
    struct _keypair_impl
    {
        _PublicKeyType<_PublicBytes> Public;
        _PrivateKeyType<_PrivateBytes> Private;
    };
    /// @brief An identifiable key of length _Bytes.
    template<std::size_t _Bytes>
    struct idkey
    {
        key<_Bytes> key;
        uint32_t    identifier;
    };
    /// @brief An identifiable key of length _Bytes with a signature of _SigBytes = _Bytes.
    template<std::size_t _Bytes, std::size_t _SigBytes = _Bytes>
    struct sidkey : idkey<_Bytes>
    {
        key<_SigBytes> signature;
    };

    /// @brief A public/private keypair of the same size.
    /// @tparam _Bytes The bytes of the keys
    /// @tparam _PublicKeyType the public key's type
    /// @tparam _PrivateKeyType the private key's type
    template<std::size_t _Bytes,
             template<std::size_t> typename _PublicKeyType = key,
             template<std::size_t> typename _PrivateKeyType = _PublicKeyType
            >
    using keypair = _keypair_impl<_PublicKeyType, _PrivateKeyType, _Bytes, _Bytes>;

    
    /// @brief A public/private keypair of unique (different) sizes.
    /// @tparam _BytesPublic the public key's bytes
    /// @tparam _BytesPrivate the private key's bytes
    /// @tparam _PublicKeyType the public key's type
    /// @tparam _PrivateKeyType the private key's type
    template<std::size_t _BytesPublic,
             std::size_t _BytesPrivate,
             template<std::size_t> typename _PublicKeyType = key,
             template<std::size_t> typename _PrivateKeyType = _PublicKeyType
            >
    using ukeypair = _keypair_impl<_PublicKeyType, _PrivateKeyType, _BytesPublic, _BytesPrivate>;

    

    /// @brief curve (X25519 alg) key
    using xckey        = key<GCRYPT_X25519_KEY_SIZE>;
    using xcikey       = idkey<GCRYPT_X25519_KEY_SIZE>;
    using xcsikey      = sidkey<GCRYPT_X25519_KEY_SIZE, GCRYPT_SIGNATURE_SIZE>;
    using xckeypair    = keypair<GCRYPT_X25519_KEY_SIZE>;
    /// @brief An identifiable xcurve key. Note that the public key contains the indentifier, yet can be used to identify the private key as well.
    using xcikeypair   = keypair<GCRYPT_X25519_KEY_SIZE, idkey, key>;
    
    /// @brief curve (Ed25519 alg) key.
    using edkeypair    = xckeypair;
    using edikeypair   = xcikeypair;
    
    /// @brief Ed25519 curve key with signature and identifier
    using edsidkey     = xcsikey;

    /// @brief quantum key
    using qpubkey      = key<MLKEM_PKB>;
    using qpubikey     = idkey<MLKEM_PKB>;
    using qprivkey     = key<MLKEM_SKB>;
    using qprivikey    = idkey<MLKEM_PKB>;

    using qpubsidkey   = sidkey<MLKEM_PKB, GCRYPT_SIGNATURE_SIZE>;
    using qprivsidkey  = sidkey<MLKEM_PKB, GCRYPT_SIGNATURE_SIZE>;

    using qkeypair     = ukeypair<MLKEM_PKB, MLKEM_SKB>;
    using qikeypair    = ukeypair<MLKEM_PKB, MLKEM_SKB, idkey, key>;
    /// @brief quantum key with signature and identifier
    using qsidkey      = sidkey<MLKEM_CTB, GCRYPT_SIGNATURE_SIZE>;
}