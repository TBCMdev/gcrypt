#pragma once
#include <expected>

#include "protocol.hpp"

namespace gcrypt::keygen
{
    enum class KeyGenError
    {
        LIBRARY_ERROR,
        UNKNOWN_ALGORITHM,
        UNKNOWN
    };

    constexpr const char* descriptive_error(const KeyGenError err)
    {
        switch(err)
        {
            case KeyGenError::LIBRARY_ERROR:
                return "Key Generation failed due to a library error.";
            case KeyGenError::UNKNOWN_ALGORITHM:
                return "Key Generation failed due to lack of an algorithm implementation.";
            default:
                return "Key Generation failed with an unknown error.";    
        }
    }

    /// @brief Creates a key, setting a number of bytes starting with the first byte in little endian form.
    /// @tparam _Size The size of the key to create
    /// @tparam ..._Bytes the bytes to set
    template<std::size_t _Size, std::convertible_to<uint8_t>... _Bytes>
    key<_Size> from_lebytes(_Bytes... bytes)
    {
        key<_Size> out{};

        std::size_t offset = 0;

        ((out[offset++] = static_cast<uint8_t>(bytes)), ...);

        return out;
    }
    /// @brief Creates a key, setting all bytes to be the given byte.
    /// @tparam _Size The size of the key to create
    /// @tparam ..._Bytes the bytes to set
    template<std::size_t _Size, std::convertible_to<uint8_t> _ByteType>
    constexpr key<_Size> from_lebyte(_ByteType byte)
    {
        key<_Size> out{};

        std::fill(out.begin(), out.end(), static_cast<uint8_t>(byte));

        return out;
    }

    /// @brief Safely zeros out the memory of the given key.
    template<std::size_t _Size>
    void kill(key<_Size>& key)
    {
        sodium_memzero(key.data(), _Size);
    }

    /// @brief Safely zeros out the memory of the given keys.
    template<std::size_t... _Sizes>
    void kill(key<_Sizes>&... keys)
    {
        (kill(keys), ...);
    }

    /// @brief Generates a cryptographically secure random key of _Size bytes.
    template<std::size_t _Size>
    key<_Size> random()
    {
        key<_Size> out{};
        randombytes_buf(out.data(), _Size);
        return out;
    }
    
    namespace X25519
    {
        std::expected<xckeypair,KeyGenError> make_pair();
        std::expected<xcikeypair,KeyGenError> make_id_pair();
    }
    namespace Ed25519
    {
        std::expected<edkeypair,KeyGenError> make_pair();
        std::expected<edikeypair,KeyGenError> make_id_pair();
    }
    namespace MLKEM_32
    {
        std::expected<qkeypair, KeyGenError> make_pair();
        std::expected<qikeypair, KeyGenError> make_id_pair();
    }
    
}