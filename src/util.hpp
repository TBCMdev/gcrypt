#pragma once
#include "protocol.hpp"
#include <type_traits>

#include <cstring>
#include <cstddef>
#include <stdexcept>

#include <sodium.h>
#include <tuple>

namespace gcrypt::util
{
    namespace types
    {
        template<std::size_t _S>
        using x2size_t = std::integral_constant<std::size_t, 2 * _S>;

        template<std::size_t... _Sizes>
        using sum_size_t = std::integral_constant<std::size_t, (... + _Sizes)>;
    }

    /// @brief Returns true if both keys are identical.
    /// @tparam _Size The byte size of the key.
    template<std::size_t _Size>
    inline bool kmatch(const key<_Size>& k1, const key<_Size>& k2)
    {
        return sodium_memcmp(k1.data(), k2.data(), _Size) == 0;
    }


    

    /// @brief Copies a keys data.
    template<std::size_t _Size>
    inline key<_Size> kcpy(const key<_Size>& k)
    {
        key<_Size> out{};
        std::memcpy(out.data(), k.data(), _Size);
        return out;
    }
    

    /// @brief Copies _Take bytes of a keys data to a key of length: _Take bytes.
    template<std::size_t _Take, std::size_t _Size>
    inline key<_Take> kcpy(const key<_Size>& k, std::size_t offset = 0)
    {
        key<_Take> out{};
        std::memcpy(out.data(), k.data() + offset, _Take);
        return out;
    }
    /// @brief Copies the keys data to the given span container of bytes, with a given offset.
    /// @throws std::invalid_argument if offset >= the spans size.
    template<std::size_t _Size>
    inline void kcpy(const key<_Size>& k, bytespan&& to, std::size_t offset = 0)
    {
        if (offset >= to.size())
            throw std::invalid_argument("Offset too large.");
        std::copy(k.begin(), k.end(), to.begin() + offset);
    }
    /// @brief Cuts or Slices the given key into two keys of size _Lhs, _Rhs respectively.
    /// @tparam _ISize The input key size.
    /// @tparam _Lhs the size of the left hand side key.
    /// @tparam _Rhs the size of the right hand side key.
    /// @return A tuple containing both keys.
    template<std::size_t _Lhs, std::size_t _Rhs, std::size_t _ISize>
    inline std::tuple<key<_Lhs>, key<_Rhs>> kcut(const key<_ISize>& ikey)
    {
        return std::make_tuple(kcpy<_Lhs>(ikey), kcpy<_Rhs>(ikey, _Lhs));
    }

    /// @brief Concatenates both same sized keys together (k1 || k2) and returns the result.
    template<std::size_t _Size>
    inline key<types::x2size_t<_Size>::value> kconcat(const key<_Size>& k1, const key<_Size>& k2)
    {
        key<types::x2size_t<_Size>::value> out{};

        std::memcpy(out.data(), k1.data(), _Size);
        std::memcpy(out.data() + _Size, k2.data(), _Size);

        return out;
    }

    /// @brief Concatenates two varying sized keys together (k1 || k2) and returns the result.
    template<std::size_t _Pre, std::size_t _Post>
    inline key<(_Pre + _Post)> kconcat(const key<_Pre>& k1, const key<_Post>& k2)
    {
        key<types::sum_size_t<_Pre, _Post>::value> out{};

        std::memcpy(out.data(), k1.data(), _Pre);
        std::memcpy(out.data() + _Pre, k2.data(), _Post);

        return out;
    }

    /// @brief Concatenates all varying sized keys together (k1 || k2 || ...) and returns the result.
    template<std::size_t... _Sizes>
    inline key<(_Sizes + ...)> kconcat(const key<_Sizes>&... keys)
    {
        key<types::sum_size_t<_Sizes...>::value> out{};

        std::size_t offset = 0;
        
        ((std::memcpy(out.data() + offset, keys.data(), _Sizes), offset += _Sizes), ...);

        return out;
    }

    /// @brief Returns the id (hash) of a key. Can be used in place of a generic counter for
    /// @brief assigning identifiers to keys. 
    /// @tparam _Sizes 
    /// @param k 
    /// @return 
    template<std::size_t _Size>
    inline uint32_t keyid(const key<_Size>& publicKey)
    {
        uint32_t key_id = 0;
        
        crypto_generichash(
            reinterpret_cast<unsigned char*>(&key_id), sizeof(key_id),
            reinterpret_cast<const unsigned char*>(publicKey.data()), _Size,
            nullptr, 0
        );

        return key_id;
    }

    /// @brief Returns a variable array (vector) of the bytes each key, concatenated sequentially.
    /// @tparam _Size The size of the keys
    /// @param key the keys of varying byte-sizes.
    /// @return the variable array of the keys internal bytes concatenated together.
    template<std::size_t... _Sizes>
    inline vkey key_bytes(const key<_Sizes>&... keys)
    {
        vkey out{};
        out.reserve(types::sum_size_t<_Sizes...>::value);
        
        size_t offset = 0;

        ((std::copy(keys.begin(), keys.end(), out.begin() + offset), offset += keys.size()), ...);
        
        return out;
    }

    /// @brief Loads the specified byte region into the specified key instance.
    /// @return Whether or not the operation was a success.
    template<std::size_t _Size>
    inline bool load_keyb(const bytespan& bytes, key<_Size>& ref, std::size_t offset = 0)
    {
        if (_Size + offset > bytes.size())
            return false;

        std::copy(bytes.begin() + offset, bytes.begin() + offset + _Size, ref.begin());

        return true;
    }
    /// @brief Loads the specified byte region into the specified key instance,
    ///        And memzeros the contents of the bytes buffer upon success.
    /// @return Whether or not the operation was a success.
    template<std::size_t _Size>
    inline bool load_keyb_s(const bytespan& bytes, key<_Size>& ref, std::size_t offset = 0)
    {
        if (!load_keyb(bytes, ref, offset))
            return false;

        sodium_memzero(bytes.data(), _Size);
        return true;
    }

}