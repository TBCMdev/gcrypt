#pragma once
#include "protocol.hpp"
#include <type_traits>
namespace gcrypt::util
{

    namespace types
    {
        template<std::size_t _S>
        using x2size_t = std::integral_constant<std::size_t, 2 * _S>;

        template<std::size_t... _Sizes>
        using sum_size_t = std::integral_constant<std::size_t, (... + _Sizes)>;
    }

    /// @brief Copies a keys data.
    template<std::size_t _Size>
    key<_Size> kcpy(const key<_Size>& key);

    /// @brief Copies _Take bytes of a keys data to a key of length: _Take bytes.
    template<std::size_t _Take, std::size_t _Size>
    key<_Take> kcpy(const key<_Size>& key, std::size_t offset = 0UL);

    /// @brief Concatenates both same sized keys together (k1 || k2) and returns the result.
    template<std::size_t _Size>
    key<types::x2size_t<_Size>::value> kconcat(const key<_Size>& k1, const key<_Size>& k2);

    /// @brief Concatenates two varying sized keys together (k1 || k2) and returns the result.
    template<std::size_t _Pre, std::size_t _Post>
    key<types::sum_size_t<_Pre, _Post>::value> kconcat(const key<_Pre>& k1, const key<_Post>& k2);
    

    /// @brief Concatenates all varying sized keys together (k1 || k2 || ...) and returns the result.
    template<std::size_t... _Sizes>
    key<types::sum_size_t<_Sizes...>::value> kconcat(const key<_Sizes>&... keys);

}