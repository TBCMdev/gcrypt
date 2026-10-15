#pragma once
#include <concepts>
// Struct byte size member name
#define SBSM_NAME _inb_byte_size
// Sets a member that queries the real size of an object in bytes.
#define sizedecl(s) static constexpr std::size_t SBSM_NAME = s;
namespace gcrypt::sizing
{



    template<typename _T>
    concept declared_byte_size = requires
    {
        { _T::SBSM_NAME } -> std::same_as<const std::size_t&>;
    };

    /// @brief returns the actual size in bytes that the structure of type
    ///        _T is.
    template<typename _T>
    constexpr inline std::size_t bytesize()
        requires declared_byte_size<_T>
    {
        return _T::SBSM_NAME;
    }
    // /// @brief Equivalent to sizeof(_T)
    // template<typename _T>
    // constexpr inline std::size_t bytesize()
    //     requires (!declared_byte_size<_T>)
    // {
    //     return sizeof(_T);
    // }

    /// @brief returns the actual size in bytes that the structure of type
    ///        the argument is.
    constexpr inline std::size_t bytesize(const auto& item)
    {
        using ty = std::decay_t<decltype(item)>;
        
        if constexpr (declared_byte_size<ty>)
            return bytesize<ty>();
        return sizeof(item);
    }

}