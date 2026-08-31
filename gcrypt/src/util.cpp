#include "util.hpp"

#include <cstring>
#include <cstddef>
namespace gcrypt::util
{
    template<std::size_t _Size>
    key<_Size> kcpy(const key<_Size>& key)
    {
        key<_Size> out{};
        std::memcpy(out.data(), key.data(), _Size);
        return out;
    }
    template<std::size_t _Take, std::size_t _Size>
    key<_Take> kcpy(const key<_Size>& key, std::size_t offset)
    {
        key<_Take> out{};
        std::memcpy(out.data(), key.data() + offset, _Take);
        return out;
    }


    template<std::size_t _Size>
    key<types::x2size_t<_Size>::value> kconcat(const key<_Size>& k1, const key<_Size>& k2)
    {
        key<types::x2size_t<_Size>::value> out{};

        std::memcpy(out.data(), k1.data(), _Size);
        std::memcpy(out.data() + _Size, k2.data(), _Size);

        return out;
    }

    template<std::size_t _Pre, std::size_t _Post>
    key<types::sum_size_t<_Pre, _Post>::value> kconcat(const key<_Pre>& k1, const key<_Post>& k2)
    {
        key<types::sum_size_t<_Pre, _Post>::value> out{};


        std::memcpy(out.data(), k1.data(), _Pre);
        std::memcpy(out.data() + _Pre, k2.data(), _Post);

        return out;
    }

    template<std::size_t... _Sizes>
    key<types::sum_size_t<_Sizes...>::value> kconcat(const key<_Sizes>&... keys)
    {
        key<types::sum_size_t<_Sizes...>::value> out{};

        std::size_t offset = 0;
        
        ((std::memcpy(out.data() + offset, keys.data(), _Sizes), offset += _Sizes), ...);

        return out;
    }

}