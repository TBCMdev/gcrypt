#pragma once
#include "protocol.hpp"
#include "util.hpp"

namespace gcrypt::kmath
{

    namespace _impl
    {
        template<std::unsigned_integral _Numeric, std::size_t _Size>
        inline _Numeric extract(const key<_Size>& k, std::size_t off = 0ULL)
        {
            if (off > _Size || _Size - off < sizeof(_Numeric))
                throw std::out_of_range("extract: read past end of key");

            _Numeric out;
            std::memcpy(&out, k.data() + off, sizeof(_Numeric));

            if constexpr (std::endian::native == std::endian::big)
                out = std::byteswap(out);

            return out;
        }
    }

    // alternating curve field element of limbs [a+1, a, a+1, ...] bytes, where a = MinLimbSize.
    template<std::size_t _MinLimbSize, std::size_t _LimbCount>
    struct alt_curve_field_element
    {
        static constexpr std::size_t LimbCount       = _LimbCount;
        static constexpr std::size_t MinLimbSize     = _MinLimbSize;
        static constexpr std::size_t LimbProductSize = (_MinLimbSize+1) * 2;

        using type           = typename util::types::integral_which_stores<(MinLimbSize+1)>::type;
        using product_type   = typename util::types::integral_which_stores<LimbProductSize>::type;
        using container      = std::array<type, LimbCount>;
        using wide_container = std::array<product_type, LimbCount>;
    };
#define GCRYPT_MAX_KEYMATH_BYTES 1024
    /// @brief Contains implementation for unsupported libsodium operations for 256 bit keys.
    ///        The implementation uses limbs for both 32bit and 64bit machines.
    ///        To use a faster and more compact method, refer to the namespace xc32_modern
    namespace xc32_universal
    {
        using field_element_t    = alt_curve_field_element<25, 10>;
        using field_element      = field_element_t::container;
        using wide_field_element = field_element_t::wide_container;

        void add(field_element& out, const field_element& a, const field_element& b);
        void sub(field_element& out, const field_element& a, const field_element& b);
        void sq(field_element& out, const field_element& a);
        void inv(field_element& out, const field_element& a);
        void mul(field_element& out, const field_element& a, const field_element& b);
        
        void carry(wide_field_element& r);
        void unpack(field_element& out, const xckey& k);
        void pack(xckey& out, const field_element& el);
    }
    /// @brief Contains implementation for unsupported libsodium operations for 256 bit keys.
    ///        The implementation uses limbs for 64bit machines only.
    ///        To use a faster and more compact method, refer to the namespace xc32_universal
    namespace xc32_modern
    {
        // todo
    }
}