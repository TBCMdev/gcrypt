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

        using type         = typename util::types::integral_which_stores<(MinLimbSize+1)>::type;
        using product_type = typename util::types::integral_which_stores<LimbProductSize>::type;
        using container    = std::array<type, LimbCount>;
    };
#define GCRYPT_MAX_KEYMATH_BYTES 1024
    /// @brief Contains implementation for unsupported libsodium operations for 256 bit keys.
    namespace xc32
    {
        /**
         * Notes:
         * 
         * U_TO_Y calculates y = [(u - 1) / (u+1)] % p
         * Since libsodium cannot compute % p for us (where p is the field prime p = 2^255 − 19),
         * The below implementations help us to accomplish this.
         * 
         * Below is the implementations for:
         *  sub, add, inv, mul
         * to perform this calculation given the rearrangement:
         *  y = [(u - 1) * (1 / u + 1)] % p
         * 
         * from the implementations seen online, we can slice each pair of bytes into a 64bit integer.
         * Therefore we can represent the numerical value of the key as:
         *  n = Σ (n_i*2^(16i)), i = 0..15
         * 
         * The below implementations were largely taken from:
         * 
         * https://github.com/dominictarr/tweetnacl/blob/master/tweetnacl.c
         *  
         */
        using field_element_t = alt_curve_field_element<25, 10>;
        using field_element   = field_element_t::container;

        void add(field_element& out, const field_element& a, const field_element& b);
        void sub(field_element& out, const field_element& a, const field_element& b);
        void sq(field_element& out, const field_element& a);
        void inv(field_element& out, const field_element& a);
        void mul(field_element& out, const field_element& a, const field_element& b);
        
        namespace impl
        {
            using sliced = std::array<int64_t, 16>;



            int64_t segment(const xckey& src, std::size_t pos);
            void unpack(sliced& out, const xckey& k);

            void pack(xckey& out, const sliced& k);
            void sel(sliced& p, sliced& q, int b);
            void carry(sliced& k);

            void sub(sliced& out, const sliced& a, const sliced& b);
            void add(sliced& out, const sliced& a, const sliced& b);
            
            void inv(sliced& out, const sliced& a);
            void mul(sliced& out, const sliced& a, const sliced& b);

            bool iszero(const sliced& s);

        }
    }
    
}