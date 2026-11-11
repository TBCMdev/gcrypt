#include "keymath.hpp"
#include <cmath>
namespace gcrypt::kmath::xc32_universal
{
    
    void add(field_element& out, const field_element& a, const field_element& b)
    {
        for(std::size_t i = 0; i < field_element_t::LimbCount; i++)
            out[i] = a[i] + b[i];
    }
    void sub(field_element& out, const field_element& a, const field_element& b)
    {
        for(std::size_t i = 0; i < field_element_t::LimbCount; i++)
            out[i] = a[i] - b[i];
    }
    void sq(field_element& out, const field_element& a)
    {
        // [TODO] Can implement better & more efficient
        mul(out, a, a);
    }
    void inv(field_element& out, const field_element& a)
    {
        field_element t0, t1, t2, t3;
        int i;

        sq(t0, a);
        sq(t1, t0);
        
        for(i = 1; i < 2; ++i) sq(t1, t1);

        mul(t1, a, t1);
        mul(t0, t0, t1);

        sq(t2, t0);

        mul(t1, t1, t2);

        sq(t2, t1);

        for(i = 1; i < 5; ++i) sq(t2, t2);

        mul(t1, t2, t1);

        sq(t2, t1);

        for(i = 1; i < 10; ++i) sq(t2, t2);

        mul(t2,t2,t1);

        sq(t3,t2); for (i = 1;i < 20;++i) sq(t3,t3);

        mul(t2,t3,t2);

        sq(t2,t2); for (i = 1; i < 10;++i) sq(t2,t2);

        mul(t1,t2,t1);

        sq(t2,t1); for (i = 1; i < 50; ++i) sq(t2,t2);

        mul(t2,t2,t1);

        sq(t3,t2); for (i = 1; i < 100; ++i) sq(t3,t3);

        mul(t2,t3,t2);

        sq(t2,t2); for (i = 1; i < 50; ++i) sq(t2,t2);

        mul(t1,t2,t1);

        sq(t1,t1); for (i = 1; i < 5; ++i) sq(t1,t1);

        mul(out, t1, t0);

    }
    void carry(wide_field_element& r)
    {
        for(std::size_t i = 0; i < field_element_t::LimbCount; i++)
        {
            const auto s = (i & 1) ? 25 : 26;

            const field_element_t::product_type carry = r[i] >> s;

            r[i] -= carry * (field_element_t::product_type{1} << s);

            if (i + 1 < field_element_t::LimbCount) r[i + 1] += carry;
            else                                    r[0]     += carry * 19;
        }
    }
    void mul(field_element& out, const field_element& a, const field_element& b)
    {
        using mul_t = field_element_t::product_type;
        constexpr std::size_t N = field_element_t::LimbCount;
        wide_field_element r{};

        for(std::size_t i = 0; i < N; i++)
        {
            for(std::size_t j = 0; j < N; j++)
            {
                auto ai_bj = mul_t{a[i]} * b[j];

                if ((i & 1) && (j & 1))
                    ai_bj *= 2;
                if (i + j >= N)
                    ai_bj *= 19;

                r[(i+j) % N]  += ai_bj;
            }
        }
        carry(r);
        carry(r);
        for(std::size_t i = 0; i < N; i++)
            out[i] = static_cast<field_element_t::type>(r[i]);
        
    }
    void unpack(field_element& out, const xckey& k)
    {
        using wide_t = field_element_t::product_type;
        // loads 3 bytes from pointer x
        constexpr auto l3 = [](const uint8_t* x) -> wide_t
        { return wide_t{x[0]} | (wide_t{x[1]} << 8) | (wide_t{x[2]} << 16); };
        // loads 4 bytes from pointer x
        constexpr auto l4 = [l3](const uint8_t* x) -> wide_t
        { return l3(x) | wide_t{x[3]} << 24; };

        wide_field_element a;
        const uint8_t* b = k.data();

        a[0] = l4(b);
        a[1] = l3(b + 4) << 6;
        a[2] = l3(b + 7) << 5;
        a[3] = l3(b + 10) << 3;
        a[4] = l3(b + 13) << 2;
        a[5] = l4(b + 16);
        a[6] = l3(b + 20) << 7;
        a[7] = l3(b + 23) << 5;
        a[8] = l3(b + 26) << 4;
        a[9] = (l3(b + 29) & 0x7FFFFF) << 2;

        carry(a);
        carry(a);

        for(std::size_t i = 0; i < field_element_t::LimbCount; i++)
            out[i] = static_cast<field_element_t::type>(a[i]);
    }
    void pack(xckey& out, const field_element& el)
    {
        wide_field_element f;

        for(int i = 0; i < field_element_t::LimbCount; i++)
            f[i] = el[i];

        // q = floor(h/p)
        field_element_t::product_type q = (19 * el[9] + ((int32_t) 1 << 24)) >> 25;
        for(int i = 0; i < 10; i++)
            q = (f[i] + q) >> (i & 1 ? 25 : 26);

        f[0] += 19 * q;

        for (int i = 0; i < 9; ++i)                  // limbs 0..8: normal carry
        {
            const unsigned s = (i & 1) ? 25 : 26;
            const field_element_t::product_type c = f[i] >> s;
            f[i + 1] += c;
            f[i]     -= c << s;
        }
        f[9] &= (field_element_t::product_type{1} << 25) - 1; 

#define B(x) static_cast<uint8_t>(x)
        uint8_t* r = out.data();
        r[0]  = B(f[0]);               r[1]  = B(f[0] >> 8);          r[2]  = B(f[0] >> 16);
        r[3]  = B((f[0] >> 24) | (f[1] << 2));
        r[4]  = B(f[1] >> 6);          r[5]  = B(f[1] >> 14);
        r[6]  = B((f[1] >> 22) | (f[2] << 3));
        r[7]  = B(f[2] >> 5);          r[8]  = B(f[2] >> 13);
        r[9]  = B((f[2] >> 21) | (f[3] << 5));
        r[10] = B(f[3] >> 3);          r[11] = B(f[3] >> 11);
        r[12] = B((f[3] >> 19) | (f[4] << 6));
        r[13] = B(f[4] >> 2);          r[14] = B(f[4] >> 10);         r[15] = B(f[4] >> 18);
        r[16] = B(f[5]);               r[17] = B(f[5] >> 8);          r[18] = B(f[5] >> 16);
        r[19] = B((f[5] >> 24) | (f[6] << 1));
        r[20] = B(f[6] >> 7);          r[21] = B(f[6] >> 15);
        r[22] = B((f[6] >> 23) | (f[7] << 3));
        r[23] = B(f[7] >> 5);          r[24] = B(f[7] >> 13);
        r[25] = B((f[7] >> 21) | (f[8] << 4));
        r[26] = B(f[8] >> 4);          r[27] = B(f[8] >> 12);
        r[28] = B((f[8] >> 20) | (f[9] << 6));
        r[29] = B(f[9] >> 2);          r[30] = B(f[9] >> 10);         r[31] = B(f[9] >> 18);
#undef B
        
    }
}