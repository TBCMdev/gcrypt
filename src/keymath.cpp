#include "keymath.hpp"
#include <cmath>
namespace gcrypt::kmath
{
    namespace xc32::impl
    {
        int64_t segment(const xckey& src, std::size_t pos)
        {
            return static_cast<int64_t>(src[2 * pos]) | (static_cast<int64_t>(src[2 * pos + 1]) << 8);
        }
        void sel(sliced& p, sliced& q, int b)
        {
            int64_t c = ~(int64_t)(b - 1);
            for (int i = 0; i < 16; ++i)
            {
                int64_t t = c & (p[i] ^ q[i]);
                p[i] ^= t; q[i] ^= t;
            }
        }
        void unpack(sliced& out, const xckey& k)
        {
            // each byte of out becomes each pair of bytes summed.
            for(std::size_t i = 0; i < 16; i++)
                out[i] = segment(k, i);
            out[15] &= 0x7FFF;
        }
        void pack(xckey& out, const sliced& n)
        {
            sliced m, t;
            for (int i = 0; i < 16; ++i) t[i] = n[i];
            carry(t); carry(t); carry(t);
            for (int j = 0; j < 2; ++j)
            {
                m[0] = t[0] - 0xFFED;
                for (int i = 1; i < 15; ++i)
                {
                    m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1);
                    m[i - 1] &= 0xFFFF;
                }
                m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1);
                int b = (m[15] >> 16) & 1;
                m[14] &= 0xFFFF;
                sel(t, m, 1 - b);
            }
            for (int i = 0; i < 16; ++i) { out[2 * i] = t[i] & 0xFF; out[2 * i + 1] = t[i] >> 8; }
        }
        void carry(sliced& k)
        {
            for (std::size_t i = 0; i < 16; i++)
            {
                int64_t s = k[i] >> 16;
                int64_t c = s >> 16; // c = overflow
                s -= c * 65536; // account for overflow

                // add overflow to next segment or first segment if final byte.
                if (i < 15)
                    k[i + 1] += c;
                else
                    k[0] += 38 * c;
            }
        }
        void add(sliced& out, const sliced& a, const sliced& b)
        {
            for(std::size_t i = 0; i < 16; i++)
                out[i] = a[i] + b[i];
        }
        void sub(sliced& out, const sliced& a, const sliced& b)
        {
            for(std::size_t i = 0; i < 16; i++)
                out[i] = a[i] - b[i];
        }
        void mul(sliced& out, const sliced& a, const sliced& b)
        {
            int64_t t[31] = {};
            for (int i = 0; i < 16; ++i)
                for (int j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
            for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
            for (int i = 0; i < 16; ++i) out[i] = t[i];
            carry(out); carry(out);
        }
        void inv(sliced& out, const sliced& i)
        {                    // i^(p-2)
            sliced c;
            for (int a = 0; a < 16; ++a) c[a] = i[a];
            for (int a = 253; a >= 0; --a)
            {
                mul(c, c, c);
                if (a != 2 && a != 4) mul(c, c, i);
            }
            for (int a = 0; a < 16; ++a) out[a] = c[a];
        }
        bool iszero(const sliced& s)
        {
            uint8_t a = 0;
            xckey out; pack(out, s);
            for(uint8_t b : out)
                a |= b;
            return a == 0;
        }
    }
}