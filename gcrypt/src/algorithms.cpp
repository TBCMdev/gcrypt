#include "algorithms.hpp"

#include <sodium.h>
#include <cstring>

#include "util.hpp"
#include "hashing.hpp"

namespace gcrypt::Ed25519
{
    bool signbit(const xkey& key)
    {
        return (key[GCRYPT_ALG_ED25519_SIGNBYTE] >> 7) & 1;
    }
    void ycoord(xkey* key)
    {
        (*key)[GCRYPT_ALG_ED25519_SIGNBYTE] &= 0x7F; // force sign bit to be 0
    }
    xkey ycoord(const xkey& key)
    {
        xkey out = util::kcpy<GCRYPT_X25519_KEY_SIZE>(key);
        ycoord(&out);
        return out;
    }
    
}

namespace gcrypt::XedDSA
{
    namespace impl
    {
        xkey bpscale(const xkey& scalar)
        {
            xkey out{};
            crypto_scalarmult_ed25519_base_noclamp(out.data(), scalar.data());
            return out;
        }
        xkeypair calculate_key_pair(xkey K)
        {
            const xkey E  = bpscale(K);
            const bool Es = Ed25519::signbit(E);
            xkeypair A{};

            // Public = A, Private = a
            A.Public = Ed25519::ycoord(E);

            if (Es)
                crypto_core_ed25519_scalar_negate(A.Private.data(), K.data());
            else
                A.Private = util::kcpy<GCRYPT_X25519_KEY_SIZE>(K);

            return A;
        }
        bool sig_in_bounds(const xkey& mkPub, const xkey& R, const xkey& s)
        {
            constexpr uint8_t P[GCRYPT_X25519_KEY_SIZE] = 
            {
                0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
            };
            // Returns false if y >= p
            if (sodium_compare(mkPub.data(), P, GCRYPT_X25519_KEY_SIZE) != -1)
                return false;
            
            if ((R[GCRYPT_X25519_KEY_SIZE - 1] & 0x80) != 0)
                return false;
            if ((s[GCRYPT_X25519_KEY_SIZE - 1] & 0xE0) != 0)
                return false;

            return true;
        }
        xkey convert_mont(const xkey& U)
        {
            // TODO
            // xkey P = u_to_y(U);

            Ed25519::ycoord(&P);

            return P;
        }
    }
    template<std::size_t _MessageSize>
    key<64> sign32(xkey K, std::array<uint8_t, _MessageSize> M, key<64> Z)
    {
        const xkeypair A = impl::calculate_key_pair(K);
        xkeypair R{};

        // hash_1(a || M || Z)
        hashing::dhash hash_1 = hashing::hash255_i(1, util::kconcat(A.Private, M, Z));

        // r = hash_1(...) (mod q)
        crypto_core_ed25519_scalar_reduce(r.Private.data(), hash_1.Digest.data());
    
        R.Public = impl::bpscale(R.Private);

        hashing::dhash hash = hashing::SHA(util::kconcat(R.Public, A.Public, M));

        xkey s{}, ha{}, h{};

        crypto_core_ed25519_scalar_reduce(h.data(), hash.Digest.data());
        {   // s = r + ha (mod q)
            crypto_core_ed25519_scalar_mul(ha.data(), h.data(), A.Private.data());
            crypto_core_ed25519_scalar_add(s.data(), R.Private.data(), ha.data());
        }
        return util::kconcat(R.Public, s);
    }

    template<std::size_t _MessageSize>
    bool verify32(xkey mkPub, std::array<uint8_t, _MessageSize> M, key<64> rcs)
    {
        // lower half of r concat s
        xkey R = util::kcpy<GCRYPT_X25519_KEY_SIZE, 64>(rcs);
        // upper half of r concat s
        xkey s = util::kcpy<GCRYPT_X25519_KEY_SIZE, 64>(rcs, GCRYPT_X25519_KEY_SIZE);

        if (!impl::sig_in_bounds(mkPub, R, s))
            return false;

        xkey A = impl::convert_mont(mkPub);
        
    }
}