#include "algorithms.hpp"

#include <sodium.h>
#include <cstring>
#include <stdexcept>

#include "util.hpp"
#include "hashing.hpp"
#include "keygen.hpp"


namespace gcrypt::Ed25519
{
    bool signbit(const xckey& key)
    {
        return (key[GCRYPT_ALG_ED25519_SIGNBYTE] >> 7) & 1;
    }
    void ycoord(xckey* key)
    {
        (*key)[GCRYPT_ALG_ED25519_SIGNBYTE] &= 0x7F; // force sign bit to be 0
    }
    xckey ycoord(const xckey& key)
    {
        xckey out = util::kcpy(key);
        ycoord(&out);
        return out;
    }
    
}

namespace gcrypt::XedDSA
{
    namespace impl
    {
        xckey bpscale(const xckey& scalar)
        {
            xckey out{};
            crypto_scalarmult_ed25519_base_noclamp(out.data(), scalar.data());
            return out;
        }
        void bpscale(xckey* scalar)
        {
            auto d = scalar->data();
            crypto_scalarmult_ed25519_base_noclamp(d, d);
        }
        xckeypair calculate_key_pair(xckey K)
        {
            const xckey E  = bpscale(K);
            const bool Es = Ed25519::signbit(E);
            xckeypair A{};

            // Public = A, Private = a
            A.Public = Ed25519::ycoord(E);
            if (Es)
                crypto_core_ed25519_scalar_negate(A.Private.data(), K.data());
            else
                A.Private = util::kcpy(K);

            return A;
        }
        bool sig_in_bounds(const xckey& mkPub, const xckey& R, const xckey& s)
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
        xckey u_to_y(const xckey& U)
        {
            // Constant 1
            const xckey C1 = keygen::from_lebytes<GCRYPT_X25519_KEY_SIZE>((uint8_t)1);

            xckey numerator{}; // Z = U - 1
            crypto_core_ed25519_scalar_sub(numerator.data(), U.data(), C1.data());
            xckey denominator{}; // Z = U - 1
            crypto_core_ed25519_scalar_add(denominator.data(), U.data(), C1.data());

            if (crypto_core_ed25519_scalar_invert(denominator.data(), denominator.data()) != 0)
                throw std::invalid_argument("Invalid scalar of ed25519 denominator (=0)");
            
            xckey result{};
            crypto_core_ed25519_scalar_mul(result.data(), numerator.data(), denominator.data());

            return result;
        }
        xckey convert_mont(const xckey& U)
        {
            xckey umasked = Ed25519::ycoord(U);
            xckey P = u_to_y(umasked);

            Ed25519::ycoord(&P);

            return P;
        }
    }
    template<std::size_t _MessageSize>
    key<64> sign32(xckey K, const std::array<uint8_t, _MessageSize>& M, key<64> Z)
    {
        const xckeypair A = impl::calculate_key_pair(K);
        xckeypair R{};

        // hash_1(a || M || Z)
        hashing::dhash hash_1 = hashing::hash255_i(1, util::kconcat(A.Private, M, Z));

        // r = hash_1(...) (mod q)
        crypto_core_ed25519_scalar_reduce(R.Private.data(), hash_1.Digest.data());
    
        R.Public = impl::bpscale(R.Private);

        hashing::dhash hash = hashing::SHA(util::kconcat(R.Public, A.Public, M));

        xckey s{}, ha{}, h{};

        crypto_core_ed25519_scalar_reduce(h.data(), hash.Digest.data());
        {   // s = r + ha (mod q)
            crypto_core_ed25519_scalar_mul(ha.data(), h.data(), A.Private.data());
            crypto_core_ed25519_scalar_add(s.data(), R.Private.data(), ha.data());
        }
        return util::kconcat(R.Public, s);
    }
    template<std::size_t _MessageSize>
    bool verify32(xckey mkPub, const std::array<uint8_t, _MessageSize>& M, key<64> rcs)
    {
        // lower half of r concat s
        xckey R = util::kcpy<GCRYPT_X25519_KEY_SIZE, 64>(rcs);
        // upper half of r concat s
        xckey s = util::kcpy<GCRYPT_X25519_KEY_SIZE, 64>(rcs, GCRYPT_X25519_KEY_SIZE);

        if (!impl::sig_in_bounds(mkPub, R, s))
            return false;

        xckey A = impl::convert_mont(mkPub);
        
        if (crypto_core_ed25519_is_valid_point(A.data()) == 0)
            return false;

        xckey h{};
        hashing::dhash hash = hashing::SHA(util::kconcat(R, A, M));
        crypto_core_ed25519_scalar_reduce(h.data(), hash.Digest.data());
    
        // r_check = sB - hA
        //         = s - h (memory wise)
        impl::bpscale(s); // s = sB

        crypto_core_ed25519_scalar_mul(h.data(), h.data(), A.data()); // h = hA

        xckey r_check{};
        crypto_core_ed25519_scalar_sub(r_check.data(), s.data(), h.data());

        // ensure bytes equal (R == R_check)
        return std::equal(r_check.begin(), r_check.end(), R.begin(), R.end());
    }
}

namespace gcrypt::HKDF
{
    template<std::size_t _Size>
    key<_Size> extract(const key<_Size>& salt, const key<_Size>& ikm)
    {
        key<_Size> out{};

        if (crypto_kdf_hkdf_sha256_extract(out.data(), salt.data(), _Size, ikm.data(), _Size) == 0)
            throw std::runtime_error("HKDF_sha256_extract failed.");

        return out;
    }
}
namespace gcrypt::MLKEM_32
{
    kem_keypair encapsulate(const qpubkey& PK)
    {
        kem_keypair out{};
        const int _Ret = mlkimpl_enc(out.cipherText.data(), out.sharedSecret.data(), PK.data());

        if (_Ret != 0)
            throw std::runtime_error("MLKEM_32 enc failed with exit code: " + std::to_string(_Ret) + ".");

        return out;
    }
    
    key<MLKEM_BYTES> decapsulate(const key<MLKEM_CTB>& cipherText, const qprivkey& privateKey)
    {
        key<MLKEM_BYTES> out{};

        const int _Ret = mlkimpl_dec(out.data(), cipherText.data(), privateKey.data());

        if (_Ret != 0)
            throw std::runtime_error("MLKEM_32 dec failed with exit code: " + std::to_string(_Ret) + ".");
        return out;
    }
}
