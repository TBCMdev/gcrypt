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
namespace gcrypt::X25519
{
    xckey ssecret(const xckey& localPrivateKey, const xckey& remotePublicKey)
    {
        xckey out{};
        if (crypto_scalarmult_curve25519(out.data(), localPrivateKey.data(), remotePublicKey.data()) != 0)
            throw std::runtime_error("Gathering shared secret in X25519 key pair failed.");
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
