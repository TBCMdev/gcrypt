#pragma once
#include "protocol.hpp"
#include "util.hpp"
#include "hashing.hpp"
#include "keygen.hpp"
#include <stdexcept>

namespace gcrypt
{
    namespace Ed25519
    {
        #define GCRYPT_ALG_ED25519_SIGNBYTE 31
        bool signbit(const xckey& key);
        /// @brief sets key = key.y, the lower 255 bits of the key.
        /// @param key 
        void ycoord(xckey* key);
        /// @brief returns the y coord of key.
        /// @param key 
        /// @return 
        xckey ycoord (const xckey& key);
    }
    namespace X25519
    {
        /// @brief Computes the shared secret between these two LPK and RPKs.
        xckey ssecret(const xckey& localPrivateKey, const xckey& remotePublicKey);
    }

    namespace XedDSA
    {
        namespace impl
        {
            /// @brief Scales the scalar key by the elliptical curve BASEPOINT.
            /// @param scalar 
            /// @return 
            xckey bpscale(const xckey& scalar);
            /// @brief Scales the scalar key's own data by the elliptical curve BASEPOINT.
            void bpscale(xckey* scalar);

            // other util functions. https://signal.org/docs/specifications/xeddsa/

            xckeypair calculate_key_pair(xckey K);
            bool sig_in_bounds(const xckey& mkPub, const xckey& R, const xckey& s);
            xckey u_to_y(const xckey& U);
            xckey convert_mont(const xckey& U);
        }
        /// @brief Returns the signature for the given key, message, and random byte sequence.
        /// @tparam _MessageSize 
        /// @param K The key to get the signature for
        /// @param M The message
        /// @param Z Random bytes
        /// @return The signature
        template<std::size_t _MessageSize>
        key<64> sign32(xckey K, const std::array<uint8_t, _MessageSize>& M, key<64> Z)
        {
            const xckeypair A = impl::calculate_key_pair(K);
            xckeypair R{};

            // hash_1(a || M || Z)
            hashing::dhash hash_1 = hashing::hash255_i(1, util::kconcat(A.Private, M, Z));

            // r = hash_1(...) (mod q)
            crypto_core_ed25519_scalar_reduce(R.Private.data(), hash_1.data());
        
            R.Public = impl::bpscale(R.Private);

            hashing::dhash hash = hashing::SHA(util::kconcat(R.Public, A.Public, M));

            xckey s{}, ha{}, h{};

            crypto_core_ed25519_scalar_reduce(h.data(), hash.data());
            {   // s = r + ha (mod q)
                crypto_core_ed25519_scalar_mul(ha.data(), h.data(), A.Private.data());
                crypto_core_ed25519_scalar_add(s.data(), R.Private.data(), ha.data());
            }
            return util::kconcat(R.Public, s);
        }

        /// @brief Verifies that the given signature is valid for the given Message (key), and the provided public identity key.
        /// @tparam _MessageSize 
        /// @return true if the verification matches, false otherwise.
        template<std::size_t _MessageSize>
        bool verify32(const xckey& mkPub, const std::array<uint8_t, _MessageSize>& M, key<64> rcs)
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
            crypto_core_ed25519_scalar_reduce(h.data(), hash.data());

            // r_check = sB - hA
            //         = s - h (memory wise)
            impl::bpscale(s); // s = sB

            crypto_core_ed25519_scalar_mul(h.data(), h.data(), A.data()); // h = hA

            xckey r_check{};
            crypto_core_ed25519_scalar_sub(r_check.data(), s.data(), h.data());

            // ensure bytes equal (R == R_check)
            return util::kmatch(r_check, R);
        }
    }
    namespace HKDF
    {
        /// @tparam _Size The size of the key to return. It must not be greater than crypto_kdf_hkdf_sha256_KEYBYTES.
        /// @param ikm the input key material
        /// @throws std::runtime_error - if the extract failed.
        /// @return a key of size _Size.
        template<std::size_t _Size>
        key<_Size> extract(const key<_Size>& salt, const key<_Size>& ikm)
        {
            key<_Size> out{};

            if (crypto_kdf_hkdf_sha256_extract(out.data(), salt.data(), _Size, ikm.data(), _Size) != 0)
                throw std::runtime_error("HKDF_sha256_extract failed.");

            return out;
        }
        
        /// @brief Implements the KDF(KM) implementation found at https://signal.org/docs/specifications/pqxdh/#introduction
        /// @throws std::runtime_error - if the extract failed.
        /// @note  uses the implementation defined for curve 25519.
        template<std::size_t _OutputSize, std::size_t _IkmSize>
        key<_OutputSize> KDF(const key<_IkmSize>& secretKeyMaterial)
        {

            // TODO: PROBLEMS WITH THIS ALGORITHMS

            // 32 bytes of 0xFF.
            const xckey K = keygen::from_lebyte<GCRYPT_X25519_KEY_SIZE>(0xFF);
            // _Size bytes of 0x00.
            const key<_Size> salt = keygen::from_lebyte<_Size>(0x00);
        
            return extract<_OutputSize>(salt, util::kconcat(K, secretKeyMaterial));
        }
    }
    namespace MLKEM_32
    {
        typedef struct kem_keypair_t
        {
            key<MLKEM_CTB>   cipherText;
            key<MLKEM_BYTES> sharedSecret;
        } kem_keypair;


        /// @brief Generates a kem key pair for a given quantum public key.
        /// @param PK 
        /// @return 
        kem_keypair encapsulate(const qpubkey& PK);


        /// @brief Generates a shared secret key<MLKEM_BYTES> from a given kem keypair.
        /// @param bundle 
        /// @return 
        key<MLKEM_BYTES> decapsulate(const key<MLKEM_CTB>& cipherText, const qprivkey& privateKey);
    }

    /// @brief The aead algorithm used in the protocol.
    namespace AEAD
    {
        
    }
};