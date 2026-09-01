#pragma once
#include "protocol.hpp"

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
    }
    namespace HKDF
    {
        /// @tparam _Size The size of the key to return. It must not be greater than crypto_kdf_hkdf_sha256_KEYBYTES.
        /// @param ikm the input key material
        /// @return a key of size _Size.
        template<std::size_t _Size>
        key<_Size> extract(const key<_Size>& salt, const key<_Size>& ikm);
    }
    namespace MLKEM_32
    {
        typedef struct kem_keypair_t
        {
            key<MLKEM_CTB>   cipherText;
            key<MLKEM_BYTES> sharedSecret;
        } kem_keypair;


        /// @brief Generates a kem key pair for a given public key<32>.
        /// @param PK 
        /// @return 
        kem_keypair encapsulate(const xckey& PK);


        /// @brief Generates a shared secret key<MLKEM_BYTES> from a given kem keypair.
        /// @param bundle 
        /// @return 
        key<MLKEM_BYTES> decapsulate(const kem_keypair& keys);
    }

    /// @brief The aead algorithm used in the protocol.
    namespace AEAD
    {
        
    }
};