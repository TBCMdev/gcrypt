#pragma once
#include "protocol.hpp"

namespace gcrypt
{
    using xkey     = key<GCRYPT_X25519_KEY_SIZE>;
    using xkeypair = keypair<GCRYPT_X25519_KEY_SIZE>;

    namespace Ed25519
    {
        #define GCRYPT_ALG_ED25519_SIGNBYTE 31
        bool signbit(const xkey& key);
        /// @brief sets key = key.y, the lower 255 bits of the key.
        /// @param key 
        void ycoord(xkey* key);
        /// @brief returns the y coord of key.
        /// @param key 
        /// @return 
        xkey ycoord (const xkey& key);

    }

    namespace XedDSA
    {
        namespace impl
        {
            /// @brief Scales the scalar key by the elliptical curve BASEPOINT.
            /// @param scalar 
            /// @return 
            xkey bpscale(const xkey& scalar);

            
        }
        // todo
    }
};