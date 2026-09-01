#include "hashing.hpp"

#include "util.hpp"

namespace gcrypt::hashing
{
    template<std::size_t _Size>
    dhash SHA(const std::array<unsigned char, _Size> data)
    {
        dhash h{};
        h.Hash = GCRYPT_HASH(data.data(), _Size, h.Digest.data());
        return h;
    }


    template<std::size_t _MSize>
    dhash hash255_i(unsigned char i, const std::array<unsigned char, _MSize> message)
    {
        std::array<unsigned char, GCRYPT_X25519_KEY_SIZE + _MSize> buffer{};

        std::fill_n(buffer.data(), GCRYPT_X25519_KEY_SIZE, 0xFF);
        buffer[GCRYPT_X25519_KEY_SIZE - 1] = 0x7F; // MSB = MAX - 1
        buffer[0] -= i; // LSB -= i

        return SHA(buffer);
    }
}