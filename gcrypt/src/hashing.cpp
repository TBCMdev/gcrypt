#include "hashing.hpp"

namespace gcrypt::hashing
{
    template<std::size_t _Size>
    dhash SHA(const std::array<unsigned char, _Size> data)
    {
        dhash h{};
        h.Hash = GCRYPT_HASH(data.data(), _Size, h.Digest.data());
        return h;
    }
}