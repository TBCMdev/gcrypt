#include <cstdint>
#include "rng_decl.h"


extern "C" int mlk_randombytes(uint8_t *out, size_t outlen)
{
#if defined(_WIN32)
    while (outlen > 0)
    {
        ULONG chunk = outlen > 0x40000000UL ? 0x40000000UL : (ULONG)outlen;
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, out, chunk,
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
            return -1;
        out += chunk;
        outlen -= chunk;
    }
#elif defined(__linux__)
    while (outlen > 0)
    {
        ssize_t n = getrandom(out, outlen, 0);
        if (n < 0) return -1;
        out += n; outlen -= (size_t)n;
    }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    arc4random_buf(out, outlen);
#endif
    return 0;
}