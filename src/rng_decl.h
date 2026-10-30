#ifndef RNG_DECL_H
#define RNG_DECL_H

#ifdef __cplusplus
#include <cstdint>
#else
#include "stdint.h"
#endif
/*
Below are the implementations needed by mlkem for mlkem_randbytes.
*/
#if defined(_WIN32)
    #include <windows.h>
    #include <bcrypt.h>
#elif defined(__linux__)
    #include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    #include <stdlib.h>
#else
    #error "No RNG implemented for this platform"
#endif

#ifdef __cplusplus
extern "C" int mlk_randombytes(uint8_t *out, size_t outlen);
#else
int mlk_randombytes(uint8_t *out, size_t outlen);
#endif
#endif /* RNG_DECL_H */