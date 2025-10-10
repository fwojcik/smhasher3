/*
 * Metrohash v1
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (C) 2015 J. Andrew Rogers
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "Platform.h"
#include "Hashlib.h"

#if defined(HAVE_X86_64_CRC32C)
  #include "Intrinsics.h"
#else
uint64_t _mm_crc32_u64( uint64_t crc, uint64_t v );

#endif

#define VARIANTS_64 5

static const uint64_t MULTK64[VARIANTS_64][8] = {
    {
        0xD6D018F5, 0xA2AA033B, 0x62992FC1, 0x30BC5B29,
        0x62992FC1, 0x62992FC1, 0x30BC5B29, 0x30BC5B29,
    },
    {
        0xC83A91E1, 0x8648DBDB, 0x7BDEC03B, 0x2F5870A5,
        0xC83A91E1, 0x8648DBDB, 0x8648DBDB, 0x7BDEC03B,
    },
    {
        0xD6D018F5, 0xA2AA033B, 0x62992FC1, 0x30BC5B29,
        0x62992FC1, 0x62992FC1, 0x30BC5B29, 0x30BC5B29,
    },
    {
        0xC83A91E1, 0x8648DBDB, 0x7BDEC03B, 0x2F5870A5,
        0xC83A91E1, 0x8648DBDB, 0x8648DBDB, 0x7BDEC03B,
    },
    {
        0xD6D018F5, 0xA2AA033B, 0x62992FC1, 0x30BC5B29,
        0xD6D018F5, 0xA2AA033B, 0xA2AA033B, 0x62992FC1,
    },
};

static const uint8_t ROTK64[VARIANTS_64][9] = {
    { 37, 29, 21, 55, 26, 48, 37, 28, 29 },
    { 33, 33, 35, 33, 15, 13, 25, 33, 33 },
    { 30, 29, 34, 36, 15, 15, 23, 28, 29 },
    { 33, 33, 35, 33, 15, 13, 25, 33, 33 },
    { 33, 33, 35, 33, 15, 13, 25, 33, 33 },
};

template <uint32_t variant, bool bswap>
static void MetroHash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    if (variant >= VARIANTS_64) { return; }

    const uint64_t *      K    = &MULTK64[variant][0];
    const uint8_t *       ROTK = &ROTK64 [variant][0];
    const uint8_t *       ptr  = (const uint8_t *)in;
    const uint8_t * const end  = ptr + len;
    uint64_t v[4];

    uint64_t vseed = ((uint64_t)seed + K[2]) * K[0];
    if (variant != 0) { vseed += len; }

    v[0] = v[1] = v[2] = v[3] = vseed;

    // bulk update
    while (ptr <= (end - 32)) {
        if (variant <= 2) {
            v[0] += GET_U64<bswap>(ptr,  0) * K[0]; v[0] = ROTR64(v[0], 29) + v[2];
            v[1] += GET_U64<bswap>(ptr,  8) * K[1]; v[1] = ROTR64(v[1], 29) + v[3];
            v[2] += GET_U64<bswap>(ptr, 16) * K[2]; v[2] = ROTR64(v[2], 29) + v[0];
            v[3] += GET_U64<bswap>(ptr, 24) * K[3]; v[3] = ROTR64(v[3], 29) + v[1];
        } else {
            v[0] ^= _mm_crc32_u64(v[0], GET_U64<bswap>(ptr,  0));
            v[1] ^= _mm_crc32_u64(v[1], GET_U64<bswap>(ptr,  8));
            v[2] ^= _mm_crc32_u64(v[2], GET_U64<bswap>(ptr, 16));
            v[3] ^= _mm_crc32_u64(v[3], GET_U64<bswap>(ptr, 24));
        }
        ptr += 32;
    }

    if (len >= 32) {
        v[2] ^= ROTR64(((v[0] + v[3]) * K[0]) + v[1], ROTK[0]) * K[1];
        v[3] ^= ROTR64(((v[1] + v[2]) * K[1]) + v[0], ROTK[0]) * K[0];
        v[0] ^= ROTR64(((v[0] + v[2]) * K[0]) + v[3], ROTK[0]) * K[1];
        v[1] ^= ROTR64(((v[1] + v[3]) * K[1]) + v[2], ROTK[0]) * K[0];

        v[0]  = vseed + (v[0] ^ v[1]);
    }

    if ((end - ptr) >= 16) {
        v[1]  = v[0] + (GET_U64<bswap>(ptr, 0) * K[4]); v[1] = ROTR64(v[1], ROTK[1]) * K[6];
        v[2]  = v[0] + (GET_U64<bswap>(ptr, 8) * K[5]); v[2] = ROTR64(v[2], ROTK[1]) * K[7];
        v[1] ^= ROTR64(v[1] * K[0], ROTK[2]) + v[2];
        v[2] ^= ROTR64(v[2] * K[3], ROTK[2]) + v[1];
        v[0] += v[2];
        ptr  += 16;
    }

    if ((end - ptr) >= 8) {
        v[0] += GET_U64<bswap>(ptr, 0) * K[3];
        v[0] ^= ROTR64(v[0], ROTK[3]) * K[1];
        ptr  += 8;
    }

    if ((end - ptr) >= 4) {
        if (variant <= 2) {
            v[0] += GET_U32<bswap>(ptr, 0) * K[3];
        } else {
            v[0] ^= _mm_crc32_u64(v[0], GET_U32<bswap>(ptr, 0));
        }
        v[0] ^= ROTR64(v[0], ROTK[4]) * K[1];
        ptr  += 4;
    }

    if ((end - ptr) >= 2) {
        if (variant <= 2) {
            v[0] += GET_U16<bswap>(ptr, 0) * K[3];
        } else {
            v[0] ^= _mm_crc32_u64(v[0], GET_U16<bswap>(ptr, 0));
        }
        v[0] ^= ROTR64(v[0], ROTK[5]) * K[1];
        ptr  += 2;
    }

    if ((end - ptr) >= 1) {
        if (variant <= 2) {
            v[0] += (*ptr) * K[3];
        } else {
            v[0] ^= _mm_crc32_u64(v[0], *ptr);
        }
        v[0] ^= ROTR64(v[0], ROTK[6]) * K[1];
    }

    v[0] ^= ROTR64(v[0], ROTK[7]);
    v[0] *= K[0];
    v[0] ^= ROTR64(v[0], ROTK[8]);

    PUT_U64<bswap>(v[0], (uint8_t *)out, 0);
}

#define VARIANTS_128 5

static const uint64_t MULTK128[VARIANTS_128][4] = {
    { 0xC83A91E1, 0x8648DBDB, 0x7BDEC03B, 0x2F5870A5 }, // Standard mixing
    { 0xC83A91E1, 0x8648DBDB, 0x7BDEC03B, 0x2F5870A5 },
    { 0xD6D018F5, 0xA2AA033B, 0x62992FC1, 0x30BC5B29 },
    { 0xC83A91E1, 0x8648DBDB, 0x7BDEC03B, 0x2F5870A5 }, // CRC-based mixing
    { 0xEE783E2F, 0xAD07C493, 0x797A90BB, 0x2E4B2E1B }
};

static const uint8_t ROTK128[VARIANTS_128][15] = {
    { 21, 21, 21, 33, 45, 33, 27, 33, 46, 33, 22, 33, 58, 13, 37, },
    { 26, 26, 30, 33, 17, 33, 20, 33, 18, 33, 24, 33, 24, 13, 37, },
    { 33, 33, 33, 29, 29, 29, 29, 29, 25, 29, 30, 29, 18, 33, 33, },
    { 34, 37, 37, 34, 30, 36, 23,  0, 19,  0, 13,  0, 17, 11, 26, },
    { 12, 19, 19, 41, 10, 34, 22,  0, 14,  0, 15,  0, 18, 15, 27, }
};

template <uint32_t variant, bool bswap>
static void MetroHash128( const void * in, const size_t len, const seed_t seed, void * out ) {
    if (variant >= VARIANTS_128) { return; }

    const uint64_t *      K    = &MULTK128[variant][0];
    const uint8_t *       ROTK = &ROTK128 [variant][0];
    const uint8_t *       ptr  = (const uint8_t *)in;
    const uint8_t * const end  = ptr + len;

    uint64_t v[4];

    v[0] = (seed - K[0]) * K[3];
    v[1] = (seed + K[1]) * K[2];
    if (variant != 0) {
        v[0] += len;
        v[1] += len;
    }

    // bulk update
    if (len >= 32) {
        v[2] = (seed + K[0]) * K[2];
        v[3] = (seed - K[1]) * K[3];
        if (variant != 0) {
            v[2] += len;
            v[3] += len;
        }

        while (ptr <= (end - 32)) {
            if (variant <= 2) {
                v[0] += GET_U64<bswap>(ptr,  0) * K[0]; v[0] = ROTR64(v[0], 29) + v[2];
                v[1] += GET_U64<bswap>(ptr,  8) * K[1]; v[1] = ROTR64(v[1], 29) + v[3];
                v[2] += GET_U64<bswap>(ptr, 16) * K[2]; v[2] = ROTR64(v[2], 29) + v[0];
                v[3] += GET_U64<bswap>(ptr, 24) * K[3]; v[3] = ROTR64(v[3], 29) + v[1];
            } else {
                v[0] ^= _mm_crc32_u64(v[0], GET_U64<bswap>(ptr,  0));
                v[1] ^= _mm_crc32_u64(v[1], GET_U64<bswap>(ptr,  8));
                v[2] ^= _mm_crc32_u64(v[2], GET_U64<bswap>(ptr, 16));
                v[3] ^= _mm_crc32_u64(v[3], GET_U64<bswap>(ptr, 24));
            }
            ptr += 32;
        }

        v[2] ^= ROTR64(((v[0] + v[3]) * K[0]) + v[1], ROTK[0]) * K[1];
        v[3] ^= ROTR64(((v[1] + v[2]) * K[1]) + v[0], ROTK[1]) * K[0];
        v[0] ^= ROTR64(((v[0] + v[2]) * K[0]) + v[3], ROTK[0]) * K[1];
        v[1] ^= ROTR64(((v[1] + v[3]) * K[1]) + v[2], ROTK[2]) * K[0];
    }

    if ((end - ptr) >= 16) {
        v[0] += (GET_U64<bswap>(ptr, 0) * K[2]); v[0] = ROTR64(v[0], ROTK[3]) * K[3];
        v[1] += (GET_U64<bswap>(ptr, 8) * K[2]); v[1] = ROTR64(v[1], ROTK[3]) * K[3];
        v[0] ^= ROTR64(v[0] * K[2] + v[1], ROTK[4]) * K[1];
        v[1] ^= ROTR64(v[1] * K[3] + v[0], ROTK[4]) * K[0];
        ptr  += 16;
    }

    if ((end - ptr) >= 8) {
        v[0] += GET_U64<bswap>(ptr, 0) * K[2];
        v[0]  = ROTR64(v[0]              , ROTK[5]) * K[3];
        v[0] ^= ROTR64(v[0] * K[2] + v[1], ROTK[6]) * K[1];
        ptr  += 8;
    }

    if ((end - ptr) >= 4) {
        if (variant <= 2) {
            v[1] += GET_U32<bswap>(ptr, 0) * K[2];
            v[1]  = ROTR64(v[1], ROTK[7]) * K[3];
        } else {
            v[1] ^= _mm_crc32_u64(v[0], GET_U32<bswap>(ptr, 0));
        }
        v[1] ^= ROTR64(v[1] * K[3] + v[0], ROTK[8]) * K[0];
        ptr  += 4;
    }

    if ((end - ptr) >= 2) {
        if (variant <= 2) {
            v[0] += GET_U16<bswap>(ptr, 0) * K[2];
            v[0]  = ROTR64(v[0], ROTK[9]) * K[3];
        } else {
            v[0] ^= _mm_crc32_u64(v[1], GET_U16<bswap>(ptr, 0));
        }
        v[0] ^= ROTR64(v[0] * K[2] + v[1], ROTK[10]) * K[1];
        ptr  += 2;
    }

    if ((end - ptr) >= 1) {
        if (variant <= 2) {
            v[1] += (*ptr) * K[2];
            v[1]  = ROTR64(v[1], ROTK[11]) * K[3];
        } else {
            v[1] ^= _mm_crc32_u64(v[0], *ptr);
        }
        v[1] ^= ROTR64(v[1] * K[3] + v[0], ROTK[12]) * K[0];
    }

    v[0] += ROTR64((v[0] * K[0]) + v[1], ROTK[13]);
    v[1] += ROTR64((v[1] * K[1]) + v[0], ROTK[14]);
    if (variant <= 2) {
        v[0] += ROTR64((v[0] * K[2]) + v[1], ROTK[13]);
        v[1] += ROTR64((v[1] * K[3]) + v[0], ROTK[14]);
    } else {
        v[0] += ROTR64((v[0] * K[0]) + v[1], ROTK[13]);
        v[1] += ROTR64((v[1] * K[1]) + v[0], ROTK[14]);
    }

    PUT_U64<bswap>(v[0], (uint8_t *)out, 0);
    PUT_U64<bswap>(v[1], (uint8_t *)out, 8);
}

REGISTER_FAMILY(metrohash,
   $.src_url    = "https://github.com/jandrewrogers/MetroHash/tree/c135424b3b83f1ca2502b7960f8d5705ddcec987",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(MetroHash_64,
   $.desc       = "Metrohash v1 base variant, 64-bit version",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x6FA828C9,
   $.verification_BE = 0xFB8D54A5,
   $.hashfn_native   = MetroHash64<0, false>,
   $.hashfn_bswap    = MetroHash64<0, true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0xffffffff9d66d03f }
 );

REGISTER_HASH(MetroHash_64__var1,
   $.desc       = "Metrohash v1 variant 1, 64-bit version",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xEE88F7D2,
   $.verification_BE = 0xCC0F03D7,
   $.hashfn_native   = MetroHash64<1, false>,
   $.hashfn_bswap    = MetroHash64<1, true>
 );

REGISTER_HASH(MetroHash_64__var2,
   $.desc       = "Metrohash v1 variant 2, 64-bit version",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xE1FC7C6E,
   $.verification_BE = 0x7F8C6EF1,
   $.hashfn_native   = MetroHash64<2, false>,
   $.hashfn_bswap    = MetroHash64<2, true>
 );

#if defined(HAVE_X86_64_CRC32C)

REGISTER_HASH(MetroHashCrc_64__var1,
   $.desc       = "Metrohash-crc v1 variant 1, 64-bit version (unofficial)",
   $.impl       = "x64crc",
   $.hash_flags =
         FLAG_HASH_CRC_BASED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x29C68A50,
   $.verification_BE = 0xACEEC1FC,
   $.hashfn_native   = MetroHash64<3, false>,
   $.hashfn_bswap    = MetroHash64<3, true>
 );

REGISTER_HASH(MetroHashCrc_64__var2,
   $.desc       = "Metrohash-crc v1 variant 2, 64-bit version (unofficial)",
   $.impl       = "x64crc",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x2C00BD9F,
   $.verification_BE = 0x590D5688,
   $.hashfn_native   = MetroHash64<4, false>,
   $.hashfn_bswap    = MetroHash64<4, true>
 );

#endif

REGISTER_HASH(MetroHash_128,
   $.desc       = "Metrohash v1 base variant, 128-bit version",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x4A6673E7,
   $.verification_BE = 0xD5F2CD8C,
   $.hashfn_native   = MetroHash128<0, false>,
   $.hashfn_bswap    = MetroHash128<0, true>
 );

REGISTER_HASH(MetroHash_128__var1,
   $.desc       = "Metrohash v1 variant 1, 128-bit version",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x20E8A1D7,
   $.verification_BE = 0x78661274,
   $.hashfn_native   = MetroHash128<1, false>,
   $.hashfn_bswap    = MetroHash128<1, true>
 );

REGISTER_HASH(MetroHash_128__var2,
   $.desc       = "Metrohash v1 variant 2, 128-bit version",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x5437C684,
   $.verification_BE = 0x01A244A6,
   $.hashfn_native   = MetroHash128<2, false>,
   $.hashfn_bswap    = MetroHash128<2, true>
 );

#if defined(HAVE_X86_64_CRC32C)

REGISTER_HASH(MetroHashCrc_128__var1,
   $.desc       = "Metrohash-crc v1 variant 1, 128-bit version",
   $.impl       = "x64crc",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x5E75144E,
   $.verification_BE = 0xCD4C6C7E,
   $.hashfn_native   = MetroHash128<3, false>,
   $.hashfn_bswap    = MetroHash128<3, true>
 );

REGISTER_HASH(MetroHashCrc_128__var2,
   $.desc       = "Metrohash-crc v1 variant 2, 128-bit version",
   $.impl       = "x64crc",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x1ACF3E77,
   $.verification_BE = 0x3772DA12,
   $.hashfn_native   = MetroHash128<4, false>,
   $.hashfn_bswap    = MetroHash128<4, true>
 );

#endif
