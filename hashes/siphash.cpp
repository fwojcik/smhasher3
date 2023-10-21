/*
 * SipHash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2018      Leo Yuriev
 * Copyright (c) 2014-2021 Reini Urban
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include "Platform.h"
#include "Hashlib.h"

#if defined(HAVE_SSSE_3) || defined(HAVE_SSE_2)
  #include "Intrinsics.h"
  #if defined(HAVE_SSSE_3)
    #define SIP_IMPL_STR "ssse3"
  #else
    #define SIP_IMPL_STR "sse2"
  #endif
#else
  #define SIP_IMPL_STR "portable"
#endif

//------------------------------------------------------------
#define SIPCOMPRESS_64                    \
  v0 += v1; v2 += v3;                     \
  v1 = ROTL64(v1,13); v3 = ROTL64(v3,16); \
  v1 ^= v0; v3 ^= v2;                     \
  v0 = ROTL64(v0,32);                     \
  v2 += v1; v0 += v3;                     \
  v1 = ROTL64(v1,17); v3 = ROTL64(v3,21); \
  v1 ^= v2; v3 ^= v0;                     \
  v2 = ROTL64(v2,32)

/* The 64bit 1-3 and 2-4 variants */
template <bool variant_2_4, bool bswap>
static uint64_t siphash_portable( const uint64_t key[2], const uint8_t * m, size_t len ) {
    uint64_t v0, v1, v2, v3;
    uint64_t mi, k0, k1;
    uint64_t last7;
    size_t   i, blocks;

    k0 = key[0];
    k1 = key[1];

    v0 = k0 ^ UINT64_C(0x736f6d6570736575);
    v1 = k1 ^ UINT64_C(0x646f72616e646f6d);
    v2 = k0 ^ UINT64_C(0x6c7967656e657261);
    v3 = k1 ^ UINT64_C(0x7465646279746573);

    for (i = 0, blocks = (len & ~7); i < blocks; i += 8) {
        mi  = GET_U64<bswap>(m, i);
        v3 ^= mi;
        SIPCOMPRESS_64;
        if (variant_2_4) {
            SIPCOMPRESS_64;
        }
        v0 ^= mi;
    }

    last7 = (uint64_t)(len & 0xff) << 56;
    switch (len - blocks) {
    case 7: last7 |= (uint64_t)m[i + 6] << 48; // FALLTHROUGH
    case 6: last7 |= (uint64_t)m[i + 5] << 40; // FALLTHROUGH
    case 5: last7 |= (uint64_t)m[i + 4] << 32; // FALLTHROUGH
    case 4: last7 |= (uint64_t)m[i + 3] << 24; // FALLTHROUGH
    case 3: last7 |= (uint64_t)m[i + 2] << 16; // FALLTHROUGH
    case 2: last7 |= (uint64_t)m[i + 1] <<  8; // FALLTHROUGH
    case 1: last7 |= (uint64_t)m[i + 0];       // FALLTHROUGH
    case 0:
    default:;
    }

    v3 ^= last7;
    SIPCOMPRESS_64;
    if (variant_2_4) {
        SIPCOMPRESS_64;
    }
    v0 ^= last7;
    v2 ^= 0xff;
    SIPCOMPRESS_64;
    SIPCOMPRESS_64;
    SIPCOMPRESS_64;
    if (variant_2_4) {
        SIPCOMPRESS_64;
    }
    return v0 ^ v1 ^ v2 ^ v3;
}

//------------------------------------------------------------
#if defined(HAVE_SSSE_3) || defined(HAVE_SSE_2)
typedef __m128i  xmmi;
typedef __m64    qmm;

typedef union packedelem64_t {
    uint64_t  u[2];
    xmmi      v;
} packedelem64;

typedef union packedelem8_t {
    uint8_t  u[16];
    xmmi     v;
} packedelem8;

/* 0,2,1,3 */
static const packedelem64 siphash_init[2] = {
    { { UINT64_C(0x736f6d6570736575), UINT64_C(0x6c7967656e657261) } },
    { { UINT64_C(0x646f72616e646f6d), UINT64_C(0x7465646279746573) } }
};

static const packedelem64 siphash_final = {
    { UINT64_C(0x0000000000000000), UINT64_C(0x00000000000000ff) }
};

static const packedelem8 siphash_rot16v3 = {
    { 14, 15, 8, 9, 10, 11, 12, 13, 8, 9, 10, 11, 12, 13, 14, 15 }
};

template <bool variant_2_4, bool bswap>
static uint64_t siphash_sse( const uint64_t key[2], const uint8_t * m, size_t len ) {
    xmmi     k, v02, v20, v13, v11, v33, mi;
    uint64_t last7;
    uint32_t lo, hi;
    size_t   i, blocks;

    k   = _mm_loadu_si128((xmmi *)key);
    v02 = siphash_init[0].v;
    v13 = siphash_init[1].v;
    v02 = _mm_xor_si128(v02, _mm_unpacklo_epi64(k, k));
    v13 = _mm_xor_si128(v13, _mm_unpackhi_epi64(k, k));

  #if defined(HAVE_SSSE_3)
#define sipcompress()                                                        \
    v11 = v13;                                                               \
    v33 = v13;                                                               \
    v11 = _mm_or_si128(_mm_slli_epi64(v11, 13), _mm_srli_epi64(v11, 64-13)); \
    v02 = _mm_add_epi64(v02, v13);                                           \
    v33 = _mm_shuffle_epi8(v33, siphash_rot16v3.v);                          \
    v13 = _mm_unpacklo_epi64(v11, v33);                                      \
    v13 = _mm_xor_si128(v13, v02);                                           \
    v20 = _mm_shuffle_epi32(v02, _MM_SHUFFLE(0,1,3,2));                      \
    v11 = v13;                                                               \
    v33 = _mm_shuffle_epi32(v13, _MM_SHUFFLE(1,0,3,2));                      \
    v11 = _mm_or_si128(_mm_slli_epi64(v11, 17), _mm_srli_epi64(v11, 64-17)); \
    v20 = _mm_add_epi64(v20, v13);                                           \
    v33 = _mm_or_si128(_mm_slli_epi64(v33, 21), _mm_srli_epi64(v33, 64-21)); \
    v13 = _mm_unpacklo_epi64(v11, v33);                                      \
    v13 = _mm_unpacklo_epi64(v11, v33);                                      \
    v02 = _mm_shuffle_epi32(v20, _MM_SHUFFLE(0,1,3,2));                      \
    v13 = _mm_xor_si128(v13, v20);
  #else
#define sipcompress()                                                        \
    v11 = v13;                                                               \
    v33 = _mm_shuffle_epi32(v13, _MM_SHUFFLE(1,0,3,2));                      \
    v11 = _mm_or_si128(_mm_slli_epi64(v11, 13), _mm_srli_epi64(v11, 64-13)); \
    v02 = _mm_add_epi64(v02, v13);                                           \
    v33 = _mm_or_si128(_mm_slli_epi64(v33, 16), _mm_srli_epi64(v33, 64-16)); \
    v13 = _mm_unpacklo_epi64(v11, v33);                                      \
    v13 = _mm_xor_si128(v13, v02);                                           \
    v20 = _mm_shuffle_epi32(v02, _MM_SHUFFLE(0,1,3,2));                      \
    v11 = v13;                                                               \
    v33 = _mm_shuffle_epi32(v13, _MM_SHUFFLE(1,0,3,2));                      \
    v11 = _mm_or_si128(_mm_slli_epi64(v11, 17), _mm_srli_epi64(v11, 64-17)); \
    v20 = _mm_add_epi64(v20, v13);                                           \
    v33 = _mm_or_si128(_mm_slli_epi64(v33, 21), _mm_srli_epi64(v33, 64-21)); \
    v13 = _mm_unpacklo_epi64(v11, v33);                                      \
    v13 = _mm_unpacklo_epi64(v11, v33);                                      \
    v02 = _mm_shuffle_epi32(v20, _MM_SHUFFLE(0,1,3,2));                      \
    v13 = _mm_xor_si128(v13, v20);
  #endif

    for (i = 0, blocks = (len & ~7); i < blocks; i += 8) {
        mi = _mm_loadl_epi64((xmmi *)(m + i));
        if (bswap) {
            mi = mm_bswap64(mi);
        }
        v13 = _mm_xor_si128(v13, _mm_slli_si128(mi, 8));
        sipcompress();
        if (variant_2_4) {
            sipcompress();
        }
        v02 = _mm_xor_si128(v02, mi);
    }

    last7 = (uint64_t)(len & 0xff) << 56;
    switch (len - blocks) {
    case 7: last7 |= (uint64_t)m[i + 6] << 48; // FALLTHROUGH
    case 6: last7 |= (uint64_t)m[i + 5] << 40; // FALLTHROUGH
    case 5: last7 |= (uint64_t)m[i + 4] << 32; // FALLTHROUGH
    case 4: last7 |= (uint64_t)m[i + 3] << 24; // FALLTHROUGH
    case 3: last7 |= (uint64_t)m[i + 2] << 16; // FALLTHROUGH
    case 2: last7 |= (uint64_t)m[i + 1] <<  8; // FALLTHROUGH
    case 1: last7 |= (uint64_t)m[i + 0];       // FALLTHROUGH
    case 0:
    default:;
    }

    mi  = _mm_unpacklo_epi32(_mm_cvtsi32_si128((uint32_t)last7), _mm_cvtsi32_si128((uint32_t)(last7 >> 32)));
    v13 = _mm_xor_si128(v13, _mm_slli_si128(mi, 8));
    sipcompress();
    if (variant_2_4) {
        sipcompress();
    }
    v02 = _mm_xor_si128(v02, mi);
    v02 = _mm_xor_si128(v02, siphash_final.v);
    sipcompress();
    sipcompress();
    sipcompress();
    if (variant_2_4) {
        sipcompress();
    }

    v02 = _mm_xor_si128(v02, v13);
    v02 = _mm_xor_si128(v02, _mm_shuffle_epi32(v02, _MM_SHUFFLE(1, 0, 3, 2)));
    lo  = _mm_cvtsi128_si32(v02);
    hi  = _mm_cvtsi128_si32(_mm_srli_si128(v02, 4));
    return ((uint64_t)hi << 32) | lo;
}

#endif

//------------------------------------------------------------
// the faster half 32bit variant for the linux kernel
#define SIPCOMPRESS_32       \
    do {                     \
        v0 += v1;            \
        v1 = ROTL32(v1, 5);  \
        v1 ^= v0;            \
        v0 = ROTL32(v0, 16); \
        v2 += v3;            \
        v3 = ROTL32(v3, 8);  \
        v3 ^= v2;            \
        v0 += v3;            \
        v3 = ROTL32(v3, 7);  \
        v3 ^= v0;            \
        v2 += v1;            \
        v1 = ROTL32(v1, 13); \
        v1 ^= v2;            \
        v2 = ROTL32(v2, 16); \
    } while (0)

template <bool bswap>
static uint32_t halfsiphash( const uint32_t key[2], const uint8_t * m, size_t len ) {
    uint32_t        v0   = 0;
    uint32_t        v1   = 0;
    uint32_t        v2   = 0x6c796765;
    uint32_t        v3   = 0x74656462;
    uint32_t        k0   = key[0];
    uint32_t        k1   = key[1];
    uint32_t        mi;
    const uint8_t * end  = m + len - (len % sizeof(uint32_t));
    const int       left = len & 3;
    uint32_t        b    = ((uint32_t)len) << 24;

    v3 ^= k1;
    v2 ^= k0;
    v1 ^= k1;
    v0 ^= k0;

    for (; m != end; m += 4) {
        mi  = GET_U32<bswap>(m, 0);
        v3 ^= mi;
        SIPCOMPRESS_32;
        SIPCOMPRESS_32;
        v0 ^= mi;
    }

    switch (left) {
    case 3:
            b |= ((uint32_t)m[2]) << 16; // FALLTHROUGH
    case 2:
            b |= ((uint32_t)m[1]) <<  8; // FALLTHROUGH
    case 1:
            b |= ((uint32_t)m[0]);
            break;
    case 0:
            break;
    }

    v3 ^= b;
    SIPCOMPRESS_32;
    SIPCOMPRESS_32;
    v0 ^= b;
    v2 ^= 0xff;
    SIPCOMPRESS_32;
    SIPCOMPRESS_32;
    SIPCOMPRESS_32;
    SIPCOMPRESS_32;
    return v1 ^ v3;
}

//------------------------------------------------------------
// Damian Gryski's Tiny SipHash variant
//
// I could find no source for this other than rurban's SMHasher
// fork. The slightly-bizarre seeding routine is a hardcoded 64-bit
// version of the awkward global-variable+Rand() one in that code.
template <bool bswap>
static uint64_t tsip( const uint64_t seed, const uint8_t * m, uint64_t len ) {
    uint64_t v0, v1;
    uint64_t mi, k0, k1;
    uint64_t last7;

    k0 = seed ^ UINT64_C(0x4915a64c00000000);
    k1 = seed ^ UINT64_C(0x1c29205700000000);

    v0 = k0   ^ UINT64_C(0x736f6d6570736575);
    v1 = k1   ^ UINT64_C(0x646f72616e646f6d);

#define tsipcompress()        \
  do {                        \
    v0 += v1;                 \
    v1 = ROTL64(v1, 13) ^ v0; \
    v0 = ROTL64(v0, 35) + v1; \
    v1 = ROTL64(v1, 17) ^ v0; \
    v0 = ROTL64(v0, 21);      \
  } while (0)

    const uint8_t * end = m + (len & ~7);

    while (m < end) {
        mi  = GET_U64<bswap>(m, 0);
        v1 ^= mi;
        tsipcompress();
        v0 ^= mi;
        m  += 8;
    }

    last7 = (uint64_t)(len & 0xff) << 56;
    switch (len & 7) {
    case 7:
            last7 |= (uint64_t)m[6] << 48; // FALLTHROUGH
    case 6:
            last7 |= (uint64_t)m[5] << 40; // FALLTHROUGH
    case 5:
            last7 |= (uint64_t)m[4] << 32; // FALLTHROUGH
    case 4:
            last7 |= (uint64_t)m[3] << 24; // FALLTHROUGH
    case 3:
            last7 |= (uint64_t)m[2] << 16; // FALLTHROUGH
    case 2:
            last7 |= (uint64_t)m[1] <<  8; // FALLTHROUGH
    case 1:
            last7 |= (uint64_t)m[0];       // FALLTHROUGH
    case 0:
    default:;
    }

    v1 ^= last7;
    tsipcompress();
    v0 ^= last7;

    // finalization
    v1 ^= 0xff;
    tsipcompress();
    v1  = ROTL64(v1, 32);
    tsipcompress();
    v1  = ROTL64(v1, 32);

    return v0 ^ v1;
}

//------------------------------------------------------------
template <bool bswap, bool xorfold>
static void SipHash_2_4( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t key[2] = { seed, 0 };
    uint64_t h64;

#if defined(HAVE_SSSE_3) || defined(HAVE_SSE_2)
    h64 = siphash_sse     <true, bswap>(key, (const uint8_t *)in, len);
#else
    h64 = siphash_portable<true, bswap>(key, (const uint8_t *)in, len);
#endif
    if (xorfold) {
        uint32_t h32 = (h64 & 0xffffffff) ^ (h64 >> 32);
        PUT_U32<bswap>(h32, (uint8_t *)out, 0);
    } else {
        PUT_U64<bswap>(h64, (uint8_t *)out, 0);
    }
}

template <bool bswap, bool xorfold>
static void SipHash_1_3( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t key[2] = { seed, 0 };
    uint64_t h64;

#if defined(HAVE_SSSE_3) || defined(HAVE_SSE_2)
    h64 = siphash_sse     <false, bswap>(key, (const uint8_t *)in, len);
#else
    h64 = siphash_portable<false, bswap>(key, (const uint8_t *)in, len);
#endif
    if (xorfold) {
        uint32_t h32 = (h64 & 0xffffffff) ^ (h64 >> 32);
        PUT_U32<bswap>(h32, (uint8_t *)out, 0);
    } else {
        PUT_U64<bswap>(h64, (uint8_t *)out, 0);
    }
}

template <bool bswap>
static void HalfSipHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t key[2] = { (uint32_t)seed, (uint32_t)(((uint64_t)seed) >> 32) };
    uint32_t h;

    h = halfsiphash<bswap>(key, (const uint8_t *)in, len);
    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void TinySipHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h;

    h = tsip<bswap>((uint64_t)seed, (const uint8_t *)in, len);
    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(siphash,
   $.src_url    = "https://github.com/floodyberry/siphash",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(SipHash_2_4,
   $.desc       = "SipHash 2-4",
   $.impl       = SIP_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_XL_SEED      |
         FLAG_HASH_CRYPTOGRAPHIC,
   $.impl_flags =
         FLAG_IMPL_VERY_SLOW    |
         FLAG_IMPL_TYPE_PUNNING |
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x57B661ED,
   $.verification_BE = 0x01B634D0,
   $.hashfn_native   = SipHash_2_4<false, false>,
   $.hashfn_bswap    = SipHash_2_4<true, false>
 );

REGISTER_HASH(SipHash_2_4__folded,
   $.desc       = "SipHash 2-4, XOR folded down to 32 bits",
   $.impl       = SIP_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_XL_SEED      |
         FLAG_HASH_CRYPTOGRAPHIC,
   $.impl_flags =
         FLAG_IMPL_VERY_SLOW    |
         FLAG_IMPL_TYPE_PUNNING |
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0xDD46AB1A,
   $.verification_BE = 0xE5FA5E53,
   $.hashfn_native   = SipHash_2_4<false, true>,
   $.hashfn_bswap    = SipHash_2_4<true, true>
 );

REGISTER_HASH(SipHash_1_3,
   $.desc       = "SipHash 1-3",
   $.impl       = SIP_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_XL_SEED      |
         FLAG_HASH_CRYPTOGRAPHIC,
   $.impl_flags =
         FLAG_IMPL_SLOW         |
         FLAG_IMPL_TYPE_PUNNING |
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x8936B193,
   $.verification_BE = 0xBEB90EAC,
   $.hashfn_native   = SipHash_1_3<false, false>,
   $.hashfn_bswap    = SipHash_1_3<true, false>
 );

REGISTER_HASH(SipHash_1_3__folded,
   $.desc       = "SipHash 1-3, XOR folded down to 32 bits",
   $.impl       = SIP_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_XL_SEED      |
         FLAG_HASH_CRYPTOGRAPHIC,
   $.impl_flags =
         FLAG_IMPL_SLOW         |
         FLAG_IMPL_TYPE_PUNNING |
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0xC7BC11F8,
   $.verification_BE = 0x5FE8339A,
   $.hashfn_native   = SipHash_1_3<false, true>,
   $.hashfn_bswap    = SipHash_1_3<true, true>
 );

REGISTER_HASH(HalfSipHash,
   $.desc       = "SipHash half-width version",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC,
   $.impl_flags =
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT  |
         FLAG_IMPL_SLOW,
   $.bits = 32,
   $.verification_LE = 0xD2BE7FD8,
   $.verification_BE = 0xEC8BC9AF,
   $.hashfn_native   = HalfSipHash<false>,
   $.hashfn_bswap    = HalfSipHash<true>
 );

REGISTER_HASH(TinySipHash,
   $.desc       = "Damian Gryski's Tiny SipHash variant",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x75C732C0,
   $.verification_BE = 0xEFE9C35D,
   $.hashfn_native   = TinySipHash<false>,
   $.hashfn_bswap    = TinySipHash<true>
 );
