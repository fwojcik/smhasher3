/*
 * nmhash
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (C) 2023       jason
 * Copyright (c) 2021, James Z.M. Gao
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "Platform.h"
#include "Hashlib.h"

//------------------------------------------------------------
// #define NMH_VERSION 2

/* vector macros */
#define NMH_SCALAR 0
#define NMH_SSE2   1
#define NMH_AVX2   2
#define NMH_AVX512 3

#if defined(HAVE_AVX512_BW)
  #define NMH_VECTOR NMH_AVX512 /* _mm512_mullo_epi16 requires AVX512BW */
  #define NMH_ACC_ALIGN 64
#elif defined(HAVE_AVX2)
  #define NMH_VECTOR NMH_AVX2
  #define NMH_ACC_ALIGN 32
#elif defined(HAVE_SSE_2)
  #define NMH_VECTOR NMH_SSE2
  #define NMH_ACC_ALIGN 16
#else
  #define NMH_VECTOR NMH_SCALAR
  #define NMH_ACC_ALIGN 16
#endif

const char * nmh_impl_str[] = {
    "scalar", // NMH_SCALAR
    "sse2",   // NMH_SSE2
    "avx2",   // NMH_AVX2
    "avx512", // NMH_AVX512
};

#if NMH_VECTOR > NMH_SCALAR
  #include "Intrinsics.h"
#endif

//------------------------------------------------------------
// constants

// primes from xxh
#define NMH_PRIME32_1  UINT32_C(0x9E3779B1)
#define NMH_PRIME32_2  UINT32_C(0x85EBCA77)
#define NMH_PRIME32_3  UINT32_C(0xC2B2AE3D)
#define NMH_PRIME32_4  UINT32_C(0x27D4EB2F)

// Pseudorandom secret taken directly from FARSH
alignas(NMH_ACC_ALIGN) static const uint32_t NMH_ACC_INIT[32] = {
    UINT32_C(0xB8FE6C39), UINT32_C(0x23A44BBE), UINT32_C(0x7C01812C), UINT32_C(0xF721AD1C),
    UINT32_C(0xDED46DE9), UINT32_C(0x839097DB), UINT32_C(0x7240A4A4), UINT32_C(0xB7B3671F),
    UINT32_C(0xCB79E64E), UINT32_C(0xCCC0E578), UINT32_C(0x825AD07D), UINT32_C(0xCCFF7221),
    UINT32_C(0xB8084674), UINT32_C(0xF743248E), UINT32_C(0xE03590E6), UINT32_C(0x813A264C),

    UINT32_C(0x3C2852BB), UINT32_C(0x91C300CB), UINT32_C(0x88D0658B), UINT32_C(0x1B532EA3),
    UINT32_C(0x71644897), UINT32_C(0xA20DF94E), UINT32_C(0x3819EF46), UINT32_C(0xA9DEACD8),
    UINT32_C(0xA8FA763F), UINT32_C(0xE39C343F), UINT32_C(0xF9DCBBC7), UINT32_C(0xC70B4F1D),
    UINT32_C(0x8A51E04B), UINT32_C(0xCDB45931), UINT32_C(0xC89F7EC9), UINT32_C(0xD9787364),
};


#define __NMH_M1 UINT32_C(0xF0D9649B)
#define __NMH_M2 UINT32_C(0x29A7935D)
#define __NMH_M3 UINT32_C(0x55D35831)

alignas(NMH_ACC_ALIGN) static const uint32_t __NMH_M1_V[32] = {
    __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1,
    __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1,
    __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1,
    __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1, __NMH_M1,
};
alignas(NMH_ACC_ALIGN) static const uint32_t __NMH_M2_V[32] = {
    __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2,
    __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2,
    __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2,
    __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2, __NMH_M2,
};
alignas(NMH_ACC_ALIGN) static const uint32_t __NMH_M3_V[32] = {
    __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3,
    __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3,
    __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3,
    __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3, __NMH_M3,
};

//------------------------------------------------------------
static inline uint32_t NMHASH_mult16( uint32_t a, uint32_t b ) {
    uint16_t al = (uint16_t)(a      );
    uint16_t ah = (uint16_t)(a >> 16);
    uint16_t bl = (uint16_t)(b      );
    uint16_t bh = (uint16_t)(b >> 16);

    al *= bl;
    ah *= bh;

    return (((uint32_t)ah) << 16) + ((uint32_t)al);
}

static inline uint32_t NMHASH32_0to8( uint32_t const x, uint32_t const seed2 ) {
    /* base mixer: [-6 -12 776bf593 -19 11 3fb39c65 -15 -9 e9139917 -11 16] = 0.027071104091278835 */
    const uint32_t m1 = UINT32_C(0x776BF593);
    const uint32_t m2 = UINT32_C(0x3FB39C65);
    const uint32_t m3 = UINT32_C(0xE9139917);

#if NMH_VECTOR == NMH_SCALAR
    {
        uint32_t vx;
        vx  = x;
        vx ^= (vx >> 12) ^ (vx >>  6);
        vx  = NMHASH_mult16(vx, m1);
        vx ^= (vx << 11) ^ (vx >> 19);
        vx  = NMHASH_mult16(vx, m2);
        vx ^= seed2;
        vx ^= (vx >> 15) ^ (vx >>  9);
        vx  = NMHASH_mult16(vx, m3);
        vx ^= (vx << 16) ^ (vx >> 11);
        return vx;
    }
#else /* at least NMH_SSE2 */
    {
        __m128i       hv = _mm_setr_epi32((int)x    , 0, 0, 0);
        const __m128i sv = _mm_setr_epi32((int)seed2, 0, 0, 0);
        const uint32_t * const result = (const uint32_t *)&hv;

        hv = _mm_xor_si128(_mm_xor_si128(hv, _mm_srli_epi32(hv, 12)), _mm_srli_epi32(hv,  6));
        hv = _mm_mullo_epi16(hv, _mm_setr_epi32((int)m1, 0, 0, 0));
        hv = _mm_xor_si128(_mm_xor_si128(hv, _mm_slli_epi32(hv, 11)), _mm_srli_epi32(hv, 19));
        hv = _mm_mullo_epi16(hv, _mm_setr_epi32((int)m2, 0, 0, 0));

        hv = _mm_xor_si128(hv, sv);

        hv = _mm_xor_si128(_mm_xor_si128(hv, _mm_srli_epi32(hv, 15)), _mm_srli_epi32(hv,  9));
        hv = _mm_mullo_epi16(hv, _mm_setr_epi32((int)m3, 0, 0, 0));
        hv = _mm_xor_si128(_mm_xor_si128(hv, _mm_slli_epi32(hv, 16)), _mm_srli_epi32(hv, 11));

        return *result;
    }
#endif
}

template <bool gt32bytes, bool bswap>
static inline uint32_t NMHASH32_9to255( const uint8_t * const RESTRICT p, size_t const len, uint32_t const seed ) {
    /* base mixer: [f0d9649b  5 -13 29a7935d -9 11 55d35831 -20 -10 ] = 0.93495901789135362 */
    uint32_t result = 0;

#if NMH_VECTOR == NMH_SCALAR
    {
        uint32_t       x[4], y[4];
        uint32_t const sl = seed + (uint32_t)len;
        size_t         j;
        x[0] = NMH_PRIME32_1;
        x[1] = NMH_PRIME32_2;
        x[2] = NMH_PRIME32_3;
        x[3] = NMH_PRIME32_4;
        for (j = 0; j < 4; ++j) { y[j] = sl; }

        if (gt32bytes) {
            /* 33 to 255 bytes */
            size_t const r = (len - 1) / 32;
            size_t       i;
            for (i = 0; i < r; ++i) {
                for (j = 0; j < 4; ++j) { x[j] ^= GET_U32<bswap>(p, i * 32 + j * 4); }
                for (j = 0; j < 4; ++j) { y[j] ^= GET_U32<bswap>(p, i * 32 + j * 4 + 16); }
                for (j = 0; j < 4; ++j) { x[j] += y[j]; }

                for (j = 0; j < 4; ++j) { x[j] = NMHASH_mult16(x[j], __NMH_M1); }

                for (j = 0; j < 4; ++j) { x[j] ^= (x[j] << 5) ^ (x[j] >> 13); }

                for (j = 0; j < 4; ++j) { x[j] = NMHASH_mult16(x[j], __NMH_M2); }

                for (j = 0; j < 4; ++j) { x[j] ^= y[j]; }

                for (j = 0; j < 4; ++j) { x[j] ^= (x[j] << 11) ^ (x[j] >> 9); }

                for (j = 0; j < 4; ++j) { x[j] = NMHASH_mult16(x[j], __NMH_M3); }

                for (j = 0; j < 4; ++j) { x[j] ^= (x[j] >> 10) ^ (x[j] >> 20); }
            }
            for (j = 0; j < 4; ++j) { x[j] ^= GET_U32<bswap>(p, len - 32 + j * 4); }
            for (j = 0; j < 4; ++j) { y[j] ^= GET_U32<bswap>(p, len - 16 + j * 4); }
        } else {
            /* 9 to 32 bytes */
            x[0] ^= GET_U32<bswap>(p, 0                              );
            x[1] ^= GET_U32<bswap>(p,           ((len >> 4) << 3)    );
            x[2] ^= GET_U32<bswap>(p, len - 8                        );
            x[3] ^= GET_U32<bswap>(p, len - 8 - ((len >> 4) << 3)    );
            y[0] ^= GET_U32<bswap>(p,                               4);
            y[1] ^= GET_U32<bswap>(p,           ((len >> 4) << 3) + 4);
            y[2] ^= GET_U32<bswap>(p, len - 8                     + 4);
            y[3] ^= GET_U32<bswap>(p, len - 8 - ((len >> 4) << 3) + 4);
        }

        for (j = 0; j < 4; ++j) { x[j] += y[j]; }
        for (j = 0; j < 4; ++j) { y[j] ^= (y[j] << 17) ^ (y[j] >> 6); }

        for (j = 0; j < 4; ++j) { x[j] = NMHASH_mult16(x[j], __NMH_M1); }
        for (j = 0; j < 4; ++j) { x[j] ^= (x[j] << 5) ^ (x[j] >> 13); }
        for (j = 0; j < 4; ++j) { x[j] = NMHASH_mult16(x[j], __NMH_M2); }

        for (j = 0; j < 4; ++j) { x[j] ^= y[j]; }

        for (j = 0; j < 4; ++j) { x[j] ^= (x[j] << 11) ^ (x[j] >> 9); }
        for (j = 0; j < 4; ++j) { x[j] = NMHASH_mult16(x[j], __NMH_M3); }
        for (j = 0; j < 4; ++j) { x[j] ^= (x[j] >> 10) ^ (x[j] >> 20); }

        x[0] ^= NMH_PRIME32_1;
        x[1] ^= NMH_PRIME32_2;
        x[2] ^= NMH_PRIME32_3;
        x[3] ^= NMH_PRIME32_4;

        for (j = 1; j < 4; ++j) { x[0] += x[j]; }

        x[0]  ^= sl + (sl >> 5);
        x[0]   = NMHASH_mult16(x[0], __NMH_M3);
        x[0]  ^= (x[0] >> 10) ^ (x[0] >> 20);

        result = x[0];
    }
#else /* at least NMH_SSE2 */
    {
        __m128i const h0 = _mm_setr_epi32((int)NMH_PRIME32_1, (int)NMH_PRIME32_2,
                (int)NMH_PRIME32_3, (int)NMH_PRIME32_4);
        __m128i const sl = _mm_set1_epi32((int)seed + (int)len);
        __m128i const m1 = _mm_set1_epi32((int)__NMH_M1       );
        __m128i const m2 = _mm_set1_epi32((int)__NMH_M2       );
        __m128i const m3 = _mm_set1_epi32((int)__NMH_M3       );
        __m128i       x  = h0;
        __m128i       y  = sl;
        const uint32_t * const px = (const uint32_t *)&x;

        if (gt32bytes) {
            /* 32 to 127 bytes */
            size_t const r = (len - 1) / 32;
            size_t       i;
            for (i = 0; i < r; ++i) {
                if (bswap) {
                    x = _mm_xor_si128(x, mm_bswap32(_mm_loadu_si128((const __m128i *)(p + i * 32     ))));
                    y = _mm_xor_si128(y, mm_bswap32(_mm_loadu_si128((const __m128i *)(p + i * 32 + 16))));
                } else {
                    x = _mm_xor_si128(x, _mm_loadu_si128((const __m128i *)(p + i * 32     )));
                    y = _mm_xor_si128(y, _mm_loadu_si128((const __m128i *)(p + i * 32 + 16)));
                }
                x = _mm_add_epi32(x, y);
                x = _mm_mullo_epi16(x, m1);
                x = _mm_xor_si128(_mm_xor_si128(x, _mm_slli_epi32(x,  5)), _mm_srli_epi32(x, 13));
                x = _mm_mullo_epi16(x, m2);
                x = _mm_xor_si128(x, y);
                x = _mm_xor_si128(_mm_xor_si128(x, _mm_slli_epi32(x, 11)), _mm_srli_epi32(x,  9));
                x = _mm_mullo_epi16(x, m3);
                x = _mm_xor_si128(_mm_xor_si128(x, _mm_srli_epi32(x, 10)), _mm_srli_epi32(x, 20));
            }
            if (bswap) {
                x = _mm_xor_si128(x, mm_bswap32(_mm_loadu_si128((const __m128i *)(p + len - 32))));
                y = _mm_xor_si128(y, mm_bswap32(_mm_loadu_si128((const __m128i *)(p + len - 16))));
            } else {
                x = _mm_xor_si128(x, _mm_loadu_si128((const __m128i *)(p + len - 32)));
                y = _mm_xor_si128(y, _mm_loadu_si128((const __m128i *)(p + len - 16)));
            }
        } else {
            /* 9 to 32 bytes */
            x = _mm_xor_si128(x, _mm_setr_epi32((int)GET_U32<bswap>(p, 0), (int)GET_U32<bswap>(
                    p, ((len >> 4) << 3))    , (int)GET_U32<bswap>(p, len - 8    ), (int)GET_U32<bswap>(
                    p, len - 8 - ((len >> 4) << 3)    )));
            y = _mm_xor_si128(y, _mm_setr_epi32((int)GET_U32<bswap>(p, 4), (int)GET_U32<bswap>(
                    p, ((len >> 4) << 3) + 4), (int)GET_U32<bswap>(p, len - 8 + 4), (int)GET_U32<bswap>(
                    p, len - 8 - ((len >> 4) << 3) + 4)));
        }

        x      = _mm_add_epi32(x, y);

        y      = _mm_xor_si128(_mm_xor_si128(y, _mm_slli_epi32(y, 17)), _mm_srli_epi32(y,  6));

        x      = _mm_mullo_epi16(x, m1);
        x      = _mm_xor_si128(_mm_xor_si128(x, _mm_slli_epi32(x,  5)), _mm_srli_epi32(x, 13));
        x      = _mm_mullo_epi16(x, m2);
        x      = _mm_xor_si128(x, y);
        x      = _mm_xor_si128(_mm_xor_si128(x, _mm_slli_epi32(x, 11)), _mm_srli_epi32(x,  9));
        x      = _mm_mullo_epi16(x, m3);
        x      = _mm_xor_si128(_mm_xor_si128(x, _mm_srli_epi32(x, 10)), _mm_srli_epi32(x, 20));

        x      = _mm_xor_si128(x, h0);
        x      = _mm_add_epi32(x, _mm_srli_si128(x, 4));
        x      = _mm_add_epi32(x, _mm_srli_si128(x, 8));

        x      = _mm_xor_si128(x, _mm_add_epi32(sl, _mm_srli_epi32(sl, 5)));
        x      = _mm_mullo_epi16(x, m3);
        x      = _mm_xor_si128(_mm_xor_si128(x, _mm_srli_epi32(x, 10)), _mm_srli_epi32(x, 20));

        result = *px;
    }
#endif

    return *&result;
}

#undef __NMH_M3
#undef __NMH_M2
#undef __NMH_M1

template <bool bswap>
static inline uint32_t NMHASH32_9to32( const uint8_t * const RESTRICT p, size_t const len, uint32_t const seed ) {
    return NMHASH32_9to255<false, bswap>(p, len, seed);
}

template <bool bswap>
static inline uint32_t NMHASH32_33to255( const uint8_t * const RESTRICT p, size_t const len, uint32_t const seed ) {
    return NMHASH32_9to255<true, bswap>(p, len, seed);
}

template <bool bswap>
static inline void NMHASH32_long_round_scalar( uint32_t * const RESTRICT accX, uint32_t * const RESTRICT accY,
        const uint8_t * const RESTRICT p ) {
    /*
     * breadth first calculation will hint some compiler to auto
     * vectorize the code on gcc, the performance becomes 10x than the
     * depth first, and about 80% of the manually vectorized code
     */
    const size_t nbGroups = sizeof(NMH_ACC_INIT) / sizeof(*NMH_ACC_INIT);
    size_t       i;

    for (i = 0; i < nbGroups; ++i) {
        accX[i] ^= GET_U32<bswap>(p, i * 4);
    }
    for (i = 0; i < nbGroups; ++i) {
        accY[i] ^= GET_U32<bswap>(p, i * 4 + sizeof(NMH_ACC_INIT));
    }
    for (i = 0; i < nbGroups; ++i) {
        accX[i] += accY[i];
    }
    for (i = 0; i < nbGroups; ++i) {
        accY[i] ^= accX[i] >> 1;
    }
    for (i = 0; i < nbGroups * 2; ++i) {
        ((uint16_t *)accX)[i] *= ((uint16_t *)__NMH_M1_V)[i];
    }
    for (i = 0; i < nbGroups; ++i) {
        accX[i] ^= accX[i] << 5 ^ accX[i] >> 13;
    }
    for (i = 0; i < nbGroups * 2; ++i) {
        ((uint16_t *)accX)[i] *= ((uint16_t *)__NMH_M2_V)[i];
    }
    for (i = 0; i < nbGroups; ++i) {
        accX[i] ^= accY[i];
    }
    for (i = 0; i < nbGroups; ++i) {
        accX[i] ^= accX[i] << 11 ^ accX[i] >> 9;
    }
    for (i = 0; i < nbGroups * 2; ++i) {
        ((uint16_t *)accX)[i] *= ((uint16_t *)__NMH_M3_V)[i];
    }
    for (i = 0; i < nbGroups; ++i) {
        accX[i] ^= accX[i] >> 10 ^ accX[i] >> 20;
    }
}

#if NMH_VECTOR > NMH_SCALAR

  #if NMH_VECTOR == NMH_SSE2
    #define _NMH_M_(F) mm_ ## F
    #define _NMH_MM_(F) _mm_ ## F
    #define _NMH_MMW_(F) _mm_ ## F ## 128
    #define _NMH_MM_T __m128i
  #elif NMH_VECTOR == NMH_AVX2
    #define _NMH_M_(F) mm256_ ## F
    #define _NMH_MM_(F) _mm256_ ## F
    #define _NMH_MMW_(F) _mm256_ ## F ## 256
    #define _NMH_MM_T __m256i
  #elif NMH_VECTOR == NMH_AVX512
    #define _NMH_M_(F) mm512_ ## F
    #define _NMH_MM_(F) _mm512_ ## F
    #define _NMH_MMW_(F) _mm512_ ## F ## 512
    #define _NMH_MM_T __m512i
  #endif

  #define NMH_VECTOR_NB_GROUP (sizeof(NMH_ACC_INIT) / sizeof(*NMH_ACC_INIT) / \
    (sizeof(_NMH_MM_T) / sizeof(*NMH_ACC_INIT)))

template <bool bswap>
static inline void NMHASH32_long_round_sse( uint32_t * const RESTRICT accX, uint32_t * const RESTRICT accY,
        const uint8_t * const RESTRICT p ) {
    const _NMH_MM_T * const RESTRICT m1 = (const _NMH_MM_T * RESTRICT) __NMH_M1_V;
    const _NMH_MM_T * const RESTRICT m2 = (const _NMH_MM_T * RESTRICT) __NMH_M2_V;
    const _NMH_MM_T * const RESTRICT m3 = (const _NMH_MM_T * RESTRICT) __NMH_M3_V;

    _NMH_MM_T * const xaccX = (_NMH_MM_T *)accX;
    _NMH_MM_T * const xaccY = (_NMH_MM_T *)accY;
    _NMH_MM_T * const xp    = (_NMH_MM_T *)p;
    size_t i;

    for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
        if (bswap) {
            xaccX[i] = _NMH_MMW_(xor_si)(xaccX[i], _NMH_M_(bswap32)(_NMH_MMW_(loadu_si)(xp + i)));
        } else {
            xaccX[i] = _NMH_MMW_(xor_si)(xaccX[i], _NMH_MMW_(loadu_si)(xp + i));
        }
    }
    for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
        if (bswap) {
            xaccY[i] = _NMH_MMW_(xor_si)(xaccY[i], _NMH_M_(bswap32)(_NMH_MMW_(loadu_si)(xp + i + NMH_VECTOR_NB_GROUP)));
        } else {
            xaccY[i] = _NMH_MMW_(xor_si)(xaccY[i], _NMH_MMW_(loadu_si)(xp + i + NMH_VECTOR_NB_GROUP));
        }
    }
    for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
        xaccX[i] = _NMH_MM_(add_epi32)(xaccX[i], xaccY[i]);
    }
    for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
        xaccY[i] = _NMH_MMW_(xor_si)(xaccY[i], _NMH_MM_(srli_epi32)(xaccX[i], 1));
    }
    for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
        xaccX[i] = _NMH_MM_(mullo_epi16)(xaccX[i], *m1);
    }
    for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
        xaccX[i] = _NMH_MMW_(xor_si)(_NMH_MMW_(xor_si)(xaccX[i], _NMH_MM_(
                slli_epi32)(xaccX[i], 5)), _NMH_MM_(srli_epi32)(xaccX[i], 13));
    }
    for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
        xaccX[i] = _NMH_MM_(mullo_epi16)(xaccX[i], *m2);
    }
    for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
        xaccX[i] = _NMH_MMW_(xor_si)(xaccX[i], xaccY[i]);
    }
    for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
        xaccX[i] = _NMH_MMW_(xor_si)(_NMH_MMW_(xor_si)(xaccX[i], _NMH_MM_(
                slli_epi32)(xaccX[i], 11)), _NMH_MM_(srli_epi32)(xaccX[i], 9));
    }
    for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
        xaccX[i] = _NMH_MM_(mullo_epi16)(xaccX[i], *m3);
    }
    for (i = 0; i < NMH_VECTOR_NB_GROUP; ++i) {
        xaccX[i] = _NMH_MMW_(xor_si)(_NMH_MMW_(xor_si)(xaccX[i], _NMH_MM_(
                srli_epi32)(xaccX[i], 10)), _NMH_MM_(srli_epi32)(xaccX[i], 20));
    }
}

  #undef _NMH_MM_
  #undef _NMH_MMW_
  #undef _NMH_MM_T
  #undef NMH_VECTOR_NB_GROUP

#endif /* NMH_VECTOR > NMH_SCALAR */

template <bool bswap>
static inline void NMHASH32_long_round( uint32_t * const RESTRICT accX, uint32_t * const RESTRICT accY,
        const uint8_t * const RESTRICT p ) {
#if NMH_VECTOR > NMH_SCALAR
    return NMHASH32_long_round_sse<bswap>(accX, accY, p);
#else
    return NMHASH32_long_round_scalar<bswap>(accX, accY, p);
#endif
}

template <bool bswap>
static uint32_t NMHASH32_long( const uint8_t * const RESTRICT p, size_t const len, uint32_t const seed ) {
    alignas(NMH_ACC_ALIGN) uint32_t accX[sizeof(NMH_ACC_INIT) / sizeof(*NMH_ACC_INIT)];
    alignas(NMH_ACC_ALIGN) uint32_t accY[sizeof(accX) / sizeof(*accX)];
    size_t const nbRounds = (len - 1) / (sizeof(accX) + sizeof(accY));
    size_t       i;
    uint32_t     sum      = 0;

    /* init */
    for (i = 0; i < sizeof(accX) / sizeof(*accX); ++i) { accX[i] = NMH_ACC_INIT[i]; }
    for (i = 0; i < sizeof(accY) / sizeof(*accY); ++i) { accY[i] = seed; }

    for (i = 0; i < nbRounds; ++i) {
        NMHASH32_long_round<bswap>(accX, accY, p + i * (sizeof(accX) + sizeof(accY)));
    }
    NMHASH32_long_round<bswap>(accX, accY, p + len - (sizeof(accX) + sizeof(accY)));

    /* merge acc */
    for (i = 0; i < sizeof(accX) / sizeof(*accX); ++i) { accX[i] ^= NMH_ACC_INIT[i]; }
    for (i = 0; i < sizeof(accX) / sizeof(*accX); ++i) { sum += accX[i]; }

    /* A no-op if size_t is 32 bits */
    sum += (uint32_t)(len >> 16 >> 16);

    return sum ^ (uint32_t)len;
}

static inline uint32_t NMHASH32_avalanche32( uint32_t const x ) {
    /* [-21 -8 cce5196d 12 -7 464be229 -21 -8] = 3.2267098842182733 */
    const uint32_t m1 = UINT32_C(0xCCE5196D);
    const uint32_t m2 = UINT32_C(0x464BE229);
    uint32_t       vx;

    vx  = x;
    vx ^= (vx >>  8) ^ (vx >> 21);
    vx  = NMHASH_mult16(vx, m1);
    vx ^= (vx << 12) ^ (vx >>  7);
    vx  = NMHASH_mult16(vx, m2);
    return vx ^ (vx >> 8) ^ (vx >> 21);
}

template <bool bswap>
static inline uint32_t NMHASH32( const void * const RESTRICT input, size_t const len, uint32_t seed ) {
    const uint8_t * const p = (const uint8_t *)input;

    if (likely(len <= 32)) {
        if (likely(len > 8)) {
            return NMHASH32_9to32<bswap>(p, len, seed);
        }
        if (likely(len > 4)) {
            uint32_t x = GET_U32<bswap>(p,   0    );
            uint32_t y = GET_U32<bswap>(p, len - 4) ^ (NMH_PRIME32_4 + 2 + seed);
            x += y;
            x ^= x << (len + 7);
            return NMHASH32_0to8(x, ROTL32(y, 5));
        } else {
            uint32_t data;
            switch (len) {
            case 0: seed += NMH_PRIME32_2;
                    data  = 0;
                    break;
            case 1: seed += NMH_PRIME32_2 + (UINT32_C(1) << 24) + (1 << 1);
                    data  = p[0];
                    break;
            case 2: seed += NMH_PRIME32_2 + (UINT32_C(2) << 24) + (2 << 1);
                    data  = GET_U16<bswap>(p, 0);
                    break;
            case 3: seed += NMH_PRIME32_2 + (UINT32_C(3) << 24) + (3 << 1);
                    data  = GET_U16<bswap>(p, 0) | (p[2] << 16);
                    break;
            case 4: seed += NMH_PRIME32_3;
                    data  = GET_U32<bswap>(p, 0);
                    break;
            default: return 0;
            }
            return NMHASH32_0to8(data + seed, ROTL32(seed, 5));
        }
    }
    if (likely(len < 256)) {
        return NMHASH32_33to255<bswap>(p, len, seed);
    }
    return NMHASH32_avalanche32(NMHASH32_long<bswap>(p, len, seed));
}

//------------------------------------------------------------
static inline uint32_t NMHASH32X_0to4( uint32_t x, uint32_t const seed ) {
    /* [bdab1ea9 18 a7896a1b 12 83796a2d 16] = 0.092922873297662509 */
    x ^= seed;
    x *= UINT32_C(0xBDAB1EA9);
    x += ROTL32(seed, 31);
    x ^= x >> 18;
    x *= UINT32_C(0xA7896A1B);
    x ^= x >> 12;
    x *= UINT32_C(0x83796A2D);
    x ^= x >> 16;
    return x;
}

template <bool bswap>
static inline uint32_t NMHASH32X_5to8( const uint8_t * const RESTRICT p, size_t const len, uint32_t const seed ) {
    /*
     * - 5 to 9 bytes
     * - mixer: [11049a7d 23 bcccdc7b 12 065e9dad 12] = 0.16577596555667246
     */
    uint32_t       x = GET_U32<bswap>(p,   0    ) ^ NMH_PRIME32_3;
    uint32_t const y = GET_U32<bswap>(p, len - 4) ^ seed;

    x += y;
    x ^= x >> len;
    x *= UINT32_C(0x11049A7D);
    x ^= x >> 23;
    x *= UINT32_C(0xBCCCDC7B);
    x ^= ROTL32(y, 3);
    x ^= x >> 12;
    x *= UINT32_C(0x065E9DAD);
    x ^= x >> 12;
    return x;
}

template <bool bswap>
static inline uint32_t NMHASH32X_9to255( const uint8_t * const RESTRICT p, size_t const len, uint32_t const seed ) {
    /*
     * - at least 9 bytes
     * - base mixer: [11049a7d 23 bcccdc7b 12 065e9dad 12] = 0.16577596555667246
     * - tail mixer: [16 a52fb2cd 15 551e4d49 16] = 0.17162579707098322
     */

    uint32_t x = NMH_PRIME32_3;
    uint32_t y = seed;
    uint32_t a = NMH_PRIME32_4;
    uint32_t b = seed;
    size_t   i, r = (len - 1) / 16;

    for (i = 0; i < r; ++i) {
        x ^= GET_U32<bswap>(p, i * 16 + 0);
        y ^= GET_U32<bswap>(p, i * 16 + 4);
        x ^= y;
        x *= UINT32_C(0x11049A7D);
        x ^= x >> 23;
        x *= UINT32_C(0xBCCCDC7B);
        y  = ROTL32(y, 4);
        x ^= y;
        x ^= x >> 12;
        x *= UINT32_C(0x065E9DAD);
        x ^= x >> 12;

        a ^= GET_U32<bswap>(p, i * 16 +  8);
        b ^= GET_U32<bswap>(p, i * 16 + 12);
        a ^= b;
        a *= UINT32_C(0x11049A7D);
        a ^= a >> 23;
        a *= UINT32_C(0xBCCCDC7B);
        b  = ROTL32(b, 3);
        a ^= b;
        a ^= a >> 12;
        a *= UINT32_C(0x065E9DAD);
        a ^= a >> 12;
    }

    if (likely(((uint8_t)len - 1) & 8)) {
        if (likely(((uint8_t)len - 1) & 4)) {
            a ^= GET_U32<bswap>(p, r * 16 + 0);
            b ^= GET_U32<bswap>(p, r * 16 + 4);
            a ^= b;
            a *= UINT32_C(0x11049A7D);
            a ^= a >> 23;
            a *= UINT32_C(0xBCCCDC7B);
            a ^= ROTL32(b, 4);
            a ^= a >> 12;
            a *= UINT32_C(0x065E9DAD);
        } else {
            a ^= GET_U32<bswap>(p, r * 16) + b;
            a ^= a >> 16;
            a *= UINT32_C(0xA52FB2CD);
            a ^= a >> 15;
            a *= UINT32_C(0x551E4D49);
        }

        x ^= GET_U32<bswap>(p, len - 8);
        y ^= GET_U32<bswap>(p, len - 4);
        x ^= y;
        x *= UINT32_C(0x11049A7D);
        x ^= x >> 23;
        x *= UINT32_C(0xBCCCDC7B);
        x ^= ROTL32(y, 3);
        x ^= x >> 12;
        x *= UINT32_C(0x065E9DAD);
    } else {
        if (likely(((uint8_t)len - 1) & 4)) {
            a ^= GET_U32<bswap>(p, r * 16) + b;
            a ^= a >> 16;
            a *= UINT32_C(0xA52FB2CD);
            a ^= a >> 15;
            a *= UINT32_C(0x551E4D49);
        }
        x ^= GET_U32<bswap>(p, len - 4) + y;
        x ^= x >> 16;
        x *= UINT32_C(0xA52FB2CD);
        x ^= x >> 15;
        x *= UINT32_C(0x551E4D49);
    }

    x ^= (uint32_t)len;
    x ^= ROTL32(a, 27); /* rotate one lane to pass Diff test */
    x ^= x >> 14;
    x *= UINT32_C(0x141CC535);

    return x;
}

static inline uint32_t NMHASH32X_avalanche32( uint32_t x ) {
    /*
     * mixer with 2 mul from skeeto/hash-prospector:
     * [15 d168aaad 15 af723597 15] = 0.15983776156606694
     */
    x ^= x >> 15;
    x *= UINT32_C(0xD168AAAD);
    x ^= x >> 15;
    x *= UINT32_C(0xAF723597);
    x ^= x >> 15;
    return x;
}

/* use 32*32->32 multiplication for short hash */
template <bool bswap>
static inline uint32_t NMHASH32X( const void * const RESTRICT input, size_t const len, uint32_t seed ) {
    const uint8_t * const p = (const uint8_t *)input;

    if (likely(len <= 8)) {
        if (likely(len > 4)) {
            return NMHASH32X_5to8<bswap>(p, len, seed);
        } else {
            /* 0-4 bytes */
            uint32_t data;
            switch (len) {
            case 0: seed += NMH_PRIME32_2;
                    data  = 0;
                    break;
            case 1: seed += NMH_PRIME32_2 + (UINT32_C(1) << 24) + (1 << 1);
                    data  = p[0];
                    break;
            case 2: seed += NMH_PRIME32_2 + (UINT32_C(2) << 24) + (2 << 1);
                    data  = GET_U16<bswap>(p, 0);
                    break;
            case 3: seed += NMH_PRIME32_2 + (UINT32_C(3) << 24) + (3 << 1);
                    data  = GET_U16<bswap>(p, 0) | (p[2] << 16);
                    break;
            case 4: seed += NMH_PRIME32_1;
                    data  = GET_U32<bswap>(p, 0);
                    break;
            default: return 0;
            }
            return NMHASH32X_0to4(data, seed);
        }
    }
    if (likely(len < 256)) {
        return NMHASH32X_9to255<bswap>(p, len, seed);
    }
    return NMHASH32X_avalanche32(NMHASH32_long<bswap>(p, len, seed));
}

//------------------------------------------------------------
template <bool bswap>
static void NMhash( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = NMHASH32<bswap>(in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void NMhashX( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = NMHASH32X<bswap>(in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(nmhash,
   $.src_url    = "https://github.com/gzm55/hash-garage",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(NMHASH,
   $.desc       = "nmhash32 v2",
   $.impl       = nmh_impl_str[NMH_VECTOR],
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE   |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_TYPE_PUNNING   |
         FLAG_IMPL_MULTIPLY       |
         FLAG_IMPL_ROTATE         |
         FLAG_IMPL_SHIFT_VARIABLE |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 32,
   $.verification_LE = 0x12A30553,
   $.verification_BE = 0xE3222AC8,
   $.hashfn_native   = NMhash<false>,
   $.hashfn_bswap    = NMhash<true>
 );

REGISTER_HASH(NMHASHX,
   $.desc       = "nmhash32x v2",
   $.impl       = nmh_impl_str[NMH_VECTOR],
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE   |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_TYPE_PUNNING   |
         FLAG_IMPL_MULTIPLY       |
         FLAG_IMPL_ROTATE         |
         FLAG_IMPL_SHIFT_VARIABLE |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 32,
   $.verification_LE = 0xA8580227,
   $.verification_BE = 0x83B36886,
   $.hashfn_native   = NMhashX<false>,
   $.hashfn_bswap    = NMhashX<true>
 );
