/*
 * SHA-1 hash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2014-2021 Reini Urban
 * Copyright (c) 2016-2018 Leo Yuriev
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
 *
 * Based on:
 *     SHA-1 in C
 *     By Steve Reid <steve@edmweb.com>
 *     100% Public Domain
 *
 *     SHA-Instrinsics
 *     Written and place in public domain by Jeffrey Walton
 *     Based on code from Intel, and by Sean Gulley for the miTLS project.
 *     Based on code from ARM, and by Johannes Schneiders,
 *     Skip Hovsmith and Barry O'Rourke for the mbedTLS project.
 */
#include "Platform.h"
#include "Hashlib.h"

#if defined(HAVE_X86_64_SHA1) || defined(HAVE_ARM_SHA1)
  #include "Intrinsics.h"
#endif

//-----------------------------------------------------------------------------
// Raw SHA-1 implementation
typedef struct {
    uint32_t  state[5];
    uint32_t  count[2];
    uint8_t   buffer[64];
} SHA1_CTX;

#define SHA1_DIGEST_SIZE 20

/* SHA1_Init - Initialize new context */
static void SHA1_Init( SHA1_CTX * context ) {
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

/* Hash a single 512-bit block. This is the core of the algorithm. */
template <bool bswap>
static void SHA1_Transform_portable( uint32_t state[5], const uint8_t buffer[64] ) {
    uint32_t a, b, c, d, e;
    uint32_t l[16];

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#define blk0(i) (l[i] = GET_U32<bswap>(buffer, 4 * (i)))
#define blk(i)  (l[i & 15] = ROTL32(                   \
                                    l[(i + 13) & 15] ^ \
                                    l[(i + 8) & 15]  ^ \
                                    l[(i + 2) & 15]  ^ \
                                    l[i & 15]          \
                                    , 1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i)                                      \
  z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + ROTL32(v, 5); \
  w = ROTL32(w, 30);
#define R1(v, w, x, y, z, i)                                     \
  z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + ROTL32(v, 5); \
  w = ROTL32(w, 30);
#define R2(v, w, x, y, z, i)                             \
  z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + ROTL32(v, 5); \
  w = ROTL32(w, 30);
#define R3(v, w, x, y, z, i)                                           \
  z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + ROTL32(v, 5); \
  w = ROTL32(w, 30);
#define R4(v, w, x, y, z, i)                             \
  z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + ROTL32(v, 5); \
  w = ROTL32(w, 30);

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a, b, c, d, e,  0);
    R0(e, a, b, c, d,  1);
    R0(d, e, a, b, c,  2);
    R0(c, d, e, a, b,  3);
    R0(b, c, d, e, a,  4);
    R0(a, b, c, d, e,  5);
    R0(e, a, b, c, d,  6);
    R0(d, e, a, b, c,  7);
    R0(c, d, e, a, b,  8);
    R0(b, c, d, e, a,  9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);

    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);

    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);

    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);

    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);

    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

#if defined(HAVE_X86_64_SHA1)

template <bool bswap>
static void SHA1_Transform_sha1NI( uint32_t state[5], const uint8_t buffer[64] ) {
    __m128i       ABCD, ABCD_SAVE, E0, E0_SAVE, E1;
    __m128i       MSG0, MSG1, MSG2, MSG3;
    const __m128i MASK = bswap ?
                _mm_set_epi64x(UINT64_C(0x0001020304050607), UINT64_C(0x08090a0b0c0d0e0f)) :
                _mm_set_epi64x(UINT64_C(0x0302010007060504), UINT64_C(0x0b0a09080f0e0d0c));

    /* Load initial values */
    ABCD = _mm_loadu_si128((const __m128i *)state);
    E0   = _mm_set_epi32(state[4], 0, 0, 0);
    ABCD = _mm_shuffle_epi32(ABCD, 0x1B);

    /* Save current state  */
    ABCD_SAVE = ABCD;
    E0_SAVE   = E0;

    /* Rounds 0-3 */
    MSG0 = _mm_loadu_si128((const __m128i *)(buffer + 0));
    MSG0 = _mm_shuffle_epi8(MSG0, MASK);
    E0   = _mm_add_epi32(E0, MSG0);
    E1   = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);

    /* Rounds 4-7 */
    MSG1 = _mm_loadu_si128((const __m128i *)(buffer + 16));
    MSG1 = _mm_shuffle_epi8(MSG1, MASK);
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);

    /* Rounds 8-11 */
    MSG2 = _mm_loadu_si128((const __m128i *)(buffer + 32));
    MSG2 = _mm_shuffle_epi8(MSG2, MASK);
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 12-15 */
    MSG3 = _mm_loadu_si128((const __m128i *)(buffer + 48));
    MSG3 = _mm_shuffle_epi8(MSG3, MASK);
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 16-19 */
    E0   = _mm_sha1nexte_epu32(E0, MSG0);
    E1   = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 20-23 */
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 24-27 */
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 28-31 */
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 32-35 */
    E0   = _mm_sha1nexte_epu32(E0, MSG0);
    E1   = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 36-39 */
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 40-43 */
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 44-47 */
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 48-51 */
    E0   = _mm_sha1nexte_epu32(E0, MSG0);
    E1   = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 52-55 */
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 56-59 */
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 60-63 */
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 64-67 */
    E0   = _mm_sha1nexte_epu32(E0, MSG0);
    E1   = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 68-71 */
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 72-75 */
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);

    /* Rounds 76-79 */
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);

    /* Combine state */
    E0   = _mm_sha1nexte_epu32(E0, E0_SAVE);
    ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);

    /* Save state */
    ABCD     = _mm_shuffle_epi32(ABCD, 0x1B);
    _mm_storeu_si128((__m128i *)state, ABCD);
    state[4] = _mm_extract_epi32(E0, 3);
}

#endif

#if defined(HAVE_ARM_SHA1)

template <bool bswap>
static void SHA1_Transform_neon( uint32_t state[5], const uint8_t buffer[64] ) {
    uint32x4_t ABCD, ABCD_SAVED;
    uint32x4_t TMP0, TMP1;
    uint32x4_t MSG0, MSG1, MSG2, MSG3;
    uint32_t   E0, E0_SAVED, E1;

    /* Load state */
    ABCD = vld1q_u32(&state[0]);
    E0   = state[4];

    /* Save state */
    ABCD_SAVED = ABCD;
    E0_SAVED   = E0;

    /* Load message */
    MSG0 = vld1q_u32((const uint32_t *)(buffer     ));
    MSG1 = vld1q_u32((const uint32_t *)(buffer + 16));
    MSG2 = vld1q_u32((const uint32_t *)(buffer + 32));
    MSG3 = vld1q_u32((const uint32_t *)(buffer + 48));

    if (bswap) {
        /* Reverse for little endian */
        MSG0 = Vbswap32_u32(MSG0);
        MSG1 = Vbswap32_u32(MSG1);
        MSG2 = Vbswap32_u32(MSG2);
        MSG3 = Vbswap32_u32(MSG3);
    }

    TMP0 = vaddq_u32(MSG0, vdupq_n_u32(0x5A827999));
    TMP1 = vaddq_u32(MSG1, vdupq_n_u32(0x5A827999));

    /* Rounds 0-3 */
    E1   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1cq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG2, vdupq_n_u32(0x5A827999));
    MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

    /* Rounds 4-7 */
    E0   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1cq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG3, vdupq_n_u32(0x5A827999));
    MSG0 = vsha1su1q_u32(MSG0, MSG3);
    MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

    /* Rounds 8-11 */
    E1   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1cq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG0, vdupq_n_u32(0x5A827999));
    MSG1 = vsha1su1q_u32(MSG1, MSG0);
    MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

    /* Rounds 12-15 */
    E0   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1cq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG1, vdupq_n_u32(0x6ED9EBA1));
    MSG2 = vsha1su1q_u32(MSG2, MSG1);
    MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

    /* Rounds 16-19 */
    E1   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1cq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG2, vdupq_n_u32(0x6ED9EBA1));
    MSG3 = vsha1su1q_u32(MSG3, MSG2);
    MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

    /* Rounds 20-23 */
    E0   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG3, vdupq_n_u32(0x6ED9EBA1));
    MSG0 = vsha1su1q_u32(MSG0, MSG3);
    MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

    /* Rounds 24-27 */
    E1   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG0, vdupq_n_u32(0x6ED9EBA1));
    MSG1 = vsha1su1q_u32(MSG1, MSG0);
    MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

    /* Rounds 28-31 */
    E0   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG1, vdupq_n_u32(0x6ED9EBA1));
    MSG2 = vsha1su1q_u32(MSG2, MSG1);
    MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

    /* Rounds 32-35 */
    E1   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG2, vdupq_n_u32(0x8F1BBCDC));
    MSG3 = vsha1su1q_u32(MSG3, MSG2);
    MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

    /* Rounds 36-39 */
    E0   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG3, vdupq_n_u32(0x8F1BBCDC));
    MSG0 = vsha1su1q_u32(MSG0, MSG3);
    MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

    /* Rounds 40-43 */
    E1   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1mq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG0, vdupq_n_u32(0x8F1BBCDC));
    MSG1 = vsha1su1q_u32(MSG1, MSG0);
    MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

    /* Rounds 44-47 */
    E0   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1mq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG1, vdupq_n_u32(0x8F1BBCDC));
    MSG2 = vsha1su1q_u32(MSG2, MSG1);
    MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

    /* Rounds 48-51 */
    E1   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1mq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG2, vdupq_n_u32(0x8F1BBCDC));
    MSG3 = vsha1su1q_u32(MSG3, MSG2);
    MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

    /* Rounds 52-55 */
    E0   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1mq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG3, vdupq_n_u32(0xCA62C1D6));
    MSG0 = vsha1su1q_u32(MSG0, MSG3);
    MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

    /* Rounds 56-59 */
    E1   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1mq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG0, vdupq_n_u32(0xCA62C1D6));
    MSG1 = vsha1su1q_u32(MSG1, MSG0);
    MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

    /* Rounds 60-63 */
    E0   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG1, vdupq_n_u32(0xCA62C1D6));
    MSG2 = vsha1su1q_u32(MSG2, MSG1);
    MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

    /* Rounds 64-67 */
    E1   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E0, TMP0);
    TMP0 = vaddq_u32(MSG2, vdupq_n_u32(0xCA62C1D6));
    MSG3 = vsha1su1q_u32(MSG3, MSG2);
    MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

    /* Rounds 68-71 */
    E0   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E1, TMP1);
    TMP1 = vaddq_u32(MSG3, vdupq_n_u32(0xCA62C1D6));
    MSG0 = vsha1su1q_u32(MSG0, MSG3);

    /* Rounds 72-75 */
    E1   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E0, TMP0);

    /* Rounds 76-79 */
    E0   = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
    ABCD = vsha1pq_u32(ABCD, E1, TMP1);

    /* Combine state */
    E0  += E0_SAVED;
    ABCD = vaddq_u32(ABCD_SAVED, ABCD);

    /* Save state */
    vst1q_u32(&state[0], ABCD);
    state[4] = E0;
}

#endif

template <bool bswap>
static void SHA1_Transform( uint32_t state[5], const uint8_t buffer[64] ) {
#if defined(HAVE_X86_64_SHA1)
    return SHA1_Transform_sha1NI<bswap>(state, buffer);
#endif
#if defined(HAVE_ARM_SHA1)
    return SHA1_Transform_neon<bswap>(state, buffer);
#endif
    return SHA1_Transform_portable<bswap>(state, buffer);
}

template <bool bswap>
static void SHA1_Update( SHA1_CTX * context, const uint8_t * data, const size_t len ) {
    size_t i, j;

    j = context->count[0];
    if ((context->count[0] += len << 3) < j) {
        context->count[1]++;
    }
    context->count[1] += (len >> 29);
    j                  = (j   >>  3) & 63;

    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1_Transform<bswap>(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            SHA1_Transform<bswap>(context->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&context->buffer[j], &data[i], len - i);
}

/* Add padding and return len bytes of the message digest. */
template <bool bswap>
static void SHA1_Final( SHA1_CTX * context, uint32_t digest_words, uint8_t * digest ) {
    uint32_t i;
    uint8_t  finalcount[8];
    uint8_t  c;

    for (i = 0; i < 8; i++) {
        finalcount[i] =
                /* Endian independent */
                (uint8_t)(context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8));
    }
    c = 0200;
    SHA1_Update<bswap>(context, &c, 1);
    while ((context->count[0] & 504) != 448) {
        c = 0000;
        SHA1_Update<bswap>(context, &c, 1);
    }
    SHA1_Update<bswap>(context, finalcount, 8); /* Should cause a SHA1_Transform() */

    if (digest_words > 5) { digest_words = 5; }
    for (i = 0; i < digest_words; i++) {
        PUT_U32<bswap>(context->state[i], digest, 4 * i);
    }
}

//-----------------------------------------------------------------------------
// Homegrown SHA-1 seeding function
static FORCE_INLINE void SHA1_Seed( SHA1_CTX * ctx, const seed_t seed ) {
    const uint32_t seedlo = seed         & 0xFFFFFFFF;
    const uint32_t seedhi = (seed >> 32) & 0xFFFFFFFF;

    ctx->state[0] ^= seedlo;
    ctx->state[1] ^= seedhi;
    ctx->state[2] += seedlo ^ seedhi;
    ctx->state[3] += seedlo;
    ctx->state[4] += seedhi;
}

//-----------------------------------------------------------------------------
template <uint32_t hashbits, bool bswap>
static void SHA1( const void * in, const size_t len, const seed_t seed, void * out ) {
    SHA1_CTX context;

    SHA1_Init(&context);
    SHA1_Seed(&context, seed);
    SHA1_Update<bswap>(&context, (uint8_t *)in, len);
    SHA1_Final<bswap>(&context, (hashbits + 31) / 32, (uint8_t *)out);
}

//-----------------------------------------------------------------------------
// Self test
//
// Test Vectors (from FIPS PUB 180-1)
//   "abc"
//       A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
//   "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
//       84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
//   A million repetitions of "a"
//       34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F

static const char * const test_data[] = {
    "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "A million repetitions of 'a'"
};
static const char * const test_results[] = {
    "A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D",
    "84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1",
    "34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F"
};

static void digest_to_hex( const uint8_t digest[SHA1_DIGEST_SIZE], char * output ) {
    int    i, j;
    char * c = output;

    for (i = 0; i < SHA1_DIGEST_SIZE / 4; i++) {
        for (j = 0; j < 4; j++) {
            sprintf(c, "%02X", digest[i * 4 + j]);
            c += 2;
        }
        sprintf(c, " ");
        c += 1;
    }
    *(c - 1) = '\0';
}

template <bool bswap>
static bool SHA1_Selftest( void ) {
    int      k;
    SHA1_CTX context;
    uint8_t  digest[20];
    char     output[80];

    for (k = 0; k < 2; k++) {
        SHA1_Init(&context);
        SHA1_Update<bswap>(&context, (uint8_t *)test_data[k], strlen(test_data[k]));
        SHA1_Final<bswap>(&context, 5, digest);
        digest_to_hex(digest, output);

        if (strcmp(output, test_results[k])) {
            fprintf(stdout, "SHA-1 self test FAILED\n"     );
            fprintf(stderr, "* hash of \"%s\" incorrect:\n", test_data[k]);
            fprintf(stderr, "\t%s returned\n", output);
            fprintf(stderr, "\t%s is correct\n", test_results[k]);
            return false;
        }
    }

    /* million 'a' vector we feed separately */
    SHA1_Init(&context);
    for (k = 0; k < 1000000; k++) {
        SHA1_Update<bswap>(&context, (uint8_t *)"a", 1);
    }
    SHA1_Final<bswap>(&context, 5, digest);
    digest_to_hex(digest, output);
    if (strcmp(output, test_results[2])) {
        fprintf(stdout, "SHA-1 self test FAILED\n"     );
        fprintf(stderr, "* hash of \"%s\" incorrect:\n", test_data[2]);
        fprintf(stderr, "\t%s returned\n", output);
        fprintf(stderr, "\t%s is correct\n", test_results[2]);
        return false;
    }

    /* success */
    return true;
}

static bool SHA1_test( void ) {
    if (isBE()) {
        return SHA1_Selftest<false>();
    } else {
        return SHA1_Selftest<true>();
    }
}

REGISTER_FAMILY(sha1,
   $.src_url    = "https://github.com/noloader/SHA-Intrinsics",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(SHA_1__32,
   $.desc       = "SHA-1, bits 0-31",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_CRYPTOGRAPHIC_WEAK   |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_BE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 32,
   $.verification_LE = 0xF0E4D9E9,
   $.verification_BE = 0xE00EF4D6,
   $.initfn          = SHA1_test,
   $.hashfn_native   = SHA1<32, false>,
   $.hashfn_bswap    = SHA1<32, true>
 );

REGISTER_HASH(SHA_1__64,
   $.desc       = "SHA-1, bits 0-63",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_CRYPTOGRAPHIC_WEAK   |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_BE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 64,
   $.verification_LE = 0x36801ECB,
   $.verification_BE = 0xFC26F4C7,
   $.initfn          = SHA1_test,
   $.hashfn_native   = SHA1<64, false>,
   $.hashfn_bswap    = SHA1<64, true>
 );

REGISTER_HASH(SHA_1,
   $.desc       = "SHA-1",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_CRYPTOGRAPHIC_WEAK   |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_BE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 128,
   $.verification_LE = 0xE444A591,
   $.verification_BE = 0x35E00C29,
   $.initfn          = SHA1_test,
   $.hashfn_native   = SHA1<128, false>,
   $.hashfn_bswap    = SHA1<128, true>
 );
