/*
 * SHA-2 hash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2019-2021 Reini Urban
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
 *     SHA-Instrinsics
 *     Written and place in public domain by Jeffrey Walton
 *     Based on code from Intel, and by Sean Gulley for the miTLS project.
 *     Based on code from ARM, and by Johannes Schneiders,
 *     Skip Hovsmith and Barry O'Rourke for the mbedTLS project.
 */
#include "Platform.h"
#include "Types.h"
#include "Hashlib.h"

#if defined(NEW_HAVE_SHA2_X86_64)
#  include <immintrin.h>
#endif

#if defined(NEW_HAVE_SHA2_ARM)
#  include <arm_neon.h>
#  if defined(NEW_HAVE_ARM_ACLE)
#    include <arm_acle.h>
#  endif
#endif

//-----------------------------------------------------------------------------
// Raw SHA-2 implementation
typedef struct {
    uint64_t length;
    uint32_t state[8], curlen;
    uint8_t  buf[64];
} SHA2_CTX;

static void SHA224_Init(SHA2_CTX * context) {
  context->curlen = 0;
  context->length = 0;
  context->state[0] = 0xc1059ed8;
  context->state[1] = 0x367cd507;
  context->state[2] = 0x3070dd17;
  context->state[3] = 0xf70e5939;
  context->state[4] = 0xffc00b31;
  context->state[5] = 0x68581511;
  context->state[6] = 0x64f98fa7;
  context->state[7] = 0xbefa4fa4;
}

/* SHA256_Init - Initialize new context */
static void SHA256_Init(SHA2_CTX * context) {
  context->curlen = 0;
  context->length = 0;
  context->state[0] = 0x6A09E667;
  context->state[1] = 0xBB67AE85;
  context->state[2] = 0x3C6EF372;
  context->state[3] = 0xA54FF53A;
  context->state[4] = 0x510E527F;
  context->state[5] = 0x9B05688C;
  context->state[6] = 0x1F83D9AB;
  context->state[7] = 0x5BE0CD19;
}

/* Hash a single 512-bit block. This is the core of the algorithm. */
static const uint32_t K256[] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

#define ROTATE(x,y)  (((x)>>(y)) | ((x)<<(32-(y))))
#define Sigma0(x)    (ROTATE((x), 2) ^ ROTATE((x),13) ^ ROTATE((x),22))
#define Sigma1(x)    (ROTATE((x), 6) ^ ROTATE((x),11) ^ ROTATE((x),25))
#define sigma0(x)    (ROTATE((x), 7) ^ ROTATE((x),18) ^ ((x)>> 3))
#define sigma1(x)    (ROTATE((x),17) ^ ROTATE((x),19) ^ ((x)>>10))

#define Ch(x,y,z)    (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

template < bool bswap >
static void SHA256_Transform_portable(uint32_t state[8], const uint8_t buffer[64]) {
  uint32_t a, b, c, d, e, f, g, h, s0, s1, T1, T2;
  uint32_t X[16], i;

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];

  for (i = 0; i < 16; i++) {
    X[i] = GET_U32<bswap>(buffer, i*4);

    T1 = h;
    T1 += Sigma1(e);
    T1 += Ch(e, f, g);
    T1 += K256[i];
    T1 += X[i];

    T2 = Sigma0(a);
    T2 += Maj(a, b, c);

    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  for (; i < 64; i++) {
    s0 = X[(i + 1) & 0x0f];
    s0 = sigma0(s0);
    s1 = X[(i + 14) & 0x0f];
    s1 = sigma1(s1);

    T1 = X[i & 0xf] += s0 + s1 + X[(i + 9) & 0xf];
    T1 += h + Sigma1(e) + Ch(e, f, g) + K256[i];
    T2 = Sigma0(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

#if defined(NEW_HAVE_SHA_X86_64)
template < bool bswap >
static void SHA256_Transform_x64(uint32_t state[8], const uint8_t data[64]) {
  __m128i STATE0, STATE1;
  __m128i MSG, TMP;
  __m128i MSG0, MSG1, MSG2, MSG3;
  __m128i ABEF_SAVE, CDGH_SAVE;
  const __m128i MASK = bswap ?
    _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL) :
    _mm_set_epi64x(0x0f0e0d0c0b0a0908ULL, 0x0706050403020100ULL);

  /* Load initial values */
  TMP = _mm_loadu_si128((const __m128i*) &state[0]);
  STATE1 = _mm_loadu_si128((const __m128i*) &state[4]);

  TMP = _mm_shuffle_epi32(TMP, 0xB1);          /* CDAB */
  STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    /* EFGH */
  STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    /* ABEF */
  STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); /* CDGH */

  /* Save current state */
  ABEF_SAVE = STATE0;
  CDGH_SAVE = STATE1;

  /* Rounds 0-3 */
  MSG = _mm_loadu_si128((const __m128i*) (data+0));
  MSG0 = _mm_shuffle_epi8(MSG, MASK);
  MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

  /* Rounds 4-7 */
  MSG1 = _mm_loadu_si128((const __m128i*) (data+16));
  MSG1 = _mm_shuffle_epi8(MSG1, MASK);
  MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
  MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

  /* Rounds 8-11 */
  MSG2 = _mm_loadu_si128((const __m128i*) (data+32));
  MSG2 = _mm_shuffle_epi8(MSG2, MASK);
  MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
  MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

  /* Rounds 12-15 */
  MSG3 = _mm_loadu_si128((const __m128i*) (data+48));
  MSG3 = _mm_shuffle_epi8(MSG3, MASK);
  MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
  MSG0 = _mm_add_epi32(MSG0, TMP);
  MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
  MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

  /* Rounds 16-19 */
  MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
  MSG1 = _mm_add_epi32(MSG1, TMP);
  MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
  MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

  /* Rounds 20-23 */
  MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
  MSG2 = _mm_add_epi32(MSG2, TMP);
  MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
  MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

  /* Rounds 24-27 */
  MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
  MSG3 = _mm_add_epi32(MSG3, TMP);
  MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
  MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

  /* Rounds 28-31 */
  MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x1429296706CA6351ULL,  0xD5A79147C6E00BF3ULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
  MSG0 = _mm_add_epi32(MSG0, TMP);
  MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
  MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

  /* Rounds 32-35 */
  MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
  MSG1 = _mm_add_epi32(MSG1, TMP);
  MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
  MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

  /* Rounds 36-39 */
  MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
  MSG2 = _mm_add_epi32(MSG2, TMP);
  MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
  MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

  /* Rounds 40-43 */
  MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
  MSG3 = _mm_add_epi32(MSG3, TMP);
  MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
  MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

  /* Rounds 44-47 */
  MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
  MSG0 = _mm_add_epi32(MSG0, TMP);
  MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
  MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

  /* Rounds 48-51 */
  MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
  MSG1 = _mm_add_epi32(MSG1, TMP);
  MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
  MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

  /* Rounds 52-55 */
  MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
  MSG2 = _mm_add_epi32(MSG2, TMP);
  MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

  /* Rounds 56-59 */
  MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
  MSG3 = _mm_add_epi32(MSG3, TMP);
  MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

  /* Rounds 60-63 */
  MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
  STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
  MSG = _mm_shuffle_epi32(MSG, 0x0E);
  STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

  /* Combine state  */
  STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
  STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

  TMP = _mm_shuffle_epi32(STATE0, 0x1B);       /* FEBA */
  STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);    /* DCHG */
  STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); /* DCBA */
  STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    /* ABEF */

  /* Save state */
  _mm_storeu_si128((__m128i*) &state[0], STATE0);
  _mm_storeu_si128((__m128i*) &state[4], STATE1);
}
#endif

#if defined(NEW_HAVE_SHA2_ARM)
template < bool bswap >
static void SHA256_Transform_neon(uint32_t state[8], const uint8_t data[64]) {
  uint32x4_t STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
  uint32x4_t MSG0, MSG1, MSG2, MSG3;
  uint32x4_t TMP0, TMP1, TMP2;

  /* Load state */
  STATE0 = vld1q_u32(&state[0]);
  STATE1 = vld1q_u32(&state[4]);

  /* Save state */
  ABEF_SAVE = STATE0;
  CDGH_SAVE = STATE1;

  /* Load message */
  MSG0 = vld1q_u32((const uint32_t *)(data +  0));
  MSG1 = vld1q_u32((const uint32_t *)(data + 16));
  MSG2 = vld1q_u32((const uint32_t *)(data + 32));
  MSG3 = vld1q_u32((const uint32_t *)(data + 48));

  /* Reverse for little endian */
  if (bswap) {
    MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
    MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
    MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
    MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));
  }

  TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x00]));

  /* Rounds 0-3 */
  MSG0 = vsha256su0q_u32(MSG0, MSG1);
  TMP2 = STATE0;
  TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x04]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
  MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

  /* Rounds 4-7 */
  MSG1 = vsha256su0q_u32(MSG1, MSG2);
  TMP2 = STATE0;
  TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x08]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
  MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

  /* Rounds 8-11 */
  MSG2 = vsha256su0q_u32(MSG2, MSG3);
  TMP2 = STATE0;
  TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x0c]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
  MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

  /* Rounds 12-15 */
  MSG3 = vsha256su0q_u32(MSG3, MSG0);
  TMP2 = STATE0;
  TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x10]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
  MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

  /* Rounds 16-19 */
  MSG0 = vsha256su0q_u32(MSG0, MSG1);
  TMP2 = STATE0;
  TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x14]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
  MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

  /* Rounds 20-23 */
  MSG1 = vsha256su0q_u32(MSG1, MSG2);
  TMP2 = STATE0;
  TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x18]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
  MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

  /* Rounds 24-27 */
  MSG2 = vsha256su0q_u32(MSG2, MSG3);
  TMP2 = STATE0;
  TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x1c]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
  MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

  /* Rounds 28-31 */
  MSG3 = vsha256su0q_u32(MSG3, MSG0);
  TMP2 = STATE0;
  TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x20]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
  MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

  /* Rounds 32-35 */
  MSG0 = vsha256su0q_u32(MSG0, MSG1);
  TMP2 = STATE0;
  TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x24]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
  MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

  /* Rounds 36-39 */
  MSG1 = vsha256su0q_u32(MSG1, MSG2);
  TMP2 = STATE0;
  TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x28]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
  MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

  /* Rounds 40-43 */
  MSG2 = vsha256su0q_u32(MSG2, MSG3);
  TMP2 = STATE0;
  TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x2c]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
  MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

  /* Rounds 44-47 */
  MSG3 = vsha256su0q_u32(MSG3, MSG0);
  TMP2 = STATE0;
  TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x30]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
  MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

  /* Rounds 48-51 */
  TMP2 = STATE0;
  TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x34]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

  /* Rounds 52-55 */
  TMP2 = STATE0;
  TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x38]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

  /* Rounds 56-59 */
  TMP2 = STATE0;
  TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x3c]));
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

  /* Rounds 60-63 */
  TMP2 = STATE0;
  STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
  STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

  /* Combine state */
  STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
  STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

  /* Save state */
  vst1q_u32(&state[0], STATE0);
  vst1q_u32(&state[4], STATE1);
}
#endif

template < bool bswap >
static void SHA256_Transform(uint32_t state[8], const uint8_t buffer[64]) {
#if defined(NEW_HAVE_SHA2_X86_64)
    return SHA256_Transform_x64<bswap>(state, buffer);
#endif
#if defined(NEW_HAVE_SHA2_ARM)
    return SHA256_Transform_neon<bswap>(state, buffer);
#endif
    return SHA256_Transform_portable<bswap>(state, buffer);
}

template < bool bswap >
static void SHA256_Update(SHA2_CTX * context, const uint8_t * data, size_t len) {
  while (len > 0) {
    if ((context->curlen == 0) && (len >= sizeof(context->buf))) {
      SHA256_Transform<bswap>(context->state, data);
      context->length += 64*8;
      len -= 64;
      data += 64;
    } else {
      size_t n = 64 - context->curlen;
      if (n > len) { n = len; }
      memcpy(&context->buf[context->curlen], data, n);
      context->curlen += n;
      len -= n;
      data += n;
      if (context->curlen == 64) {
	SHA256_Transform<bswap>(context->state, context->buf);
	context->curlen = 0;
	context->length += 64*8;
      }
    }
  }
}

/* Add padding and return len bytes of the message digest. */
template < bool bswap >
static void SHA256_Final(SHA2_CTX * context, uint32_t digest_words, uint8_t * digest) {
  uint32_t i;
  uint8_t finalcount[8];
  uint8_t c;

  context->length += context->curlen * 8;
  for (i = 0; i < 8; i++) {
    finalcount[i] = (uint8_t)(context->length >> ((7 - i) * 8)); // Endian independent
  }
  c = 0200;
  SHA256_Update<bswap>(context, &c, 1);
  while ((context->curlen) != 56) {
    c = 0000;
    SHA256_Update<bswap>(context, &c, 1);
  }
  SHA256_Update<bswap>(context, finalcount, 8); /* Should cause a SHA256_Transform() */

  if (digest_words > 8) { digest_words = 8; }
  for (i = 0; i < digest_words; i++) {
      PUT_U32<bswap>(context->state[i], digest, 4*i);
  }
}

//-----------------------------------------------------------------------------
// Homegrown SHA-2 seeding function
static FORCE_INLINE void SHA256_Seed(SHA2_CTX * ctx, const seed_t seed) {
    const uint32_t seedlo = seed         & 0xFFFFFFFF;
    const uint32_t seedhi = (seed >> 32) & 0xFFFFFFFF;
    ctx->state[1] ^= seedlo;
    ctx->state[3] += seedlo + seedhi;
    ctx->state[5] ^= seedhi;
}

//-----------------------------------------------------------------------------
template < uint32_t hashbits, bool bswap >
void SHA256(const void * in, const size_t len, const seed_t seed, void * out) {
  SHA2_CTX context;

  SHA256_Init         (&context);
  SHA256_Seed         (&context, seed);
  SHA256_Update<bswap>(&context, (uint8_t*)in, len);
  SHA256_Final<bswap> (&context, (hashbits+31)/32, (uint8_t*)out);
}

template < uint32_t hashbits, bool bswap >
void SHA224(const void * in, const size_t len, const seed_t seed, void * out) {
  SHA2_CTX context;

  SHA224_Init         (&context);
  SHA256_Seed         (&context, seed);
  SHA256_Update<bswap>(&context, (uint8_t*)in, len);
  SHA256_Final<bswap> (&context, (hashbits+31)/32, (uint8_t*)out);
}

//-----------------------------------------------------------------------------
// Self test
//
// Test Vectors
//
//   "" (empty string)
//       e3b0c442 98fc1c14 9afbf4c8 996fb924
//       27ae41e4 649b934c a495991b 7852b855
//   "abc"
// 	 ba7816bf 8f01cfea 414140de 5dae2223
//       b00361a3 96177a9c b410ff61 f20015ad
//   A million repetitions of "a"
//       cdc76e5c 9914fb92 81a1c7e2 84d73e67
//       f1809a48 a497200e 046d39cc c7112cd0
static const char *const test_data[] = {
    "", "abc",
    "A million repetitions of 'a'"};
static const char *const test_results[] = {
  "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855",
  "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad",
  "cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0",
};

static void digest_to_hex(const uint8_t digest[32], char * output) {
    int i, j;
    char * c = output;

    for (i = 0; i < 32 / 4; i++) {
        for (j = 0; j < 4; j++) {
            sprintf(c, "%02x", digest[i * 4 + j]);
            c += 2;
        }
        sprintf(c, " ");
        c += 1;
    }
    *(c - 1) = '\0';
}

template < bool bswap >
static bool SHA256_Selftest(void) {
  int k;
  SHA2_CTX context;
  uint8_t digest[32];
  char output[72];

  for (k = 0; k < 2; k++) {
      SHA256_Init         (&context);
      SHA256_Update<bswap>(&context, (uint8_t *)test_data[k], strlen(test_data[k]));
      SHA256_Final<bswap> (&context, 8, digest);
      digest_to_hex(digest, output);

      if (strcmp(output, test_results[k])) {
          fprintf(stdout, "SHA-256 self test FAILED\n");
          fprintf(stderr, "* hash of \"%s\" incorrect:\n", test_data[k]);
          fprintf(stderr, "\t%s returned\n", output);
          fprintf(stderr, "\t%s is correct\n", test_results[k]);
          return false;
      }
  }

  /* million 'a' vector we feed separately */
  SHA256_Init(&context);
  for (k = 0; k < 1000000; k++) {
      SHA256_Update<bswap>(&context, (uint8_t *)"a", 1);
  }
  SHA256_Final<bswap>(&context, 8, digest);
  digest_to_hex(digest, output);
  if (strcmp(output, test_results[2])) {
      fprintf(stdout, "SHA-256 self test FAILED\n");
      fprintf(stderr, "* hash of \"%s\" incorrect:\n", test_data[2]);
      fprintf(stderr, "\t%s returned\n", output);
      fprintf(stderr, "\t%s is correct\n", test_results[2]);
      return false;
  }

  /* success */
  return true;
}

bool SHA256_test(void) {
  if (isBE()) {
      return SHA256_Selftest<false>();
  } else {
      return SHA256_Selftest<true>();
  }
}

REGISTER_FAMILY(sha2);

REGISTER_HASH(sha2_256_64,
  $.desc = "SHA-2, bits 0-63",
  $.hash_flags =
        FLAG_HASH_CRYPTOGRAPHIC        |
        FLAG_HASH_ENDIAN_INDEPENDENT   |
        FLAG_HASH_NO_SEED,
  $.impl_flags =
        FLAG_IMPL_LICENSE_MIT          |
        FLAG_IMPL_CANONICAL_BE         |
        FLAG_IMPL_ROTATE               |
        FLAG_IMPL_INCREMENTAL          |
        FLAG_IMPL_VERY_SLOW,
  $.bits = 64,
  $.verification_LE = 0x31C40E74,
  $.verification_BE = 0x6E81AB0B,
  $.initfn = SHA256_test,
  $.hashfn_native = SHA256<64,false>,
  $.hashfn_bswap = SHA256<64,true>
);

REGISTER_HASH(sha2_256,
  $.desc = "SHA-2",
  $.hash_flags =
        FLAG_HASH_CRYPTOGRAPHIC        |
        FLAG_HASH_ENDIAN_INDEPENDENT   |
        FLAG_HASH_NO_SEED,
  $.impl_flags =
        FLAG_IMPL_LICENSE_MIT          |
        FLAG_IMPL_CANONICAL_BE         |
        FLAG_IMPL_ROTATE               |
        FLAG_IMPL_INCREMENTAL          |
        FLAG_IMPL_VERY_SLOW,
  $.bits = 256,
  $.verification_LE = 0x33BD25DE,
  $.verification_BE = 0x1643B047,
  $.initfn = SHA256_test,
  $.hashfn_native = SHA256<256,false>,
  $.hashfn_bswap = SHA256<256,true>
);

REGISTER_HASH(sha2_224_64,
  $.desc = "SHA-2, bits 0-63",
  $.hash_flags =
        FLAG_HASH_CRYPTOGRAPHIC        |
        FLAG_HASH_ENDIAN_INDEPENDENT   |
        FLAG_HASH_NO_SEED,
  $.impl_flags =
        FLAG_IMPL_LICENSE_MIT          |
        FLAG_IMPL_CANONICAL_BE         |
        FLAG_IMPL_ROTATE               |
        FLAG_IMPL_INCREMENTAL          |
        FLAG_IMPL_VERY_SLOW,
  $.bits = 64,
  $.verification_LE = 0x36C55CA5,
  $.verification_BE = 0x8C3C0B2A,
  $.initfn = SHA256_test,
  $.hashfn_native = SHA224<64,false>,
  $.hashfn_bswap = SHA224<64,true>
);

REGISTER_HASH(sha2_224,
  $.desc = "SHA-2",
  $.hash_flags =
        FLAG_HASH_CRYPTOGRAPHIC        |
        FLAG_HASH_ENDIAN_INDEPENDENT   |
        FLAG_HASH_NO_SEED,
  $.impl_flags =
        FLAG_IMPL_LICENSE_MIT          |
        FLAG_IMPL_CANONICAL_BE         |
        FLAG_IMPL_ROTATE               |
        FLAG_IMPL_INCREMENTAL          |
        FLAG_IMPL_VERY_SLOW,
  $.bits = 224,
  $.verification_LE = 0x6BA219E5,
  $.verification_BE = 0x56F30297,
  $.initfn = SHA256_test,
  $.hashfn_native = SHA224<224,false>,
  $.hashfn_bswap = SHA224<224,true>
);
