/*
 * BLAKE2 hashes
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
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
 * based on:
 *     BLAKE2 reference source code package - reference C implementations
 * used under terms of CC0.
 */
#include "Platform.h"
#include "Types.h"
#include "Hashlib.h"

#if defined(NEW_HAVE_SSE_4_1)
#include <immintrin.h>
#endif

static const uint64_t blake2b_IV[8] =
{
  UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
  UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
  UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
  UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)
};

static const uint32_t blake2s_IV[8] =
{
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const uint8_t blake2_sigma[12][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

typedef struct blake2b_context_ {
  uint64_t h[8];
  uint64_t t[2];
  uint64_t f[2];
  uint8_t  buf[128];
  size_t   buflen;
} blake2b_context;

typedef struct blake2s_context_ {
  uint32_t h[8];
  uint32_t t[2];
  uint32_t f[2];
  uint8_t  buf[64];
  size_t   buflen;
} blake2s_context;

struct blake2_params_prefix {
  uint8_t  digest_length; /* 1 */
  uint8_t  key_length;    /* 2 */
  uint8_t  fanout;        /* 3 */
  uint8_t  depth;         /* 4 */
  uint32_t zero;          /* 8 */
};

template < typename T >
NEVER_INLINE static void blake2_Init(T * ctx, unsigned hashbits, uint64_t seed) {
  const uint32_t seedlo = seed         & 0xFFFFFFFF;
  const uint32_t seedhi = (seed >> 32) & 0xFFFFFFFF;

  memset(ctx, 0, sizeof(*ctx));
  for (int i = 0; i < 8; i++) {
    if (sizeof(ctx->h[0]) == 8) {
      ctx->h[i] = blake2b_IV[i];
    } else {
      ctx->h[i] = blake2s_IV[i];
    }
  }

  struct blake2_params_prefix params;
  memset(&params, 0, sizeof(params));
  params.digest_length = hashbits/8;
  params.fanout = 1;
  params.depth = 1;
  ctx->h[0] ^= *((typeof(ctx->h[0])*)(&params));

  // Legacy BLAKE2 seeding
  ctx->h[0] ^= seedlo;
}

#if defined(NEW_HAVE_SSE_4_1)
#define LOADU(p)  _mm_loadu_si128( (const __m128i *)(p) )
#define STOREU(p,r) _mm_storeu_si128((__m128i *)(p), r)

#define LOAD_MSG_0_1(b0, b1)  b0 = _mm_unpacklo_epi64(m0, m1); b1 = _mm_unpacklo_epi64(m2, m3);
#define LOAD_MSG_0_2(b0, b1)  b0 = _mm_unpackhi_epi64(m0, m1); b1 = _mm_unpackhi_epi64(m2, m3);
#define LOAD_MSG_0_3(b0, b1)  b0 = _mm_unpacklo_epi64(m4, m5); b1 = _mm_unpacklo_epi64(m6, m7);
#define LOAD_MSG_0_4(b0, b1)  b0 = _mm_unpackhi_epi64(m4, m5); b1 = _mm_unpackhi_epi64(m6, m7);
#define LOAD_MSG_1_1(b0, b1)  b0 = _mm_unpacklo_epi64(m7, m2); b1 = _mm_unpackhi_epi64(m4, m6);
#define LOAD_MSG_1_2(b0, b1)  b0 = _mm_unpacklo_epi64(m5, m4); b1 = _mm_alignr_epi8(m3, m7, 8);
#define LOAD_MSG_1_3(b0, b1)  b0 = _mm_shuffle_epi32(m0, _MM_SHUFFLE(1,0,3,2)); b1 = _mm_unpackhi_epi64(m5, m2);
#define LOAD_MSG_1_4(b0, b1)  b0 = _mm_unpacklo_epi64(m6, m1); b1 = _mm_unpackhi_epi64(m3, m1);
#define LOAD_MSG_2_1(b0, b1)  b0 = _mm_alignr_epi8(m6, m5, 8); b1 = _mm_unpackhi_epi64(m2, m7);
#define LOAD_MSG_2_2(b0, b1)  b0 = _mm_unpacklo_epi64(m4, m0); b1 = _mm_blend_epi16(m1, m6, 0xF0);
#define LOAD_MSG_2_3(b0, b1)  b0 = _mm_blend_epi16(m5, m1, 0xF0); b1 = _mm_unpackhi_epi64(m3, m4);
#define LOAD_MSG_2_4(b0, b1)  b0 = _mm_unpacklo_epi64(m7, m3); b1 = _mm_alignr_epi8(m2, m0, 8);
#define LOAD_MSG_3_1(b0, b1)  b0 = _mm_unpackhi_epi64(m3, m1); b1 = _mm_unpackhi_epi64(m6, m5);
#define LOAD_MSG_3_2(b0, b1)  b0 = _mm_unpackhi_epi64(m4, m0); b1 = _mm_unpacklo_epi64(m6, m7);
#define LOAD_MSG_3_3(b0, b1)  b0 = _mm_blend_epi16(m1, m2, 0xF0); b1 = _mm_blend_epi16(m2, m7, 0xF0);
#define LOAD_MSG_3_4(b0, b1)  b0 = _mm_unpacklo_epi64(m3, m5); b1 = _mm_unpacklo_epi64(m0, m4);
#define LOAD_MSG_4_1(b0, b1)  b0 = _mm_unpackhi_epi64(m4, m2); b1 = _mm_unpacklo_epi64(m1, m5);
#define LOAD_MSG_4_2(b0, b1)  b0 = _mm_blend_epi16(m0, m3, 0xF0); b1 = _mm_blend_epi16(m2, m7, 0xF0);
#define LOAD_MSG_4_3(b0, b1)  b0 = _mm_blend_epi16(m7, m5, 0xF0); b1 = _mm_blend_epi16(m3, m1, 0xF0);
#define LOAD_MSG_4_4(b0, b1)  b0 = _mm_alignr_epi8(m6, m0, 8); b1 = _mm_blend_epi16(m4, m6, 0xF0);
#define LOAD_MSG_5_1(b0, b1)  b0 = _mm_unpacklo_epi64(m1, m3); b1 = _mm_unpacklo_epi64(m0, m4);
#define LOAD_MSG_5_2(b0, b1)  b0 = _mm_unpacklo_epi64(m6, m5); b1 = _mm_unpackhi_epi64(m5, m1);
#define LOAD_MSG_5_3(b0, b1)  b0 = _mm_blend_epi16(m2, m3, 0xF0); b1 = _mm_unpackhi_epi64(m7, m0);
#define LOAD_MSG_5_4(b0, b1)  b0 = _mm_unpackhi_epi64(m6, m2); b1 = _mm_blend_epi16(m7, m4, 0xF0);
#define LOAD_MSG_6_1(b0, b1)  b0 = _mm_blend_epi16(m6, m0, 0xF0); b1 = _mm_unpacklo_epi64(m7, m2);
#define LOAD_MSG_6_2(b0, b1)  b0 = _mm_unpackhi_epi64(m2, m7); b1 = _mm_alignr_epi8(m5, m6, 8);
#define LOAD_MSG_6_3(b0, b1)  b0 = _mm_unpacklo_epi64(m0, m3); b1 = _mm_shuffle_epi32(m4, _MM_SHUFFLE(1,0,3,2));
#define LOAD_MSG_6_4(b0, b1)  b0 = _mm_unpackhi_epi64(m3, m1); b1 = _mm_blend_epi16(m1, m5, 0xF0);
#define LOAD_MSG_7_1(b0, b1)  b0 = _mm_unpackhi_epi64(m6, m3); b1 = _mm_blend_epi16(m6, m1, 0xF0);
#define LOAD_MSG_7_2(b0, b1)  b0 = _mm_alignr_epi8(m7, m5, 8); b1 = _mm_unpackhi_epi64(m0, m4);
#define LOAD_MSG_7_3(b0, b1)  b0 = _mm_unpackhi_epi64(m2, m7); b1 = _mm_unpacklo_epi64(m4, m1);
#define LOAD_MSG_7_4(b0, b1)  b0 = _mm_unpacklo_epi64(m0, m2); b1 = _mm_unpacklo_epi64(m3, m5);
#define LOAD_MSG_8_1(b0, b1)  b0 = _mm_unpacklo_epi64(m3, m7); b1 = _mm_alignr_epi8(m0, m5, 8);
#define LOAD_MSG_8_2(b0, b1)  b0 = _mm_unpackhi_epi64(m7, m4); b1 = _mm_alignr_epi8(m4, m1, 8);
#define LOAD_MSG_8_3(b0, b1)  b0 = m6; b1 = _mm_alignr_epi8(m5, m0, 8);
#define LOAD_MSG_8_4(b0, b1)  b0 = _mm_blend_epi16(m1, m3, 0xF0); b1 = m2;
#define LOAD_MSG_9_1(b0, b1)  b0 = _mm_unpacklo_epi64(m5, m4); b1 = _mm_unpackhi_epi64(m3, m0);
#define LOAD_MSG_9_2(b0, b1)  b0 = _mm_unpacklo_epi64(m1, m2); b1 = _mm_blend_epi16(m3, m2, 0xF0);
#define LOAD_MSG_9_3(b0, b1)  b0 = _mm_unpackhi_epi64(m7, m4); b1 = _mm_unpackhi_epi64(m1, m6);
#define LOAD_MSG_9_4(b0, b1)  b0 = _mm_alignr_epi8(m7, m5, 8); b1 = _mm_unpacklo_epi64(m6, m0);
#define LOAD_MSG_10_1(b0, b1)  b0 = _mm_unpacklo_epi64(m0, m1); b1 = _mm_unpacklo_epi64(m2, m3);
#define LOAD_MSG_10_2(b0, b1)  b0 = _mm_unpackhi_epi64(m0, m1); b1 = _mm_unpackhi_epi64(m2, m3);
#define LOAD_MSG_10_3(b0, b1)  b0 = _mm_unpacklo_epi64(m4, m5); b1 = _mm_unpacklo_epi64(m6, m7);
#define LOAD_MSG_10_4(b0, b1)  b0 = _mm_unpackhi_epi64(m4, m5); b1 = _mm_unpackhi_epi64(m6, m7);
#define LOAD_MSG_11_1(b0, b1)  b0 = _mm_unpacklo_epi64(m7, m2); b1 = _mm_unpackhi_epi64(m4, m6);
#define LOAD_MSG_11_2(b0, b1)  b0 = _mm_unpacklo_epi64(m5, m4); b1 = _mm_alignr_epi8(m3, m7, 8);
#define LOAD_MSG_11_3(b0, b1)  b0 = _mm_shuffle_epi32(m0, _MM_SHUFFLE(1,0,3,2)); b1 = _mm_unpackhi_epi64(m5, m2);
#define LOAD_MSG_11_4(b0, b1)  b0 = _mm_unpacklo_epi64(m6, m1); b1 = _mm_unpackhi_epi64(m3, m1);

#define _mm_roti_epi64(x, c)					 \
    (-(c) == 32) ? _mm_shuffle_epi32((x), _MM_SHUFFLE(2,3,0,1))  \
    : (-(c) == 24) ? _mm_shuffle_epi8((x), r24) \
    : (-(c) == 16) ? _mm_shuffle_epi8((x), r16) \
    : (-(c) == 63) ? _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_add_epi64((x), (x)))  \
    : _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_slli_epi64((x), 64-(-(c))))

#define G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l); \
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h); \
  \
  row4l = _mm_xor_si128(row4l, row1l); \
  row4h = _mm_xor_si128(row4h, row1h); \
  \
  row4l = _mm_roti_epi64(row4l, -32); \
  row4h = _mm_roti_epi64(row4h, -32); \
  \
  row3l = _mm_add_epi64(row3l, row4l); \
  row3h = _mm_add_epi64(row3h, row4h); \
  \
  row2l = _mm_xor_si128(row2l, row3l); \
  row2h = _mm_xor_si128(row2h, row3h); \
  \
  row2l = _mm_roti_epi64(row2l, -24); \
  row2h = _mm_roti_epi64(row2h, -24); \

#define G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l); \
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h); \
  \
  row4l = _mm_xor_si128(row4l, row1l); \
  row4h = _mm_xor_si128(row4h, row1h); \
  \
  row4l = _mm_roti_epi64(row4l, -16); \
  row4h = _mm_roti_epi64(row4h, -16); \
  \
  row3l = _mm_add_epi64(row3l, row4l); \
  row3h = _mm_add_epi64(row3h, row4h); \
  \
  row2l = _mm_xor_si128(row2l, row3l); \
  row2h = _mm_xor_si128(row2h, row3h); \
  \
  row2l = _mm_roti_epi64(row2l, -63); \
  row2h = _mm_roti_epi64(row2h, -63); \

#define DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  t0 = row4l;\
  t1 = row2l;\
  row4l = row3l;\
  row3l = row3h;\
  row3h = row4l;\
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0)); \
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h)); \
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h)); \
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1))

#define UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  t0 = row3l;\
  row3l = row3h;\
  row3h = t0;\
  t0 = row2l;\
  t1 = row4l;\
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l)); \
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h)); \
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h)); \
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1))

#define ROUND(r) \
  LOAD_MSG_ ##r ##_1(b0, b1); \
  G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
  LOAD_MSG_ ##r ##_2(b0, b1); \
  G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
  DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
  LOAD_MSG_ ##r ##_3(b0, b1); \
  G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
  LOAD_MSG_ ##r ##_4(b0, b1); \
  G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
  UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);

template < bool bswap >
static void blake2_compress_sse41(blake2b_context * ctx, const uint8_t * in) {
  const __m128i MASK = _mm_set_epi64x(0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL);
  __m128i row1l, row1h;
  __m128i row2l, row2h;
  __m128i row3l, row3h;
  __m128i row4l, row4h;
  __m128i b0, b1;
  __m128i t0, t1;

  const __m128i r16 = _mm_setr_epi8( 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9 );
  const __m128i r24 = _mm_setr_epi8( 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10 );

  const __m128i m0 = bswap ? _mm_shuffle_epi8(LOADU(in + 00), MASK) : LOADU( in + 00 );
  const __m128i m1 = bswap ? _mm_shuffle_epi8(LOADU(in + 16), MASK) : LOADU( in + 16 );
  const __m128i m2 = bswap ? _mm_shuffle_epi8(LOADU(in + 32), MASK) : LOADU( in + 32 );
  const __m128i m3 = bswap ? _mm_shuffle_epi8(LOADU(in + 48), MASK) : LOADU( in + 48 );
  const __m128i m4 = bswap ? _mm_shuffle_epi8(LOADU(in + 64), MASK) : LOADU( in + 64 );
  const __m128i m5 = bswap ? _mm_shuffle_epi8(LOADU(in + 80), MASK) : LOADU( in + 80 );
  const __m128i m6 = bswap ? _mm_shuffle_epi8(LOADU(in + 96), MASK) : LOADU( in + 96 );
  const __m128i m7 = bswap ? _mm_shuffle_epi8(LOADU(in + 112), MASK) : LOADU( in + 112 );

  row1l = LOADU( &(ctx->h[0]) );
  row1h = LOADU( &(ctx->h[2]) );
  row2l = LOADU( &(ctx->h[4]) );
  row2h = LOADU( &(ctx->h[6]) );
  row3l = LOADU( &blake2b_IV[0] );
  row3h = LOADU( &blake2b_IV[2] );
  row4l = _mm_xor_si128( LOADU( &blake2b_IV[4] ), LOADU( &(ctx->t[0]) ) );
  row4h = _mm_xor_si128( LOADU( &blake2b_IV[6] ), LOADU( &(ctx->f[0]) ) );

  ROUND( 0 );
  ROUND( 1 );
  ROUND( 2 );
  ROUND( 3 );
  ROUND( 4 );
  ROUND( 5 );
  ROUND( 6 );
  ROUND( 7 );
  ROUND( 8 );
  ROUND( 9 );
  ROUND( 10 );
  ROUND( 11 );

  row1l = _mm_xor_si128( row3l, row1l );
  row1h = _mm_xor_si128( row3h, row1h );
  STOREU( &(ctx->h[0]), _mm_xor_si128( LOADU( &(ctx->h[0]) ), row1l ) );
  STOREU( &(ctx->h[2]), _mm_xor_si128( LOADU( &(ctx->h[2]) ), row1h ) );
  row2l = _mm_xor_si128( row4l, row2l );
  row2h = _mm_xor_si128( row4h, row2h );
  STOREU( &(ctx->h[4]), _mm_xor_si128( LOADU( &(ctx->h[4]) ), row2l ) );
  STOREU( &(ctx->h[6]), _mm_xor_si128( LOADU( &(ctx->h[6]) ), row2h ) );
}

#undef G1
#undef G2
#undef DIAGONALIZE
#undef UNDIAGONALIZE
#undef ROUND
#undef LOAD_MSG_0_1
#undef LOAD_MSG_0_2
#undef LOAD_MSG_0_3
#undef LOAD_MSG_0_4
#undef LOAD_MSG_1_1
#undef LOAD_MSG_1_2
#undef LOAD_MSG_1_3
#undef LOAD_MSG_1_4
#undef LOAD_MSG_2_1
#undef LOAD_MSG_2_2
#undef LOAD_MSG_2_3
#undef LOAD_MSG_2_4
#undef LOAD_MSG_3_1
#undef LOAD_MSG_3_2
#undef LOAD_MSG_3_3
#undef LOAD_MSG_3_4
#undef LOAD_MSG_4_1
#undef LOAD_MSG_4_2
#undef LOAD_MSG_4_3
#undef LOAD_MSG_4_4
#undef LOAD_MSG_5_1
#undef LOAD_MSG_5_2
#undef LOAD_MSG_5_3
#undef LOAD_MSG_5_4
#undef LOAD_MSG_6_1
#undef LOAD_MSG_6_2
#undef LOAD_MSG_6_3
#undef LOAD_MSG_6_4
#undef LOAD_MSG_7_1
#undef LOAD_MSG_7_2
#undef LOAD_MSG_7_3
#undef LOAD_MSG_7_4
#undef LOAD_MSG_8_1
#undef LOAD_MSG_8_2
#undef LOAD_MSG_8_3
#undef LOAD_MSG_8_4
#undef LOAD_MSG_9_1
#undef LOAD_MSG_9_2
#undef LOAD_MSG_9_3
#undef LOAD_MSG_9_4
#undef LOAD_MSG_10_1
#undef LOAD_MSG_10_2
#undef LOAD_MSG_10_3
#undef LOAD_MSG_10_4
#undef LOAD_MSG_11_1
#undef LOAD_MSG_11_2
#undef LOAD_MSG_11_3
#undef LOAD_MSG_11_4

#define TOF(reg) _mm_castsi128_ps((reg))
#define TOI(reg) _mm_castps_si128((reg))

#define LOAD_MSG_0_1(buf) buf = TOI(_mm_shuffle_ps(TOF(m0), TOF(m1), _MM_SHUFFLE(2,0,2,0)));
#define LOAD_MSG_0_2(buf) buf = TOI(_mm_shuffle_ps(TOF(m0), TOF(m1), _MM_SHUFFLE(3,1,3,1)));
#define LOAD_MSG_0_3(buf) t0 = _mm_shuffle_epi32(m2, _MM_SHUFFLE(3,2,0,1)); \
  t1 = _mm_shuffle_epi32(m3, _MM_SHUFFLE(0,1,3,2));			\
  buf = _mm_blend_epi16(t0, t1, 0xC3);
#define LOAD_MSG_0_4(buf) t0 = _mm_blend_epi16(t0, t1, 0x3C);	\
  buf = _mm_shuffle_epi32(t0, _MM_SHUFFLE(2,3,0,1));
#define LOAD_MSG_1_1(buf) t0 = _mm_blend_epi16(m1, m2, 0x0C); \
  t1 = _mm_slli_si128(m3, 4);				      \
  t2 = _mm_blend_epi16(t0, t1, 0xF0);			      \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,0,3));
#define LOAD_MSG_1_2(buf) t0 = _mm_shuffle_epi32(m2,_MM_SHUFFLE(0,0,2,0)); \
  t1 = _mm_blend_epi16(m1,m3,0xC0);					\
  t2 = _mm_blend_epi16(t0, t1, 0xF0);					\
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,3,0,1));
#define LOAD_MSG_1_3(buf) t0 = _mm_slli_si128(m1, 4); \
  t1 = _mm_blend_epi16(m2, t0, 0x30);		      \
  t2 = _mm_blend_epi16(m0, t1, 0xF0);		      \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,0,1,2));
#define LOAD_MSG_1_4(buf) t0 = _mm_unpackhi_epi32(m0,m1); \
  t1 = _mm_slli_si128(m3, 4);				  \
  t2 = _mm_blend_epi16(t0, t1, 0x0C);			  \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,0,1,2));
#define LOAD_MSG_2_1(buf) t0 = _mm_unpackhi_epi32(m2,m3);	\
  t1 = _mm_blend_epi16(m3,m1,0x0C);				\
  t2 = _mm_blend_epi16(t0, t1, 0x0F);				\
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,1,0,2));
#define LOAD_MSG_2_2(buf) t0 = _mm_unpacklo_epi32(m2,m0);	\
  t1 = _mm_blend_epi16(t0, m0, 0xF0);				\
  t2 = _mm_slli_si128(m3, 8);					\
  buf = _mm_blend_epi16(t1, t2, 0xC0);
#define LOAD_MSG_2_3(buf) t0 = _mm_blend_epi16(m0, m2, 0x3C);	\
  t1 = _mm_srli_si128(m1, 12);					\
  t2 = _mm_blend_epi16(t0,t1,0x03);				\
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(0,3,2,1));
#define LOAD_MSG_2_4(buf) t0 = _mm_slli_si128(m3, 4);	\
  t1 = _mm_blend_epi16(m0, m1, 0x33);			\
  t2 = _mm_blend_epi16(t1, t0, 0xC0);			\
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1,2,3,0));
#define LOAD_MSG_3_1(buf) t0 = _mm_unpackhi_epi32(m0,m1);	\
  t1 = _mm_unpackhi_epi32(t0, m2);				\
  t2 = _mm_blend_epi16(t1, m3, 0x0C);				\
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,1,0,2));
#define LOAD_MSG_3_2(buf) t0 = _mm_slli_si128(m2, 8);	\
  t1 = _mm_blend_epi16(m3,m0,0x0C);			\
  t2 = _mm_blend_epi16(t1, t0, 0xC0);			\
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,0,1,3));
#define LOAD_MSG_3_3(buf) t0 = _mm_blend_epi16(m0,m1,0x0F);	\
  t1 = _mm_blend_epi16(t0, m3, 0xC0);				\
  buf = _mm_shuffle_epi32(t1, _MM_SHUFFLE(0,1,2,3));
#define LOAD_MSG_3_4(buf) t0 = _mm_alignr_epi8(m0, m1, 4);	\
  buf = _mm_blend_epi16(t0, m2, 0x33);
#define LOAD_MSG_4_1(buf) t0 = _mm_unpacklo_epi64(m1,m2); \
  t1 = _mm_unpackhi_epi64(m0,m2);			  \
  t2 = _mm_blend_epi16(t0,t1,0x33);			  \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,0,1,3));
#define LOAD_MSG_4_2(buf) t0 = _mm_unpackhi_epi64(m1,m3);	\
  t1 = _mm_unpacklo_epi64(m0,m1);				\
  buf = _mm_blend_epi16(t0,t1,0x33);
#define LOAD_MSG_4_3(buf) t0 = _mm_unpackhi_epi64(m3,m1); \
  t1 = _mm_unpackhi_epi64(m2,m0);			  \
  t2 = _mm_blend_epi16(t1,t0,0x33);			  \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,0,3));
#define LOAD_MSG_4_4(buf) t0 = _mm_blend_epi16(m0,m2,0x03);	\
  t1 = _mm_slli_si128(t0, 8);					\
  t2 = _mm_blend_epi16(t1,m3,0x0F);				\
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,0,3,1));
#define LOAD_MSG_5_1(buf) t0 = _mm_unpackhi_epi32(m0,m1);	\
  t1 = _mm_unpacklo_epi32(m0,m2);				\
  buf = _mm_unpacklo_epi64(t0,t1);
#define LOAD_MSG_5_2(buf) t0 = _mm_srli_si128(m2, 4);	\
  t1 = _mm_blend_epi16(m0,m3,0x03);			\
  buf = _mm_blend_epi16(t1,t0,0x3C);
#define LOAD_MSG_5_3(buf) t0 = _mm_blend_epi16(m1,m0,0x0C); \
  t1 = _mm_srli_si128(m3, 4);				    \
  t2 = _mm_blend_epi16(t0,t1,0x30);			    \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,3,0,1));
#define LOAD_MSG_5_4(buf) t0 = _mm_unpacklo_epi64(m2,m1); \
  t1 = _mm_shuffle_epi32(m3, _MM_SHUFFLE(2,0,1,0));	  \
  t2 = _mm_srli_si128(t0, 4);				  \
  buf = _mm_blend_epi16(t1,t2,0x33);
#define LOAD_MSG_6_1(buf) t0 = _mm_slli_si128(m1, 12); \
  t1 = _mm_blend_epi16(m0,m3,0x33);		       \
  buf = _mm_blend_epi16(t1,t0,0xC0);
#define LOAD_MSG_6_2(buf) t0 = _mm_blend_epi16(m3,m2,0x30); \
  t1 = _mm_srli_si128(m1, 4);				    \
  t2 = _mm_blend_epi16(t0,t1,0x03);			    \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,3,0));
#define LOAD_MSG_6_3(buf) t0 = _mm_unpacklo_epi64(m0,m2);	\
  t1 = _mm_srli_si128(m1, 4);					\
  t2 = _mm_blend_epi16(t0,t1,0x0C);				\
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,1,0,2));
#define LOAD_MSG_6_4(buf) t0 = _mm_unpackhi_epi32(m1,m2); \
  t1 = _mm_unpackhi_epi64(m0,t0);			  \
  buf = _mm_shuffle_epi32(t1, _MM_SHUFFLE(0,1,2,3));
#define LOAD_MSG_7_1(buf) t0 = _mm_unpackhi_epi32(m0,m1);	\
  t1 = _mm_blend_epi16(t0,m3,0x0F);				\
  buf = _mm_shuffle_epi32(t1,_MM_SHUFFLE(2,0,3,1));
#define LOAD_MSG_7_2(buf) t0 = _mm_blend_epi16(m2,m3,0x30); \
  t1 = _mm_srli_si128(m0,4);				    \
  t2 = _mm_blend_epi16(t0,t1,0x03);			    \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1,0,2,3));
#define LOAD_MSG_7_3(buf) t0 = _mm_unpackhi_epi64(m0,m3); \
  t1 = _mm_unpacklo_epi64(m1,m2);			  \
  t2 = _mm_blend_epi16(t0,t1,0x3C);			  \
  buf = _mm_shuffle_epi32(t2,_MM_SHUFFLE(2,3,1,0));
#define LOAD_MSG_7_4(buf) t0 = _mm_unpacklo_epi32(m0,m1);	\
  t1 = _mm_unpackhi_epi32(m1,m2);				\
  t2 = _mm_unpacklo_epi64(t0,t1);				\
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,0,3));
#define LOAD_MSG_8_1(buf) t0 = _mm_unpackhi_epi32(m1,m3);	\
  t1 = _mm_unpacklo_epi64(t0,m0);				\
  t2 = _mm_blend_epi16(t1,m2,0xC0);				\
  buf = _mm_shufflehi_epi16(t2,_MM_SHUFFLE(1,0,3,2));
#define LOAD_MSG_8_2(buf) t0 = _mm_unpackhi_epi32(m0,m3);	\
  t1 = _mm_blend_epi16(m2,t0,0xF0);				\
  buf = _mm_shuffle_epi32(t1,_MM_SHUFFLE(0,2,1,3));
#define LOAD_MSG_8_3(buf) t0 = _mm_unpacklo_epi64(m0,m3);	\
  t1 = _mm_srli_si128(m2,8);					\
  t2 = _mm_blend_epi16(t0,t1,0x03);				\
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1,3,2,0));
#define LOAD_MSG_8_4(buf) t0 = _mm_blend_epi16(m1,m0,0x30); \
  buf = _mm_shuffle_epi32(t0,_MM_SHUFFLE(0,3,2,1));
#define LOAD_MSG_9_1(buf) t0 = _mm_blend_epi16(m0,m2,0x03);	\
  t1 = _mm_blend_epi16(m1,m2,0x30);				\
  t2 = _mm_blend_epi16(t1,t0,0x0F);				\
  buf = _mm_shuffle_epi32(t2,_MM_SHUFFLE(1,3,0,2));
#define LOAD_MSG_9_2(buf) t0 = _mm_slli_si128(m0,4);	\
  t1 = _mm_blend_epi16(m1,t0,0xC0);			\
  buf = _mm_shuffle_epi32(t1,_MM_SHUFFLE(1,2,0,3));
#define LOAD_MSG_9_3(buf) t0 = _mm_unpackhi_epi32(m0,m3);	\
  t1 = _mm_unpacklo_epi32(m2,m3);				\
  t2 = _mm_unpackhi_epi64(t0,t1);				\
  buf = _mm_shuffle_epi32(t2,_MM_SHUFFLE(0,2,1,3));
#define LOAD_MSG_9_4(buf) t0 = _mm_blend_epi16(m3,m2,0xC0);	\
  t1 = _mm_unpacklo_epi32(m0,m3);				\
  t2 = _mm_blend_epi16(t0,t1,0x0F);				\
  buf = _mm_shuffle_epi32(t2,_MM_SHUFFLE(1,2,3,0));

#define _mm_roti_epi32(r, c) (			   \
                (8==-(c)) ? _mm_shuffle_epi8(r,r8) \
              : (16==-(c)) ? _mm_shuffle_epi8(r,r16) \
              : _mm_xor_si128(_mm_srli_epi32( (r), -(c) ),_mm_slli_epi32( (r), 32-(-(c)) )) )

#define G1(row1,row2,row3,row4,buf) \
  row1 = _mm_add_epi32( _mm_add_epi32( row1, buf), row2 ); \
  row4 = _mm_xor_si128( row4, row1 ); \
  row4 = _mm_roti_epi32(row4, -16); \
  row3 = _mm_add_epi32( row3, row4 );   \
  row2 = _mm_xor_si128( row2, row3 ); \
  row2 = _mm_roti_epi32(row2, -12);

#define G2(row1,row2,row3,row4,buf) \
  row1 = _mm_add_epi32( _mm_add_epi32( row1, buf), row2 ); \
  row4 = _mm_xor_si128( row4, row1 ); \
  row4 = _mm_roti_epi32(row4, -8); \
  row3 = _mm_add_epi32( row3, row4 );   \
  row2 = _mm_xor_si128( row2, row3 ); \
  row2 = _mm_roti_epi32(row2, -7);

#define DIAGONALIZE(row1,row2,row3,row4) \
  row1 = _mm_shuffle_epi32( row1, _MM_SHUFFLE(2,1,0,3) ); \
  row4 = _mm_shuffle_epi32( row4, _MM_SHUFFLE(1,0,3,2) ); \
  row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE(0,3,2,1) );

#define UNDIAGONALIZE(row1,row2,row3,row4) \
  row1 = _mm_shuffle_epi32( row1, _MM_SHUFFLE(0,3,2,1) ); \
  row4 = _mm_shuffle_epi32( row4, _MM_SHUFFLE(1,0,3,2) ); \
  row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE(2,1,0,3) );

#define ROUND(r)  \
  LOAD_MSG_ ##r ##_1(buf1); \
  G1(row1,row2,row3,row4,buf1); \
  LOAD_MSG_ ##r ##_2(buf2); \
  G2(row1,row2,row3,row4,buf2); \
  DIAGONALIZE(row1,row2,row3,row4); \
  LOAD_MSG_ ##r ##_3(buf3); \
  G1(row1,row2,row3,row4,buf3); \
  LOAD_MSG_ ##r ##_4(buf4); \
  G2(row1,row2,row3,row4,buf4); \
  UNDIAGONALIZE(row1,row2,row3,row4); \

template < bool bswap >
static void blake2_compress_sse41(blake2s_context * ctx, const uint8_t * in) {
  const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
  __m128i row1, row2, row3, row4;
  __m128i buf1, buf2, buf3, buf4;
  __m128i t0, t1, t2;
  __m128i ff0, ff1;

  const __m128i r8 = _mm_set_epi8( 12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1 );
  const __m128i r16 = _mm_set_epi8( 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2 );

  const __m128i m0 = bswap ? _mm_shuffle_epi8(LOADU(in + 00), MASK) : LOADU( in + 00 );
  const __m128i m1 = bswap ? _mm_shuffle_epi8(LOADU(in + 16), MASK) : LOADU( in + 16 );
  const __m128i m2 = bswap ? _mm_shuffle_epi8(LOADU(in + 32), MASK) : LOADU( in + 32 );
  const __m128i m3 = bswap ? _mm_shuffle_epi8(LOADU(in + 48), MASK) : LOADU( in + 48 );

  row1 = ff0 = LOADU( &ctx->h[0] );
  row2 = ff1 = LOADU( &ctx->h[4] );
  row3 = _mm_loadu_si128( (__m128i const *)&blake2s_IV[0] );
  row4 = _mm_xor_si128( _mm_loadu_si128( (__m128i const *)&blake2s_IV[4] ), LOADU( &ctx->t[0] ) );

  ROUND( 0 );
  ROUND( 1 );
  ROUND( 2 );
  ROUND( 3 );
  ROUND( 4 );
  ROUND( 5 );
  ROUND( 6 );
  ROUND( 7 );
  ROUND( 8 );
  ROUND( 9 );

  STOREU( &ctx->h[0], _mm_xor_si128( ff0, _mm_xor_si128( row1, row3 ) ) );
  STOREU( &ctx->h[4], _mm_xor_si128( ff1, _mm_xor_si128( row2, row4 ) ) );
}

#undef G1
#undef G2
#undef DIAGONALIZE
#undef UNDIAGONALIZE
#undef ROUND
#undef LOAD_MSG_0_1
#undef LOAD_MSG_0_2
#undef LOAD_MSG_0_3
#undef LOAD_MSG_0_4
#undef LOAD_MSG_1_1
#undef LOAD_MSG_1_2
#undef LOAD_MSG_1_3
#undef LOAD_MSG_1_4
#undef LOAD_MSG_2_1
#undef LOAD_MSG_2_2
#undef LOAD_MSG_2_3
#undef LOAD_MSG_2_4
#undef LOAD_MSG_3_1
#undef LOAD_MSG_3_2
#undef LOAD_MSG_3_3
#undef LOAD_MSG_3_4
#undef LOAD_MSG_4_1
#undef LOAD_MSG_4_2
#undef LOAD_MSG_4_3
#undef LOAD_MSG_4_4
#undef LOAD_MSG_5_1
#undef LOAD_MSG_5_2
#undef LOAD_MSG_5_3
#undef LOAD_MSG_5_4
#undef LOAD_MSG_6_1
#undef LOAD_MSG_6_2
#undef LOAD_MSG_6_3
#undef LOAD_MSG_6_4
#undef LOAD_MSG_7_1
#undef LOAD_MSG_7_2
#undef LOAD_MSG_7_3
#undef LOAD_MSG_7_4
#undef LOAD_MSG_8_1
#undef LOAD_MSG_8_2
#undef LOAD_MSG_8_3
#undef LOAD_MSG_8_4
#undef LOAD_MSG_9_1
#undef LOAD_MSG_9_2
#undef LOAD_MSG_9_3
#undef LOAD_MSG_9_4

#undef TOF
#undef TOI
#undef LOADU
#undef STOREU

#endif /* defined(NEW_HAVE_SSE_4_1) */

#define G(r,i,a,b,c,d)			    \
  do {                                      \
    a = a + b + m[blake2_sigma[r][2*i+0]];  \
    d = rotr64(d ^ a, 32);                  \
    c = c + d;                              \
    b = rotr64(b ^ c, 24);                  \
    a = a + b + m[blake2_sigma[r][2*i+1]];  \
    d = rotr64(d ^ a, 16);                  \
    c = c + d;                              \
    b = rotr64(b ^ c, 63);                  \
  } while(0)

#define ROUND(r)                    \
  do {                              \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
} while(0)

template < bool bswap >
static void blake2_compress(blake2b_context * ctx, const uint8_t * in) {
#if defined(NEW_HAVE_SSE_4_1)
  return blake2_compress_sse41<bswap>(ctx, in);
#else
  uint64_t m[16];
  uint64_t v[16];
  size_t i;

  for( i = 0; i < 16; ++i ) {
    m[i] = GET_U64<bswap>(in, i * sizeof(m[i]));
  }

  for( i = 0; i < 8; ++i ) {
    v[i] = ctx->h[i];
  }

  v[ 8] = blake2b_IV[0];
  v[ 9] = blake2b_IV[1];
  v[10] = blake2b_IV[2];
  v[11] = blake2b_IV[3];
  v[12] = blake2b_IV[4] ^ ctx->t[0];
  v[13] = blake2b_IV[5] ^ ctx->t[1];
  v[14] = blake2b_IV[6] ^ ctx->f[0];
  v[15] = blake2b_IV[7] ^ ctx->f[1];

  ROUND( 0 );
  ROUND( 1 );
  ROUND( 2 );
  ROUND( 3 );
  ROUND( 4 );
  ROUND( 5 );
  ROUND( 6 );
  ROUND( 7 );
  ROUND( 8 );
  ROUND( 9 );
  ROUND( 10 );
  ROUND( 11 );

  for( i = 0; i < 8; ++i ) {
    ctx->h[i] = ctx->h[i] ^ v[i] ^ v[i + 8];
  }
#endif
}

#undef G

#define G(r,i,a,b,c,d)			    \
  do {                                      \
    a = a + b + m[blake2_sigma[r][2*i+0]];  \
    d = rotr32(d ^ a, 16);                  \
    c = c + d;                              \
    b = rotr32(b ^ c, 12);                  \
    a = a + b + m[blake2_sigma[r][2*i+1]];  \
    d = rotr32(d ^ a,  8);                  \
    c = c + d;                              \
    b = rotr32(b ^ c,  7);                  \
  } while(0)

template < bool bswap >
static void blake2_compress(blake2s_context * ctx, const uint8_t * in) {
#if defined(NEW_HAVE_SSE_4_1)
  return blake2_compress_sse41<bswap>(ctx, in);
#else
  uint32_t m[16];
  uint32_t v[16];
  size_t i;

  for( i = 0; i < 16; ++i ) {
    m[i] = GET_U32<bswap>(in, i * sizeof(m[i]));
  }

  for( i = 0; i < 8; ++i ) {
    v[i] = ctx->h[i];
  }

  v[ 8] = blake2s_IV[0];
  v[ 9] = blake2s_IV[1];
  v[10] = blake2s_IV[2];
  v[11] = blake2s_IV[3];
  v[12] = blake2s_IV[4] ^ ctx->t[0];
  v[13] = blake2s_IV[5] ^ ctx->t[1];
  v[14] = blake2s_IV[6] ^ ctx->f[0];
  v[15] = blake2s_IV[7] ^ ctx->f[1];

  ROUND( 0 );
  ROUND( 1 );
  ROUND( 2 );
  ROUND( 3 );
  ROUND( 4 );
  ROUND( 5 );
  ROUND( 6 );
  ROUND( 7 );
  ROUND( 8 );
  ROUND( 9 );

  for( i = 0; i < 8; ++i ) {
    ctx->h[i] = ctx->h[i] ^ v[i] ^ v[i + 8];
  }
#endif
}

#undef G
#undef ROUND

template < typename T >
static int blake2_is_lastblock( const T * ctx ) {
  return ctx->f[0] != 0;
}

template < typename T >
static void blake2_set_lastblock( T * ctx ) {
  ctx->f[0] = (typeof(ctx->f[0]))-1;
}

template < typename T >
static void blake2_increment_counter( T * ctx, const uint64_t inc ) {
  ctx->t[0] += inc;
  ctx->t[1] += ( ctx->t[0] < inc );
}

template < bool bswap, typename T >
static void blake2_Update(T * ctx, const uint8_t * in, size_t inlen) {
  const uint64_t BLOCKBYTES = sizeof(ctx->buf);

  if ( inlen > 0 ) {
    size_t left = ctx->buflen;
    size_t fill = BLOCKBYTES - left;
    if ( inlen > fill ) {
      ctx->buflen = 0;
      memcpy( ctx->buf + left, in, fill ); /* Fill buffer */
      blake2_increment_counter(ctx, BLOCKBYTES );
      blake2_compress<bswap>(ctx, ctx->buf ); /* Compress */
      in += fill; inlen -= fill;
      while(inlen > BLOCKBYTES) {
        blake2_increment_counter(ctx, BLOCKBYTES);
	blake2_compress<bswap>(ctx,in);
        in += BLOCKBYTES;
        inlen -= BLOCKBYTES;
      }
    }
    memcpy( ctx->buf + ctx->buflen, in, inlen );
    ctx->buflen += inlen;
  }
}

template < bool bswap, typename T >
static void blake2_Finalize(T * ctx) {
  const uint64_t BLOCKBYTES = sizeof(ctx->buf);

  if (blake2_is_lastblock(ctx)) {
    return;
  }

  blake2_increment_counter( ctx, ctx->buflen );
  blake2_set_lastblock( ctx );
  memset( ctx->buf + ctx->buflen, 0, BLOCKBYTES - ctx->buflen ); /* Padding */
  blake2_compress<bswap>( ctx, ctx->buf );
}

template < uint32_t hashbits, uint32_t outbits, bool bswap >
void BLAKE2B(const void * in, const size_t len, const seed_t seed, void * out) {
  blake2b_context ctx;

  blake2_Init(&ctx, hashbits, (uint64_t)seed);
  blake2_Update<bswap>(&ctx, (const uint8_t *)in, len);
  blake2_Finalize<bswap>(&ctx);

  uint8_t buf[32];
  for (int i = 0; i < 4; ++i ) {
    PUT_U64<bswap>(ctx.h[i], buf, i*8);
  }
  memcpy(out, buf, (outbits >= 256) ? 32 : (outbits+7)/8);
}

template < uint32_t hashbits, uint32_t outbits, bool bswap >
void BLAKE2S(const void * in, const size_t len, const seed_t seed, void * out) {
  blake2s_context ctx;

  blake2_Init(&ctx, hashbits, (uint64_t)seed);
  blake2_Update<bswap>(&ctx, (const uint8_t *)in, len);
  blake2_Finalize<bswap>(&ctx);

  uint8_t buf[32];
  for (int i = 0; i < 8; ++i ) {
    PUT_U32<bswap>(ctx.h[i], buf, i*4);
  }
  memcpy(out, buf, (outbits >= 256) ? 32 : (outbits+7)/8);
}

REGISTER_FAMILY(blake2);

REGISTER_HASH(blake2b_256,
  $.desc = "BLAKE 2b, 256-bit digest",
  $.hash_flags =
        FLAG_HASH_CRYPTOGRAPHIC        |
        FLAG_HASH_ENDIAN_INDEPENDENT   |
        FLAG_HASH_NO_SEED,
  $.impl_flags =
        FLAG_IMPL_LICENSE_MIT          |
        FLAG_IMPL_CANONICAL_LE         |
        FLAG_IMPL_ROTATE               |
        FLAG_IMPL_INCREMENTAL          |
        FLAG_IMPL_VERY_SLOW,
  $.bits = 256,
  $.verification_LE = 0xC9D8D995,
  $.verification_BE = 0xCDB3E566,
  $.hashfn_native = BLAKE2B<256,256,false>,
  $.hashfn_bswap = BLAKE2B<256,256,true>
);

REGISTER_HASH(blake2b_224,
  $.desc = "BLAKE 2b, 224-bit digest",
  $.hash_flags =
        FLAG_HASH_CRYPTOGRAPHIC        |
        FLAG_HASH_ENDIAN_INDEPENDENT   |
        FLAG_HASH_NO_SEED,
  $.impl_flags =
        FLAG_IMPL_LICENSE_MIT          |
        FLAG_IMPL_CANONICAL_LE         |
        FLAG_IMPL_ROTATE               |
        FLAG_IMPL_INCREMENTAL          |
        FLAG_IMPL_VERY_SLOW,
  $.bits = 224,
  $.verification_LE = 0x101A62A4,
  $.verification_BE = 0x77BE80ED,
  $.hashfn_native = BLAKE2B<224,224,false>,
  $.hashfn_bswap = BLAKE2B<224,224,true>
);

REGISTER_HASH(blake2b_160,
  $.desc = "BLAKE 2b, 160-bit digest",
  $.hash_flags =
        FLAG_HASH_CRYPTOGRAPHIC        |
        FLAG_HASH_ENDIAN_INDEPENDENT   |
        FLAG_HASH_NO_SEED,
  $.impl_flags =
        FLAG_IMPL_LICENSE_MIT          |
        FLAG_IMPL_CANONICAL_LE         |
        FLAG_IMPL_ROTATE               |
        FLAG_IMPL_INCREMENTAL          |
        FLAG_IMPL_VERY_SLOW,
  $.bits = 160,
  $.verification_LE = 0x28ADDA30,
  $.verification_BE = 0xFF79839E,
  $.hashfn_native = BLAKE2B<160,160,false>,
  $.hashfn_bswap = BLAKE2B<160,160,true>
);

REGISTER_HASH(blake2b_256_64,
  $.desc = "BLAKE 2b, 256-bit digest, bits 0-63",
  $.hash_flags =
        FLAG_HASH_CRYPTOGRAPHIC        |
        FLAG_HASH_ENDIAN_INDEPENDENT   |
        FLAG_HASH_NO_SEED,
  $.impl_flags =
        FLAG_IMPL_LICENSE_MIT          |
        FLAG_IMPL_CANONICAL_LE         |
        FLAG_IMPL_ROTATE               |
        FLAG_IMPL_INCREMENTAL          |
        FLAG_IMPL_VERY_SLOW,
  $.bits = 64,
  $.verification_LE = 0xCF4F7EC3,
  $.verification_BE = 0x0EB38190,
  $.hashfn_native = BLAKE2B<256,64,false>,
  $.hashfn_bswap = BLAKE2B<256,64,true>
);

REGISTER_HASH(blake2s_256,
  $.desc = "BLAKE 2s, 256-bit digest",
  $.hash_flags =
        FLAG_HASH_CRYPTOGRAPHIC        |
        FLAG_HASH_ENDIAN_INDEPENDENT   |
        FLAG_HASH_NO_SEED,
  $.impl_flags =
        FLAG_IMPL_LICENSE_MIT          |
        FLAG_IMPL_CANONICAL_LE         |
        FLAG_IMPL_ROTATE               |
        FLAG_IMPL_INCREMENTAL          |
        FLAG_IMPL_VERY_SLOW,
  $.bits = 256,
  $.verification_LE = 0x841D6354,
  $.verification_BE = 0x9F85F5C2,
  $.hashfn_native = BLAKE2S<256,256,false>,
  $.hashfn_bswap = BLAKE2S<256,256,true>
);

REGISTER_HASH(blake2s_224,
  $.desc = "BLAKE 2s, 224-bit digest",
  $.hash_flags =
        FLAG_HASH_CRYPTOGRAPHIC        |
        FLAG_HASH_ENDIAN_INDEPENDENT   |
        FLAG_HASH_NO_SEED,
  $.impl_flags =
        FLAG_IMPL_LICENSE_MIT          |
        FLAG_IMPL_CANONICAL_LE         |
        FLAG_IMPL_ROTATE               |
        FLAG_IMPL_INCREMENTAL          |
        FLAG_IMPL_VERY_SLOW,
  $.bits = 224,
  $.verification_LE = 0x19B36D2C,
  $.verification_BE = 0xBD261F10,
  $.hashfn_native = BLAKE2S<224,224,false>,
  $.hashfn_bswap = BLAKE2S<224,224,true>
);

REGISTER_HASH(blake2s_160,
  $.desc = "BLAKE 2s, 160-bit digest",
  $.hash_flags =
        FLAG_HASH_CRYPTOGRAPHIC        |
        FLAG_HASH_ENDIAN_INDEPENDENT   |
        FLAG_HASH_NO_SEED,
  $.impl_flags =
        FLAG_IMPL_LICENSE_MIT          |
        FLAG_IMPL_CANONICAL_LE         |
        FLAG_IMPL_ROTATE               |
        FLAG_IMPL_INCREMENTAL          |
        FLAG_IMPL_VERY_SLOW,
  $.bits = 160,
  $.verification_LE = 0xD50FF144,
  $.verification_BE = 0xF9579BEA,
  $.hashfn_native = BLAKE2S<160,160,false>,
  $.hashfn_bswap = BLAKE2S<160,160,true>
);

REGISTER_HASH(blake2s_128,
  $.desc = "BLAKE 2s, 128-bit digest",
  $.hash_flags =
        FLAG_HASH_CRYPTOGRAPHIC        |
        FLAG_HASH_ENDIAN_INDEPENDENT   |
        FLAG_HASH_NO_SEED,
  $.impl_flags =
        FLAG_IMPL_LICENSE_MIT          |
        FLAG_IMPL_CANONICAL_LE         |
        FLAG_IMPL_ROTATE               |
        FLAG_IMPL_INCREMENTAL          |
        FLAG_IMPL_VERY_SLOW,
  $.bits = 128,
  $.verification_LE = 0xE8D8FCDF,
  $.verification_BE = 0x9C786057,
  $.hashfn_native = BLAKE2S<128,128,false>,
  $.hashfn_bswap = BLAKE2S<128,128,true>
);

REGISTER_HASH(blake2s_256_64,
  $.desc = "BLAKE 2s, 256-bit digest, bits 0-63",
  $.hash_flags =
        FLAG_HASH_CRYPTOGRAPHIC        |
        FLAG_HASH_ENDIAN_INDEPENDENT   |
        FLAG_HASH_NO_SEED,
  $.impl_flags =
        FLAG_IMPL_LICENSE_MIT          |
        FLAG_IMPL_CANONICAL_LE         |
        FLAG_IMPL_ROTATE               |
        FLAG_IMPL_INCREMENTAL          |
        FLAG_IMPL_VERY_SLOW,
  $.bits = 64,
  $.verification_LE = 0x53000BB2,
  $.verification_BE = 0x901DDE1D,
  $.hashfn_native = BLAKE2S<256,64,false>,
  $.hashfn_bswap = BLAKE2S<256,64,true>
);

#if 0
  { blake2s128_test,     128, 0xE8D8FCDF, "blake2s-128",  "blake2s-128", GOOD, {0x6a09e667} },
  { blake2s160_test,     160, 0xD50FF144, "blake2s-160",  "blake2s-160", GOOD, {0x6a09e667} },
  { blake2s224_test,     224, 0x19B36D2C, "blake2s-224",  "blake2s-224", GOOD, {0x6a09e667} },
  { blake2s256_test,     256, 0x841D6354, "blake2s-256",  "blake2s-256", GOOD,
    {0x31, 0x32, 0x15e, 0x432, 0x447, 0x8000001e, 0x80000021 } /* !! and >1000 more */ },
  { blake2s256_64,        64, 0x53000BB2, "blake2s-256_64","blake2s-256, low 64 bits", GOOD,
    {0xa, 0xe, 0x2d, 0x2f, 0x53, 0x40000003, 0x40000005, 0x40000006 } /* !! and >1000 more */ },
  { blake2s160_test,     160, 0x28ADDA30, "blake2s-160",  "blake2s-160", GOOD,
    {0x4a, 0x5a, 0x5e, 0x74, 0x7f, 0x81} /* !! and >1000 more */ },
  { blake2s224_test,     224, 0x101A62A4, "blake2s-224",  "blake2b-224", GOOD,
    {0x12, 0x2e, 0x32, 0x99a, 0xc80, 0xc98, 0xc9c} /* !! and >1000 more */ },
  { blake2b256_test,     256, 0xC9D8D995, "blake2b-256",  "blake2b-256", POOR, {} },
  { blake2b256_64,        64, 0xCF4F7EC3, "blake2b-256_64","blake2b-256, low 64 bits", GOOD, {} },

#endif
