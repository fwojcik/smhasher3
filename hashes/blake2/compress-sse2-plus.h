// blake2_compress() for both BLAKE2b and BLAKE2s, for CPUs supporting
// at least SSE2. Additional specializations are included for SSSE3,
// SSE 4.1, and AMD's XOP.
//
// It is generally assumed that supporting a later/higher instruction
// set includes support for previous/lower instruction sets.

#define LOADU(p)  _mm_loadu_si128((const __m128i *)(p))
#define STOREU(p, r) _mm_storeu_si128((__m128i *)(p), r)

//-----------------------------------------------------------------------------
// BLAKE2b code

#if defined(HAVE_SSE_4_1)

  #define LOAD_MSG_0_1(b0, b1)  b0  = _mm_unpacklo_epi64(m0, m1); b1 = _mm_unpacklo_epi64(m2, m3);
  #define LOAD_MSG_0_2(b0, b1)  b0  = _mm_unpackhi_epi64(m0, m1); b1 = _mm_unpackhi_epi64(m2, m3);
  #define LOAD_MSG_0_3(b0, b1)  b0  = _mm_unpacklo_epi64(m4, m5); b1 = _mm_unpacklo_epi64(m6, m7);
  #define LOAD_MSG_0_4(b0, b1)  b0  = _mm_unpackhi_epi64(m4, m5); b1 = _mm_unpackhi_epi64(m6, m7);
  #define LOAD_MSG_1_1(b0, b1)  b0  = _mm_unpacklo_epi64(m7, m2); b1 = _mm_unpackhi_epi64(m4, m6);
  #define LOAD_MSG_1_2(b0, b1)  b0  = _mm_unpacklo_epi64(m5, m4); b1 = _mm_alignr_epi8(m3, m7, 8);
  #define LOAD_MSG_1_3(b0, b1)  b0  = _mm_shuffle_epi32(m0, _MM_SHUFFLE(1, 0, 3, 2)); b1 = _mm_unpackhi_epi64(m5, m2);
  #define LOAD_MSG_1_4(b0, b1)  b0  = _mm_unpacklo_epi64(m6, m1); b1 = _mm_unpackhi_epi64(m3, m1);
  #define LOAD_MSG_2_1(b0, b1)  b0  = _mm_alignr_epi8(m6, m5, 8); b1 = _mm_unpackhi_epi64(m2, m7);
  #define LOAD_MSG_2_2(b0, b1)  b0  = _mm_unpacklo_epi64(m4, m0); b1 = _mm_blend_epi16(m1, m6, 0xF0);
  #define LOAD_MSG_2_3(b0, b1)  b0  = _mm_blend_epi16(m5, m1, 0xF0); b1 = _mm_unpackhi_epi64(m3, m4);
  #define LOAD_MSG_2_4(b0, b1)  b0  = _mm_unpacklo_epi64(m7, m3); b1 = _mm_alignr_epi8(m2, m0, 8);
  #define LOAD_MSG_3_1(b0, b1)  b0  = _mm_unpackhi_epi64(m3, m1); b1 = _mm_unpackhi_epi64(m6, m5);
  #define LOAD_MSG_3_2(b0, b1)  b0  = _mm_unpackhi_epi64(m4, m0); b1 = _mm_unpacklo_epi64(m6, m7);
  #define LOAD_MSG_3_3(b0, b1)  b0  = _mm_blend_epi16(m1, m2, 0xF0); b1 = _mm_blend_epi16(m2, m7, 0xF0);
  #define LOAD_MSG_3_4(b0, b1)  b0  = _mm_unpacklo_epi64(m3, m5); b1 = _mm_unpacklo_epi64(m0, m4);
  #define LOAD_MSG_4_1(b0, b1)  b0  = _mm_unpackhi_epi64(m4, m2); b1 = _mm_unpacklo_epi64(m1, m5);
  #define LOAD_MSG_4_2(b0, b1)  b0  = _mm_blend_epi16(m0, m3, 0xF0); b1 = _mm_blend_epi16(m2, m7, 0xF0);
  #define LOAD_MSG_4_3(b0, b1)  b0  = _mm_blend_epi16(m7, m5, 0xF0); b1 = _mm_blend_epi16(m3, m1, 0xF0);
  #define LOAD_MSG_4_4(b0, b1)  b0  = _mm_alignr_epi8(m6, m0, 8); b1 = _mm_blend_epi16(m4, m6, 0xF0);
  #define LOAD_MSG_5_1(b0, b1)  b0  = _mm_unpacklo_epi64(m1, m3); b1 = _mm_unpacklo_epi64(m0, m4);
  #define LOAD_MSG_5_2(b0, b1)  b0  = _mm_unpacklo_epi64(m6, m5); b1 = _mm_unpackhi_epi64(m5, m1);
  #define LOAD_MSG_5_3(b0, b1)  b0  = _mm_blend_epi16(m2, m3, 0xF0); b1 = _mm_unpackhi_epi64(m7, m0);
  #define LOAD_MSG_5_4(b0, b1)  b0  = _mm_unpackhi_epi64(m6, m2); b1 = _mm_blend_epi16(m7, m4, 0xF0);
  #define LOAD_MSG_6_1(b0, b1)  b0  = _mm_blend_epi16(m6, m0, 0xF0); b1 = _mm_unpacklo_epi64(m7, m2);
  #define LOAD_MSG_6_2(b0, b1)  b0  = _mm_unpackhi_epi64(m2, m7); b1 = _mm_alignr_epi8(m5, m6, 8);
  #define LOAD_MSG_6_3(b0, b1)  b0  = _mm_unpacklo_epi64(m0, m3); b1 = _mm_shuffle_epi32(m4, _MM_SHUFFLE(1, 0, 3, 2));
  #define LOAD_MSG_6_4(b0, b1)  b0  = _mm_unpackhi_epi64(m3, m1); b1 = _mm_blend_epi16(m1, m5, 0xF0);
  #define LOAD_MSG_7_1(b0, b1)  b0  = _mm_unpackhi_epi64(m6, m3); b1 = _mm_blend_epi16(m6, m1, 0xF0);
  #define LOAD_MSG_7_2(b0, b1)  b0  = _mm_alignr_epi8(m7, m5, 8); b1 = _mm_unpackhi_epi64(m0, m4);
  #define LOAD_MSG_7_3(b0, b1)  b0  = _mm_unpackhi_epi64(m2, m7); b1 = _mm_unpacklo_epi64(m4, m1);
  #define LOAD_MSG_7_4(b0, b1)  b0  = _mm_unpacklo_epi64(m0, m2); b1 = _mm_unpacklo_epi64(m3, m5);
  #define LOAD_MSG_8_1(b0, b1)  b0  = _mm_unpacklo_epi64(m3, m7); b1 = _mm_alignr_epi8(m0, m5, 8);
  #define LOAD_MSG_8_2(b0, b1)  b0  = _mm_unpackhi_epi64(m7, m4); b1 = _mm_alignr_epi8(m4, m1, 8);
  #define LOAD_MSG_8_3(b0, b1)  b0  = m6; b1 = _mm_alignr_epi8(m5, m0, 8);
  #define LOAD_MSG_8_4(b0, b1)  b0  = _mm_blend_epi16(m1, m3, 0xF0); b1 = m2;
  #define LOAD_MSG_9_1(b0, b1)  b0  = _mm_unpacklo_epi64(m5, m4); b1 = _mm_unpackhi_epi64(m3, m0);
  #define LOAD_MSG_9_2(b0, b1)  b0  = _mm_unpacklo_epi64(m1, m2); b1 = _mm_blend_epi16(m3, m2, 0xF0);
  #define LOAD_MSG_9_3(b0, b1)  b0  = _mm_unpackhi_epi64(m7, m4); b1 = _mm_unpackhi_epi64(m1, m6);
  #define LOAD_MSG_9_4(b0, b1)  b0  = _mm_alignr_epi8(m7, m5, 8); b1 = _mm_unpacklo_epi64(m6, m0);
  #define LOAD_MSG_10_1(b0, b1)  b0 = _mm_unpacklo_epi64(m0, m1); b1 = _mm_unpacklo_epi64(m2, m3);
  #define LOAD_MSG_10_2(b0, b1)  b0 = _mm_unpackhi_epi64(m0, m1); b1 = _mm_unpackhi_epi64(m2, m3);
  #define LOAD_MSG_10_3(b0, b1)  b0 = _mm_unpacklo_epi64(m4, m5); b1 = _mm_unpacklo_epi64(m6, m7);
  #define LOAD_MSG_10_4(b0, b1)  b0 = _mm_unpackhi_epi64(m4, m5); b1 = _mm_unpackhi_epi64(m6, m7);
  #define LOAD_MSG_11_1(b0, b1)  b0 = _mm_unpacklo_epi64(m7, m2); b1 = _mm_unpackhi_epi64(m4, m6);
  #define LOAD_MSG_11_2(b0, b1)  b0 = _mm_unpacklo_epi64(m5, m4); b1 = _mm_alignr_epi8(m3, m7, 8);
  #define LOAD_MSG_11_3(b0, b1)  b0 = _mm_shuffle_epi32(m0, _MM_SHUFFLE(1, 0, 3, 2)); b1 = _mm_unpackhi_epi64(m5, m2);
  #define LOAD_MSG_11_4(b0, b1)  b0 = _mm_unpacklo_epi64(m6, m1); b1 = _mm_unpackhi_epi64(m3, m1);

#else

  #define LOAD_MSG_0_1(b0, b1) b0  = _mm_set_epi64x(m2 , m0 ); b1 = _mm_set_epi64x(m6, m4)
  #define LOAD_MSG_0_2(b0, b1) b0  = _mm_set_epi64x(m3 , m1 ); b1 = _mm_set_epi64x(m7, m5)
  #define LOAD_MSG_0_3(b0, b1) b0  = _mm_set_epi64x(m10, m8 ); b1 = _mm_set_epi64x(m14, m12)
  #define LOAD_MSG_0_4(b0, b1) b0  = _mm_set_epi64x(m11, m9 ); b1 = _mm_set_epi64x(m15, m13)
  #define LOAD_MSG_1_1(b0, b1) b0  = _mm_set_epi64x(m4 , m14); b1 = _mm_set_epi64x(m13, m9)
  #define LOAD_MSG_1_2(b0, b1) b0  = _mm_set_epi64x(m8 , m10); b1 = _mm_set_epi64x(m6, m15)
  #define LOAD_MSG_1_3(b0, b1) b0  = _mm_set_epi64x(m0 , m1 ); b1 = _mm_set_epi64x(m5, m11)
  #define LOAD_MSG_1_4(b0, b1) b0  = _mm_set_epi64x(m2 , m12); b1 = _mm_set_epi64x(m3, m7)
  #define LOAD_MSG_2_1(b0, b1) b0  = _mm_set_epi64x(m12, m11); b1 = _mm_set_epi64x(m15, m5)
  #define LOAD_MSG_2_2(b0, b1) b0  = _mm_set_epi64x(m0 , m8 ); b1 = _mm_set_epi64x(m13, m2)
  #define LOAD_MSG_2_3(b0, b1) b0  = _mm_set_epi64x(m3 , m10); b1 = _mm_set_epi64x(m9, m7)
  #define LOAD_MSG_2_4(b0, b1) b0  = _mm_set_epi64x(m6 , m14); b1 = _mm_set_epi64x(m4, m1)
  #define LOAD_MSG_3_1(b0, b1) b0  = _mm_set_epi64x(m3 , m7 ); b1 = _mm_set_epi64x(m11, m13)
  #define LOAD_MSG_3_2(b0, b1) b0  = _mm_set_epi64x(m1 , m9 ); b1 = _mm_set_epi64x(m14, m12)
  #define LOAD_MSG_3_3(b0, b1) b0  = _mm_set_epi64x(m5 , m2 ); b1 = _mm_set_epi64x(m15, m4)
  #define LOAD_MSG_3_4(b0, b1) b0  = _mm_set_epi64x(m10, m6 ); b1 = _mm_set_epi64x(m8, m0)
  #define LOAD_MSG_4_1(b0, b1) b0  = _mm_set_epi64x(m5 , m9 ); b1 = _mm_set_epi64x(m10, m2)
  #define LOAD_MSG_4_2(b0, b1) b0  = _mm_set_epi64x(m7 , m0 ); b1 = _mm_set_epi64x(m15, m4)
  #define LOAD_MSG_4_3(b0, b1) b0  = _mm_set_epi64x(m11, m14); b1 = _mm_set_epi64x(m3, m6)
  #define LOAD_MSG_4_4(b0, b1) b0  = _mm_set_epi64x(m12, m1 ); b1 = _mm_set_epi64x(m13, m8)
  #define LOAD_MSG_5_1(b0, b1) b0  = _mm_set_epi64x(m6 , m2 ); b1 = _mm_set_epi64x(m8, m0)
  #define LOAD_MSG_5_2(b0, b1) b0  = _mm_set_epi64x(m10, m12); b1 = _mm_set_epi64x(m3, m11)
  #define LOAD_MSG_5_3(b0, b1) b0  = _mm_set_epi64x(m7 , m4 ); b1 = _mm_set_epi64x(m1, m15)
  #define LOAD_MSG_5_4(b0, b1) b0  = _mm_set_epi64x(m5 , m13); b1 = _mm_set_epi64x(m9, m14)
  #define LOAD_MSG_6_1(b0, b1) b0  = _mm_set_epi64x(m1 , m12); b1 = _mm_set_epi64x(m4, m14)
  #define LOAD_MSG_6_2(b0, b1) b0  = _mm_set_epi64x(m15, m5 ); b1 = _mm_set_epi64x(m10, m13)
  #define LOAD_MSG_6_3(b0, b1) b0  = _mm_set_epi64x(m6 , m0 ); b1 = _mm_set_epi64x(m8, m9)
  #define LOAD_MSG_6_4(b0, b1) b0  = _mm_set_epi64x(m3 , m7 ); b1 = _mm_set_epi64x(m11, m2)
  #define LOAD_MSG_7_1(b0, b1) b0  = _mm_set_epi64x(m7 , m13); b1 = _mm_set_epi64x(m3, m12)
  #define LOAD_MSG_7_2(b0, b1) b0  = _mm_set_epi64x(m14, m11); b1 = _mm_set_epi64x(m9, m1)
  #define LOAD_MSG_7_3(b0, b1) b0  = _mm_set_epi64x(m15, m5 ); b1 = _mm_set_epi64x(m2, m8)
  #define LOAD_MSG_7_4(b0, b1) b0  = _mm_set_epi64x(m4 , m0 ); b1 = _mm_set_epi64x(m10, m6)
  #define LOAD_MSG_8_1(b0, b1) b0  = _mm_set_epi64x(m14, m6 ); b1 = _mm_set_epi64x(m0, m11)
  #define LOAD_MSG_8_2(b0, b1) b0  = _mm_set_epi64x(m9 , m15); b1 = _mm_set_epi64x(m8, m3)
  #define LOAD_MSG_8_3(b0, b1) b0  = _mm_set_epi64x(m13, m12); b1 = _mm_set_epi64x(m10, m1)
  #define LOAD_MSG_8_4(b0, b1) b0  = _mm_set_epi64x(m7 , m2 ); b1 = _mm_set_epi64x(m5, m4)
  #define LOAD_MSG_9_1(b0, b1) b0  = _mm_set_epi64x(m8 , m10); b1 = _mm_set_epi64x(m1, m7)
  #define LOAD_MSG_9_2(b0, b1) b0  = _mm_set_epi64x(m4 , m2 ); b1 = _mm_set_epi64x(m5, m6)
  #define LOAD_MSG_9_3(b0, b1) b0  = _mm_set_epi64x(m9 , m15); b1 = _mm_set_epi64x(m13, m3)
  #define LOAD_MSG_9_4(b0, b1) b0  = _mm_set_epi64x(m14, m11); b1 = _mm_set_epi64x(m0, m12)
  #define LOAD_MSG_10_1(b0, b1) b0 = _mm_set_epi64x(m2 , m0 ); b1 = _mm_set_epi64x(m6, m4)
  #define LOAD_MSG_10_2(b0, b1) b0 = _mm_set_epi64x(m3 , m1 ); b1 = _mm_set_epi64x(m7, m5)
  #define LOAD_MSG_10_3(b0, b1) b0 = _mm_set_epi64x(m10, m8 ); b1 = _mm_set_epi64x(m14, m12)
  #define LOAD_MSG_10_4(b0, b1) b0 = _mm_set_epi64x(m11, m9 ); b1 = _mm_set_epi64x(m15, m13)
  #define LOAD_MSG_11_1(b0, b1) b0 = _mm_set_epi64x(m4 , m14); b1 = _mm_set_epi64x(m13, m9)
  #define LOAD_MSG_11_2(b0, b1) b0 = _mm_set_epi64x(m8 , m10); b1 = _mm_set_epi64x(m6, m15)
  #define LOAD_MSG_11_3(b0, b1) b0 = _mm_set_epi64x(m0 , m1 ); b1 = _mm_set_epi64x(m5, m11)
  #define LOAD_MSG_11_4(b0, b1) b0 = _mm_set_epi64x(m2 , m12); b1 = _mm_set_epi64x(m3, m7)

#endif

#if defined(HAVE_SSSE_3) && !defined(HAVE_XOP)
  #undef _mm_roti_epi64
  #define _mm_roti_epi64(x, c)                                                         \
    (-(c) == 32) ? _mm_shuffle_epi32((x), _MM_SHUFFLE(2,3,0,1))                        \
    : (-(c) == 24) ? _mm_shuffle_epi8((x), r24)                                        \
    : (-(c) == 16) ? _mm_shuffle_epi8((x), r16)                                        \
    : (-(c) == 63) ? _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_add_epi64((x), (x))) \
    : _mm_xor_si128(_mm_srli_epi64((x), -(c)), _mm_slli_epi64((x), 64-(-(c))))
#elif !defined(HAVE_SSSE_3) && !defined(HAVE_XOP)
  #undef _mm_roti_epi64
  #define _mm_roti_epi64(r, c) _mm_xor_si128(_mm_srli_epi64((r), -(c)), _mm_slli_epi64((r), 64 - (-(c))))
#endif

#define G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);         \
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);         \
                                                                  \
  row4l = _mm_xor_si128(row4l, row1l);                            \
  row4h = _mm_xor_si128(row4h, row1h);                            \
                                                                  \
  row4l = _mm_roti_epi64(row4l, -32);                             \
  row4h = _mm_roti_epi64(row4h, -32);                             \
                                                                  \
  row3l = _mm_add_epi64(row3l, row4l);                            \
  row3h = _mm_add_epi64(row3h, row4h);                            \
                                                                  \
  row2l = _mm_xor_si128(row2l, row3l);                            \
  row2h = _mm_xor_si128(row2h, row3h);                            \
                                                                  \
  row2l = _mm_roti_epi64(row2l, -24);                             \
  row2h = _mm_roti_epi64(row2h, -24);                             \

#define G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
  row1l = _mm_add_epi64(_mm_add_epi64(row1l, b0), row2l);         \
  row1h = _mm_add_epi64(_mm_add_epi64(row1h, b1), row2h);         \
                                                                  \
  row4l = _mm_xor_si128(row4l, row1l);                            \
  row4h = _mm_xor_si128(row4h, row1h);                            \
                                                                  \
  row4l = _mm_roti_epi64(row4l, -16);                             \
  row4h = _mm_roti_epi64(row4h, -16);                             \
                                                                  \
  row3l = _mm_add_epi64(row3l, row4l);                            \
  row3h = _mm_add_epi64(row3h, row4h);                            \
                                                                  \
  row2l = _mm_xor_si128(row2l, row3l);                            \
  row2h = _mm_xor_si128(row2h, row3h);                            \
                                                                  \
  row2l = _mm_roti_epi64(row2l, -63);                             \
  row2h = _mm_roti_epi64(row2h, -63);                             \

#if defined(HAVE_SSSE_3)
#define DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  t0 = _mm_alignr_epi8(row2h, row2l, 8);                             \
  t1 = _mm_alignr_epi8(row2l, row2h, 8);                             \
  row2l = t0;                                                        \
  row2h = t1;                                                        \
                                                                     \
  t0 = row3l;                                                        \
  row3l = row3h;                                                     \
  row3h = t0;                                                        \
                                                                     \
  t0 = _mm_alignr_epi8(row4h, row4l, 8);                             \
  t1 = _mm_alignr_epi8(row4l, row4h, 8);                             \
  row4l = t1;                                                        \
  row4h = t0;

#define UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  t0 = _mm_alignr_epi8(row2l, row2h, 8);                               \
  t1 = _mm_alignr_epi8(row2h, row2l, 8);                               \
  row2l = t0;                                                          \
  row2h = t1;                                                          \
                                                                       \
  t0 = row3l;                                                          \
  row3l = row3h;                                                       \
  row3h = t0;                                                          \
                                                                       \
  t0 = _mm_alignr_epi8(row4l, row4h, 8);                               \
  t1 = _mm_alignr_epi8(row4h, row4l, 8);                               \
  row4l = t1;                                                          \
  row4h = t0;

#else

#define DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h)   \
  t0 = row4l;                                                          \
  t1 = row2l;                                                          \
  row4l = row3l;                                                       \
  row3l = row3h;                                                       \
  row3h = row4l;                                                       \
  row4l = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t0, t0));       \
  row4h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row4h, row4h));    \
  row2l = _mm_unpackhi_epi64(row2l, _mm_unpacklo_epi64(row2h, row2h)); \
  row2h = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(t1, t1))

#define UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  t0 = row3l;                                                          \
  row3l = row3h;                                                       \
  row3h = t0;                                                          \
  t0 = row2l;                                                          \
  t1 = row4l;                                                          \
  row2l = _mm_unpackhi_epi64(row2h, _mm_unpacklo_epi64(row2l, row2l)); \
  row2h = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(row2h, row2h));    \
  row4l = _mm_unpackhi_epi64(row4l, _mm_unpacklo_epi64(row4h, row4h)); \
  row4h = _mm_unpackhi_epi64(row4h, _mm_unpacklo_epi64(t1, t1))

#endif

#define ROUND(r)                                                \
  LOAD_MSG_ ##r ##_1(b0, b1);                                   \
  G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);    \
  LOAD_MSG_ ##r ##_2(b0, b1);                                   \
  G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);    \
  DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
  LOAD_MSG_ ##r ##_3(b0, b1);                                   \
  G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);    \
  LOAD_MSG_ ##r ##_4(b0, b1);                                   \
  G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);    \
  UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);

template <bool bswap>
static void blake2_compress( blake2b_context * ctx, const uint8_t * in ) {
    __m128i row1l, row1h;
    __m128i row2l, row2h;
    __m128i row3l, row3h;
    __m128i row4l, row4h;
    __m128i b0, b1;
    __m128i t0, t1;

    const __m128i r16 = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8,  9);
    const __m128i r24 = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15,  8, 9, 10);

#if defined(HAVE_SSE_4_1)
    const __m128i m0  = bswap ? mm_bswap64(LOADU(in +  00)) : LOADU(in +  00);
    const __m128i m1  = bswap ? mm_bswap64(LOADU(in +  16)) : LOADU(in +  16);
    const __m128i m2  = bswap ? mm_bswap64(LOADU(in +  32)) : LOADU(in +  32);
    const __m128i m3  = bswap ? mm_bswap64(LOADU(in +  48)) : LOADU(in +  48);
    const __m128i m4  = bswap ? mm_bswap64(LOADU(in +  64)) : LOADU(in +  64);
    const __m128i m5  = bswap ? mm_bswap64(LOADU(in +  80)) : LOADU(in +  80);
    const __m128i m6  = bswap ? mm_bswap64(LOADU(in +  96)) : LOADU(in +  96);
    const __m128i m7  = bswap ? mm_bswap64(LOADU(in + 112)) : LOADU(in + 112);
#else
    const uint64_t m0 =  GET_U64<bswap>(in,   0), m1  = GET_U64<bswap>(in,   8);
    const uint64_t m2  = GET_U64<bswap>(in,  16), m3  = GET_U64<bswap>(in,  24);
    const uint64_t m4  = GET_U64<bswap>(in,  32), m5  = GET_U64<bswap>(in,  40);
    const uint64_t m6  = GET_U64<bswap>(in,  48), m7  = GET_U64<bswap>(in,  56);
    const uint64_t m8  = GET_U64<bswap>(in,  64), m9  = GET_U64<bswap>(in,  72);
    const uint64_t m10 = GET_U64<bswap>(in,  80), m11 = GET_U64<bswap>(in,  88);
    const uint64_t m12 = GET_U64<bswap>(in,  96), m13 = GET_U64<bswap>(in, 104);
    const uint64_t m14 = GET_U64<bswap>(in, 112), m15 = GET_U64<bswap>(in, 120);
#endif

    row1l = LOADU(&(ctx->h   [0]));
    row1h = LOADU(&(ctx->h   [2]));
    row2l = LOADU(&(ctx->h   [4]));
    row2h = LOADU(&(ctx->h   [6]));
    row3l = LOADU(&blake2b_IV[0] );
    row3h = LOADU(&blake2b_IV[2] );
    row4l = _mm_xor_si128(LOADU(&blake2b_IV[4]), LOADU(&(ctx->t[0])));
    row4h = _mm_xor_si128(LOADU(&blake2b_IV[6]), LOADU(&(ctx->f[0])));

    ROUND( 0);
    ROUND( 1);
    ROUND( 2);
    ROUND( 3);
    ROUND( 4);
    ROUND( 5);
    ROUND( 6);
    ROUND( 7);
    ROUND( 8);
    ROUND( 9);
    ROUND(10);
    ROUND(11);

    row1l = _mm_xor_si128(row3l, row1l);
    row1h = _mm_xor_si128(row3h, row1h);
    STOREU(&(ctx->h[0]), _mm_xor_si128(LOADU(&(ctx->h[0])), row1l));
    STOREU(&(ctx->h[2]), _mm_xor_si128(LOADU(&(ctx->h[2])), row1h));
    row2l = _mm_xor_si128(row4l, row2l);
    row2h = _mm_xor_si128(row4h, row2h);
    STOREU(&(ctx->h[4]), _mm_xor_si128(LOADU(&(ctx->h[4])), row2l));
    STOREU(&(ctx->h[6]), _mm_xor_si128(LOADU(&(ctx->h[6])), row2h));
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

//-----------------------------------------------------------------------------
// BLAKE2s code

#define TOF(reg) _mm_castsi128_ps((reg))
#define TOI(reg) _mm_castps_si128((reg))

#if defined(HAVE_XOP)

  #define TOB(x) ((x) * 4 * 0x01010101 + 0x03020100) /* ..or not TOB */

  #define LOAD_MSG_0_1(buf) buf = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(6), TOB(4), TOB(2), TOB(0)));
  #define LOAD_MSG_0_2(buf) buf = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(7), TOB(5), TOB(3), TOB(1)));
  #define LOAD_MSG_0_3(buf) buf = _mm_perm_epi8(m2, m3, _mm_set_epi32(TOB(4), TOB(2), TOB(0), TOB(6)));
  #define LOAD_MSG_0_4(buf) buf = _mm_perm_epi8(m2, m3, _mm_set_epi32(TOB(5), TOB(3), TOB(1), TOB(7)));
#define LOAD_MSG_1_1(buf) t0 = _mm_perm_epi8(m1, m2, _mm_set_epi32(TOB(0),TOB(5),TOB(0),TOB(0)) ); \
  buf = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(5),TOB(2),TOB(1),TOB(6)) );
#define LOAD_MSG_1_2(buf) t1 = _mm_perm_epi8(m1, m2, _mm_set_epi32(TOB(2),TOB(0),TOB(4),TOB(6)) ); \
  buf = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3),TOB(7),TOB(1),TOB(0)) );
#define LOAD_MSG_1_3(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(5),TOB(0),TOB(0),TOB(1)) ); \
  buf = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(7),TOB(1),TOB(0),TOB(3)) );
#define LOAD_MSG_1_4(buf) t1 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(3),TOB(7),TOB(2),TOB(0)) ); \
  buf = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(2),TOB(1),TOB(4),TOB(3)) );
#define LOAD_MSG_2_1(buf) t0 = _mm_perm_epi8(m1, m2, _mm_set_epi32(TOB(0),TOB(1),TOB(0),TOB(7)) ); \
  buf = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(7),TOB(2),TOB(4),TOB(0)) );
#define LOAD_MSG_2_2(buf) t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(0),TOB(2),TOB(0),TOB(4)) ); \
  buf = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(5),TOB(2),TOB(1),TOB(0)) );
#define LOAD_MSG_2_3(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0),TOB(7),TOB(3),TOB(0)) ); \
  buf = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(2),TOB(1),TOB(6),TOB(5)) );
#define LOAD_MSG_2_4(buf) t1 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(4),TOB(1),TOB(6),TOB(0)) ); \
  buf = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(2),TOB(1),TOB(6),TOB(3)) );
#define LOAD_MSG_3_1(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0),TOB(0),TOB(3),TOB(7)) ); \
  t0 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(7),TOB(2),TOB(1),TOB(0)) );                         \
  buf = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(3),TOB(5),TOB(1),TOB(0)) );
#define LOAD_MSG_3_2(buf) t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(0),TOB(0),TOB(1),TOB(5)) ); \
  buf = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(6),TOB(4),TOB(1),TOB(0)) );
#define LOAD_MSG_3_3(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0),TOB(4),TOB(5),TOB(2)) ); \
  buf = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(2),TOB(1),TOB(0),TOB(7)) );
#define LOAD_MSG_3_4(buf) t1 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0),TOB(0),TOB(0),TOB(6)) ); \
  buf = _mm_perm_epi8(t1, m2, _mm_set_epi32(TOB(2),TOB(6),TOB(0),TOB(4)) );
#define LOAD_MSG_4_1(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0),TOB(2),TOB(5),TOB(0)) ); \
  buf = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(6),TOB(2),TOB(1),TOB(5)) );
#define LOAD_MSG_4_2(buf) t1 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0),TOB(4),TOB(7),TOB(0)) ); \
  buf = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(7),TOB(2),TOB(1),TOB(0)) );
#define LOAD_MSG_4_3(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(3),TOB(6),TOB(0),TOB(0)) ); \
  t0 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(3),TOB(2),TOB(7),TOB(0)) );                         \
  buf = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(2),TOB(1),TOB(6),TOB(3)) );
#define LOAD_MSG_4_4(buf) t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(0),TOB(4),TOB(0),TOB(1)) ); \
  buf = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(2),TOB(4),TOB(0),TOB(5)) );
#define LOAD_MSG_5_1(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0),TOB(0),TOB(6),TOB(2)) ); \
  buf = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(4),TOB(2),TOB(1),TOB(0)) );
#define LOAD_MSG_5_2(buf) t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(3),TOB(7),TOB(6),TOB(0)) ); \
  buf = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3),TOB(2),TOB(1),TOB(4)) );
#define LOAD_MSG_5_3(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(1),TOB(0),TOB(7),TOB(4)) ); \
  buf = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(7),TOB(1),TOB(0),TOB(3)) );
#define LOAD_MSG_5_4(buf) t1 = _mm_perm_epi8(m1, m2, _mm_set_epi32(TOB(5),TOB(0),TOB(1),TOB(0)) ); \
  buf = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(6),TOB(1),TOB(5),TOB(3)) );
#define LOAD_MSG_6_1(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(4),TOB(0),TOB(1),TOB(0)) ); \
  buf = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(3),TOB(6),TOB(1),TOB(4)) );
#define LOAD_MSG_6_2(buf) t1 = _mm_perm_epi8(m1, m2, _mm_set_epi32(TOB(6),TOB(0),TOB(0),TOB(1)) ); \
  buf = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3),TOB(5),TOB(7),TOB(0)) );
#define LOAD_MSG_6_3(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0),TOB(0),TOB(6),TOB(0)) ); \
  buf = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(5),TOB(1),TOB(0),TOB(4)) );
#define LOAD_MSG_6_4(buf) t1 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0),TOB(2),TOB(3),TOB(7)) ); \
  buf = _mm_perm_epi8(t1, m2, _mm_set_epi32(TOB(2),TOB(1),TOB(0),TOB(7)) );
#define LOAD_MSG_7_1(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(3),TOB(0),TOB(7),TOB(0)) ); \
  buf = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(3),TOB(4),TOB(1),TOB(5)) );
#define LOAD_MSG_7_2(buf) t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(5),TOB(1),TOB(0),TOB(7)) ); \
  buf = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3),TOB(2),TOB(6),TOB(0)) );
#define LOAD_MSG_7_3(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(2),TOB(0),TOB(0),TOB(5)) ); \
  t0 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(3),TOB(4),TOB(1),TOB(0)) );                         \
  buf = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(2),TOB(7),TOB(0),TOB(3)) );
#define LOAD_MSG_7_4(buf) t1 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0),TOB(6),TOB(4),TOB(0)) ); \
  buf = _mm_perm_epi8(t1, m2, _mm_set_epi32(TOB(2),TOB(1),TOB(0),TOB(6)) );
#define LOAD_MSG_8_1(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(0),TOB(0),TOB(0),TOB(6)) ); \
  t0 = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(3),TOB(7),TOB(1),TOB(0)) );                         \
  buf = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(3),TOB(2),TOB(6),TOB(0)) );
#define LOAD_MSG_8_2(buf) t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(4),TOB(3),TOB(5),TOB(0)) ); \
  buf = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(3),TOB(2),TOB(1),TOB(7)) );
#define LOAD_MSG_8_3(buf) t0 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(6),TOB(1),TOB(0),TOB(0)) ); \
  buf = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(2),TOB(5),TOB(4),TOB(3)) );
  #define LOAD_MSG_8_4(buf) buf = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(4), TOB(7), TOB(2), TOB(5)));
#define LOAD_MSG_9_1(buf) t0 = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(1),TOB(7),TOB(0),TOB(0)) ); \
  buf = _mm_perm_epi8(t0, m2, _mm_set_epi32(TOB(3),TOB(2),TOB(4),TOB(6)) );
  #define LOAD_MSG_9_2(buf) buf = _mm_perm_epi8(m0, m1, _mm_set_epi32(TOB(5), TOB(6), TOB(4), TOB(2)));
#define LOAD_MSG_9_3(buf) t0 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(0),TOB(3),TOB(5),TOB(0)) ); \
  buf = _mm_perm_epi8(t0, m3, _mm_set_epi32(TOB(2),TOB(1),TOB(7),TOB(5)) );
#define LOAD_MSG_9_4(buf) t1 = _mm_perm_epi8(m0, m2, _mm_set_epi32(TOB(0),TOB(0),TOB(0),TOB(7)) ); \
  buf = _mm_perm_epi8(t1, m3, _mm_set_epi32(TOB(4),TOB(6),TOB(0),TOB(3)) );

#elif defined(HAVE_SSE_4_1)

  #define LOAD_MSG_0_1(buf) buf = TOI(_mm_shuffle_ps(TOF(m0), TOF(m1), _MM_SHUFFLE(2, 0, 2, 0)));
  #define LOAD_MSG_0_2(buf) buf = TOI(_mm_shuffle_ps(TOF(m0), TOF(m1), _MM_SHUFFLE(3, 1, 3, 1)));
#define LOAD_MSG_0_3(buf) t0 = _mm_shuffle_epi32(m2, _MM_SHUFFLE(3,2,0,1)); \
  t1 = _mm_shuffle_epi32(m3, _MM_SHUFFLE(0,1,3,2));                         \
  buf = _mm_blend_epi16(t0, t1, 0xC3);
#define LOAD_MSG_0_4(buf) t0 = _mm_blend_epi16(t0, t1, 0x3C); \
  buf = _mm_shuffle_epi32(t0, _MM_SHUFFLE(2,3,0,1));
#define LOAD_MSG_1_1(buf) t0 = _mm_blend_epi16(m1, m2, 0x0C); \
  t1 = _mm_slli_si128(m3, 4);                                 \
  t2 = _mm_blend_epi16(t0, t1, 0xF0);                         \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,0,3));
#define LOAD_MSG_1_2(buf) t0 = _mm_shuffle_epi32(m2,_MM_SHUFFLE(0,0,2,0)); \
  t1 = _mm_blend_epi16(m1,m3,0xC0);                                        \
  t2 = _mm_blend_epi16(t0, t1, 0xF0);                                      \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,3,0,1));
#define LOAD_MSG_1_3(buf) t0 = _mm_slli_si128(m1, 4); \
  t1 = _mm_blend_epi16(m2, t0, 0x30);                 \
  t2 = _mm_blend_epi16(m0, t1, 0xF0);                 \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,0,1,2));
#define LOAD_MSG_1_4(buf) t0 = _mm_unpackhi_epi32(m0,m1); \
  t1 = _mm_slli_si128(m3, 4);                             \
  t2 = _mm_blend_epi16(t0, t1, 0x0C);                     \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,0,1,2));
#define LOAD_MSG_2_1(buf) t0 = _mm_unpackhi_epi32(m2,m3); \
  t1 = _mm_blend_epi16(m3,m1,0x0C);                       \
  t2 = _mm_blend_epi16(t0, t1, 0x0F);                     \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,1,0,2));
#define LOAD_MSG_2_2(buf) t0 = _mm_unpacklo_epi32(m2,m0); \
  t1 = _mm_blend_epi16(t0, m0, 0xF0);                     \
  t2 = _mm_slli_si128(m3, 8);                             \
  buf = _mm_blend_epi16(t1, t2, 0xC0);
#define LOAD_MSG_2_3(buf) t0 = _mm_blend_epi16(m0, m2, 0x3C); \
  t1 = _mm_srli_si128(m1, 12);                                \
  t2 = _mm_blend_epi16(t0,t1,0x03);                           \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(0,3,2,1));
#define LOAD_MSG_2_4(buf) t0 = _mm_slli_si128(m3, 4); \
  t1 = _mm_blend_epi16(m0, m1, 0x33);                 \
  t2 = _mm_blend_epi16(t1, t0, 0xC0);                 \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1,2,3,0));
#define LOAD_MSG_3_1(buf) t0 = _mm_unpackhi_epi32(m0,m1); \
  t1 = _mm_unpackhi_epi32(t0, m2);                        \
  t2 = _mm_blend_epi16(t1, m3, 0x0C);                     \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,1,0,2));
#define LOAD_MSG_3_2(buf) t0 = _mm_slli_si128(m2, 8); \
  t1 = _mm_blend_epi16(m3,m0,0x0C);                   \
  t2 = _mm_blend_epi16(t1, t0, 0xC0);                 \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,0,1,3));
#define LOAD_MSG_3_3(buf) t0 = _mm_blend_epi16(m0,m1,0x0F); \
  t1 = _mm_blend_epi16(t0, m3, 0xC0);                       \
  buf = _mm_shuffle_epi32(t1, _MM_SHUFFLE(0,1,2,3));
#define LOAD_MSG_3_4(buf) t0 = _mm_alignr_epi8(m0, m1, 4); \
  buf = _mm_blend_epi16(t0, m2, 0x33);
#define LOAD_MSG_4_1(buf) t0 = _mm_unpacklo_epi64(m1,m2); \
  t1 = _mm_unpackhi_epi64(m0,m2);                         \
  t2 = _mm_blend_epi16(t0,t1,0x33);                       \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,0,1,3));
#define LOAD_MSG_4_2(buf) t0 = _mm_unpackhi_epi64(m1,m3); \
  t1 = _mm_unpacklo_epi64(m0,m1);                         \
  buf = _mm_blend_epi16(t0,t1,0x33);
#define LOAD_MSG_4_3(buf) t0 = _mm_unpackhi_epi64(m3,m1); \
  t1 = _mm_unpackhi_epi64(m2,m0);                         \
  t2 = _mm_blend_epi16(t1,t0,0x33);                       \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,0,3));
#define LOAD_MSG_4_4(buf) t0 = _mm_blend_epi16(m0,m2,0x03); \
  t1 = _mm_slli_si128(t0, 8);                               \
  t2 = _mm_blend_epi16(t1,m3,0x0F);                         \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,0,3,1));
#define LOAD_MSG_5_1(buf) t0 = _mm_unpackhi_epi32(m0,m1); \
  t1 = _mm_unpacklo_epi32(m0,m2);                         \
  buf = _mm_unpacklo_epi64(t0,t1);
#define LOAD_MSG_5_2(buf) t0 = _mm_srli_si128(m2, 4); \
  t1 = _mm_blend_epi16(m0,m3,0x03);                   \
  buf = _mm_blend_epi16(t1,t0,0x3C);
#define LOAD_MSG_5_3(buf) t0 = _mm_blend_epi16(m1,m0,0x0C); \
  t1 = _mm_srli_si128(m3, 4);                               \
  t2 = _mm_blend_epi16(t0,t1,0x30);                         \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,3,0,1));
#define LOAD_MSG_5_4(buf) t0 = _mm_unpacklo_epi64(m2,m1); \
  t1 = _mm_shuffle_epi32(m3, _MM_SHUFFLE(2,0,1,0));       \
  t2 = _mm_srli_si128(t0, 4);                             \
  buf = _mm_blend_epi16(t1,t2,0x33);
#define LOAD_MSG_6_1(buf) t0 = _mm_slli_si128(m1, 12); \
  t1 = _mm_blend_epi16(m0,m3,0x33);                    \
  buf = _mm_blend_epi16(t1,t0,0xC0);
#define LOAD_MSG_6_2(buf) t0 = _mm_blend_epi16(m3,m2,0x30); \
  t1 = _mm_srli_si128(m1, 4);                               \
  t2 = _mm_blend_epi16(t0,t1,0x03);                         \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,3,0));
#define LOAD_MSG_6_3(buf) t0 = _mm_unpacklo_epi64(m0,m2); \
  t1 = _mm_srli_si128(m1, 4);                             \
  t2 = _mm_blend_epi16(t0,t1,0x0C);                       \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(3,1,0,2));
#define LOAD_MSG_6_4(buf) t0 = _mm_unpackhi_epi32(m1,m2); \
  t1 = _mm_unpackhi_epi64(m0,t0);                         \
  buf = _mm_shuffle_epi32(t1, _MM_SHUFFLE(0,1,2,3));
#define LOAD_MSG_7_1(buf) t0 = _mm_unpackhi_epi32(m0,m1); \
  t1 = _mm_blend_epi16(t0,m3,0x0F);                       \
  buf = _mm_shuffle_epi32(t1,_MM_SHUFFLE(2,0,3,1));
#define LOAD_MSG_7_2(buf) t0 = _mm_blend_epi16(m2,m3,0x30); \
  t1 = _mm_srli_si128(m0,4);                                \
  t2 = _mm_blend_epi16(t0,t1,0x03);                         \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1,0,2,3));
#define LOAD_MSG_7_3(buf) t0 = _mm_unpackhi_epi64(m0,m3); \
  t1 = _mm_unpacklo_epi64(m1,m2);                         \
  t2 = _mm_blend_epi16(t0,t1,0x3C);                       \
  buf = _mm_shuffle_epi32(t2,_MM_SHUFFLE(2,3,1,0));
#define LOAD_MSG_7_4(buf) t0 = _mm_unpacklo_epi32(m0,m1); \
  t1 = _mm_unpackhi_epi32(m1,m2);                         \
  t2 = _mm_unpacklo_epi64(t0,t1);                         \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2,1,0,3));
#define LOAD_MSG_8_1(buf) t0 = _mm_unpackhi_epi32(m1,m3); \
  t1 = _mm_unpacklo_epi64(t0,m0);                         \
  t2 = _mm_blend_epi16(t1,m2,0xC0);                       \
  buf = _mm_shufflehi_epi16(t2,_MM_SHUFFLE(1,0,3,2));
#define LOAD_MSG_8_2(buf) t0 = _mm_unpackhi_epi32(m0,m3); \
  t1 = _mm_blend_epi16(m2,t0,0xF0);                       \
  buf = _mm_shuffle_epi32(t1,_MM_SHUFFLE(0,2,1,3));
#define LOAD_MSG_8_3(buf) t0 = _mm_unpacklo_epi64(m0,m3); \
  t1 = _mm_srli_si128(m2,8);                              \
  t2 = _mm_blend_epi16(t0,t1,0x03);                       \
  buf = _mm_shuffle_epi32(t2, _MM_SHUFFLE(1,3,2,0));
#define LOAD_MSG_8_4(buf) t0 = _mm_blend_epi16(m1,m0,0x30); \
  buf = _mm_shuffle_epi32(t0,_MM_SHUFFLE(0,3,2,1));
#define LOAD_MSG_9_1(buf) t0 = _mm_blend_epi16(m0,m2,0x03); \
  t1 = _mm_blend_epi16(m1,m2,0x30);                         \
  t2 = _mm_blend_epi16(t1,t0,0x0F);                         \
  buf = _mm_shuffle_epi32(t2,_MM_SHUFFLE(1,3,0,2));
#define LOAD_MSG_9_2(buf) t0 = _mm_slli_si128(m0,4); \
  t1 = _mm_blend_epi16(m1,t0,0xC0);                  \
  buf = _mm_shuffle_epi32(t1,_MM_SHUFFLE(1,2,0,3));
#define LOAD_MSG_9_3(buf) t0 = _mm_unpackhi_epi32(m0,m3); \
  t1 = _mm_unpacklo_epi32(m2,m3);                         \
  t2 = _mm_unpackhi_epi64(t0,t1);                         \
  buf = _mm_shuffle_epi32(t2,_MM_SHUFFLE(0,2,1,3));
#define LOAD_MSG_9_4(buf) t0 = _mm_blend_epi16(m3,m2,0xC0); \
  t1 = _mm_unpacklo_epi32(m0,m3);                           \
  t2 = _mm_blend_epi16(t0,t1,0x0F);                         \
  buf = _mm_shuffle_epi32(t2,_MM_SHUFFLE(1,2,3,0));

#else

  #define LOAD_MSG_0_1(buf) buf = _mm_set_epi32(m6 , m4 , m2 , m0 )
  #define LOAD_MSG_0_2(buf) buf = _mm_set_epi32(m7 , m5 , m3 , m1 )
  #define LOAD_MSG_0_3(buf) buf = _mm_set_epi32(m12, m10, m8 , m14)
  #define LOAD_MSG_0_4(buf) buf = _mm_set_epi32(m13, m11, m9 , m15)
  #define LOAD_MSG_1_1(buf) buf = _mm_set_epi32(m13, m9 , m4 , m14)
  #define LOAD_MSG_1_2(buf) buf = _mm_set_epi32(m6 , m15, m8 , m10)
  #define LOAD_MSG_1_3(buf) buf = _mm_set_epi32(m11, m0 , m1 , m5 )
  #define LOAD_MSG_1_4(buf) buf = _mm_set_epi32(m7 , m2 , m12, m3 )
  #define LOAD_MSG_2_1(buf) buf = _mm_set_epi32(m15, m5 , m12, m11)
  #define LOAD_MSG_2_2(buf) buf = _mm_set_epi32(m13, m2 , m0 , m8 )
  #define LOAD_MSG_2_3(buf) buf = _mm_set_epi32(m7 , m3 , m10, m9 )
  #define LOAD_MSG_2_4(buf) buf = _mm_set_epi32(m1 , m6 , m14, m4 )
  #define LOAD_MSG_3_1(buf) buf = _mm_set_epi32(m11, m13, m3 , m7 )
  #define LOAD_MSG_3_2(buf) buf = _mm_set_epi32(m14, m12, m1 , m9 )
  #define LOAD_MSG_3_3(buf) buf = _mm_set_epi32(m4 , m5 , m2 , m15)
  #define LOAD_MSG_3_4(buf) buf = _mm_set_epi32(m0 , m10, m6 , m8 )
  #define LOAD_MSG_4_1(buf) buf = _mm_set_epi32(m10, m2 , m5 , m9 )
  #define LOAD_MSG_4_2(buf) buf = _mm_set_epi32(m15, m4 , m7 , m0 )
  #define LOAD_MSG_4_3(buf) buf = _mm_set_epi32(m6 , m11, m14, m3 )
  #define LOAD_MSG_4_4(buf) buf = _mm_set_epi32(m8 , m12, m1 , m13)
  #define LOAD_MSG_5_1(buf) buf = _mm_set_epi32(m8 , m0 , m6 , m2 )
  #define LOAD_MSG_5_2(buf) buf = _mm_set_epi32(m3 , m11, m10, m12)
  #define LOAD_MSG_5_3(buf) buf = _mm_set_epi32(m15, m7 , m4 , m1 )
  #define LOAD_MSG_5_4(buf) buf = _mm_set_epi32(m14, m5 , m13, m9 )
  #define LOAD_MSG_6_1(buf) buf = _mm_set_epi32(m4 , m14, m1 , m12)
  #define LOAD_MSG_6_2(buf) buf = _mm_set_epi32(m10, m13, m15, m5 )
  #define LOAD_MSG_6_3(buf) buf = _mm_set_epi32(m9 , m6 , m0 , m8 )
  #define LOAD_MSG_6_4(buf) buf = _mm_set_epi32(m2 , m3 , m7 , m11)
  #define LOAD_MSG_7_1(buf) buf = _mm_set_epi32(m3 , m12, m7 , m13)
  #define LOAD_MSG_7_2(buf) buf = _mm_set_epi32(m9 , m1 , m14, m11)
  #define LOAD_MSG_7_3(buf) buf = _mm_set_epi32(m8 , m15, m5 , m2 )
  #define LOAD_MSG_7_4(buf) buf = _mm_set_epi32(m6 , m4 , m0 , m10)
  #define LOAD_MSG_8_1(buf) buf = _mm_set_epi32(m0 , m11, m14, m6 )
  #define LOAD_MSG_8_2(buf) buf = _mm_set_epi32(m8 , m3 , m9 , m15)
  #define LOAD_MSG_8_3(buf) buf = _mm_set_epi32(m1 , m13, m12, m10)
  #define LOAD_MSG_8_4(buf) buf = _mm_set_epi32(m4 , m7 , m2 , m5 )
  #define LOAD_MSG_9_1(buf) buf = _mm_set_epi32(m1 , m7 , m8 , m10)
  #define LOAD_MSG_9_2(buf) buf = _mm_set_epi32(m5 , m6 , m4 , m2 )
  #define LOAD_MSG_9_3(buf) buf = _mm_set_epi32(m3 , m9 , m15, m13)
  #define LOAD_MSG_9_4(buf) buf = _mm_set_epi32(m12, m14, m11, m0 )

#endif

#if defined(HAVE_SSSE_3) && !defined(HAVE_XOP)
  #undef _mm_roti_epi32
  #define _mm_roti_epi32(r, c) (                     \
                (8==-(c)) ? _mm_shuffle_epi8(r,r8)   \
              : (16==-(c)) ? _mm_shuffle_epi8(r,r16) \
              : _mm_xor_si128(_mm_srli_epi32( (r), -(c) ),_mm_slli_epi32( (r), 32-(-(c)) )) )
#elif !defined(HAVE_SSSE_3) && !defined(HAVE_XOP)
  #undef _mm_roti_epi32
  #define _mm_roti_epi32(r, c) _mm_xor_si128(_mm_srli_epi32((r), -(c)), _mm_slli_epi32((r), 32 - (-(c))))
#endif

#define G1(row1,row2,row3,row4,buf)                        \
  row1 = _mm_add_epi32( _mm_add_epi32( row1, buf), row2 ); \
  row4 = _mm_xor_si128( row4, row1 );                      \
  row4 = _mm_roti_epi32(row4, -16);                        \
  row3 = _mm_add_epi32( row3, row4 );                      \
  row2 = _mm_xor_si128( row2, row3 );                      \
  row2 = _mm_roti_epi32(row2, -12);

#define G2(row1,row2,row3,row4,buf)                        \
  row1 = _mm_add_epi32( _mm_add_epi32( row1, buf), row2 ); \
  row4 = _mm_xor_si128( row4, row1 );                      \
  row4 = _mm_roti_epi32(row4, -8);                         \
  row3 = _mm_add_epi32( row3, row4 );                      \
  row2 = _mm_xor_si128( row2, row3 );                      \
  row2 = _mm_roti_epi32(row2, -7);

#define DIAGONALIZE(row1,row2,row3,row4)                  \
  row1 = _mm_shuffle_epi32( row1, _MM_SHUFFLE(2,1,0,3) ); \
  row4 = _mm_shuffle_epi32( row4, _MM_SHUFFLE(1,0,3,2) ); \
  row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE(0,3,2,1) );

#define UNDIAGONALIZE(row1,row2,row3,row4)                \
  row1 = _mm_shuffle_epi32( row1, _MM_SHUFFLE(0,3,2,1) ); \
  row4 = _mm_shuffle_epi32( row4, _MM_SHUFFLE(1,0,3,2) ); \
  row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE(2,1,0,3) );

#define ROUND(r)                      \
  LOAD_MSG_ ##r ##_1(buf1);           \
  G1(row1,row2,row3,row4,buf1);       \
  LOAD_MSG_ ##r ##_2(buf2);           \
  G2(row1,row2,row3,row4,buf2);       \
  DIAGONALIZE(row1,row2,row3,row4);   \
  LOAD_MSG_ ##r ##_3(buf3);           \
  G1(row1,row2,row3,row4,buf3);       \
  LOAD_MSG_ ##r ##_4(buf4);           \
  G2(row1,row2,row3,row4,buf4);       \
  UNDIAGONALIZE(row1,row2,row3,row4); \

template <bool bswap>
static void blake2_compress( blake2s_context * ctx, const uint8_t * in ) {
    __m128i row1, row2, row3, row4;
    __m128i buf1, buf2, buf3, buf4;
    __m128i t0, t1, t2;
    __m128i ff0, ff1;

    const __m128i r8  = _mm_set_epi8(12, 15, 14, 13, 8, 11, 10,  9, 4, 7, 6, 5, 0, 3, 2, 1);
    const __m128i r16 = _mm_set_epi8(13, 12, 15, 14, 9,  8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);

#if defined(HAVE_XOP) || defined(HAVE_SSE_4_1)
    const __m128i m0  = bswap ? mm_bswap32(LOADU(in + 00)) : LOADU(in + 00);
    const __m128i m1  = bswap ? mm_bswap32(LOADU(in + 16)) : LOADU(in + 16);
    const __m128i m2  = bswap ? mm_bswap32(LOADU(in + 32)) : LOADU(in + 32);
    const __m128i m3  = bswap ? mm_bswap32(LOADU(in + 48)) : LOADU(in + 48);
#else
    const uint32_t m0 =  GET_U32<bswap>(in,  0), m1  = GET_U32<bswap>(in,  4);
    const uint32_t m2  = GET_U32<bswap>(in,  8), m3  = GET_U32<bswap>(in, 12);
    const uint32_t m4  = GET_U32<bswap>(in, 16), m5  = GET_U32<bswap>(in, 20);
    const uint32_t m6  = GET_U32<bswap>(in, 24), m7  = GET_U32<bswap>(in, 28);
    const uint32_t m8  = GET_U32<bswap>(in, 32), m9  = GET_U32<bswap>(in, 36);
    const uint32_t m10 = GET_U32<bswap>(in, 40), m11 = GET_U32<bswap>(in, 44);
    const uint32_t m12 = GET_U32<bswap>(in, 48), m13 = GET_U32<bswap>(in, 52);
    const uint32_t m14 = GET_U32<bswap>(in, 56), m15 = GET_U32<bswap>(in, 60);
#endif

    row1 = ff0 = LOADU(&ctx->h[0]);
    row2 = ff1 = LOADU(&ctx->h[4]);
    row3 = _mm_loadu_si128((__m128i const *)&blake2s_IV[0]);
    row4 = _mm_xor_si128(_mm_loadu_si128((__m128i const *)&blake2s_IV[4]), LOADU(&ctx->t[0]));

    ROUND(0);
    ROUND(1);
    ROUND(2);
    ROUND(3);
    ROUND(4);
    ROUND(5);
    ROUND(6);
    ROUND(7);
    ROUND(8);
    ROUND(9);

    STOREU(&ctx->h[0], _mm_xor_si128(ff0, _mm_xor_si128(row1, row3)));
    STOREU(&ctx->h[4], _mm_xor_si128(ff1, _mm_xor_si128(row2, row4)));
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
