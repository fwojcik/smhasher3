/*
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (C) 2012-2021 Yann Collet
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#pragma once

#if defined(HAVE_X86INTRIN)
  #include <x86intrin.h>
#elif defined(HAVE_AMMINTRIN)
  #include <ammintrin.h>
#elif defined(HAVE_IMMINTRIN)
  #include <immintrin.h>
#endif

#if defined(HAVE_ARM_NEON)
/* circumvent a clang bug */
  #if defined(__GNUC__) || defined(__clang__)
    #if defined(__ARM_NEON__) || defined(__ARM_NEON) || \
        defined(__aarch64__)  || defined(_M_ARM)     || \
        defined(_M_ARM64)     || defined(_M_ARM64EC)
      #define inline __inline__
    #endif
  #endif
  #include <arm_neon.h>
  #if defined(__GNUC__) || defined(__clang__)
    #if defined(__ARM_NEON__) || defined(__ARM_NEON) || \
        defined(__aarch64__)  || defined(_M_ARM)     || \
        defined(_M_ARM64)     || defined(_M_ARM64EC)
      #undef inline
    #endif
  #endif
  #if defined(HAVE_ARM_ACLE)
    #include <arm_acle.h>
  #endif
#endif


#if defined(HAVE_PPC_VSX)
/*
 * Annoyingly, these headers _may_ define three macros: `bool`,
 * `vector`, and `pixel`. This is a problem for obvious reasons.
 *
 * These keywords are unnecessary; the spec literally says they are
 * equivalent to `__bool`, `__vector`, and `__pixel` and may be
 * undef'd after including the header.
 *
 * We use pragma push_macro/pop_macro to keep the namespace clean.
 */
  #pragma push_macro("bool")
  #pragma push_macro("vector")
  #pragma push_macro("pixel")
/* silence potential macro redefined warnings */
  #undef bool
  #undef vector
  #undef pixel

  #if defined(__s390x__)
    #include <s390intrin.h>
  #else
    #include <altivec.h>
  #endif

/* Restore the original macro values, if applicable. */
  #pragma pop_macro("pixel")
  #pragma pop_macro("vector")
  #pragma pop_macro("bool")

  #if defined(__ibmxl__) || (defined(_AIX) && defined(__xlC__))
typedef  __vector unsigned char vec_t;
    #define vec_encrypt(a, b) __vcipher(a, b);
    #define vec_encryptlast(a, b) __vcipherlast(a, b);
    #define vec_decrypt(a, b) __vncipher(a, b);
    #define vec_encryptlast(a, b) __vncipherlast(a, b);
  #elif defined(__clang__)
typedef  __vector unsigned long long vec_t;
    #define vec_encrypt(a, b) __builtin_altivec_crypto_vcipher(a, b);
    #define vec_encryptlast(a, b) __builtin_altivec_crypto_vcipherlast(a, b);
    #define vec_decrypt(a, b) __builtin_altivec_crypto_vncipher(a, b);
    #define vec_decryptlast(a, b) __builtin_altivec_crypto_vncipherlast(a, b);
  #elif defined(__GNUC__)
typedef  __vector unsigned long long vec_t;
    #define vec_encrypt(a, b) __builtin_crypto_vcipher(a, b);
    #define vec_encryptlast(a, b) __builtin_crypto_vcipherlast(a, b);
    #define vec_decrypt(a, b) __builtin_crypto_vncipher(a, b);
    #define vec_decryptlast(a, b) __builtin_crypto_vncipherlast(a, b);
  #else
    #error "PPC AES intrinsic mapping unimplemented"
  #endif
#endif

//-----------------------------------------------------------------------------
// Fallback versions of loadu intrinsics

#if defined(HAVE_SSE_2)
  #if !defined(HAVE_GOOD_LOADU_64)
static FORCE_INLINE __m128i _mm_loadu_si64( const void * ptr ) {
    uint64_t val;
    memcpy(&val, ptr, sizeof(uint64_t));
    return _mm_cvtsi64_si128(val);
}
  #endif
  #if !defined(HAVE_GOOD_LOADU_32)
static FORCE_INLINE __m128i _mm_loadu_si32( const void * ptr ) {
    uint32_t val;
    memcpy(&val, ptr, sizeof(uint32_t));
    return _mm_cvtsi32_si128(val);
}
static FORCE_INLINE __m128i _mm_loadu_si16( const void * ptr ) {
    uint16_t val;
    memcpy(&val, ptr, sizeof(uint16_t));
    return _mm_cvtsi32_si128(val);
}
  #endif
#endif

//------------------------------------------------------------
// Make prefetch() use intrinsic support, if available
// This is helpful for MSVC, which doesn't have a usable
// prefetch() implementation without this.

#if defined(HAVE_SSE_2)
  #undef prefetch
  #define prefetch(x) _mm_prefetch((const char*)(x), _MM_HINT_T0)
#endif

//------------------------------------------------------------
// Vectorized byteswapping

#if defined(HAVE_ARM_NEON)

static FORCE_INLINE uint64x2_t Vbswap64_u64( const uint64x2_t v ) {
    return vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(v)));
}

static FORCE_INLINE uint32x4_t Vbswap32_u32( const uint32x4_t v ) {
    return vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(v)));
}

#endif

#if defined(HAVE_AVX512_BW)

static FORCE_INLINE __m512i mm512_bswap64( const __m512i v ) {
    const __m512i MASK = _mm512_set_epi64(UINT64_C(0x08090a0b0c0d0e0f), UINT64_C(0x0001020304050607),
            UINT64_C(0x08090a0b0c0d0e0f), UINT64_C(0x0001020304050607), UINT64_C(0x08090a0b0c0d0e0f),
            UINT64_C(0x0001020304050607), UINT64_C(0x08090a0b0c0d0e0f), UINT64_C(0x0001020304050607));

    return _mm512_shuffle_epi8(v, MASK);
}

static FORCE_INLINE __m512i mm512_bswap32( const __m512i v ) {
    const __m512i MASK = _mm512_set_epi64(UINT64_C(0x0c0d0e0f08090a0b), UINT64_C(0x0405060700010203),
            UINT64_C(0x0c0d0e0f08090a0b), UINT64_C(0x0405060700010203), UINT64_C(0x0c0d0e0f08090a0b),
            UINT64_C(0x0405060700010203), UINT64_C(0x0c0d0e0f08090a0b), UINT64_C(0x0405060700010203));

    return _mm512_shuffle_epi8(v, MASK);
}

#elif defined(HAVE_AVX512_F)

static FORCE_INLINE __m512i mm512_bswap64( const __m512i v ) {
    // Byteswapping 256 bits at a time, since _mm512_shuffle_epi8()
    // requires AVX512-BW in addition to AVX512-F.
    const __m256i MASK = _mm256_set_epi64x(UINT64_C(0x08090a0b0c0d0e0f), UINT64_C(0x0001020304050607),
            UINT64_C(0x08090a0b0c0d0e0f), UINT64_C(0x0001020304050607));
    __m256i blk1       = _mm512_extracti64x4_epi64(v, 0);
    __m256i blk2       = _mm512_extracti64x4_epi64(v, 1);

    blk1 = _mm256_shuffle_epi8(blk1, MASK);
    blk2 = _mm256_shuffle_epi8(blk2, MASK);
    v    = _mm512_inserti64x4(v, blk1, 0);
    v    = _mm512_inserti64x4(v, blk2, 1);
    return v;
}

static FORCE_INLINE __m512i mm512_bswap64( const __m512i v ) {
    // Byteswapping 256 bits at a time, since _mm512_shuffle_epi8()
    // requires AVX512-BW in addition to AVX512-F.
    const __m256i MASK = _mm256_set_epi64x(UINT64_C(0x0c0d0e0f08090a0b), UINT64_C(0x0405060700010203),
            UINT64_C(0x0c0d0e0f08090a0b), UINT64_C(0x0405060700010203));
    __m256i blk1       = _mm512_extracti64x4_epi64(v, 0);
    __m256i blk2       = _mm512_extracti64x4_epi64(v, 1);

    blk1 = _mm256_shuffle_epi8(blk1, MASK);
    blk2 = _mm256_shuffle_epi8(blk2, MASK);
    v    = _mm512_inserti64x4(v, blk1, 0);
    v    = _mm512_inserti64x4(v, blk2, 1);
    return v;
}

#endif

#if defined(HAVE_AVX2)

static FORCE_INLINE __m256i mm256_bswap64( const __m256i v ) {
    const __m256i MASK = _mm256_set_epi64x(UINT64_C(0x08090a0b0c0d0e0f), UINT64_C(0x0001020304050607),
            UINT64_C(0x08090a0b0c0d0e0f), UINT64_C(0x0001020304050607));

    return _mm256_shuffle_epi8(v, MASK);
}

static FORCE_INLINE __m256i mm256_bswap32( const __m256i v ) {
    const __m256i MASK = _mm256_set_epi64x(UINT64_C(0x0c0d0e0f08090a0b), UINT64_C(0x0405060700010203),
            UINT64_C(0x0c0d0e0f08090a0b), UINT64_C(0x0405060700010203));

    return _mm256_shuffle_epi8(v, MASK);
}

#endif

#if defined(HAVE_SSSE_3)

static FORCE_INLINE __m128i mm_bswap64( const __m128i v ) {
    const __m128i MASK = _mm_set_epi64x(UINT64_C(0x08090a0b0c0d0e0f), UINT64_C(0x0001020304050607));

    return _mm_shuffle_epi8(v, MASK);
}

static FORCE_INLINE __m128i mm_bswap32( const __m128i v ) {
    const __m128i MASK = _mm_set_epi64x(UINT64_C(0x0c0d0e0f08090a0b), UINT64_C(0x0405060700010203));

    return _mm_shuffle_epi8(v, MASK);
}

#elif defined(HAVE_SSE_2)

static FORCE_INLINE __m128i mm_bswap64( const __m128i v ) {
    // Swap each pair of bytes
    __m128i tmp = _mm_or_si128(_mm_srli_epi16(v, 8), _mm_slli_epi16(v, 8));

    // Swap 16-bit words
    tmp = _mm_shufflelo_epi16(tmp, _MM_SHUFFLE(0, 1, 2, 3));
    tmp = _mm_shufflehi_epi16(tmp, _MM_SHUFFLE(0, 1, 2, 3));
}

static FORCE_INLINE __m128i mm_bswap32( const __m128i v ) {
    // Swap each pair of bytes
    __m128i tmp = _mm_or_si128(_mm_srli_epi16(v, 8), _mm_slli_epi16(v, 8));

    // Swap 16-bit words
    tmp = _mm_shufflelo_epi16(tmp, _MM_SHUFFLE(2, 3, 0, 1));
    tmp = _mm_shufflehi_epi16(tmp, _MM_SHUFFLE(2, 3, 0, 1));
}

#endif
