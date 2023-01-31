/*
 * XXH3 SSE2-specific code
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
 *
 * You can contact the author at:
 *   - xxHash homepage: https://www.xxhash.com
 *   - xxHash source repository: https://github.com/Cyan4973/xxHash
 */
template <bool bswap>
static FORCE_INLINE void XXH3_accumulate_512_sse2( void * RESTRICT acc, const void * RESTRICT input,
        const void * RESTRICT secret ) {
    XXH_ASSERT((((size_t)acc) & 15) == 0);
    /* SSE2 is just a half-scale version of the AVX2 version. */
    __m128i       * const xacc    = (__m128i *      )acc;
    /*
     * Unaligned. This is mainly for pointer arithmetic, and because
     * _mm_loadu_si128 requires a const __m128i * pointer for some reason.
     */
    const __m128i * const xinput  = (const __m128i *)input;
    /*
     * Unaligned. This is mainly for pointer arithmetic, and because
     * _mm_loadu_si128 requires a const __m128i * pointer for some reason.
     */
    const __m128i * const xsecret = (const __m128i *)secret;

    for (size_t i = 0; i < XXH_STRIPE_LEN / sizeof(__m128i); i++) {
        /* data_vec    = xinput[i]; */
        __m128i const data_vec = bswap ?
                    mm_bswap64(_mm_loadu_si128(xinput + i)) :
                    _mm_loadu_si128(xinput + i);
        /* key_vec     = xsecret[i]; */
        __m128i const key_vec = bswap ?
                    mm_bswap64(_mm_loadu_si128(xsecret + i)) :
                    _mm_loadu_si128(xsecret + i);
        /* data_key    = data_vec ^ key_vec; */
        __m128i const data_key    = _mm_xor_si128(data_vec, key_vec);
        /* data_key_lo = data_key >> 32; */
        __m128i const data_key_lo = _mm_shuffle_epi32(data_key, _MM_SHUFFLE(0, 3, 0, 1));
        /* product     = (data_key & 0xffffffff) * (data_key_lo & 0xffffffff); */
        __m128i const product     = _mm_mul_epu32(data_key, data_key_lo);
        /* xacc[i] += swap(data_vec); */
        __m128i const data_swap   = _mm_shuffle_epi32(data_vec, _MM_SHUFFLE(1, 0, 3, 2));
        __m128i const sum         = _mm_add_epi64(xacc[i], data_swap);
        /* xacc[i] += product; */
        xacc[i] = _mm_add_epi64(product, sum);
    }
}

template <bool bswap>
static FORCE_INLINE void XXH3_scrambleAcc_sse2( void * RESTRICT acc, const void * RESTRICT secret ) {
    XXH_ASSERT((((size_t)acc) & 15) == 0);
    __m128i       * const xacc    = (__m128i *      )acc;
    /*
     * Unaligned. This is mainly for pointer arithmetic, and because
     * _mm_loadu_si128 requires a const __m128i * pointer for some reason.
     */
    const __m128i * const xsecret = (const __m128i *)secret;
    const __m128i         prime32 = _mm_set1_epi32((int)XXH_PRIME32_1);

    for (size_t i = 0; i < XXH_STRIPE_LEN / sizeof(__m128i); i++) {
        /* xacc[i] ^= (xacc[i] >> 47) */
        __m128i const acc_vec  = xacc[i];
        __m128i const shifted  = _mm_srli_epi64(acc_vec, 47);
        __m128i const data_vec = _mm_xor_si128(acc_vec , shifted);
        /* xacc[i] ^= xsecret[i]; */
        __m128i const key_vec  = bswap ?
                    mm_bswap64(_mm_loadu_si128(xsecret + i)) :
                    _mm_loadu_si128(xsecret + i);
        __m128i const data_key = _mm_xor_si128(data_vec, key_vec);

        /* xacc[i] *= XXH_PRIME32_1; */
        __m128i const data_key_hi = _mm_shuffle_epi32(data_key, _MM_SHUFFLE(0, 3, 0, 1));
        __m128i const prod_lo     = _mm_mul_epu32(data_key   , prime32);
        __m128i const prod_hi     = _mm_mul_epu32(data_key_hi, prime32);
        xacc[i] = _mm_add_epi64(prod_lo, _mm_slli_epi64(prod_hi, 32));
    }
}

/*
 * On GCC & Clang, marking 'dest' as modified will cause the compiler to:
 *   - not extract the secret from sse registers in the internal loop
 *   - use less common registers, and avoid pushing these reg into stack
 */
template <bool bswap>
static FORCE_INLINE void XXH3_initCustomSecret_sse2( void * RESTRICT customSecret, uint64_t seed64 ) {
    int const nbRounds = XXH3_SECRET_DEFAULT_SIZE / sizeof(__m128i);

    /* MSVC 32bit mode does not support _mm_set_epi64x before 2015 */
#if defined(_MSC_VER) && defined(_M_IX86) && _MSC_VER < 1900
    alignas(16) const uint64_t seed64x2[2] = {
        (uint64_t)seed64, (uint64_t)(UINT64_C(0) - seed64)
    };
    __m128i const seed       = _mm_load_si128((__m128i const *)seed64x2);
#else
    __m128i const seed       = _mm_set_epi64x((uint64_t)(UINT64_C(0) - seed64), (uint64_t)seed64);
#endif
    const void * const src16 = XXH3_kSecret;
    __m128i *          dst16 = (__m128i *)customSecret;

#if defined(__GNUC__) || defined(__clang__)
    XXH_COMPILER_GUARD(dst16);
#endif
    XXH_ASSERT(((size_t)src16 & 15) == 0); /* control alignment */
    XXH_ASSERT(((size_t)dst16 & 15) == 0);

    for (int i = 0; i < nbRounds; ++i) {
        if (bswap) {
            dst16[i] = mm_bswap64(_mm_add_epi64(mm_bswap64(_mm_load_si128((const __m128i *)src16 + i)), seed));
        } else {
            dst16[i] = _mm_add_epi64(_mm_load_si128((const __m128i *)src16 + i), seed);
        }
    }
}
