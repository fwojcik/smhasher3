/*
 * XXH3 AVX2-specific code
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
static FORCE_INLINE void XXH3_accumulate_512_avx2( void * RESTRICT acc, const void * RESTRICT input,
        const void * RESTRICT secret ) {
    XXH_ASSERT((((size_t)acc) & 31) == 0);
    __m256i       * const xacc    = (__m256i *      )acc;
    /*
     * Unaligned. This is mainly for pointer arithmetic, and because
     * _mm256_loadu_si256 requires  a const __m256i * pointer for some reason.
     */
    const __m256i * const xinput  = (const __m256i *)input;
    /*
     * Unaligned. This is mainly for pointer arithmetic, and because
     * _mm256_loadu_si256 requires a const __m256i * pointer for some reason.
     */
    const __m256i * const xsecret = (const __m256i *)secret;

    for (size_t i = 0; i < XXH_STRIPE_LEN / sizeof(__m256i); i++) {
        /* data_vec    = xinput[i]; */
        __m256i const data_vec = bswap ?
                    mm256_bswap64(_mm256_loadu_si256(xinput + i)) :
                    _mm256_loadu_si256(xinput + i);
        /* key_vec     = xsecret[i]; */
        __m256i const key_vec = bswap ?
                    mm256_bswap64(_mm256_loadu_si256(xsecret + i)) :
                    _mm256_loadu_si256(xsecret + i);
        /* data_key    = data_vec ^ key_vec; */
        __m256i const data_key    = _mm256_xor_si256(data_vec, key_vec);
        /* data_key_lo = data_key >> 32; */
        __m256i const data_key_lo = _mm256_srli_epi64(data_key, 32);
        /* product     = (data_key & 0xffffffff) * (data_key_lo & 0xffffffff); */
        __m256i const product     = _mm256_mul_epu32(data_key, data_key_lo);
        /* xacc[i] += swap(data_vec); */
        __m256i const data_swap   = _mm256_shuffle_epi32(data_vec, _MM_SHUFFLE(1, 0, 3, 2));
        __m256i const sum         = _mm256_add_epi64(xacc[i], data_swap);
        /* xacc[i] += product; */
        xacc[i] = _mm256_add_epi64(product, sum);
    }
}

template <bool bswap>
static FORCE_INLINE void XXH3_scrambleAcc_avx2( void * RESTRICT acc, const void * RESTRICT secret ) {
    XXH_ASSERT((((size_t)acc) & 31) == 0);
    __m256i       * const xacc    = (__m256i *      )acc;
    /*
     * Unaligned. This is mainly for pointer arithmetic, and because
     * _mm256_loadu_si256 requires a const __m256i * pointer for some reason.
     */
    const __m256i * const xsecret = (const __m256i *)secret;
    const __m256i         prime32 = _mm256_set1_epi32((int)XXH_PRIME32_1);

    for (size_t i = 0; i < XXH_STRIPE_LEN / sizeof(__m256i); i++) {
        /* xacc[i] ^= (xacc[i] >> 47) */
        __m256i const acc_vec  = xacc[i];
        __m256i const shifted  = _mm256_srli_epi64(acc_vec, 47);
        __m256i const data_vec = _mm256_xor_si256(acc_vec , shifted);
        /* xacc[i] ^= xsecret; */
        __m256i const key_vec  = bswap ?
                    mm256_bswap64(_mm256_loadu_si256(xsecret + i)) :
                    _mm256_loadu_si256(xsecret + i);
        __m256i const data_key = _mm256_xor_si256(data_vec, key_vec);

        /* xacc[i] *= XXH_PRIME32_1; */
        __m256i const data_key_hi = _mm256_srli_epi64(data_key, 32);
        __m256i const prod_lo     = _mm256_mul_epu32(data_key   , prime32);
        __m256i const prod_hi     = _mm256_mul_epu32(data_key_hi, prime32);
        xacc[i] = _mm256_add_epi64(prod_lo, _mm256_slli_epi64(prod_hi, 32));
    }
}

/*
 * On GCC & Clang, marking 'dest' as modified will cause the compiler to:
 *   - not extract the secret from sse registers in the internal loop
 *   - use less common registers, and avoid pushing these reg into stack
 */
template <bool bswap>
static FORCE_INLINE void XXH3_initCustomSecret_avx2( void * RESTRICT customSecret, uint64_t seed64 ) {
    _mm_prefetch((const char *)customSecret, _MM_HINT_T0);
    __m256i const seed = _mm256_set_epi64x((int64_t)(UINT64_C(0) - seed64), (int64_t)seed64,
            (int64_t)(UINT64_C(0) - seed64), (int64_t)seed64);

    const __m256i * const src = (const __m256i *)((const void *)XXH3_kSecret);
    __m256i       * dest =      (__m256i *      )customSecret;

#if defined(__GNUC__) || defined(__clang__)
    XXH_COMPILER_GUARD(dest);
#endif
    XXH_ASSERT(((size_t)src & 31) == 0); /* control alignment */
    XXH_ASSERT(((size_t)dest & 31) == 0);

    /* GCC -O2 need unroll loop manually */
    if (bswap) {
        dest[0] = mm256_bswap64(_mm256_add_epi64(mm256_bswap64(_mm256_load_si256(src + 0)), seed));
        dest[1] = mm256_bswap64(_mm256_add_epi64(mm256_bswap64(_mm256_load_si256(src + 1)), seed));
        dest[2] = mm256_bswap64(_mm256_add_epi64(mm256_bswap64(_mm256_load_si256(src + 2)), seed));
        dest[3] = mm256_bswap64(_mm256_add_epi64(mm256_bswap64(_mm256_load_si256(src + 3)), seed));
        dest[4] = mm256_bswap64(_mm256_add_epi64(mm256_bswap64(_mm256_load_si256(src + 4)), seed));
        dest[5] = mm256_bswap64(_mm256_add_epi64(mm256_bswap64(_mm256_load_si256(src + 5)), seed));
    } else {
        dest[0] = _mm256_add_epi64(_mm256_load_si256(src + 0), seed);
        dest[1] = _mm256_add_epi64(_mm256_load_si256(src + 1), seed);
        dest[2] = _mm256_add_epi64(_mm256_load_si256(src + 2), seed);
        dest[3] = _mm256_add_epi64(_mm256_load_si256(src + 3), seed);
        dest[4] = _mm256_add_epi64(_mm256_load_si256(src + 4), seed);
        dest[5] = _mm256_add_epi64(_mm256_load_si256(src + 5), seed);
    }
}
