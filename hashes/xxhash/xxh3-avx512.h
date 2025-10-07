/*
 * XXH3 AVX-512-specific code
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
static FORCE_INLINE void XXH3_accumulate_512_avx512( void * RESTRICT acc,
        const void * RESTRICT input, const void * RESTRICT secret ) {
    XXH_ASSERT((((size_t)acc) & 63) == 0);
    __m512i * const xacc   = (__m512i *)acc;
    /* data_vec    = input[0]; */
    __m512i const data_vec = bswap ?
                mm512_bswap64(_mm512_loadu_si512(input))  :
                _mm512_loadu_si512(input);
    /* key_vec     = secret[0]; */
    __m512i const key_vec = bswap ?
                mm512_bswap64(_mm512_loadu_si512(secret))  :
                _mm512_loadu_si512(secret);
    /* data_key    = data_vec ^ key_vec; */
    __m512i const data_key    = _mm512_xor_si512(data_vec, key_vec);
    /* data_key_lo = data_key >> 32; */
    __m512i const data_key_lo = _mm512_srli_epi64(data_key, 32);
    /* product     = (data_key & 0xffffffff) * (data_key_lo & 0xffffffff); */
    __m512i const product     = _mm512_mul_epu32(data_key, data_key_lo);
    /* xacc[0] += swap(data_vec); */
    __m512i const data_swap   = _mm512_shuffle_epi32(data_vec, (_MM_PERM_ENUM)_MM_SHUFFLE(1, 0, 3, 2));
    __m512i const sum         = _mm512_add_epi64(*xacc, data_swap);

    /* xacc[0] += product; */
    *xacc = _mm512_add_epi64(product, sum);
}

template <bool bswap>
static FORCE_INLINE void XXH3_scrambleAcc_avx512( void * RESTRICT acc, const void * RESTRICT secret ) {
    XXH_ASSERT((((size_t)acc) & 63) == 0);
    __m512i * const xacc    = (__m512i *)acc;
    const __m512i   prime32 = _mm512_set1_epi32((int)XXH_PRIME32_1);

    /* xacc[0] ^= (xacc[0] >> 47) */
    __m512i const acc_vec = *xacc;
    __m512i const shifted = _mm512_srli_epi64(acc_vec, 47);
    /* xacc[0] ^= secret; */
    __m512i const key_vec = bswap ?
                mm512_bswap64(_mm512_loadu_si512(secret))  :
                _mm512_loadu_si512(secret);
    /* 0x96 == key_vec ^ acc_vec ^ shifted */
    __m512i const data_key = _mm512_ternarylogic_epi32(key_vec, acc_vec, shifted, 0x96);

    /* xacc[0] *= XXH_PRIME32_1; */
    __m512i const data_key_hi = _mm512_srli_epi64(data_key, 32);
    __m512i const prod_lo     = _mm512_mul_epu32(data_key   , prime32);
    __m512i const prod_hi     = _mm512_mul_epu32(data_key_hi, prime32);

    *xacc = _mm512_add_epi64(prod_lo, _mm512_slli_epi64(prod_hi, 32));
}

// GCC has a bug, _mm512_stream_load_si512 accepts 'void*', not 'void
// const*', this will warn "discards 'const' qualifier".
//
// fwojcik: Make this GCC-only, since it explicitly supports
// union-based type punning, which is otherwise Undefined Behavior
template <bool bswap>
static FORCE_INLINE void XXH3_initCustomSecret_avx512( void * RESTRICT customSecret, uint64_t seed64 ) {
    XXH_ASSERT(((size_t)customSecret & 63) == 0);
    int const     nbRounds     = XXH3_SECRET_DEFAULT_SIZE / sizeof(__m512i);
    __m512i const seed_pos     = _mm512_set1_epi64((int64_t)seed64);
    __m512i const seed         = _mm512_mask_sub_epi64(seed_pos, 0xAA, _mm512_set1_epi8(0), seed_pos);

    const __m512i * const src  = (const __m512i *)((const void *)XXH3_kSecret);
    __m512i       * const dest = (__m512i *      )customSecret;

    XXH_ASSERT(((size_t)src & 63) == 0); /* control alignment */
    XXH_ASSERT(((size_t)dest & 63) == 0);
    for (int i = 0; i < nbRounds; ++i) {
        if (bswap) {
            dest[i] = mm512_bswap64(_mm512_add_epi64(mm512_bswap64(_mm512_load_si512(src + i)), seed));
        } else {
            dest[i] = _mm512_add_epi64(_mm512_load_si512(src + i), seed);
        }
    }
}
