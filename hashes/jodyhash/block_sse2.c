/*
 * Jody Bruchon's fast hashing algorithm
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (c) 2014-2023 Jody Bruchon
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

template <typename T, bool bswap>
static size_t jody_block_hash_simd( const uint8_t * data, T * hash, const size_t count ) {
    __m128i         v1, v2, v3, v4, v5, v6;
    __m128          vzero;
    __m128i         vec_const, vec_ror2;
    const __m128i * vec_data = (const __m128i *)data;

    /* Constants preload */
    vec_const = _mm_set1_epi64x(JODY_HASH_CONSTANT);
    vec_ror2  = _mm_set1_epi64x(ROTR64(JODY_HASH_CONSTANT, JH_SHIFT2));
    vzero     = _mm_setzero_ps();

    for (size_t i = 0; i < 2 * (count / 32); i++) {
        v1 = _mm_loadu_si128(&vec_data[i]);
        v3 = _mm_loadu_si128(&vec_data[i]);
        if (bswap) {
            v1 = mm_bswap64(v1);
            v3 = mm_bswap64(v3);
        }
        i++;
        v4 = _mm_loadu_si128(&vec_data[i]);
        v6 = _mm_loadu_si128(&vec_data[i]);
        if (bswap) {
            v4 = mm_bswap64(v4);
            v6 = mm_bswap64(v6);
        }

        /* "element2" gets RORed (two logical shifts ORed together) */
        v1 = _mm_srli_epi64(v1, JODY_HASH_SHIFT);
        v2 = _mm_slli_epi64(v3, (64 - JODY_HASH_SHIFT));
        v1 = _mm_or_si128(v1, v2);
        v1 = _mm_xor_si128(v1, vec_ror2); // XOR against the ROR2 constant
        v4 = _mm_srli_epi64(v4, JODY_HASH_SHIFT);
        v5 = _mm_slli_epi64(v6, (64 - JODY_HASH_SHIFT));
        v4 = _mm_or_si128(v4, v5);
        v4 = _mm_xor_si128(v4, vec_ror2); // XOR against the ROR2 constant

        /* Add the constant to "element" */
        v3 = _mm_add_epi64(v3, vec_const);
        v6 = _mm_add_epi64(v6, vec_const);

        /* Perform the rest of the hash */
        for (int j = 0; j < 4; j++) {
            uint64_t ep1, ep2;
            switch (j) {
            default:
            case 0:
                    /* Lower v1-v3 */
                    ep1 = (uint64_t)_mm_cvtsi128_si64(v3);
                    ep2 = (uint64_t)_mm_cvtsi128_si64(v1);
                    break;

            case 1:
                    /* Upper v1-v3 */
                    ep1 = (uint64_t)_mm_cvtsi128_si64(_mm_castps_si128(_mm_movehl_ps(vzero, _mm_castsi128_ps(v3))));
                    ep2 = (uint64_t)_mm_cvtsi128_si64(_mm_castps_si128(_mm_movehl_ps(vzero, _mm_castsi128_ps(v1))));
                    break;

            case 2:
                    /* Lower v4-v6 */
                    ep1 = (uint64_t)_mm_cvtsi128_si64(v6);
                    ep2 = (uint64_t)_mm_cvtsi128_si64(v4);
                    break;

            case 3:
                    /* Upper v4-v6 */
                    ep1 = (uint64_t)_mm_cvtsi128_si64(_mm_castps_si128(_mm_movehl_ps(vzero, _mm_castsi128_ps(v6))));
                    ep2 = (uint64_t)_mm_cvtsi128_si64(_mm_castps_si128(_mm_movehl_ps(vzero, _mm_castsi128_ps(v4))));
                    break;
            }
            *hash += ep1;
            *hash ^= ep2;
            *hash  = JH_ROL(*hash, JH_SHIFT2);
            *hash += ep1;
        }      // End of hash finish loop
    }      // End of main SSE for loop

    return count & ~(size_t)31;
}
