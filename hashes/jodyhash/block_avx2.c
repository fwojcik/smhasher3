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
    /* Regs used in groups of 3; 1=ROR/XOR work, 2=temp, 3=data+constant */
    __m256i         vx1, vx2, vx3;
    __m256i         avx_const, avx_ror2;
    const __m256i * vec_data = (const __m256i *)data;

    /* Constants preload */
    avx_const = _mm256_set1_epi64x(JODY_HASH_CONSTANT);
    avx_ror2  = _mm256_set1_epi64x(ROTR64(JODY_HASH_CONSTANT, JH_SHIFT2));

    for (size_t i = 0; i < (count / 32); i++) {
        vx1 = _mm256_loadu_si256(&vec_data[i]);
        vx3 = _mm256_loadu_si256(&vec_data[i]);
        if (bswap) {
            vx1 = mm256_bswap64(vx1);
            vx3 = mm256_bswap64(vx3);
        }

        /* "element2" gets RORed (two logical shifts ORed together) */
        vx1 = _mm256_srli_epi64(vx1, JODY_HASH_SHIFT);
        vx2 = _mm256_slli_epi64(vx3, (64 - JODY_HASH_SHIFT));
        vx1 = _mm256_or_si256(vx1, vx2);
        vx1 = _mm256_xor_si256(vx1, avx_ror2); // XOR against the ROR2 constant

        /* Add the constant to "element" */
        vx3 = _mm256_add_epi64(vx3, avx_const);

        /* Perform the rest of the hash */
        for (int j = 0; j < 4; j++) {
            uint64_t ep1, ep2;
            switch (j) {
            default:
            case 0:
                    ep1 = (uint64_t)_mm256_extract_epi64(vx3, 0);
                    ep2 = (uint64_t)_mm256_extract_epi64(vx1, 0);
                    break;
            case 1:
                    ep1 = (uint64_t)_mm256_extract_epi64(vx3, 1);
                    ep2 = (uint64_t)_mm256_extract_epi64(vx1, 1);
                    break;
            case 2:
                    ep1 = (uint64_t)_mm256_extract_epi64(vx3, 2);
                    ep2 = (uint64_t)_mm256_extract_epi64(vx1, 2);
                    break;
            case 3:
                    ep1 = (uint64_t)_mm256_extract_epi64(vx3, 3);
                    ep2 = (uint64_t)_mm256_extract_epi64(vx1, 3);
                    break;
            }
            *hash += ep1;
            *hash ^= ep2;
            *hash  = JH_ROL(*hash, JH_SHIFT2);
            *hash += ep1;
        } // End of hash finish loop
    } // End of main AVX for loop

    return count & ~(size_t)31;
}
