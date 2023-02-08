/*
 * Pearson hashing
 * This is free and unencumbered software released into the public
 * domain under The Unlicense (http://unlicense.org/).
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a
 * compiled binary, for any purpose, commercial or non-commercial, and
 * by any means.
 *
 * In jurisdictions that recognize copyright laws, the author or
 * authors of this software dedicate any and all copyright interest in
 * the software to the public domain. We make this dedication for the
 * benefit of the public at large and to the detriment of our heirs
 * and successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to
 * this software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */
static void pearson_hash_256( uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in ) {
    size_t i;

    uint8_t upper[8]         = { 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08 };
    uint8_t lower[8]         = { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

    uint64_t upper_hash_mask = GET_U64<false>(upper, 0);
    uint64_t lower_hash_mask = GET_U64<false>(lower, 0);

    __m128i tmp            = _mm_set1_epi8(0x10);

    __m128i hash_mask      = _mm_set_epi64x(lower_hash_mask, upper_hash_mask);
    __m128i high_hash_mask = _mm_xor_si128(tmp, hash_mask);
    __m128i hash           = _mm_set_epi64x(hash_in, hash_in);
    __m128i high_hash      = _mm_set_epi64x(hash_in, hash_in);

    // table lookup preparation
    __m128i ZERO = _mm_setzero_si128();
    __m128i ISOLATE_SBOX_MASK = _mm_set_epi32(0x0306090C, 0x0F020508, 0x0B0E0104, 0x070A0D00);

    for (i = 0; i < len; i++) {
        // broadcast the character, xor into hash, make them different permutations
        __m128i cc = _mm_set1_epi8(in[i]);
        hash      = _mm_xor_si128(hash     , cc       );
        high_hash = _mm_xor_si128(high_hash, cc       );
        hash      = _mm_xor_si128(hash     , hash_mask);
        high_hash = _mm_xor_si128(high_hash, high_hash_mask);

        // table lookup
        hash      = _mm_shuffle_epi8(hash     , ISOLATE_SBOX_MASK); // re-order along AES round
        high_hash = _mm_shuffle_epi8(high_hash, ISOLATE_SBOX_MASK); // re-order along AES round
        hash      = _mm_aesenclast_si128(hash     , ZERO);
        high_hash = _mm_aesenclast_si128(high_hash, ZERO);
    }

    // store output
    _mm_storeu_si128((__m128i *)out     , high_hash);
    _mm_storeu_si128((__m128i *)&out[16], hash     );
}

static void pearson_hash_128( uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in ) {
    size_t i;

    uint8_t upper[8]         = { 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08 };
    uint8_t lower[8]         = { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

    uint64_t upper_hash_mask = GET_U64<false>(upper, 0);
    uint64_t lower_hash_mask = GET_U64<false>(lower, 0);

    __m128i hash_mask        = _mm_set_epi64x(lower_hash_mask, upper_hash_mask);
    __m128i hash = _mm_set_epi64x(hash_in, hash_in);

    // table lookup preparation
    __m128i ZERO = _mm_setzero_si128();
    __m128i ISOLATE_SBOX_MASK = _mm_set_epi32(0x0306090C, 0x0F020508, 0x0B0E0104, 0x070A0D00);

    for (i = 0; i < len; i++) {
        // broadcast the character, xor into hash, make them different permutations
        __m128i cc = _mm_set1_epi8(in[i]);
        hash = _mm_xor_si128(hash, cc       );
        hash = _mm_xor_si128(hash, hash_mask);

        // table lookup
        hash = _mm_shuffle_epi8(hash, ISOLATE_SBOX_MASK); // re-order along AES round
        hash = _mm_aesenclast_si128(hash, ZERO);
    }
    // store output
    _mm_storeu_si128((__m128i *)out, hash);
}

static void pearson_hash_64( uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in ) {
    size_t  i;
    __m128i hash_mask = _mm_cvtsi64_si128(UINT64_C(0x0706050403020100));
    __m128i hash      = _mm_cvtsi64_si128(hash_in);

    // table lookup preparation
    __m128i ZERO = _mm_setzero_si128();
    __m128i ISOLATE_SBOX_MASK = _mm_set_epi32(0x0306090C, 0x0F020508, 0x0B0E0104, 0x070A0D00);

    for (i = 0; i < len; i++) {
        // broadcast the character, xor into hash, make them different permutations
        __m128i cc = _mm_set1_epi8(in[i]);
        hash = _mm_xor_si128(hash, cc       );
        hash = _mm_xor_si128(hash, hash_mask);

        // table lookup
        hash = _mm_shuffle_epi8(hash, ISOLATE_SBOX_MASK); // re-order along AES round
        hash = _mm_aesenclast_si128(hash, ZERO);
    }

    // store output
    _mm_storel_epi64((__m128i *)out, hash);
}
