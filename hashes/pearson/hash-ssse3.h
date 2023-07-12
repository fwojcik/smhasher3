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
    __m128i const p16             = _mm_set1_epi8(0x10);
    __m128i       lut_result      = _mm_xor_si128(lut_result     , lut_result);
    __m128i       high_lut_result = _mm_xor_si128(high_lut_result, high_lut_result);
    __m128i       selected_entries;
    __m128i       high_selected_entries;
    __m128i       table_line;

    for (i = 0; i < len; i++) {
        // broadcast the character, xor into hash, make them different permutations
        __m128i cc = _mm_set1_epi8(in[i]);
        hash      =       _mm_xor_si128(hash     , cc       );
        high_hash =       _mm_xor_si128(high_hash, cc       );
        hash      =       _mm_xor_si128(hash     , hash_mask);
        high_hash =       _mm_xor_si128(high_hash, high_hash_mask);

        // table lookup
        size_t  j;
        __m128i lut_index      = hash;
        __m128i high_lut_index = high_hash;
        lut_result      = _mm_xor_si128(lut_result, lut_result);
        high_lut_result = _mm_xor_si128(lut_result, lut_result);
        for (j = 0; j < 256; j += 16) {
            table_line            = _mm_load_si128((__m128i *)&t[j]);
            selected_entries      = _mm_min_epu8(lut_index, p16);
            selected_entries      = _mm_cmpeq_epi8(selected_entries, p16);
            selected_entries      = _mm_or_si128(selected_entries, lut_index);
            selected_entries      = _mm_shuffle_epi8(table_line, selected_entries);
            high_selected_entries = _mm_min_epu8(high_lut_index, p16);
            high_selected_entries = _mm_cmpeq_epi8(high_selected_entries, p16);
            high_selected_entries = _mm_or_si128(high_selected_entries, high_lut_index);
            high_selected_entries = _mm_shuffle_epi8(table_line, high_selected_entries);
            lut_result            = _mm_or_si128(lut_result, selected_entries);
            lut_index             = _mm_sub_epi8(lut_index, p16);
            high_lut_result       = _mm_or_si128(high_lut_result, high_selected_entries);
            high_lut_index        = _mm_sub_epi8(high_lut_index, p16);
        }
        hash      = lut_result;
        high_hash = high_lut_result;
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
    __m128i const p16        = _mm_set1_epi8(0x10);
    __m128i       lut_result = _mm_xor_si128(lut_result, lut_result);
    __m128i       selected_entries;
    __m128i       table_line;

    for (i = 0; i < len; i++) {
        // broadcast the character, xor into hash, make them different permutations
        __m128i cc = _mm_set1_epi8(in[i]);
        hash =       _mm_xor_si128(hash, cc       );
        hash =       _mm_xor_si128(hash, hash_mask);

        // table lookup
        size_t  j;
        __m128i lut_index = hash;
        lut_result = _mm_xor_si128(lut_result, lut_result);
        for (j = 0; j < 256; j += 16) {
            table_line       = _mm_load_si128((__m128i *)&t[j]);
            selected_entries = _mm_min_epu8(lut_index, p16);
            selected_entries = _mm_cmpeq_epi8(selected_entries, p16);
            selected_entries = _mm_or_si128(selected_entries, lut_index);
            selected_entries = _mm_shuffle_epi8(table_line, selected_entries);
            lut_result       = _mm_or_si128(lut_result, selected_entries);
            lut_index        = _mm_sub_epi8(lut_index, p16);
        }
        hash = lut_result;
    }
    // store output
    _mm_storeu_si128((__m128i *)out, hash);
}

static void pearson_hash_64( uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in ) {
    size_t  i;
    // _mm_cvtsi64_si28 doesn't exist on x86-32
    __m128i hash_mask = _mm_set_epi64x(0, UINT64_C(0x0706050403020100));
    __m128i hash      = _mm_set_epi64x(0, hash_in);

    // table lookup preparation
    __m128i const p16        = _mm_set1_epi8(0x10);
    __m128i       lut_result = _mm_xor_si128(lut_result, lut_result);

    for (i = 0; i < len; i++) {
        // broadcast the character, xor into hash, make them different permutations
        __m128i cc = _mm_set1_epi8(in[i]);
        hash =       _mm_xor_si128(hash, cc       );
        hash =       _mm_xor_si128(hash, hash_mask);

        // table lookup
        size_t  j;
        __m128i lut_index = hash;
        lut_result = _mm_xor_si128(lut_result, lut_result);
        for (j = 0; j < 256; j += 16) {
            __m128i table_line       = _mm_load_si128((__m128i *)&t[j]);
            __m128i selected_entries = _mm_min_epu8(lut_index, p16);
            selected_entries = _mm_cmpeq_epi8(selected_entries, p16);
            selected_entries = _mm_or_si128(selected_entries, lut_index);
            selected_entries = _mm_shuffle_epi8(table_line, selected_entries);
            lut_result       = _mm_or_si128(lut_result, selected_entries);
            lut_index        = _mm_sub_epi8(lut_index, p16);
        }
        hash = lut_result;
    }

    // store output
    _mm_storel_epi64((__m128i *)out, hash);
}
