/*
 * khashv
 * Copyright (c) 2022 Keith-Cancel
 * Copyright (C) 2022 Frank J. T. Wojcik
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

static const uint8_t khashv_s1[16] = {
    0x1c, 0x5d, 0xf8, 0xe3, 0xc1, 0x9c, 0xda, 0xb7,
    0x63, 0x91, 0x59, 0xb3, 0x2b, 0xa5, 0xee, 0x12,
};

static const uint8_t khashv_s2[16] = {
    0xef, 0xce, 0x66, 0xf3, 0xf6, 0x21, 0x42, 0xa5,
    0x11, 0xad, 0x5b, 0xc6, 0x72, 0x38, 0x95, 0x7a,
};

static KHASH_FINLINE __m128i khashv_mix_words_vector( __m128i val ) {
    __m128i tmp1;
    __m128i tmp2;

    tmp1 = _mm_srli_epi32(val, 3);
    val  = _mm_xor_si128(tmp1, val);

    tmp1 = _mm_alignr_epi8(val, val, 5);
    tmp1 = _mm_add_epi32(val, tmp1);
#if defined(HAVE_AVX512_VL)
    tmp1 = _mm_ror_epi32(tmp1, 5);
    val  = _mm_xor_si128(val, tmp1);
#else
    tmp2 = _mm_srli_epi32(tmp1, 5);
    tmp1 = _mm_slli_epi32(tmp1, 27);
    val  = _mm_xor_si128(val, tmp2);
    val  = _mm_xor_si128(val, tmp1);
#endif

    tmp1 = _mm_alignr_epi8(val, val, 5);
    tmp1 = _mm_add_epi32(val, tmp1);
#if defined(HAVE_AVX512_VL)
    tmp1 = _mm_ror_epi32(tmp1, 7);
    val  = _mm_xor_si128(val, tmp1);
#else
    tmp2 = _mm_srli_epi32(tmp1, 7);
    tmp1 = _mm_slli_epi32(tmp1, 25);
    val  = _mm_xor_si128(val, tmp2);
    val  = _mm_xor_si128(val, tmp1);
#endif

    tmp1 = _mm_alignr_epi8(val, val, 5);
    tmp1 = _mm_add_epi32(tmp1, val);
#if defined(HAVE_AVX512_VL)
    tmp1 = _mm_ror_epi32(tmp1, 11);
    val  = _mm_xor_si128(val, tmp1);
#else
    tmp2 = _mm_srli_epi32(tmp1, 11);
    tmp1 = _mm_slli_epi32(tmp1, 21);
    val  = _mm_xor_si128(val, tmp2);
    val  = _mm_xor_si128(val, tmp1);
#endif

    tmp1 = _mm_alignr_epi8(val, val, 5);
    tmp1 = _mm_add_epi32(tmp1, val);
#if defined(HAVE_AVX512_VL)
    tmp1 = _mm_ror_epi32(tmp1, 17);
    val  = _mm_xor_si128(val, tmp1);
#else
    tmp2 = _mm_srli_epi32(tmp1, 17);
    tmp1 = _mm_slli_epi32(tmp1, 15);
    val  = _mm_xor_si128(val, tmp2);
    val  = _mm_xor_si128(val, tmp1);
#endif

    return val;
}

static KHASH_FINLINE __m128i khashv_part_load_vector( const uint8_t * data, size_t len ) {
    __m128i tmp  = { 0 };

    switch (len) {
    case  1:
#if defined(HAVE_SSE_4_1)
             tmp = _mm_insert_epi8(tmp, data[0], 0);
#else
             tmp = _mm_cvtsi32_si128(data   [0]);
#endif
             break;
    case  2:
             tmp = _mm_loadu_si16(data);
             break;
    case  3:
             tmp = _mm_loadu_si16(data);
#if defined(HAVE_SSE_4_1)
             tmp = _mm_insert_epi8(tmp , data[2], 2);
#else
             tmp = _mm_insert_epi16(tmp, data[2], 1);
#endif
             break;
    case  4:
             tmp = _mm_loadu_si32(data);
             break;
    case  5:
             tmp = _mm_loadu_si32(data);
#if defined(HAVE_SSE_4_1)
             tmp = _mm_insert_epi8(tmp , data[4], 4);
#else
             tmp = _mm_insert_epi16(tmp, data[4], 2);
#endif
             break;
    case  6:
             tmp = _mm_loadu_si32(data);
             tmp = _mm_insert_epi16(tmp, *(uint16_t *)(data + 4), 2);
             break;
    case  7:
             tmp = _mm_loadu_si32(data);
             tmp = _mm_insert_epi16(tmp, *(uint16_t *)(data + 4), 2);
#if defined(HAVE_SSE_4_1)
             tmp = _mm_insert_epi8(tmp , data[6], 6);
#else
             tmp = _mm_insert_epi16(tmp, data[6], 3);
#endif
             break;
    case  8:
             tmp = _mm_loadu_si64(data);
             break;
    case  9:
             tmp = _mm_loadu_si64(data);
#if defined(HAVE_SSE_4_1)
             tmp = _mm_insert_epi8(tmp , data[8], 8);
#else
             tmp = _mm_insert_epi16(tmp, data[8], 4);
#endif
             break;
    case 10:
             tmp = _mm_loadu_si64(data);
             tmp = _mm_insert_epi16(tmp, *(uint16_t *)(data + 8), 4);
             break;
    case 11:
             tmp = _mm_loadu_si64(data);
             tmp = _mm_insert_epi16(tmp, *(uint16_t *)(data + 8), 4);
#if defined(HAVE_SSE_4_1)
             tmp = _mm_insert_epi8(tmp , data[10], 10);
#else
             tmp = _mm_insert_epi16(tmp, data[10],  5);
#endif
             break;
    case 12:
             tmp  = _mm_loadu_si64(data);
#if defined(HAVE_SSE_4_1)
             tmp  = _mm_insert_epi32(tmp, *(uint32_t *)(data + 8), 2);
#else
             tmp2 = _mm_loadu_si32(data + 8);
             tmp2 = _mm_shuffle_epi32(tmp2, 0x4f);
             tmp  = _mm_or_si128(tmp, tmp2);
#endif
             break;
    case 13:
             tmp  = _mm_loadu_si64(data);
#if defined(HAVE_SSE_4_1)
             tmp  = _mm_insert_epi32(tmp, *(uint32_t *)(data + 8), 2);
             tmp  = _mm_insert_epi8(tmp  , data[12], 12);
#else
             tmp2 = _mm_loadu_si32(data + 8);
             tmp2 = _mm_insert_epi16(tmp2, data[12],  2);
             tmp2 = _mm_shuffle_epi32(tmp2, 0x4f);
             tmp  = _mm_or_si128(tmp, tmp2);
#endif
             break;
    case 14:
             tmp  = _mm_loadu_si64(data);
#if defined(HAVE_SSE_4_1)
             tmp  = _mm_insert_epi32(tmp , *(uint32_t *)(data +  8), 2);
             tmp  = _mm_insert_epi16(tmp , *(uint16_t *)(data + 12), 6);
#else
             tmp2 = _mm_loadu_si32(data + 8);
             tmp2 = _mm_insert_epi16(tmp2, *(uint16_t *)(data + 12), 6);
             tmp2 = _mm_shuffle_epi32(tmp2, 0x4f);
             tmp  = _mm_or_si128(tmp, tmp2);
#endif
             break;
    case 15:
             tmp  = _mm_loadu_si64(data);
#if defined(HAVE_SSE_4_1)
             tmp  = _mm_insert_epi32(tmp, * (uint32_t *)(data +  8), 2);
             tmp  = _mm_insert_epi16(tmp, * (uint16_t *)(data + 12), 6);
             tmp  = _mm_insert_epi8(tmp, data  [14], 14);
#else
             tmp2 = _mm_loadu_si32(data + 8);
             tmp2 = _mm_insert_epi16(tmp2, *(uint16_t *)(data + 12), 6);
             tmp2 = _mm_insert_epi16(tmp2, data[14],  7);
             tmp2 = _mm_shuffle_epi32(tmp2, 0x4f);
             tmp  = _mm_or_si128(tmp, tmp2);
#endif
             break;
    case 16:
        tmp = _mm_loadu_si128((__m128i*)data);
        break;
    }
    return tmp;
}

static const uint8_t khashv_shuff[16] = {
    0x7, 0xe, 0x9, 0x0, 0xc, 0xf, 0xd, 0x8,
    0x5, 0xb, 0x6, 0x3, 0x4, 0x2, 0xa, 0x1
};

static KHASH_FINLINE __m128i khashv_hash_vector( __m128i hash, const uint8_t * data, size_t data_len ) {
    const __m128i s1    = _mm_loadu_si128((const __m128i *)khashv_s1   );
    const __m128i s2    = _mm_loadu_si128((const __m128i *)khashv_s2   );
    const __m128i shuff = _mm_loadu_si128((const __m128i *)khashv_shuff);
    const __m128i mask  = _mm_set1_epi32(0x0f0f0f0f);

    __m128i tmp_1;
    __m128i tmp_2;

#if !defined(HAVE_32BIT_PLATFORM)
    tmp_1 = _mm_cvtsi64_si128(data_len);
#else
    tmp_1 = _mm_cvtsi32_si128(data_len);
#endif
    hash  = _mm_xor_si128(tmp_1, hash);

    const uint8_t * end  = data + (data_len & ~((size_t)15));
    const uint8_t * end2 = data + data_len;
    while (data_len > 16 && data < end) {
        tmp_1 = _mm_lddqu_si128((const __m128i *)data);
        tmp_2 = _mm_srli_epi32(tmp_1, 4);

        tmp_1 = _mm_and_si128(tmp_1, mask);
        tmp_2 = _mm_and_si128(tmp_2, mask);
        tmp_1 = _mm_shuffle_epi8(s1, tmp_1);
        tmp_2 = _mm_shuffle_epi8(s2, tmp_2);
        tmp_1 = _mm_xor_si128(tmp_1, tmp_2);

        tmp_2 = _mm_slli_epi32(tmp_1, 13);
        tmp_2 = _mm_add_epi32(tmp_1, tmp_2);
        tmp_2 = _mm_xor_si128(hash, tmp_2);
        tmp_2 = _mm_alignr_epi8(tmp_2, tmp_2, 5);
        hash  = _mm_add_epi32(tmp_2, tmp_1);

        tmp_1 = _mm_shuffle_epi8(hash, shuff);
        hash  = _mm_add_epi32(hash, tmp_1);

        data += 16;
    }
    uintptr_t trailing = end2 - data;
    if (trailing) {
        tmp_1 = khashv_part_load_vector(data, trailing);
        tmp_2 = _mm_srli_epi32(tmp_1, 4);

        tmp_1 = _mm_and_si128(tmp_1, mask);
        tmp_2 = _mm_and_si128(tmp_2, mask);
        tmp_1 = _mm_shuffle_epi8(s1, tmp_1);
        tmp_2 = _mm_shuffle_epi8(s2, tmp_2);
        tmp_1 = _mm_xor_si128(tmp_1, tmp_2);

        tmp_2 = _mm_slli_epi32(tmp_1, 13);
        tmp_2 = _mm_add_epi32(tmp_1, tmp_2);
        tmp_2 = _mm_xor_si128(hash, tmp_2);
        tmp_2 = _mm_alignr_epi8(tmp_2, tmp_2, 5);
        hash  = _mm_add_epi32(tmp_2, tmp_1);

        tmp_1 = _mm_shuffle_epi8(hash, shuff);
        hash  = _mm_add_epi32(hash, tmp_1);
    }
    hash = khashv_mix_words_vector(hash);
    return hash;
}

//------------------------------------------------------------

static void khashv_prep_seed32( khashvSeed * seed_prepped, uint32_t seed ) {
    __m128i s = _mm_loadu_si128((const __m128i *)&khash_v_init);

    s = _mm_xor_si128(s, _mm_cvtsi32_si128(seed));
    seed_prepped->vec = khashv_mix_words_vector(s);
}

static void khashv_prep_seed64( khashvSeed * seed_prepped, uint64_t seed ) {
    __m128i s = _mm_loadu_si128((const __m128i *)&khash_v_init);
    __m128i t = _mm_cvtsi32_si128(seed >> 32);

    s = _mm_xor_si128(s, _mm_cvtsi32_si128(seed));
    s = khashv_mix_words_vector(s);
    s = _mm_xor_si128(s, _mm_shuffle_epi32(t, 0xf3));
    seed_prepped->vec = khashv_mix_words_vector(s);
}

static void khashv_prep_seed128( khashvSeed * seed_prepped, const uint32_t seed[4] ) {
    seed_prepped->vec = _mm_loadu_si128((const __m128i *)seed);
}

static uint32_t khashv32( const khashvSeed * seed, const uint8_t * data, size_t data_len ) {
    __m128i h = khashv_hash_vector(seed->vec, data, data_len);

    // using word[3] to avoid any overlap with with the
    // 64 bit hash which uses words [0] and [1], this ensures
    // the 2 bit outputs should behave differently when used.
#if defined(HAVE_SSE_4_1)
    return _mm_extract_epi32(h, 3);
#else
    h = _mm_shuffle_epi32(h, 0xff);
    return _mm_cvtsi128_si32(h);
#endif
}

static uint64_t khashv64( const khashvSeed * seed, const uint8_t * data, size_t data_len ) {
    __m128i h = khashv_hash_vector(seed->vec, data, data_len);

#if defined(HAVE_32BIT_PLATFORM)
    // _mm_cvtsi128_si64 isn't available on 32-bit platforms, so we use
    // _mm_storel_epi64 instead.
    uint64_t r;
    _mm_storel_epi64((__m128i *)&r, h);
    return r;
#else
    return _mm_cvtsi128_si64(h);
#endif
}
