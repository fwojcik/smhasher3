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

#if defined(__GNUC__) && !defined(__clang__)
  #define KHASH_GCC_LEAST__(maj, min)     (__GNUC__ > maj || __GNUC__ == maj && __GNUC_MINOR__ >= min)
#else
  #define KHASH_GCC_LEAST__(maj, min) 0
#endif

#if defined(__clang__) && defined(__has_attribute)
  #define KHASH_CHK_ATTRIBUTE__(attr) __has_attribute(attr)
#elif defined(__has_attribute) && KHASH_GCC_LEAST__(5, 0)
  #define KHASH_CHK_ATTRIBUTE__(attr) __has_attribute(attr)
#else
  #define KHASH_CHK_ATTRIBUTE__(attr) 0
#endif

#if KHASH_CHK_ATTRIBUTE__(optimize) || KHASH_GCC_LEAST__(4, 8)
  #define KHASH_OPT_SZ __attribute__((optimize("Os")))
#else
  #define KHASH_OPT_SZ
#endif

static const uint8_t khashv_xored[256] = {
    0xf3, 0xb2, 0x17, 0x0c, 0x2e, 0x73, 0x35, 0x58,
    0x8c, 0x7e, 0xb6, 0x5c, 0xc4, 0x4a, 0x01, 0xfd,
    0xd2, 0x93, 0x36, 0x2d, 0x0f, 0x52, 0x14, 0x79,
    0xad, 0x5f, 0x97, 0x7d, 0xe5, 0x6b, 0x20, 0xdc,
    0x7a, 0x3b, 0x9e, 0x85, 0xa7, 0xfa, 0xbc, 0xd1,
    0x05, 0xf7, 0x3f, 0xd5, 0x4d, 0xc3, 0x88, 0x74,
    0xef, 0xae, 0x0b, 0x10, 0x32, 0x6f, 0x29, 0x44,
    0x90, 0x62, 0xaa, 0x40, 0xd8, 0x56, 0x1d, 0xe1,
    0xea, 0xab, 0x0e, 0x15, 0x37, 0x6a, 0x2c, 0x41,
    0x95, 0x67, 0xaf, 0x45, 0xdd, 0x53, 0x18, 0xe4,
    0x3d, 0x7c, 0xd9, 0xc2, 0xe0, 0xbd, 0xfb, 0x96,
    0x42, 0xb0, 0x78, 0x92, 0x0a, 0x84, 0xcf, 0x33,
    0x5e, 0x1f, 0xba, 0xa1, 0x83, 0xde, 0x98, 0xf5,
    0x21, 0xd3, 0x1b, 0xf1, 0x69, 0xe7, 0xac, 0x50,
    0xb9, 0xf8, 0x5d, 0x46, 0x64, 0x39, 0x7f, 0x12,
    0xc6, 0x34, 0xfc, 0x16, 0x8e, 0x00, 0x4b, 0xb7,
    0x0d, 0x4c, 0xe9, 0xf2, 0xd0, 0x8d, 0xcb, 0xa6,
    0x72, 0x80, 0x48, 0xa2, 0x3a, 0xb4, 0xff, 0x03,
    0xb1, 0xf0, 0x55, 0x4e, 0x6c, 0x31, 0x77, 0x1a,
    0xce, 0x3c, 0xf4, 0x1e, 0x86, 0x08, 0x43, 0xbf,
    0x47, 0x06, 0xa3, 0xb8, 0x9a, 0xc7, 0x81, 0xec,
    0x38, 0xca, 0x02, 0xe8, 0x70, 0xfe, 0xb5, 0x49,
    0xda, 0x9b, 0x3e, 0x25, 0x07, 0x5a, 0x1c, 0x71,
    0xa5, 0x57, 0x9f, 0x75, 0xed, 0x63, 0x28, 0xd4,
    0x6e, 0x2f, 0x8a, 0x91, 0xb3, 0xee, 0xa8, 0xc5,
    0x11, 0xe3, 0x2b, 0xc1, 0x59, 0xd7, 0x9c, 0x60,
    0x24, 0x65, 0xc0, 0xdb, 0xf9, 0xa4, 0xe2, 0x8f,
    0x5b, 0xa9, 0x61, 0x8b, 0x13, 0x9d, 0xd6, 0x2a,
    0x89, 0xc8, 0x6d, 0x76, 0x54, 0x09, 0x4f, 0x22,
    0xf6, 0x04, 0xcc, 0x26, 0xbe, 0x30, 0x7b, 0x87,
    0x66, 0x27, 0x82, 0x99, 0xbb, 0xe6, 0xa0, 0xcd,
    0x19, 0xeb, 0x23, 0xc9, 0x51, 0xdf, 0x94, 0x68,
};

static KHASH_FINLINE void khashv_bswap_be_block_scalar( khashvBlock * in ) {
    // Byte swapping is only needed if we are not on on a little endian system
    if (khashv_is_little_endian()) {
        return;
    }
    for (int i = 0; i < 4; i++) {
        in->words[i] = KHASH_BSWAP32(in->words[i]);
    }
}

static KHASH_FINLINE void khashv_rotr_5_bytes_scalar( khashvBlock * in ) {
    khashv_bswap_be_block_scalar(in);
    khashvBlock tmp1;
    khashvBlock tmp2;
    // Avoid aliasing issues by using memcpy between these union values.
    memcpy(tmp1.bytes, in->words , 16);
    for (int i = 0; i < 16; i++) {
        tmp2.bytes[i] = tmp1.bytes[(i + 5) & 0xf];
    }
    memcpy(in->words , tmp2.bytes, 16);
    khashv_bswap_be_block_scalar(in);
}

static KHASH_FINLINE void khashv_shuffle_bytes_scalar( khashvBlock * in ) {
    static const uint8_t shuffle[16] = {
        0x7, 0xe, 0x9, 0x0, 0xc, 0xf, 0xd, 0x8,
        0x5, 0xb, 0x6, 0x3, 0x4, 0x2, 0xa, 0x1
    };

    khashv_bswap_be_block_scalar(in);
    khashvBlock tmp1;
    khashvBlock tmp2;
    // Avoid aliasing issues by using memcpy between these union values.
    memcpy(tmp1.bytes, in->words , 16);
    for (int i = 0; i < 16; i++) {
        tmp2.bytes[i] = tmp1.bytes[shuffle[i]];
    }
    memcpy(in->words , tmp2.bytes, 16);
    khashv_bswap_be_block_scalar(in);
}

static KHASH_FINLINE void khashv_shl_13_block_scalar( khashvBlock * in ) {
    for (int i = 0; i < 4; i++) {
        in->words[i] <<= 13;
    }
}

static KHASH_FINLINE void khashv_shr_3_block_scalar( khashvBlock * in ) {
    for (int i = 0; i < 4; i++) {
        in->words[i] >>= 3;
    }
}

static KHASH_FINLINE void khashv_add_block_scalar( khashvBlock * RESTRICT a, const khashvBlock * RESTRICT b ) {
    for (int i = 0; i < 4; i++) {
        a->words[i] += b->words[i];
    }
}

static KHASH_FINLINE void khashv_xor_block_scalar( khashvBlock * RESTRICT a, const khashvBlock * RESTRICT b ) {
    for (int i = 0; i < 4; i++) {
        a->words[i] ^= b->words[i];
    }
}

// GCC and Clang with -O3 were vectorizing this quite poorly with -O3
// They could not detect that only a PSHUFB was needed and instead
// where generating tons of inserts and extracts from the vector
// registers. Thusly it was running slower than code that was not being
// vectorized on my machine. So I specify the optimization level directly.
// Tried a few other things to get GCC and Clang to generate more sane
// code or code using PSHUFB, but this seemed the cleanest.
// Example of what I mean: https://godbolt.org/z/PMnzsThPc
// Compared to this: https://godbolt.org/z/dWfjr7GWP
/*static KHASH_OPT_SZ void khashv_sub16(khashvBlock* tmp, const uint8_t sub[16]) {
    #if defined(__clang__)
        // Stop clang from being annoying!!!
        // The auto-vectorized code was worse at the time of writing this
        #pragma nounroll
        #pragma clang loop vectorize(disable)
        #pragma clang loop interleave(disable)
    #endif
    for (int i = 0; i < 16; i++) {
        tmp->bytes[i] = sub[tmp->bytes[i]];
    }
}

static KHASH_FINLINE void khashv_replace_scalar(khashvBlock* replace) {
    khashvBlock tmp;
    for (int i = 0; i < 16; i++) {
        tmp.bytes[i] = (replace->bytes[i] >> 4);
        replace->bytes[i] &= 0x0f;
    }
    khashv_sub16(replace, khashv_s1);
    khashv_sub16(&tmp, khashv_s2);
    for (int i = 0; i < 16; i++) {
        replace->bytes[i] ^= tmp.bytes[i];
    }
}*/

// Similar issue as the commented out code so stop the optimizers
// from getting crazy
static KHASH_OPT_SZ void khashv_replace_scalar( khashvBlock * replace ) {
    khashvBlock tmp;

    memcpy(tmp.bytes, replace->words, 16);
#if defined(__clang__)
    // Stop clang from being annoying!!!
    // The auto-vectorized code was worse at the time of writing this
  #pragma nounroll
  #pragma clang loop vectorize(disable)
  #pragma clang loop interleave(disable)
#endif
    for (int i = 0; i < 16; i++) {
        tmp.bytes[i] = khashv_xored[tmp.bytes[i]];
    }
    memcpy(replace->words, tmp.bytes, 16);
}

static KHASH_FINLINE void khashv_mix_words_scalar( khashvBlock * in ) {
    unsigned    rots[4] = { 5, 7, 11, 17 };
    khashvBlock tmp     = { 0 };

    tmp = *in;
    khashv_shr_3_block_scalar(&tmp);
    khashv_xor_block_scalar(in, &tmp);

    for (int i = 0; i < 4; i++) {
        unsigned rot = rots[i];
        tmp = *in;
        khashv_rotr_5_bytes_scalar(&tmp);
        khashv_add_block_scalar(&tmp, in);
        for (int j = 0; j < 4; j++) {
            tmp.words[j] = KHASH_ROTR32(tmp.words[j], rot);
        }
        khashv_xor_block_scalar(in, &tmp);
    }
}

static void khashv_hash_scalar( khashvBlock * hash, const uint8_t * data, size_t data_len ) {
    hash->words[0] ^= data_len;
    // size_t is bigger than 32 bits
#if !defined(HAVE_32BIT_PLATFORM)
    hash->words[1] ^= data_len >> 32;
#endif

    khashvBlock tmp_1;
    khashvBlock tmp_2;
    khashvBlock tmp_h = *hash;

    const uint8_t * end = data + (data_len & ~((size_t)15));

    while (data < end) {
        memcpy(&tmp_2, data, 16);
        khashv_replace_scalar(&tmp_2);
        memcpy(&tmp_1.words, tmp_2.bytes, 16);

        khashv_bswap_be_block_scalar(&tmp_1);

        tmp_2 = tmp_1;
        // khashv_shl_13_block_scalar(&tmp_2);
        // khashv_add_block_scalar(&tmp_2, &tmp_1);
        for (int i = 0; i < 4; i++) {
            tmp_2.words[i] *= 8193;
        }
        khashv_xor_block_scalar(&tmp_h, &tmp_2);
        khashv_rotr_5_bytes_scalar(&tmp_h);
        khashv_add_block_scalar(&tmp_h, &tmp_1);

        tmp_1 = tmp_h;
        khashv_shuffle_bytes_scalar(&tmp_1);
        khashv_add_block_scalar(&tmp_h, &tmp_1);

        data += 16;
    }

    unsigned trailing = data_len & 0xf;
    if (trailing) {
        memset(&tmp_2, 0, 16);

        memcpy(&tmp_2.bytes, data, trailing);
        khashv_replace_scalar(&tmp_2);
        memcpy(&tmp_1.words, tmp_2.bytes, 16);

        khashv_bswap_be_block_scalar(&tmp_1);

        tmp_2 = tmp_1;
        // khashv_shl_13_block_scalar(&tmp_2);
        // khashv_add_block_scalar(&tmp_2, &tmp_1);
        for (int i = 0; i < 4; i++) {
            tmp_2.words[i] *= 8193;
        }
        khashv_xor_block_scalar(&tmp_h, &tmp_2);
        khashv_rotr_5_bytes_scalar(&tmp_h);
        khashv_add_block_scalar(&tmp_h, &tmp_1);

        tmp_1 = tmp_h;
        khashv_shuffle_bytes_scalar(&tmp_1);
        khashv_add_block_scalar(&tmp_h, &tmp_1);
    }
    khashv_mix_words_scalar(&tmp_h);
    *hash = tmp_h;
}

//------------------------------------------------------------

static void khashv_prep_seed32( khashvSeed * seed_prepped, uint32_t seed ) {
    *seed_prepped = khash_v_init;
    seed_prepped->words[0] ^= seed;
    khashv_mix_words_scalar(seed_prepped);
}

static void khashv_prep_seed64( khashvSeed * seed_prepped, uint64_t seed ) {
    *seed_prepped = khash_v_init;
    seed_prepped->words[0] ^= seed;
    khashv_mix_words_scalar(seed_prepped);
    // Do it again with the other part to make it different than the 32 bit seed.
    seed_prepped->words[1] ^= seed >> 32;
    khashv_mix_words_scalar(seed_prepped);
}

static void khashv_prep_seed128( khashvSeed * seed_prepped, const uint32_t seed[4] ) {
    for (int i = 0; i < 4; i++) {
        seed_prepped->words[i] = seed[i];
    }
}

static uint32_t khashv32( const khashvSeed * seed, const uint8_t * data, size_t data_len ) {
    khashvBlock h = *seed;

    khashv_hash_scalar(&h, data, data_len);
    return h.words[3];
}

static uint64_t khashv64( const khashvSeed * seed, const uint8_t * data, size_t data_len ) {
    khashvBlock h = *seed;

    khashv_hash_scalar(&h, data, data_len);
    uint64_t r = h.words[1];
    r <<= 32;
    r  |= h.words[0];
    return r;
}
