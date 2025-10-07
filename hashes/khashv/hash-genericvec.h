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
/* Vectorization via GCCs Vectorization builtins */
// Handy since it allows vectorization without explicit intrinsics
// for a particular CPU.

#define KHASH_SHUFFLE(v, s) VECTOR_SHUFFLE_1(v, s)

typedef uint8_t  kv16ui VECTOR_SIZE( 16 );
typedef uint32_t kv4ui  VECTOR_SIZE( 16 );

static KHASH_FINLINE kv16ui khashv_sub_s1_gcc( kv16ui in ) {
    const kv16ui mask = {
        0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf,
        0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf
    };
    const kv16ui subLE = {
        0x1c, 0x5d, 0xf8, 0xe3, 0xc1, 0x9c, 0xda, 0xb7,
        0x63, 0x91, 0x59, 0xb3, 0x2b, 0xa5, 0xee, 0x12,
    };

    in &= mask;
    return KHASH_SHUFFLE(subLE, in);
}

static KHASH_FINLINE kv16ui khashv_sub_s2_gcc( kv16ui in ) {
    const kv16ui subLE = {
        0xef, 0xce, 0x66, 0xf3, 0xf6, 0x21, 0x42, 0xa5,
        0x11, 0xad, 0x5b, 0xc6, 0x72, 0x38, 0x95, 0x7a,
    };

    in >>= 4;
    return KHASH_SHUFFLE(subLE, in);
}

static KHASH_FINLINE kv4ui khashv_rotr_5_bytes_gcc( kv4ui input ) {
    const kv16ui rotrLE = {
        0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc,
        0xd, 0xe, 0xf, 0x0, 0x1, 0x2, 0x3, 0x4
    };
    const kv16ui rotrBE = {
        0xb, 0x4, 0x5, 0x6, 0xf, 0x8, 0x9, 0xa,
        0x3, 0xc, 0xd, 0xe, 0x7, 0x0, 0x1, 0x2
    };
    kv16ui tmp;

    memcpy(&tmp, &input, 16);
    tmp = KHASH_SHUFFLE(tmp, khashv_is_little_endian() ? rotrLE : rotrBE);
    memcpy(&input, &tmp, 16);
    return input;
}

static KHASH_FINLINE kv4ui khashv_shuffle_bytes_gcc( kv4ui input ) {
    const kv16ui shuffLE = {
        0x7, 0xe, 0x9, 0x0, 0xc, 0xf, 0xd, 0x8,
        0x5, 0xb, 0x6, 0x3, 0x4, 0x2, 0xa, 0x1
    };
    const kv16ui shuffBE = {
        0x3, 0xa, 0xd, 0x4, 0xb, 0xe, 0xc, 0xf,
        0x0, 0x5, 0x8, 0x6, 0x2, 0x9, 0x1, 0x7,
    };
    kv16ui tmp;
    memcpy(&tmp, &input, 16);
    tmp = KHASH_SHUFFLE(tmp, khashv_is_little_endian() ? shuffLE : shuffBE);
    memcpy(&input, &tmp, 16);
    return input;
}

static KHASH_FINLINE kv4ui khash_byteswap_vec32_gcc( kv4ui input ) {
    const kv16ui bswap32 = {
        0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4,
        0xb, 0xa, 0x9, 0x8, 0xf, 0xe, 0xd, 0xc,
    };
    kv16ui b;

    memcpy(&b, &input, 16);
    b = KHASH_SHUFFLE(b, bswap32);
    memcpy(&input, &b, 16);
    return input;
}

static KHASH_FINLINE kv4ui khashv_replace_gcc( kv4ui input ) {
    kv16ui s1;
    kv16ui s2;

    memcpy(&s1, &input, 16);
    s2  = khashv_sub_s2_gcc(s1);
    s1  = khashv_sub_s1_gcc(s1);
    s1 ^= s2;
    memcpy(&input, &s1, 16);
    return input;
}

static KHASH_FINLINE kv4ui khashv_mix_words_gcc( kv4ui val ) {
    const unsigned rots[4] = { 5, 7, 11, 17 };
    kv4ui tmp = val >> 3;
    val ^= tmp;
    for (int i = 0; i < 4; i++) {
        unsigned rot = rots[i];
        kv4ui    tmp = val;
        tmp  = khashv_rotr_5_bytes_gcc(tmp);
        tmp += val;
        tmp  = (tmp >> rot) | (tmp << (32 - rot));
        val ^= tmp;
    }
    return val;
}

static KHASH_FINLINE kv4ui khashv_hash_block_gcc( kv4ui hash, kv4ui input ) {
    kv4ui tmp_1 = khashv_replace_gcc(input);

    if (!khashv_is_little_endian()) {
        tmp_1 = khash_byteswap_vec32_gcc(tmp_1);
    }

    kv4ui tmp_2 = tmp_1 * 8193;

    tmp_2 ^= hash;
    tmp_2  = khashv_rotr_5_bytes_gcc(tmp_2);
    hash   = tmp_1 + tmp_2;

    tmp_1  = khashv_shuffle_bytes_gcc(hash);
    hash   = hash + tmp_1;
    return hash;
}

static KHASH_FINLINE kv4ui khashv_hash_gcc( kv4ui hash, const uint8_t * data, size_t data_len ) {
    hash[0] ^= data_len;
#if !defined(HAVE_32BIT_PLATFORM)
    hash[1] ^= data_len >> 32;
#endif

    kv4ui data_v;
    const uint8_t * end = data + (data_len & ~((size_t)15));
    while (data < end) {
        memcpy(&data_v, data, 16);
        hash  = khashv_hash_block_gcc(hash, data_v);
        data += 16;
    }

    unsigned trailing = data_len & 0xf;
    if (trailing) {
        memset(&data_v, 0, 16);
        memcpy(&data_v, data, trailing);
        hash = khashv_hash_block_gcc(hash, data_v);
    }
    return khashv_mix_words_gcc(hash);
}

//------------------------------------------------------------

static void khashv_prep_seed32( khashvSeed * seed_prepped, uint32_t seed ) {
    kv4ui s;

    memcpy(&s, &khash_v_init, 16);
    s[0] ^= seed;
    s     = khashv_mix_words_gcc(s);
    memcpy(seed_prepped, &s, 16);
}

static void khashv_prep_seed64( khashvSeed * seed_prepped, uint64_t seed ) {
    kv4ui s;

    memcpy(&s, &khash_v_init, 16);
    s[0] ^= seed;
    s     = khashv_mix_words_gcc(s);
    s[1] ^= seed >> 32;
    s     = khashv_mix_words_gcc(s);
    memcpy(seed_prepped, &s, 16);
}

static void khashv_prep_seed128( khashvSeed * seed_prepped, const uint32_t seed[4] ) {
    memcpy(seed_prepped->words, seed, 16);
}

static uint32_t khashv32( const khashvSeed * seed, const uint8_t * data, size_t data_len ) {
    kv4ui h;

    memcpy(&h, seed, 16);
    h = khashv_hash_gcc(h, data, data_len);
    uint32_t ret = h[3];
    return ret;
}

static uint64_t khashv64( const khashvSeed * seed, const uint8_t * data, size_t data_len ) {
    kv4ui h;

    memcpy(&h, seed, 16);
    h = khashv_hash_gcc(h, data, data_len);
    uint64_t ret = h[1];
    ret = (ret << 32) | h[0];
    return ret;
}
