/*
 * aHash
 * Copyright (C) 2023 Frank J. T. Wojcik
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
#include "Platform.h"
#include "Hashlib.h"
#include "Mathmult.h"
#include "AES.h"

#include <cassert>

//------------------------------------------------------------
// Random state generation

static const uint64_t PI[4] = {
    UINT64_C(0x243f6a8885a308d3), UINT64_C(0x13198a2e03707344),
    UINT64_C(0xa4093822299f31d0), UINT64_C(0x082efa98ec4e6c89),
};

static const uint64_t PI2[4] = {
    UINT64_C(0x452821e638d01377), UINT64_C(0xbe5466cf34e90c6c),
    UINT64_C(0xc0ac29b7c97c50dd), UINT64_C(0x3f84d5b5b5470917),
};

static thread_local uint64_t RANDOM_STATE[4];

static uintptr_t init_state( seed_t seed ) {
    for (unsigned j = 0; j < 4; j++) {
        RANDOM_STATE[j] = PI2[j] ^ (uint64_t)seed;
    }
    return (uintptr_t)(void *)RANDOM_STATE;
}

//------------------------------------------------------------
// AES API wrappers

template <bool bswap>
static void aesenc( uint64_t value[2], const uint64_t xorv[2] ) {
    if (bswap) {
        uint64_t xorv_swp[2];
        value   [0] = BSWAP(value[0]);
        value   [1] = BSWAP(value[1]);
        xorv_swp[0] = BSWAP(xorv [0]);
        xorv_swp[1] = BSWAP(xorv [1]);
        AES_EncryptRound((const uint8_t *)xorv_swp, (uint8_t *)value);
        value   [0] = BSWAP(value[0]);
        value   [1] = BSWAP(value[1]);
    } else {
        AES_EncryptRound((const uint8_t *)xorv, (uint8_t *)value);
    }
}

template <bool bswap>
static void aesdec( uint64_t value[2], const uint64_t xorv[2] ) {
    if (bswap) {
        uint64_t xorv_swp[2];
        value   [0] = BSWAP(value[0]);
        value   [1] = BSWAP(value[1]);
        xorv_swp[0] = BSWAP(xorv [0]);
        xorv_swp[1] = BSWAP(xorv [1]);
        AES_DecryptRound((const uint8_t *)xorv_swp, (uint8_t *)value);
        value   [0] = BSWAP(value[0]);
        value   [1] = BSWAP(value[1]);
    } else {
        AES_DecryptRound((const uint8_t *)xorv, (uint8_t *)value);
    }
}

//------------------------------------------------------------
// Read and convert 8 or fewer bytes into 2 64-bit words

template <bool bswap>
static void read_small( const uint8_t * RESTRICT in, size_t len, uint64_t out[2] ) {
    assert(len <= 8);
    if (len >= 2) {
        if (len >= 4) {
            // len 4-8
            out[0] = GET_U32<bswap>(in, 0);
            out[1] = GET_U32<bswap>(in, len - 4);
        } else {
            // len 2-3
            out[0] = GET_U16<bswap>(in, 0);
            out[1] = in[len - 1];
        }
    } else {
        if (len > 0) {
            out[0] = out[1] = in[0];
        } else {
            out[0] = out[1] = 0;
        }
    }
}

//------------------------------------------------------------
// AES-based hash

typedef struct {
    uint64_t  enc[2];
    uint64_t  sum[2];
    uint64_t  key[2];
} AHasher;

static void from_random_state( AHasher * s, const uint64_t random_state[4] ) {
    s->enc[0] = random_state[0];
    s->enc[1] = random_state[1];
    s->sum[0] = random_state[2];
    s->sum[1] = random_state[3];
    s->key[0] = s->enc[0] ^ s->sum[0];
    s->key[1] = s->enc[1] ^ s->sum[1];
    //printf("FRS aes %016lx %016lx %016lx %016lx\n", random_state[0],random_state[1],random_state[2],random_state[3]);
}

// This is a constant with a lot of special properties found by automated search.
static const uint8_t SHUFFLE_MASK[16] = {
    0x4, 0xb, 0x9, 0x6, 0x8, 0xd, 0xf, 0x5,
    0xe, 0x3, 0x1, 0xc, 0x0, 0x7, 0xa, 0x2,
};

template <bool hw_shuffle>
static void shuffle( uint64_t vals[2] ) {
    if (hw_shuffle) {
#if defined(HAVE_SSSE_3)
        const __m128i shuf = _mm_loadu_si128((const __m128i *)SHUFFLE_MASK);
        __m128i       data = _mm_loadu_si128((const __m128i *)vals        );
        data = _mm_shuffle_epi8(data, shuf);
        _mm_storeu_si128((__m128i *)vals, data);
#elif defined(HAVE_GENERIC_VECTOR) && defined(HAVE_GENERIC_VECTOR_SHUFFLE)
        typedef uint8_t vec16b VECTOR_SIZE( 16 );
        vec16b data, shuf;
        if (isBE()) {
            vals[0] = BSWAP64(vals[0]);
            vals[1] = BSWAP64(vals[1]);
        }
        memcpy(&data, vals        , 16);
        memcpy(&shuf, SHUFFLE_MASK, 16);
        data = VECTOR_SHUFFLE_1(data, shuf);
        memcpy(vals, &data, 16);
        if (isBE()) {
            vals[0] = BSWAP64(vals[0]);
            vals[1] = BSWAP64(vals[1]);
        }
#else
  #error "Not implemented yet"
#endif
    } else {
        vals[0] = BSWAP64(vals[0]);
        vals[1] = BSWAP64(vals[1]);
        std::swap(vals[0], vals[1]);
    }
}

template <bool hw_shuffle>
static void shuffle_and_add( uint64_t a[2], const uint64_t b[2] ) {
    // printf("preshuf aes %016lx %016lx\n", a[0], a[1]);
    shuffle<hw_shuffle>(a);
    // printf("posshuf aes %016lx %016lx\n", a[0], a[1]);
    a[0] += b[0];
    a[1] += b[1];
}

static void add_in_length( uint64_t enc[2], uint64_t len ) {
    enc[0] += len;
}

template <bool bswap, bool hw_shuffle>
static void hash_in( AHasher * s, uint64_t value[2] ) {
    // printf("hash_in aes %016lx %016lx\n", value[0], value[1]);
    // printf("hash_in aes <- %016lx %016lx %016lx %016lx\n",
    //        s->enc[0], s->enc[1], s->sum[0], s->sum[1]);
    aesenc<bswap>(s->enc, value);
    shuffle_and_add<hw_shuffle>(s->sum, value);
    // printf("hash_in aes -> %016lx %016lx %016lx %016lx\n",
    //       s->enc[0], s->enc[1], s->sum[0], s->sum[1]);
}

template <bool bswap, bool hw_shuffle>
static void add_data( AHasher * s, const uint8_t * RESTRICT data, const size_t len ) {
    uint64_t len128[2] = { (uint64_t)len, 0 };

    hash_in<bswap, hw_shuffle>(s, len128);
    add_in_length(s->enc, len);

    // printf("WRITE\n");
    if (len <= 8) {
        uint64_t value[2];
        read_small<bswap>(data, len, value);
        hash_in<bswap, hw_shuffle>(s, value);
    } else {
        if (len > 32) {
            if (len > 64) {
                uint64_t current[4][2];
                for (unsigned i = 0; i < 4; i++) {
                    current[i][0] = s->key[0];
                    current[i][1] = s->key[1];
                }
                uint64_t sum[2][2];
                for (unsigned i = 0; i < 2; i++) {
                    sum    [i][0] = s->key[0];
                    sum    [i][1] = s->key[1];
                }
                {
                    uint64_t tail[2];
                    tail[0]    = GET_U64<bswap>(data, len - 64     );
                    tail[1]    = GET_U64<bswap>(data, len - 64 +  8);
                    aesenc<bswap>(current[0], tail);
                    sum[0][0] += tail[0];
                    sum[0][1] += tail[1];

                    tail[0]    = GET_U64<bswap>(data, len - 64 + 16);
                    tail[1]    = GET_U64<bswap>(data, len - 64 + 24);
                    aesenc<bswap>(current[1], tail);
                    sum[1][0] += tail[0];
                    sum[1][1] += tail[1];

                    tail[0]    = GET_U64<bswap>(data, len - 64 + 32);
                    tail[1]    = GET_U64<bswap>(data, len - 64 + 40);
                    aesenc<bswap>(current[2], tail);
                    shuffle_and_add<hw_shuffle>(sum[0], tail);

                    tail[0]    = GET_U64<bswap>(data, len - 64 + 48);
                    tail[1]    = GET_U64<bswap>(data, len - 64 + 56);
                    aesenc<bswap>(current[3], tail);
                    shuffle_and_add<hw_shuffle>(sum[1], tail);
                }
                uint64_t blocks[2];
                size_t   l = len;
                while (l > 64) {
                    blocks[0] = GET_U64<bswap>(data, 0);
                    blocks[1] = GET_U64<bswap>(data, 8);
                    aesenc<bswap>(current[0], blocks);
                    shuffle_and_add<hw_shuffle>(sum[0], blocks);
                    data += 16;

                    blocks[0] = GET_U64<bswap>(data, 0);
                    blocks[1] = GET_U64<bswap>(data, 8);
                    aesenc<bswap>(current[1], blocks);
                    shuffle_and_add<hw_shuffle>(sum[1], blocks);
                    data += 16;

                    blocks[0] = GET_U64<bswap>(data, 0);
                    blocks[1] = GET_U64<bswap>(data, 8);
                    aesenc<bswap>(current[2], blocks);
                    shuffle_and_add<hw_shuffle>(sum[0], blocks);
                    data += 16;

                    blocks[0] = GET_U64<bswap>(data, 0);
                    blocks[1] = GET_U64<bswap>(data, 8);
                    aesenc<bswap>(current[3], blocks);
                    shuffle_and_add<hw_shuffle>(sum[1], blocks);
                    data += 16;

                    l -= 64;
                }
                aesenc<bswap>(current[0], current[1]);
                aesenc<bswap>(current[2], current[3]);
                hash_in<bswap, hw_shuffle>(s, current[0]);
                hash_in<bswap, hw_shuffle>(s, current[2]);

                sum[0][0] += sum[1][0];
                sum[0][1] += sum[1][1];
                hash_in<bswap, hw_shuffle>(s, sum[0]);
            } else {
                // len 33-64
                uint64_t head[2][2], tail[2][2];
                head[0][0] = GET_U64<bswap>(data,  0);
                head[0][1] = GET_U64<bswap>(data,  8);
                head[1][0] = GET_U64<bswap>(data, 16);
                head[1][1] = GET_U64<bswap>(data, 24);
                data += len - 32;
                tail[0][0] = GET_U64<bswap>(data,  0);
                tail[0][1] = GET_U64<bswap>(data,  8);
                tail[1][0] = GET_U64<bswap>(data, 16);
                tail[1][1] = GET_U64<bswap>(data, 24);

                hash_in<bswap, hw_shuffle>(s, head[0]);
                hash_in<bswap, hw_shuffle>(s, head[1]);
                hash_in<bswap, hw_shuffle>(s, tail[0]);
                hash_in<bswap, hw_shuffle>(s, tail[1]);
            }
        } else {
            if (len > 16) {
                // len 17-32
                uint64_t head[2], tail[2];
                head[0] = GET_U64<bswap>(data, 0);
                head[1] = GET_U64<bswap>(data, 8);
                data   += len - 16;
                tail[0] = GET_U64<bswap>(data, 0);
                tail[1] = GET_U64<bswap>(data, 8);

                hash_in<bswap, hw_shuffle>(s, head);
                hash_in<bswap, hw_shuffle>(s, tail);
            } else {
                // len 9-16
                uint64_t value[2];
                value[0] = GET_U64<bswap>(data,       0);
                value[1] = GET_U64<bswap>(data, len - 8);

                hash_in<bswap, hw_shuffle>(s, value);
            }
        }
    }
}

template <bool bswap>
static uint64_t finish( AHasher * s ) {
    uint64_t tmp[2] = { s->sum[0], s->sum[1] };

    aesdec<bswap>(tmp, s->enc);
    uint64_t combined[2] = { tmp[0], tmp[1] };
    aesenc<bswap>(combined, s->key);
    aesenc<bswap>(combined, tmp   );
    return combined[0];
}

//------------------------------------------------------------
// Fallback hash

// This constant comes from Kunth's prng (Empirically it works better than
// those from splitmix32).
static const uint64_t MULTIPLE = UINT64_C(6364136223846793005);

template <bool bigmult>
static uint64_t folded_multiply( uint64_t s, uint64_t by ) {
    if (bigmult) {
        // printf("FOLD %016lx %016lx -> ", s, by);
        MathMult::mult64_128(s, by, s, by);
        // printf("%016lx\n", s ^ by);
        return s ^ by;
    } else {
        uint64_t b1 = s * BSWAP64(by);
        uint64_t b2 = BSWAP64(s) * ~by;
        // printf("FOLD %016lx %016lx -> %016lx\n", s, by, b1 ^ BSWAP64(b2));
        return b1 ^ BSWAP64(b2);
    }
}

typedef struct {
    uint64_t  buffer;
    uint64_t  pad;
    uint64_t  extra_keys[2];
} AFBHasher;

static void fb_from_random_state( AFBHasher * s, const uint64_t random_state[4] ) {
    s->buffer        = random_state[0];
    s->pad           = random_state[1];
    s->extra_keys[0] = random_state[2];
    s->extra_keys[1] = random_state[3];
    // printf("FRS fallback %016lx %016lx %016lx %016lx\n",
    // random_state[0],random_state[1],random_state[2],random_state[3]);
}

template <bool bigmult>
static void large_update( AFBHasher * s, const uint64_t block[2] ) {
    // printf("fallback large_update %016lx %016lx\n", block[0], block[1]);
    uint64_t combined = folded_multiply<bigmult>(block[0] ^ s->extra_keys[0], block[1] ^ s->extra_keys[1]);

    s->buffer += s->pad;
    s->buffer ^= combined;
    s->buffer  = ROTL64(s->buffer, 23);
}

template <bool bswap, bool bigmult>
static void fb_add_data( AFBHasher * s, const uint8_t * RESTRICT data, const size_t len ) {
    // printf("fallback update %016lx\n", (uint64_t)len);
    s->buffer ^= (uint64_t)len;
    s->buffer  = folded_multiply<bigmult>(s->buffer, MULTIPLE);
    // printf("fallback write %016lx\n", (uint64_t)len);
    s->buffer += (uint64_t)len;
    s->buffer *= MULTIPLE;
    if (len > 8) {
        if (len > 16) {
            uint64_t tail[2];
            tail[0] = GET_U64<bswap>(data, len - 16);
            tail[1] = GET_U64<bswap>(data, len -  8);
            large_update<bigmult>(s, tail);

            uint64_t block[2];
            size_t   l = len;
            while (l > 16) {
                block[0] = GET_U64<bswap>(data, 0);
                block[1] = GET_U64<bswap>(data, 8);
                large_update<bigmult>(s, block);
                l       -= 16;
                data    += 16;
            }
        } else {
            uint64_t block[2];
            block[0] = GET_U64<bswap>(data,   0    );
            block[1] = GET_U64<bswap>(data, len - 8);
            large_update<bigmult>(s, block);
        }
    } else {
        uint64_t value[2];
        read_small<bswap>(data, len, value);
        large_update<bigmult>(s, value);
    }
}

template <bool bigmult>
static uint64_t fb_finish( AFBHasher * s ) {
    uint64_t r = folded_multiply<bigmult>(s->buffer, s->pad);

    r = ROTL64(r, s->buffer & 63);
    return r;
}

//------------------------------------------------------------
template <bool bswap, bool hw_shuffle>
static void rust_ahash( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint64_t * random_state = (const uint64_t *)(void *)(uintptr_t)seed;
    AHasher          hasher;
    uint64_t         hash;

    from_random_state(&hasher, random_state);
    add_data<bswap, hw_shuffle>(&hasher, (const uint8_t *)in, len);
    hash = finish<bswap>(&hasher);
    // printf("HASH %zd\t%016lx\n", len, hash);
    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}

template <bool bswap, bool bigmult>
static void rust_ahash_fb( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint64_t * random_state = (const uint64_t *)(void *)(uintptr_t)seed;
    AFBHasher        hasher;
    uint64_t         hash;

    fb_from_random_state(&hasher, random_state);
    fb_add_data<bswap, bigmult>(&hasher, (const uint8_t *)in, len);
    hash = fb_finish<bigmult>(&hasher);
    // printf("%zd\t%016lx\n", len, hash);
    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(rust_ahash,
   $.src_url    = "https://github.com/tkaitchuck/aHash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(rust_ahash,
   $.desc            = "aHash (ported from Rust, AES-based version)",
   $.sort_order      = 0,
   $.hash_flags      =
         FLAG_HASH_AES_BASED     |
         FLAG_HASH_XL_SEED       ,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.verification_LE = 0x39BA33B2,
   $.verification_BE = 0x429DE41B,
   $.hashfn_native   = rust_ahash<false, true>,
   $.hashfn_bswap    = rust_ahash<true, true>,
   $.seedfn          = init_state
 );

REGISTER_HASH(rust_ahash__noshuf,
   $.desc            = "aHash (ported from Rust, AES-based version, without SSSE3 shuffle)",
   $.sort_order      = 10,
   $.hash_flags      =
         FLAG_HASH_AES_BASED     |
         FLAG_HASH_XL_SEED       ,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.verification_LE = 0x7C9B210C,
   $.verification_BE = 0x372595BE,
   $.hashfn_native   = rust_ahash<false, false>,
   $.hashfn_bswap    = rust_ahash<true, false>,
   $.seedfn          = init_state
 );

REGISTER_HASH(rust_ahash_fb,
   $.desc            = "aHash (ported from Rust, fallback version)",
   $.sort_order      = 20,
   $.hash_flags      =
         FLAG_HASH_XL_SEED         ,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128 |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_ROTATE_VARIABLE |
         FLAG_IMPL_LICENSE_MIT     ,
   $.bits            = 64,
   $.verification_LE = 0x6241D275,
   $.verification_BE = 0x3C9E98E0,
   $.hashfn_native   = rust_ahash_fb<false, true>,
   $.hashfn_bswap    = rust_ahash_fb<true, true>,
   $.seedfn          = init_state
 );

REGISTER_HASH(rust_ahash_fb__nofold,
   $.desc            = "aHash (ported from Rust, fallback version, folded_multiply disabled)",
   $.sort_order      = 30,
   $.hash_flags      =
         FLAG_HASH_XL_SEED         ,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY        |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_ROTATE_VARIABLE |
         FLAG_IMPL_LICENSE_MIT     ,
   $.bits            = 64,
   $.verification_LE = 0xF5A72075,
   $.verification_BE = 0x12DE4593,
   $.hashfn_native   = rust_ahash_fb<false, false>,
   $.hashfn_bswap    = rust_ahash_fb<true, false>,
   $.seedfn          = init_state
 );
