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

// This is unused in this configuration
//static const uint64_t PI[4] = {
//    UINT64_C(0x243f6a8885a308d3), UINT64_C(0x13198a2e03707344),
//    UINT64_C(0xa4093822299f31d0), UINT64_C(0x082efa98ec4e6c89),
//};

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

#define AHASH_SHUFFLE_SSSE3    0
#define AHASH_SHUFFLE_GVEC     1
#define AHASH_SHUFFLE_PORTABLE 2

static const char * ahash_shuffle_str[] = {
    "ssse3",       // AHASH_SHUFFLE_SSSE3
    "gvec",        // AHASH_SHUFFLE_GVEC
    "portable",    // AHASH_SHUFFLE_PORTABLE
};

static_assert(sizeof(SHUFFLE_MASK) == 16, "shuffle() assumes a 16-byte shuffle");

template <bool hw_shuffle>
static void shuffle( uint64_t vals[2] ) {
    if (hw_shuffle) {
#if defined(HAVE_SSSE_3)
  #define AHASH_SHUFFLE AHASH_SHUFFLE_SSSE3
        const __m128i shuf = _mm_loadu_si128((const __m128i *)SHUFFLE_MASK);
        __m128i       data = _mm_loadu_si128((const __m128i *)vals        );
        data = _mm_shuffle_epi8(data, shuf);
        _mm_storeu_si128((__m128i *)vals, data);
#elif defined(HAVE_GENERIC_VECTOR) && defined(HAVE_GENERIC_VECTOR_SHUFFLE)
  #define AHASH_SHUFFLE AHASH_SHUFFLE_GVEC
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
  #define AHASH_SHUFFLE AHASH_SHUFFLE_PORTABLE
        uint8_t   tmp[16];
        uint8_t * valptr = (uint8_t *)&vals[0];
        if (isBE()) {
            vals[0] = BSWAP64(vals[0]);
            vals[1] = BSWAP64(vals[1]);
        }
        for (size_t i = 0; i < 16; i++) {
            tmp[i] = valptr[SHUFFLE_MASK[i]];
        }
        memcpy(valptr, &tmp[0], 16);
        if (isBE()) {
            vals[0] = BSWAP64(vals[0]);
            vals[1] = BSWAP64(vals[1]);
        }
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
    aesdec<bswap>(s->enc, value);
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
                sum[0][0] = s->key[0];
                sum[0][1] = s->key[1];
                sum[1][0] = ~s->key[0];
                sum[1][1] = ~s->key[1];
                {
                    uint64_t tail[2];
                    tail[0]    = GET_U64<bswap>(data, len - 64     );
                    tail[1]    = GET_U64<bswap>(data, len - 64 +  8);
                    aesenc<bswap>(current[0], tail);
                    sum[0][0] += tail[0];
                    sum[0][1] += tail[1];

                    tail[0]    = GET_U64<bswap>(data, len - 64 + 16);
                    tail[1]    = GET_U64<bswap>(data, len - 64 + 24);
                    aesdec<bswap>(current[1], tail);
                    sum[1][0] += tail[0];
                    sum[1][1] += tail[1];

                    tail[0]    = GET_U64<bswap>(data, len - 64 + 32);
                    tail[1]    = GET_U64<bswap>(data, len - 64 + 40);
                    aesenc<bswap>(current[2], tail);
                    shuffle_and_add<hw_shuffle>(sum[0], tail);

                    tail[0]    = GET_U64<bswap>(data, len - 64 + 48);
                    tail[1]    = GET_U64<bswap>(data, len - 64 + 56);
                    aesdec<bswap>(current[3], tail);
                    shuffle_and_add<hw_shuffle>(sum[1], tail);
                }
                uint64_t blocks[2];
                size_t   l = len;
                while (l > 64) {
                    blocks[0] = GET_U64<bswap>(data, 0);
                    blocks[1] = GET_U64<bswap>(data, 8);
                    aesdec<bswap>(current[0], blocks);
                    shuffle_and_add<hw_shuffle>(sum[0], blocks);
                    data += 16;

                    blocks[0] = GET_U64<bswap>(data, 0);
                    blocks[1] = GET_U64<bswap>(data, 8);
                    aesdec<bswap>(current[1], blocks);
                    shuffle_and_add<hw_shuffle>(sum[1], blocks);
                    data += 16;

                    blocks[0] = GET_U64<bswap>(data, 0);
                    blocks[1] = GET_U64<bswap>(data, 8);
                    aesdec<bswap>(current[2], blocks);
                    shuffle_and_add<hw_shuffle>(sum[0], blocks);
                    data += 16;

                    blocks[0] = GET_U64<bswap>(data, 0);
                    blocks[1] = GET_U64<bswap>(data, 8);
                    aesdec<bswap>(current[3], blocks);
                    shuffle_and_add<hw_shuffle>(sum[1], blocks);
                    data += 16;

                    l -= 64;
                }
                hash_in<bswap, hw_shuffle>(s, current[0]);
                hash_in<bswap, hw_shuffle>(s, current[1]);
                hash_in<bswap, hw_shuffle>(s, current[2]);
                hash_in<bswap, hw_shuffle>(s, current[3]);
                hash_in<bswap, hw_shuffle>(s, sum[0]);
                hash_in<bswap, hw_shuffle>(s, sum[1]);
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
    uint64_t combined     [2] = { s->sum[0], s->sum[1] };

    aesenc<bswap>(combined, s->enc);
    uint64_t combined_prev[2] = { combined[0], combined[1] };
    aesdec<bswap>(combined, s->key       );
    aesdec<bswap>(combined, combined_prev);
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
    s->buffer        = random_state[1];
    s->pad           = random_state[0];
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
   $.impl            = ahash_shuffle_str[AHASH_SHUFFLE],
   $.sort_order      = 0,
   $.hash_flags      =
         FLAG_HASH_AES_BASED     |
         FLAG_HASH_XL_SEED       ,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.verification_LE = 0x3BF4383B,
   $.verification_BE = 0x1B4F8057,
   $.hashfn_native   = rust_ahash<false, true>,
   $.hashfn_bswap    = rust_ahash<true, true>,
   $.seedfn          = init_state
 );

REGISTER_HASH(rust_ahash__noshuf,
   $.desc            = "aHash (ported from Rust, AES-based version, without shuffle)",
   $.sort_order      = 10,
   $.hash_flags      =
         FLAG_HASH_AES_BASED     |
         FLAG_HASH_XL_SEED       ,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.verification_LE = 0x84CD29E5,
   $.verification_BE = 0x5CC04B62,
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
   $.verification_LE = 0x53C9F167,
   $.verification_BE = 0x0AB24D79,
   $.hashfn_native   = rust_ahash_fb<false, true>,
   $.hashfn_bswap    = rust_ahash_fb<true, true>,
   $.seedfn          = init_state,
   $.seedfixfn       = excludeBadseeds,
   $.badseeddesc     = "Many bad seeds, unsure of details; see rust-ahash.cpp for examples",
   $.badseeds        = {
            0x0004063d, 0x0013d513, 0x001f1935, 0x00339a4f, 0x00519a91, 0x005292a9, 0x005959a8, 0x005d3303,
            0x006091ea, 0x0061e1b8, 0x0071f2c5, 0x007824f7, 0x008a3ec0, 0x008abac4, 0x008d1a78, 0x008e1a0d,
            0x008e4289, 0x00913f3d, 0x0091b9f4, 0x0095c37f, 0x00a59ce9, 0x00b28517, 0x00c61c20, 0x00cca04c,
            0x00d925bc, 0x00e9c524, 0x00ef6c12, 0x00fe7dc6, 0x01033705, 0x0124ba2a, 0x01381eae, 0x014a8bf4,
            0x014bc4d4, 0x0152f835, 0x016f3c9e, 0x01a77d45, 0x01c98045, 0x025a035f, 0x026019a8, 0x0275c8f0,
            0x0278b009, 0x02ad401d, 0x030948b5, 0x030a2d7d, 0x03113e3d, 0x03160588, 0x032323f1, 0x032e95c6,
            0x0333fbd4, 0x03418b51, 0x034605e2, 0x034ac442, 0x03517309, 0x035b184b, 0x035b6c14, 0x0363e396,
            0x036402a0, 0x03674200, 0x036a5528, 0x036ce816, 0x038e1a59, 0x039c7174, 0x03a67d2a, 0x03d07823,
            0x03e06864, 0x03e10e1d, 0x03f8b1d2, 0x04103bb0, 0x046ef942, 0x0481daca, 0x048404c8, 0x0487e218,
            0x049d3bdf, 0x04ad94f7, 0x04b9a1b4, 0x04bd1d64, 0x04c02b38, 0x04c3c3f5, 0x04d63b58, 0x04dd8ad1,
            0x04e9370b, 0x04ef214d, 0x05074b74, 0x0529fbee, 0x052dfdbe, 0x053d4301, 0x05532e0a, 0x05588a81,
            0x058464c7, 0x05fa8b97, 0x061f2bff, 0x064cac35, 0x066a9700, 0x066b2020, 0x0673cd46, 0x06a0884c,
            0x06acaffc, 0x06bce0f6, 0x06c3c09c, 0x06f20f56, 0x07025eff, 0x0739868d, 0x0747030c, 0x07680a9d,
            0x07865f8c, 0x079f4bbc, 0x07b0ca54, 0x07ec3d3d, 0x081484fe, 0x08204a1b, 0x08214342, 0x0841118c,
            0x08484a79, 0x085e282b, 0x085fecdb, 0x08690336, 0x08711e0e, 0x08806a45, 0x08890592, 0x088b8741,
            0x089a41c1, 0x089abcb4, 0x08a058e3, 0x08a67ae3, 0x08a9b32b, 0x08b0ec33, 0x08b1fa81, 0x08b37f41,
            0x08cb9d5b, 0x08e417be, 0x08fa9444, 0x09024a25, 0x090ee4c1, 0x091e45e7, 0x0930ac30, 0x093a56f6,
            0x094ba64e, 0x0950643c, 0x0950bab3, 0x09592737, 0x095be514, 0x095e0c82, 0x096235cb, 0x09769c0a,
            0x097cfbf2, 0x099ae285, 0x0a5008b5, 0x0a6d9f75, 0x0a814e0b, 0x0a8d348f, 0x0a91d4f8, 0x0a96bbec,
            0x0a9b0cc8, 0x0aa3f8d7, 0x0ab0d332, 0x0ab1acfd, 0x0ab26ada, 0x0abf9579, 0x0ade63c6, 0x0ae7e082,
            0x0af2701b, 0x0b09afde, 0x0b09bf67, 0x0b260017, 0x0b276c2f, 0x0b40d1ac, 0x0b486447, 0x0b48ca59,
            0x0b4bf548, 0x0b5185ec, 0x0b56b082, 0x0b603c35, 0x0b6162c7, 0x0b6710e8, 0x0b804971, 0x0b99c489,
            0x0b9a4df9, 0x0ba1bd9c, 0x0ba6e394, 0x0ba99693, 0x0be401fb, 0x0be4e71b, 0x0be9b5a8, 0x0beb403c,
            0x0c4beec6, 0x0cad524f, 0x0cb0ca35, 0x0d16f342, 0x0d4b03c1, 0x0dab3740, 0x0e44cd77, 0x0e70f938,
            0x0f2bb081, 0x0f607fde, 0x100e6d69, 0x101b1053, 0x1027d400, 0x10352f52, 0x1036ca9b, 0x10406bc1,
            0x104ba34b, 0x105072b7, 0x106c8126, 0x10909d02, 0x109470b2, 0x109be6e3, 0x109d1794, 0x109edec8,
            0x10a10f89, 0x10a37dc3, 0x10a44536, 0x10b77dd5, 0x10ce66c1, 0x10ef738c, 0x10f3ffd4, 0x10f887ac,
            0x1106651c, 0x11084c79, 0x1108581b, 0x1134ea9b, 0x11483008, 0x114ea20b, 0x115ab54b, 0x115cc740,
            0x116c4b20, 0x116fbd53, 0x117c813f, 0x1190f79b, 0x11a701f7, 0x11b5e21b, 0x11cfd4c8, 0x11d05434,
            0x11d8d0de, 0x1200ac1b, 0x12202282, 0x122751c1, 0x122c03f5, 0x123b283a, 0x123f7bac, 0x1251122c,
            0x1254b53f, 0x12594c59, 0x127c9ffd, 0x128ff7c1, 0x1295ec49, 0x129fc7c7, 0x12a51abe, 0x12b39c34,
            0x12b49ce0, 0x12bba2a9, 0x12cf8e38, 0x13039b75, 0x130a4975, 0x1310eeb3, 0x131cd8dd, 0x1332f15e,
            0x133515e1, 0x134d3395, 0x135a9511, 0x135e2f8b, 0x135e8485, 0x135ff3e9, 0x1367028e, 0x1367dedd,
            0x136a40b3, 0x136cbb73, 0x136df408, 0x136f4ed1, 0x1370e160, 0x138d0952, 0x13aff422, 0x13beecde,
            0x13bf4346, 0x13cde290, 0x13d23429, 0x13fbfdde, 0x13fef5bc, 0x14084874, 0x141298dc, 0x143df974,
            0x1468fbf5, 0x148571a1, 0x1485d67c, 0x148f0f61, 0x149f8de8, 0x14a3cf3c, 0x14a64cbd, 0x14ae593f,
            0x14b749f3, 0x14cb759c, 0x14e255a9, 0x14e26154, 0x14e2644b, 0x14e3fbcd, 0x14e44793, 0x14e68cd4,
            0x1511df47, 0x151d2c63, 0x1538a08a, 0x1543a203, 0x15440ad2,
            0xffffffff00342258, 0xffffffff00666de2, 0xffffffff00a45aa4, 0xffffffff00a7f3ae,
            0xffffffff00abcb21, 0xffffffff00b59415, 0xffffffff00f23532, 0xffffffff0157f4ed,
            0xffffffff022ffee3, 0xffffffff023aeb46, 0xffffffff0266083f, 0xffffffff02684cc7,
            0xffffffff026ba10c, 0xffffffff02a84840, 0xffffffff02a8f0b4, 0xffffffff02acb85b,
            0xffffffff02b043df, 0xffffffff02b4e209, 0xffffffff03625497, 0xffffffff0362d256,
            0xffffffff036fc920, 0xffffffff0371aa2a, 0xffffffff03a02c63, 0xffffffff03ac1403,
            0xffffffff03e21022, 0xffffffff03e5bd50, 0xffffffff040ada56, 0xffffffff0481c3a4,
            0xffffffff049fd543, 0xffffffff04a49d23, 0xffffffff04ab4809, 0xffffffff04de0262,
            0xffffffff04e564a0, 0xffffffff04fb2bbc, 0xffffffff04fe3d1a, 0xffffffff0544b98a,
            0xffffffff054cc7ba, 0xffffffff0579f727, 0xffffffff05b1e7a8, 0xffffffff05dd21c7,
            0xffffffff06131a06, 0xffffffff064c5657, 0xffffffff065198c6, 0xffffffff06b70aa9,
            0xffffffff070cf821, 0xffffffff071c7f7a, 0xffffffff0720fbc6, 0xffffffff072d00e5,
            0xffffffff07332e52, 0xffffffff0744d9a3, 0xffffffff0755fbb9, 0xffffffff075fc8f3,
            0xffffffff0760831d, 0xffffffff076399be, 0xffffffff0764586e, 0xffffffff0764f400,
            0xffffffff0766e1df, 0xffffffff077a9836, 0xffffffff077e005c, 0xffffffff0797eaf6,
            0xffffffff07be24d9, 0xffffffff07d35f27, 0xffffffff07d7dd3c, 0xffffffff07ed5ee2,
            0xffffffff07edeb31, 0xffffffff07f94367, 0xffffffff0805eff4, 0xffffffff081f25d4,
            0xffffffff08294367, 0xffffffff089aa634, 0xffffffff089f3202, 0xffffffff08cd6cae,
            0xffffffff08e71ec9, 0xffffffff09158bcc, 0xffffffff0a2dc4bc, 0xffffffff0a4c73c0,
            0xffffffff0a68712e, 0xffffffff0a81ac38, 0xffffffff0a8b3419, 0xffffffff0aa374b6,
            0xffffffff0ae16e91, 0xffffffff0aea64d4, 0xffffffff0b06bc41, 0xffffffff0b1274eb,
            0xffffffff0b13d4cd, 0xffffffff0b291c9b, 0xffffffff0b3614ae, 0xffffffff0b673eaf,
            0xffffffff0b6e797c, 0xffffffff0ba38bb0, 0xffffffff0bada057, 0xffffffff0be4cc16,
            0xffffffff0c00b4ea, 0xffffffff0c358be8, 0xffffffff0c3e1f81, 0xffffffff0c70e904,
            0xffffffff0c8c9100, 0xffffffff0c911d5d, 0xffffffff0c9cf0e9, 0xffffffff0ca2162b,
            0xffffffff0ca8686e, 0xffffffff0cb1bd8c, 0xffffffff0cbe1614, 0xffffffff0cc0e5cc,
            0xffffffff0cc18a84, 0xffffffff0cc59702, 0xffffffff0cdab5c8, 0xffffffff0cf1e246,
            0xffffffff0cf93aea, 0xffffffff0d456de4, 0xffffffff0d9884eb, 0xffffffff0db782bb,
            0xffffffff0db9077e, 0xffffffff0e6154ab, 0xffffffff0e65b0b0, 0xffffffff0eb40500,
            0xffffffff0f1d09ea, 0xffffffff0f2cb291, 0xffffffff0f48be0c, 0xffffffff0f63b6eb,
            0xffffffff0f63dbc0, 0xffffffff0f6986a2, 0xffffffff0f6f61fc, 0xffffffff0f7182f0,
            0xffffffff0f71bfe1, 0xffffffff0f77d660, 0xffffffff0f793239, 0xffffffff0f7e9cbd,
            0xffffffff0f8d7d55, 0xffffffff0f9c9cea, 0xffffffff0fc224b6, 0xffffffff0feb2780,
            0xffffffff0ffaccdd, 0xffffffff10546528, 0xffffffff10b0aad5, 0xffffffff10b96d77,
            0xffffffff10c6caa7, 0xffffffff10eeb269, 0xffffffff114fade3, 0xffffffff11d989c3,
            0xffffffff12016b3c, 0xffffffff120a132a, 0xffffffff1212f2c7, 0xffffffff1236ca1e,
            0xffffffff1251090c, 0xffffffff12bd8751, 0xffffffff1330bc5c, 0xffffffff1338e534,
            0xffffffff134bc3ed, 0xffffffff134de8df, 0xffffffff134f756d, 0xffffffff136b33a3,
            0xffffffff1376ee5e, 0xffffffff137ca68e, 0xffffffff137df22a, 0xffffffff13c070ac,
            0xffffffff14021b27, 0xffffffff1404267f, 0xffffffff142114ea, 0xffffffff1424db1f,
            0xffffffff1439097d, 0xffffffff1462dcb2, 0xffffffff147ca30a, 0xffffffff14821dc9,
            0xffffffff14a24cdf, 0xffffffff14a27e04, 0xffffffff14adb4b6, 0xffffffff14b1a377,
            0xffffffff14b7cbc3, 0xffffffff14bb2e3f, 0xffffffff14bbbaa2, 0xffffffff14bf8ee3,
            0xffffffff14c725dc, 0xffffffff14e1aa5a, 0xffffffff14e84304, 0xffffffff14fe7520,
            0xffffffff1503252d, 0xffffffff1519fb84, 0xffffffff15280340, 0xffffffff152eac9c,
            0xffffffff1533d738, 0xffffffff15434168, 0xffffffff15705150, 0xffffffff15ad756b,
            0xffffffff15b4f77e, 0xffffffff15bf63db, 0xffffffff15c1a9f6, 0xffffffff15c23f77,
            0xffffffff16272d5c, 0xffffffff16273fe8, 0xffffffff16804a23, 0xffffffff168123d9,
            0xffffffff16a90b3c, 0xffffffff16ac0b77, 0xffffffff16adb7d5, 0xffffffff16c70dfb,
            0xffffffff16d4f0e0, 0xffffffff170c1ed6, 0xffffffff17236a16, 0xffffffff17316215,
            0xffffffff1733c0a4, 0xffffffff17441112, 0xffffffff174de8df, 0xffffffff1753e584,
            0xffffffff1762d901, 0xffffffff17649e6e, 0xffffffff1774535e, 0xffffffff179d7866,
            0xffffffff179e23a3, 0xffffffff17ab101b, 0xffffffff17f663a4, 0xffffffff17f89a9b,
            0xffffffff18117ba8, 0xffffffff183155e3, 0xffffffff1843c509, 0xffffffff1844862e,
            0xffffffff1871fcb6, 0xffffffff18783eee, 0xffffffff18a2fb6f, 0xffffffff18a47a8d,
            0xffffffff18a4cece, 0xffffffff18a7e2fd, 0xffffffff18a88b1f, 0xffffffff18a8e5ae,
            0xffffffff18aaaf39, 0xffffffff18bd03f7, 0xffffffff18de28e4, 0xffffffff18e86bd4,
            0xffffffff18fec31a, 0xffffffff1935cfdc, 0xffffffff1969bce5, 0xffffffff196ce6ad,
            0xffffffff19834528, 0xffffffff198cb620, 0xffffffff19d969c6, 0xffffffff19e5d857,
            0xffffffff19ebc29d, 0xffffffff19f50e46, 0xffffffff19fc11fb, 0xffffffff1a2ff8f1,
            0xffffffff1a57e8d2, 0xffffffff1a6e501e, 0xffffffff1a81c07c, 0xffffffff1a83ac56,
            0xffffffff1a8b1ba3, 0xffffffff1aa1b4cf, 0xffffffff1aa8c248, 0xffffffff1ae7005f,
            0xffffffff1aea686e, 0xffffffff1b034942, 0xffffffff1b10b4df, 0xffffffff1b3c1539,
            0xffffffff1b65db55, 0xffffffff1b68175d, 0xffffffff1b71f4b1, 0xffffffff1b731f5d,
            0xffffffff1b7770d1, 0xffffffff1b7f1b79, 0xffffffff1b841989, 0xffffffff1b94e5a6,
            0xffffffff1bbf847b, 0xffffffff1be231df, 0xffffffff1c041efe, 0xffffffff1c25a78b,
            0xffffffff1c33e25f, 0xffffffff1c6cfa2a, 0xffffffff1c6f501c, 0xffffffff1c7e7a1c,
            0xffffffff1c8538aa, 0xffffffff1c8ac207, 0xffffffff1ca55e69, 0xffffffff1ca61127,
            0xffffffff1ca95b24, 0xffffffff1cbb996d, 0xffffffff1ccb72ef, 0xffffffff1cddd2dc,
            0xffffffff1ceea139, 0xffffffff1cfd0eb5, 0xffffffff1cfe981d, 0xffffffff1d07dbdc,
            0xffffffff1d2945cb, 0xffffffff1d6de83d, 0xffffffff1d974d50, 0xffffffff1da642d5,
            0xffffffff1da814d5, 0xffffffff1db29bfd, 0xffffffff1e05019f, 0xffffffff1e2c8e14,
            0xffffffff1e4c4c60, 0xffffffff1e6a3391, 0xffffffff1e6ce399, 0xffffffff1e6da5a7,
            0xffffffff1e6fb30c, 0xffffffff1e7678aa, 0xffffffff1e7c4456, 0xffffffff1e883782,
            0xffffffff1ea6b95f, 0xffffffff1ea9a8d7, 0xffffffff1ebea490, 0xffffffff1f033ba4,
            0xffffffff1f2a7dda
        }
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
   $.verification_LE = 0x3FDD068C,
   $.verification_BE = 0x87A5FD69,
   $.hashfn_native   = rust_ahash_fb<false, false>,
   $.hashfn_bswap    = rust_ahash_fb<true, false>,
   $.seedfn          = init_state
 );
