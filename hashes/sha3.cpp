/*
 * SHA3-256 hash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2015-2020 brainhub
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
 *
 * based on public domain code from:
 *     Aug 2015. Andrey Jivsov. crypto@brainhub.org
 */
#include "Platform.h"
#include "Hashlib.h"

#include <cassert>

/* 'Words' here refers to uint64_t */
#define SHA3_KECCAK_SPONGE_WORDS (((1600) / 8 /*bits to byte*/) / sizeof(uint64_t))
#define SHA3_KECCAK_ROUNDS 24

typedef struct sha3_context_ {
    uint64_t  s[SHA3_KECCAK_SPONGE_WORDS]; /* Keccak's state */
    uint64_t  saved;                       /*
                                            *         the portion of the input message that we
                                            * didn't consume yet
                                            */
    uint32_t  byteIndex;                   /*
                                            *         0..7--the next byte after the set one
                                            * (starts from 0; 0--none are buffered)
                                            */
    uint32_t  wordIndex;                   /*
                                            *         0..24--the next word to integrate input
                                            * (starts from 0)
                                            */
    uint32_t  capacityWords;               /*
                                            *         the double size of the hash output in
                                            * words (e.g. 16 for Keccak 512)
                                            */
} sha3_context;

static const uint64_t keccakf_rndc[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
};

static const unsigned keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static void keccakf( uint64_t s[25] ) {
    int      i, j, round;
    uint64_t t, bc[5];

    for (round = 0; round < SHA3_KECCAK_ROUNDS; round++) {
        /* Theta */
        for (i = 0; i < 5; i++) {
            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
        }

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                s[j + i] ^= t;
            }
        }
        /* Rho Pi */
        t = s[1];
        for (i = 0; i < 24; i++) {
            j     = keccakf_piln[i];
            bc[0] = s [j];
            s[j]  = ROTL64(t, keccakf_rotc[i]);
            t     = bc[0];
        }
        /* Chi */
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                bc[i] = s[j + i];
            }
            for (i = 0; i < 5; i++) {
                s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }
        /* Iota */
        s[0] ^= keccakf_rndc[round];
    }
}

static void sha3_Init( sha3_context * ctx, unsigned bitSize ) {
    assert(bitSize == 256 || bitSize == 384 || bitSize == 512);
    memset(ctx, 0, sizeof(*ctx));
    ctx->capacityWords = 2 * bitSize / (8 * sizeof(uint64_t));
}

/*
 * Homegrown SHA3 seeding -- alter the capacity bytes so that merely
 * changing the hashed bytes cannot easily reveal the seed nor
 * trivially collide the hash state.
 */
static void sha3_Seed( sha3_context * ctx, uint64_t seed ) {
    if (ctx->capacityWords >= 2) {
        ctx->s[SHA3_KECCAK_SPONGE_WORDS - 2] ^= seed;
        ctx->s[SHA3_KECCAK_SPONGE_WORDS - 1] ^= seed * UINT64_C(0x9E3779B97F4A7C15);
    } else {
        ctx->s[SHA3_KECCAK_SPONGE_WORDS - 1] ^= seed;
    }
}

template <bool bswap>
static void sha3_Process( sha3_context * ctx, const uint8_t * in, size_t inlen ) {
    /* 0...7 -- how much is needed to have a word */
    uint32_t old_tail = (8 - ctx->byteIndex) & 7;
    uint32_t tail;
    size_t   words, i;

    if (inlen == 0) { return; } /* nothing to do */

    if (inlen < old_tail) { /* have no complete word or haven't started the word yet */
        while (inlen--) {
            ctx->saved |= (uint64_t)(*(in++)) << ((ctx->byteIndex++) * 8);
        }
        return;
    }

    if (old_tail) { /* will have one word to process */
        inlen -= old_tail;
        while (old_tail--) {
            ctx->saved |= (uint64_t)(*(in++)) << ((ctx->byteIndex++) * 8);
        }

        /* now ready to add saved to the sponge */
        ctx->s[ctx->wordIndex] ^= ctx->saved;
        ctx->byteIndex          = 0;
        ctx->saved = 0;
        if (++ctx->wordIndex == (SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
            keccakf(ctx->s);
            ctx->wordIndex = 0;
        }
    }

    /* now work in full words directly from input */
    words = inlen         / sizeof(uint64_t);
    tail  = inlen - words * sizeof(uint64_t);

    for (i = 0; i < words; i++, in += sizeof(uint64_t)) {
        uint64_t t = GET_U64<bswap>(in, 0);
        ctx->s[ctx->wordIndex] ^= t;
        if (++ctx->wordIndex == (SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
            keccakf(ctx->s);
            ctx->wordIndex = 0;
        }
    }

    /* finally, save the partial word */
    while (tail--) {
        ctx->saved |= (uint64_t)(*(in++)) << ((ctx->byteIndex++) * 8);
    }
    return;
}

template <bool bswap>
static void sha3_Finalize( sha3_context * ctx, size_t digest_words, uint8_t * digest ) {
    /*
     * Append 2-bit suffix 01, per SHA-3 spec. Instead of 1 for padding
     * we use 1<<2 below. The 0x02 below corresponds to the suffix 01.
     * Overall, we feed 0, then 1, and finally 1 to start
     * padding. Without M || 01, we would simply use 1 to start padding.
     */
    uint64_t t = (uint64_t)(((uint64_t)(0x02 | (1 << 2))) << ((ctx->byteIndex) * 8));

    ctx->s[ctx->wordIndex] ^= ctx->saved ^ t;
    ctx->s[SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords - 1] ^= UINT64_C(0x8000000000000000);
    keccakf(ctx->s);

    uint32_t maxdigest_words = ctx->capacityWords / 2;
    if (digest_words > maxdigest_words) { digest_words = maxdigest_words; }
    for (size_t i = 0; i < digest_words; i++) {
        PUT_U64<bswap>(ctx->s[i], digest, 8 * i);
    }

    return;
}

template <uint32_t hashbits, bool bswap>
static void SHA3_256( const void * in, const size_t len, const seed_t seed, void * out ) {
    sha3_context context;

    sha3_Init(&context, 256);
    sha3_Seed(&context, (uint64_t)seed);
    sha3_Process<bswap>(&context, (const uint8_t *)in, len);
    sha3_Finalize<bswap>(&context, (hashbits + 63) / 64, (uint8_t *)out);
}

REGISTER_FAMILY(sha3,
   $.src_url    = "https://github.com/brainhub/SHA3IUF",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(SHA_3_256__64,
   $.desc       = "SHA-3, bits 0-63",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 64,
   $.verification_LE = 0x76804BEC,
   $.verification_BE = 0xC7D2D825,
   $.hashfn_native   = SHA3_256<64, false>,
   $.hashfn_bswap    = SHA3_256<64, true>
 );

REGISTER_HASH(SHA_3,
   $.desc       = "SHA-3",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 256,
   $.verification_LE = 0x79AEFB60,
   $.verification_BE = 0x074CB90C,
   $.hashfn_native   = SHA3_256<256, false>,
   $.hashfn_bswap    = SHA3_256<256, true>
 );
