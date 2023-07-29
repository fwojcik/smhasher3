/*
 * BLAKE2 hashes
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
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
 * based on:
 *     BLAKE2 reference source code package - reference C implementations
 * used under terms of CC0.
 */
#include "Platform.h"
#include "Hashlib.h"

static const uint64_t blake2b_IV [ 8]     = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)
};

static const uint32_t blake2s_IV [ 8]     = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

#if !defined(HAVE_SSE_2)
static const uint8_t blake2_sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};
#endif

typedef struct blake2b_context_ {
    uint64_t  h[8];
    uint64_t  t[2];
    uint64_t  f[2];
    uint8_t   buf[128];
    size_t    buflen;
} blake2b_context;

typedef struct blake2s_context_ {
    uint32_t  h[8];
    uint32_t  t[2];
    uint32_t  f[2];
    uint8_t   buf[64];
    size_t    buflen;
} blake2s_context;

// This layout is explicitly little-endian
struct blake2_params_prefix {
    uint8_t   digest_length; /* 1 */
    uint8_t   key_length;    /* 2 */
    uint8_t   fanout;        /* 3 */
    uint8_t   depth;         /* 4 */
    uint32_t  zero;          /* 8 */
};

template <typename T>
NEVER_INLINE static void blake2_Init( T * ctx, unsigned hashbits, uint64_t seed ) {
    const uint32_t seedlo = seed         & 0xFFFFFFFF;
    const uint32_t seedhi = (seed >> 32) & 0xFFFFFFFF;

    memset(ctx    , 0, sizeof(*ctx)  );
    for (int i = 0; i < 8; i++) {
        if (sizeof(ctx->h[0]) == 8) {
            ctx->h[i] = blake2b_IV[i];
        } else {
            ctx->h[i] = blake2s_IV[i];
        }
    }

    struct blake2_params_prefix params;
    memset(&params, 0, sizeof(params));
    params.digest_length = hashbits / 8;
    params.fanout        = 1;
    params.depth         = 1;
    if (sizeof(ctx->h[0]) == 8) {
        ctx->h[0] ^= isLE() ?
                    GET_U64<false>((const uint8_t *)(&params), 0) :
                    GET_U64<true >((const uint8_t *)(&params), 0);
    } else {
        ctx->h[0] ^= isLE() ?
                    GET_U32<false>((const uint8_t *)(&params), 0) :
                    GET_U32<true >((const uint8_t *)(&params), 0);
    }

    // Legacy homegrown BLAKE2 seeding for SMHasher3
    ctx->h[0] ^= seedlo;
    ctx->h[1] ^= seedhi;
}

template <typename T>
static int blake2_is_lastblock( const T * ctx ) {
    return ctx->f[0] != 0;
}

template <typename T>
static void blake2_set_lastblock( T * ctx ) {
    ctx->f[0] = 0;
    ctx->f[0]--;
}

template <typename T>
static void blake2_increment_counter( T * ctx, const uint64_t inc ) {
    ctx->t[0] += inc;
    ctx->t[1] += (ctx->t[0] < inc);
}

//
// These includes each define the following function stub for both 2b
// contexts and 2s contexts:
//
//   template < typename T, bool bswap >
//   static void blake2_compress(T * ctx, const uint8_t * in) {
//   }
#if defined(HAVE_SSE_2)
  #include "Intrinsics.h"
  #include "blake2/compress-sse2-plus.h"
  #define BLAKE2_IMPL_STR "sse2"
#else
  #include "blake2/compress-portable.h"
  #define BLAKE2_IMPL_STR "portable"
#endif

template <bool bswap, typename T>
static void blake2_Update( T * ctx, const uint8_t * in, size_t inlen ) {
    const uint64_t BLOCKBYTES = sizeof(ctx->buf);

    if (inlen > 0) {
        size_t left = ctx->buflen;
        size_t fill = BLOCKBYTES - left;
        if (inlen > fill) {
            ctx->buflen = 0;
            memcpy(ctx->buf + left, in, fill);     /* Fill buffer */
            blake2_increment_counter(ctx, BLOCKBYTES);
            blake2_compress<bswap>(ctx, ctx->buf); /* Compress */
            in += fill; inlen -= fill;
            while (inlen > BLOCKBYTES) {
                blake2_increment_counter(ctx, BLOCKBYTES);
                blake2_compress<bswap>(ctx, in);
                in    += BLOCKBYTES;
                inlen -= BLOCKBYTES;
            }
        }
        memcpy(ctx->buf + ctx->buflen, in, inlen);
        ctx->buflen += inlen;
    }
}

template <bool bswap, typename T>
static void blake2_Finalize( T * ctx ) {
    const uint64_t BLOCKBYTES = sizeof(ctx->buf);

    if (blake2_is_lastblock(ctx)) {
        return;
    }

    blake2_increment_counter(ctx, ctx->buflen);
    blake2_set_lastblock(ctx);
    memset(ctx->buf + ctx->buflen, 0, BLOCKBYTES - ctx->buflen); /* Padding */
    blake2_compress<bswap>(ctx, ctx->buf);
}

template <uint32_t hashbits, uint32_t outbits, bool bswap>
static void BLAKE2B( const void * in, const size_t len, const seed_t seed, void * out ) {
    blake2b_context ctx;

    blake2_Init(&ctx, hashbits, (uint64_t)seed);
    blake2_Update<bswap>(&ctx, (const uint8_t *)in, len);
    blake2_Finalize<bswap>(&ctx);

    uint8_t buf[32];
    for (int i = 0; i < 4; ++i) {
        PUT_U64<bswap>(ctx.h[i], buf, i * 8);
    }
    memcpy(out, buf, (outbits >= 256) ? 32 : (outbits + 7) / 8);
}

template <uint32_t hashbits, uint32_t outbits, bool bswap>
static void BLAKE2S( const void * in, const size_t len, const seed_t seed, void * out ) {
    blake2s_context ctx;

    blake2_Init(&ctx, hashbits, (uint64_t)seed);
    blake2_Update<bswap>(&ctx, (const uint8_t *)in, len);
    blake2_Finalize<bswap>(&ctx);

    uint8_t buf[32];
    for (int i = 0; i < 8; ++i) {
        PUT_U32<bswap>(ctx.h[i], buf, i * 4);
    }
    memcpy(out, buf, (outbits >= 256) ? 32 : (outbits + 7) / 8);
}

REGISTER_FAMILY(blake2,
   $.src_url    = "https://github.com/BLAKE2/BLAKE2",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(blake2b_256,
   $.desc       = "BLAKE 2b, 256-bit digest",
   $.impl       = BLAKE2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_LOOKUP_TABLE         |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 256,
   $.verification_LE = 0xC9D8D995,
   $.verification_BE = 0xCDB3E566,
   $.hashfn_native   = BLAKE2B<256, 256, false>,
   $.hashfn_bswap    = BLAKE2B<256, 256, true>
 );

REGISTER_HASH(blake2b_224,
   $.desc       = "BLAKE 2b, 224-bit digest",
   $.impl       = BLAKE2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_LOOKUP_TABLE         |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 224,
   $.verification_LE = 0x101A62A4,
   $.verification_BE = 0x77BE80ED,
   $.hashfn_native   = BLAKE2B<224, 224, false>,
   $.hashfn_bswap    = BLAKE2B<224, 224, true>
 );

REGISTER_HASH(blake2b_160,
   $.desc       = "BLAKE 2b, 160-bit digest",
   $.impl       = BLAKE2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_LOOKUP_TABLE         |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 160,
   $.verification_LE = 0x28ADDA30,
   $.verification_BE = 0xFF79839E,
   $.hashfn_native   = BLAKE2B<160, 160, false>,
   $.hashfn_bswap    = BLAKE2B<160, 160, true>
 );

REGISTER_HASH(blake2b_128,
   $.desc       = "BLAKE 2b, 128-bit digest",
   $.impl       = BLAKE2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_LOOKUP_TABLE         |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 128,
   $.verification_LE = 0x7DC97611,
   $.verification_BE = 0xDD6695FD,
   $.hashfn_native   = BLAKE2B<128, 128, false>,
   $.hashfn_bswap    = BLAKE2B<128, 128, true>
 );

REGISTER_HASH(blake2b_256__64,
   $.desc       = "BLAKE 2b, 256-bit digest, bits 0-63",
   $.impl       = BLAKE2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_LOOKUP_TABLE         |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 64,
   $.verification_LE = 0xCF4F7EC3,
   $.verification_BE = 0x0EB38190,
   $.hashfn_native   = BLAKE2B<256, 64, false>,
   $.hashfn_bswap    = BLAKE2B<256, 64, true>
 );

REGISTER_HASH(blake2s_256,
   $.desc       = "BLAKE 2s, 256-bit digest",
   $.impl       = BLAKE2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_LOOKUP_TABLE         |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 256,
   $.verification_LE = 0x841D6354,
   $.verification_BE = 0x9F85F5C2,
   $.hashfn_native   = BLAKE2S<256, 256, false>,
   $.hashfn_bswap    = BLAKE2S<256, 256, true>
 );

REGISTER_HASH(blake2s_224,
   $.desc       = "BLAKE 2s, 224-bit digest",
   $.impl       = BLAKE2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_LOOKUP_TABLE         |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 224,
   $.verification_LE = 0x19B36D2C,
   $.verification_BE = 0xBD261F10,
   $.hashfn_native   = BLAKE2S<224, 224, false>,
   $.hashfn_bswap    = BLAKE2S<224, 224, true>
 );

REGISTER_HASH(blake2s_160,
   $.desc       = "BLAKE 2s, 160-bit digest",
   $.impl       = BLAKE2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_LOOKUP_TABLE         |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 160,
   $.verification_LE = 0xD50FF144,
   $.verification_BE = 0xF9579BEA,
   $.hashfn_native   = BLAKE2S<160, 160, false>,
   $.hashfn_bswap    = BLAKE2S<160, 160, true>
 );

REGISTER_HASH(blake2s_128,
   $.desc       = "BLAKE 2s, 128-bit digest",
   $.impl       = BLAKE2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_LOOKUP_TABLE         |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 128,
   $.verification_LE = 0xE8D8FCDF,
   $.verification_BE = 0x9C786057,
   $.hashfn_native   = BLAKE2S<128, 128, false>,
   $.hashfn_bswap    = BLAKE2S<128, 128, true>
 );

REGISTER_HASH(blake2s_256__64,
   $.desc       = "BLAKE 2s, 256-bit digest, bits 0-63",
   $.impl       = BLAKE2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_LOOKUP_TABLE         |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 64,
   $.verification_LE = 0x53000BB2,
   $.verification_BE = 0x901DDE1D,
   $.hashfn_native   = BLAKE2S<256, 64, false>,
   $.hashfn_bswap    = BLAKE2S<256, 64, true>
 );
