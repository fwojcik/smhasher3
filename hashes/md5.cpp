/*
 * MD5 hash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (C) 2006-2010, Paul Bakker <polarssl_maintainer at polarssl.org>
 *   All rights reserved.
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 *     Copyright (c) 2014-2021 Reini Urban
 *
 *     Permission is hereby granted, free of charge, to any person
 *     obtaining a copy of this software and associated documentation
 *     files (the "Software"), to deal in the Software without
 *     restriction, including without limitation the rights to use,
 *     copy, modify, merge, publish, distribute, sublicense, and/or
 *     sell copies of the Software, and to permit persons to whom the
 *     Software is furnished to do so, subject to the following
 *     conditions:
 *
 *     The above copyright notice and this permission notice shall be
 *     included in all copies or substantial portions of the Software.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *     HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *     WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *     FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *     OTHER DEALINGS IN THE SOFTWARE.
 */
#include "Platform.h"
#include "Types.h"
#include "Hashlib.h"

//-----------------------------------------------------------------------------
// Raw MD5 implementation
typedef struct {
    uint32_t total[2];     /*!< number of bytes processed  */
    uint32_t state[4];     /*!< intermediate digest state  */
    uint8_t  buffer[64];   /*!< data block being processed */

    uint8_t  ipad[64];     /*!< HMAC: inner padding        */
    uint8_t  opad[64];     /*!< HMAC: outer padding        */
} md5_context;

/*
 * 32-bit integer manipulation macros. These move data in
 * little-endian format no matter the endianness of the system.
 */
#define GET_U32_LE(n,b,i)                             \
    {                                                 \
        (n) = ( (uint32_t) (b)[(i)    ]       )       \
            | ( (uint32_t) (b)[(i) + 1] <<  8 )       \
            | ( (uint32_t) (b)[(i) + 2] << 16 )       \
            | ( (uint32_t) (b)[(i) + 3] << 24 );      \
    }
#define PUT_U32_LE(n,b,i)                             \
    {                                                 \
        (b)[(i)    ] = (uint8_t) ( (n)       );       \
        (b)[(i) + 1] = (uint8_t) ( (n) >>  8 );       \
        (b)[(i) + 2] = (uint8_t) ( (n) >> 16 );       \
        (b)[(i) + 3] = (uint8_t) ( (n) >> 24 );       \
    }

/*
 * MD5 context setup
 */
static void md5_starts(md5_context * ctx) {
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
}

/*
 * MD5 process single data block
 */
static void md5_process(md5_context * ctx, uint8_t data[64]) {
    uint32_t X[16], A, B, C, D;

    GET_U32_LE( X[ 0], data,  0 );
    GET_U32_LE( X[ 1], data,  4 );
    GET_U32_LE( X[ 2], data,  8 );
    GET_U32_LE( X[ 3], data, 12 );
    GET_U32_LE( X[ 4], data, 16 );
    GET_U32_LE( X[ 5], data, 20 );
    GET_U32_LE( X[ 6], data, 24 );
    GET_U32_LE( X[ 7], data, 28 );
    GET_U32_LE( X[ 8], data, 32 );
    GET_U32_LE( X[ 9], data, 36 );
    GET_U32_LE( X[10], data, 40 );
    GET_U32_LE( X[11], data, 44 );
    GET_U32_LE( X[12], data, 48 );
    GET_U32_LE( X[13], data, 52 );
    GET_U32_LE( X[14], data, 56 );
    GET_U32_LE( X[15], data, 60 );

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define P(a,b,c,d,k,s,t)                                \
{                                                       \
    a += F(b,c,d) + X[k] + t; a = S(a,s) + b;           \
}

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];

#define F(x,y,z) (z ^ (x & (y ^ z)))

    P( A, B, C, D,  0,  7, 0xD76AA478 );
    P( D, A, B, C,  1, 12, 0xE8C7B756 );
    P( C, D, A, B,  2, 17, 0x242070DB );
    P( B, C, D, A,  3, 22, 0xC1BDCEEE );
    P( A, B, C, D,  4,  7, 0xF57C0FAF );
    P( D, A, B, C,  5, 12, 0x4787C62A );
    P( C, D, A, B,  6, 17, 0xA8304613 );
    P( B, C, D, A,  7, 22, 0xFD469501 );
    P( A, B, C, D,  8,  7, 0x698098D8 );
    P( D, A, B, C,  9, 12, 0x8B44F7AF );
    P( C, D, A, B, 10, 17, 0xFFFF5BB1 );
    P( B, C, D, A, 11, 22, 0x895CD7BE );
    P( A, B, C, D, 12,  7, 0x6B901122 );
    P( D, A, B, C, 13, 12, 0xFD987193 );
    P( C, D, A, B, 14, 17, 0xA679438E );
    P( B, C, D, A, 15, 22, 0x49B40821 );

#undef F

#define F(x,y,z) (y ^ (z & (x ^ y)))

    P( A, B, C, D,  1,  5, 0xF61E2562 );
    P( D, A, B, C,  6,  9, 0xC040B340 );
    P( C, D, A, B, 11, 14, 0x265E5A51 );
    P( B, C, D, A,  0, 20, 0xE9B6C7AA );
    P( A, B, C, D,  5,  5, 0xD62F105D );
    P( D, A, B, C, 10,  9, 0x02441453 );
    P( C, D, A, B, 15, 14, 0xD8A1E681 );
    P( B, C, D, A,  4, 20, 0xE7D3FBC8 );
    P( A, B, C, D,  9,  5, 0x21E1CDE6 );
    P( D, A, B, C, 14,  9, 0xC33707D6 );
    P( C, D, A, B,  3, 14, 0xF4D50D87 );
    P( B, C, D, A,  8, 20, 0x455A14ED );
    P( A, B, C, D, 13,  5, 0xA9E3E905 );
    P( D, A, B, C,  2,  9, 0xFCEFA3F8 );
    P( C, D, A, B,  7, 14, 0x676F02D9 );
    P( B, C, D, A, 12, 20, 0x8D2A4C8A );

#undef F

#define F(x,y,z) (x ^ y ^ z)

    P( A, B, C, D,  5,  4, 0xFFFA3942 );
    P( D, A, B, C,  8, 11, 0x8771F681 );
    P( C, D, A, B, 11, 16, 0x6D9D6122 );
    P( B, C, D, A, 14, 23, 0xFDE5380C );
    P( A, B, C, D,  1,  4, 0xA4BEEA44 );
    P( D, A, B, C,  4, 11, 0x4BDECFA9 );
    P( C, D, A, B,  7, 16, 0xF6BB4B60 );
    P( B, C, D, A, 10, 23, 0xBEBFBC70 );
    P( A, B, C, D, 13,  4, 0x289B7EC6 );
    P( D, A, B, C,  0, 11, 0xEAA127FA );
    P( C, D, A, B,  3, 16, 0xD4EF3085 );
    P( B, C, D, A,  6, 23, 0x04881D05 );
    P( A, B, C, D,  9,  4, 0xD9D4D039 );
    P( D, A, B, C, 12, 11, 0xE6DB99E5 );
    P( C, D, A, B, 15, 16, 0x1FA27CF8 );
    P( B, C, D, A,  2, 23, 0xC4AC5665 );

#undef F

#define F(x,y,z) (y ^ (x | ~z))

    P( A, B, C, D,  0,  6, 0xF4292244 );
    P( D, A, B, C,  7, 10, 0x432AFF97 );
    P( C, D, A, B, 14, 15, 0xAB9423A7 );
    P( B, C, D, A,  5, 21, 0xFC93A039 );
    P( A, B, C, D, 12,  6, 0x655B59C3 );
    P( D, A, B, C,  3, 10, 0x8F0CCC92 );
    P( C, D, A, B, 10, 15, 0xFFEFF47D );
    P( B, C, D, A,  1, 21, 0x85845DD1 );
    P( A, B, C, D,  8,  6, 0x6FA87E4F );
    P( D, A, B, C, 15, 10, 0xFE2CE6E0 );
    P( C, D, A, B,  6, 15, 0xA3014314 );
    P( B, C, D, A, 13, 21, 0x4E0811A1 );
    P( A, B, C, D,  4,  6, 0xF7537E82 );
    P( D, A, B, C, 11, 10, 0xBD3AF235 );
    P( C, D, A, B,  2, 15, 0x2AD7D2BB );
    P( B, C, D, A,  9, 21, 0xEB86D391 );

#undef F

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
}

/*
 * MD5 process buffer
 */
static void md5_update(md5_context *ctx, uint8_t *input, int ilen) {
    uint32_t fill, left;

    if (ilen <= 0) { return; }

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if (ctx->total[0] < (uint32_t)ilen) { ctx->total[1]++; }

    if (left && (ilen >= fill)) {
        memcpy((void *)(ctx->buffer + left), (void *)input, fill);
        md5_process(ctx, ctx->buffer);
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while (ilen >= 64) {
        md5_process(ctx, input);
        input += 64;
        ilen  -= 64;
    }

    if (ilen > 0) {
        memcpy((void *)(ctx->buffer + left), (void *)input, ilen);
    }
}

static const uint8_t md5_padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * MD5 final digest
 */
static void md5_finish(md5_context * ctx, uint8_t output[16]) {
    uint32_t last, padn;
    uint32_t high, low;
    uint8_t msglen[8];

    high = (ctx->total[0] >> 29)
         | (ctx->total[1] <<  3);
    low  = (ctx->total[0] <<  3);

    PUT_U32_LE(low,  msglen, 0);
    PUT_U32_LE(high, msglen, 4);

    last = ctx->total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    md5_update(ctx, (uint8_t *) md5_padding, padn);
    md5_update(ctx, msglen, 8);

    PUT_U32_LE(ctx->state[0], output,  0);
    PUT_U32_LE(ctx->state[1], output,  4);
    PUT_U32_LE(ctx->state[2], output,  8);
    PUT_U32_LE(ctx->state[3], output, 12);
}

//-----------------------------------------------------------------------------
// Homegrown MD5 seeding function
static FORCE_INLINE void seed_md5(md5_context * ctx, const seed_t seed) {
    const uint32_t seedlo = seed         & 0xFFFFFFFF;
    const uint32_t seedhi = (seed >> 32) & 0xFFFFFFFF;
    ctx->state[0] ^= seedlo;
    ctx->state[1] ^= seedhi;
#ifdef NOT_YET
    ctx->state[2] += seedlo;
    ctx->state[3] += seedhi;
#endif
}

//-----------------------------------------------------------------------------
// Wrappers for rest of SMHasher3
void MD5_128(const void * in, const size_t len, const seed_t seed, void * out) {
    md5_context md5_ctx;
    md5_starts(&md5_ctx);
    seed_md5  (&md5_ctx, seed);
    md5_update(&md5_ctx, (uint8_t *)in, len);
    md5_finish(&md5_ctx, (uint8_t *)out);
}

void MD5_64(const void * in, const size_t len, const seed_t seed, void * out) {
    uint8_t hash[16];
    md5_context md5_ctx;
    md5_starts(&md5_ctx);
    seed_md5  (&md5_ctx, seed);
    md5_update(&md5_ctx, (uint8_t *)in, len);
    md5_finish(&md5_ctx, hash);

    // The "B" and "C" states were modified last in the hash rounds,
    // so return the second and third word of output.
    memcpy(out, hash + 4, 8);
}

void MD5_32(const void * in, const size_t len, const seed_t seed, void * out) {
    uint8_t hash[16];
    md5_context md5_ctx;
    md5_starts(&md5_ctx);
    seed_md5  (&md5_ctx, seed);
    md5_update(&md5_ctx, (uint8_t *)in, len);
    md5_finish(&md5_ctx, hash);

    // The "B" state was modified last in the hash round, so return
    // the second word of output.
    memcpy(out, hash + 4, 4);
}

REGISTER_FAMILY(md5);

REGISTER_HASH(md5_32,
  $.desc = "MD5, bits 32-63",
  $.hash_flags = FLAG_HASH_CRYPTOGRAPHIC        |
                 FLAG_HASH_CRYPTOGRAPHIC_WEAK   |
                 FLAG_HASH_ENDIAN_INDEPENDENT   |
                 FLAG_HASH_NO_SEED,
  $.impl_flags = FLAG_IMPL_LICENSE_GPL3         |
                 FLAG_IMPL_ROTATE               |
                 FLAG_IMPL_VERY_SLOW,
  $.bits = 32,
#ifdef NOT_YET
  $.verification_LE = 0x4003D7EE,
  $.verification_BE = 0x4003D7EE,
#else
  $.verification_LE = 0xF3DFF19F,
  $.verification_BE = 0xF3DFF19F,
#endif
  $.hashfn_native = MD5_32,
  $.hashfn_bswap = MD5_32
);

REGISTER_HASH(md5_64,
  $.desc = "MD5, bits 32-95",
  $.hash_flags = FLAG_HASH_CRYPTOGRAPHIC        |
                 FLAG_HASH_CRYPTOGRAPHIC_WEAK   |
                 FLAG_HASH_ENDIAN_INDEPENDENT   |
                 FLAG_HASH_NO_SEED,
  $.impl_flags = FLAG_IMPL_LICENSE_GPL3         |
                 FLAG_IMPL_ROTATE               |
                 FLAG_IMPL_VERY_SLOW,
  $.bits = 64,
#ifdef NOT_YET
  $.verification_LE = 0xF2E011D4,
  $.verification_BE = 0xF2E011D4,
#else
  $.verification_LE = 0x12F0BA8E,
  $.verification_BE = 0x12F0BA8E,
#endif
  $.hashfn_native = MD5_64,
  $.hashfn_bswap = MD5_64
);

REGISTER_HASH(md5_128,
  $.desc = "MD5",
  $.hash_flags = FLAG_HASH_CRYPTOGRAPHIC        |
                 FLAG_HASH_CRYPTOGRAPHIC_WEAK   |
                 FLAG_HASH_ENDIAN_INDEPENDENT   |
                 FLAG_HASH_NO_SEED,
  $.impl_flags = FLAG_IMPL_LICENSE_GPL3         |
                 FLAG_IMPL_ROTATE               |
                 FLAG_IMPL_VERY_SLOW,
  $.bits = 128,
#ifdef NOT_YET
  $.verification_LE = 0x1363415D,
  $.verification_BE = 0x1363415D,
#else
  $.verification_LE = 0xF263F96F,
  $.verification_BE = 0xF263F96F,
#endif
  $.hashfn_native = MD5_128,
  $.hashfn_bswap = MD5_128
);
