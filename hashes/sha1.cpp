/*
 * SHA-1 hash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2014-2021 Reini Urban
 * Copyright (c) 2016-2018 Leo Yuriev
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
 * Based on:
 *     SHA-1 in C
 *     By Steve Reid <steve@edmweb.com>
 *     100% Public Domain
 *
 *     SHA-Instrinsics
 *     Written and place in public domain by Jeffrey Walton
 *     Based on code from Intel, and by Sean Gulley for the miTLS project.
 *     Based on code from ARM, and by Johannes Schneiders,
 *     Skip Hovsmith and Barry O'Rourke for the mbedTLS project.
 */
#include "Platform.h"
#include "Hashlib.h"

//-----------------------------------------------------------------------------
// Raw SHA-1 implementation
typedef struct {
    uint32_t  state[5];
    uint32_t  count[2];
    uint8_t   buffer[64];
} SHA1_CTX;

#define SHA1_DIGEST_SIZE 20

/* SHA1_Init - Initialize new context */
static void SHA1_Init( SHA1_CTX * context ) {
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

#if defined(HAVE_X86_64_SHA1)
  #include "Intrinsics.h"
  #include "sha1/transform-sha1x64.h"
  #define SHA1_IMPL_STR "x64"
#elif defined(HAVE_ARM_SHA1)
  #include "Intrinsics.h"
  #include "sha1/transform-neon.h"
  #define SHA1_IMPL_STR "neon"
#else
  #include "sha1/transform-portable.h"
  #define SHA1_IMPL_STR "portable"
#endif

template <bool bswap>
static void SHA1_Update( SHA1_CTX * context, const uint8_t * data, const size_t len ) {
    size_t i, j;

    j = context->count[0];
    if ((context->count[0] += len << 3) < j) {
        context->count[1]++;
    }
    context->count[1] += (len >> 29);
    j = (j >> 3) & 63;

    if ((j + len) > 63) {
        // #pragmas are a workaround for GCC bug 106709 in 12+
#if defined(HAVE_GCC_COMPILER) && __GNUG__ >= 12
  #pragma GCC diagnostic ignored "-Wstringop-overread"
  #pragma GCC diagnostic ignored "-Warray-bounds"
#endif
        memcpy(&context->buffer[j], data, (i = 64 - j));
#if defined(HAVE_GCC_COMPILER)
  #pragma GCC diagnostic pop
  #pragma GCC diagnostic pop
#endif
        SHA1_Transform<bswap>(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            SHA1_Transform<bswap>(context->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&context->buffer[j], &data[i], len - i);
}

/* Add padding and return len bytes of the message digest. */
template <bool bswap>
static void SHA1_Final( SHA1_CTX * context, uint32_t digest_words, uint8_t * digest ) {
    uint32_t i;
    uint8_t  finalcount[8];
    uint8_t  c;

    for (i = 0; i < 8; i++) {
        finalcount[i] =
                /* Endian independent */
                (uint8_t)(context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8));
    }
    c = 0200;
    SHA1_Update<bswap>(context, &c, 1);
    while ((context->count[0] & 504) != 448) {
        c = 0000;
        SHA1_Update<bswap>(context, &c, 1);
    }
    SHA1_Update<bswap>(context, finalcount, 8); /* Should cause a SHA1_Transform() */

    if (digest_words > 5) { digest_words = 5; }
    for (i = 0; i < digest_words; i++) {
        PUT_U32<bswap>(context->state[i], digest, 4 * i);
    }
}

//-----------------------------------------------------------------------------
// Homegrown SHA-1 seeding function
static FORCE_INLINE void SHA1_Seed( SHA1_CTX * ctx, const seed_t seed ) {
    const uint32_t seedlo = seed         & 0xFFFFFFFF;
    const uint32_t seedhi = (seed >> 32) & 0xFFFFFFFF;

    ctx->state[0] ^= seedlo;
    ctx->state[1] ^= seedhi;
    ctx->state[2] += seedlo ^ seedhi;
    ctx->state[3] += seedlo;
    ctx->state[4] += seedhi;
}

//-----------------------------------------------------------------------------
template <uint32_t hashbits, bool bswap>
static void SHA1( const void * in, const size_t len, const seed_t seed, void * out ) {
    SHA1_CTX context;

    SHA1_Init(&context);
    SHA1_Seed(&context, seed);
    SHA1_Update<bswap>(&context, (uint8_t *)in, len);
    SHA1_Final<bswap>(&context, (hashbits + 31) / 32, (uint8_t *)out);
}

//-----------------------------------------------------------------------------
// Self test
//
// Test Vectors (from FIPS PUB 180-1)
//   "abc"
//       A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
//   "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
//       84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
//   A million repetitions of "a"
//       34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F

static const char * const test_data[] = {
    "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "A million repetitions of 'a'"
};
static const char * const test_results[] = {
    "A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D",
    "84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1",
    "34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F"
};

static void digest_to_hex( const uint8_t digest[SHA1_DIGEST_SIZE], char * output ) {
    int    i, j;
    char * c = output;

    for (i = 0; i < SHA1_DIGEST_SIZE / 4; i++) {
        for (j = 0; j < 4; j++) {
            sprintf(c, "%02X", digest[i * 4 + j]);
            c += 2;
        }
        sprintf(c, " ");
        c += 1;
    }
    *(c - 1) = '\0';
}

template <bool bswap>
static bool SHA1_Selftest( void ) {
    int      k;
    SHA1_CTX context;
    uint8_t  digest[20];
    char     output[80];

    for (k = 0; k < 2; k++) {
        SHA1_Init(&context);
        SHA1_Update<bswap>(&context, (uint8_t *)test_data[k], strlen(test_data[k]));
        SHA1_Final<bswap>(&context, 5, digest);
        digest_to_hex(digest, output);

        if (strcmp(output, test_results[k])) {
            fprintf(stdout, "SHA-1 self test FAILED\n"     );
            fprintf(stderr, "* hash of \"%s\" incorrect:\n", test_data[k]);
            fprintf(stderr, "\t%s returned\n", output);
            fprintf(stderr, "\t%s is correct\n", test_results[k]);
            return false;
        }
    }

    /* million 'a' vector we feed separately */
    SHA1_Init(&context);
    for (k = 0; k < 1000000; k++) {
        SHA1_Update<bswap>(&context, (uint8_t *)"a", 1);
    }
    SHA1_Final<bswap>(&context, 5, digest);
    digest_to_hex(digest, output);
    if (strcmp(output, test_results[2])) {
        fprintf(stdout, "SHA-1 self test FAILED\n"     );
        fprintf(stderr, "* hash of \"%s\" incorrect:\n", test_data[2]);
        fprintf(stderr, "\t%s returned\n", output);
        fprintf(stderr, "\t%s is correct\n", test_results[2]);
        return false;
    }

    /* success */
    return true;
}

static bool SHA1_test( void ) {
    if (isBE()) {
        return SHA1_Selftest<false>();
    } else {
        return SHA1_Selftest<true>();
    }
}

REGISTER_FAMILY(sha1,
   $.src_url    = "https://github.com/noloader/SHA-Intrinsics",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(SHA_1__32,
   $.desc       = "SHA-1, bits 0-31",
   $.impl       = SHA1_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_CRYPTOGRAPHIC_WEAK   |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_BE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 32,
   $.verification_LE = 0xF0E4D9E9,
   $.verification_BE = 0xE00EF4D6,
   $.initfn          = SHA1_test,
   $.hashfn_native   = SHA1<32, false>,
   $.hashfn_bswap    = SHA1<32, true>
 );

REGISTER_HASH(SHA_1__64,
   $.desc       = "SHA-1, bits 0-63",
   $.impl       = SHA1_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_CRYPTOGRAPHIC_WEAK   |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_BE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 64,
   $.verification_LE = 0x36801ECB,
   $.verification_BE = 0xFC26F4C7,
   $.initfn          = SHA1_test,
   $.hashfn_native   = SHA1<64, false>,
   $.hashfn_bswap    = SHA1<64, true>
 );

REGISTER_HASH(SHA_1,
   $.desc       = "SHA-1",
   $.impl       = SHA1_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_CRYPTOGRAPHIC_WEAK   |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_BE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 128,
   $.verification_LE = 0xE444A591,
   $.verification_BE = 0x35E00C29,
   $.initfn          = SHA1_test,
   $.hashfn_native   = SHA1<128, false>,
   $.hashfn_bswap    = SHA1<128, true>
 );
