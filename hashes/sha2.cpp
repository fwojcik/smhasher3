/*
 * SHA-2 hash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2019-2021 Reini Urban
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
 *     SHA-Instrinsics
 *     Written and place in public domain by Jeffrey Walton
 *     Based on code from Intel, and by Sean Gulley for the miTLS project.
 *     Based on code from ARM, and by Johannes Schneiders,
 *     Skip Hovsmith and Barry O'Rourke for the mbedTLS project.
 */
#include "Platform.h"
#include "Hashlib.h"

//-----------------------------------------------------------------------------
// Raw SHA-2 implementation
typedef struct {
    uint64_t  length;
    uint32_t  state[8], curlen;
    uint8_t   buf[64];
} SHA2_CTX;

static void SHA224_Init( SHA2_CTX * context ) {
    context->curlen   = 0;
    context->length   = 0;
    context->state[0] = 0xc1059ed8;
    context->state[1] = 0x367cd507;
    context->state[2] = 0x3070dd17;
    context->state[3] = 0xf70e5939;
    context->state[4] = 0xffc00b31;
    context->state[5] = 0x68581511;
    context->state[6] = 0x64f98fa7;
    context->state[7] = 0xbefa4fa4;
}

/* SHA256_Init - Initialize new context */
static void SHA256_Init( SHA2_CTX * context ) {
    context->curlen   = 0;
    context->length   = 0;
    context->state[0] = 0x6A09E667;
    context->state[1] = 0xBB67AE85;
    context->state[2] = 0x3C6EF372;
    context->state[3] = 0xA54FF53A;
    context->state[4] = 0x510E527F;
    context->state[5] = 0x9B05688C;
    context->state[6] = 0x1F83D9AB;
    context->state[7] = 0x5BE0CD19;
}

//-----------------------------------------------------------------------------
// Hash a single 512-bit block. This is the core of the algorithm.

#if defined(HAVE_X86_64_SHA2)
  #include "Intrinsics.h"
  #include "sha2/transform-sha2x64.h"
  #define SHA2_IMPL_STR "x64"
#elif defined(HAVE_ARM_SHA2)
  #include "Intrinsics.h"
  #include "sha2/transform-neon.h"
  #define SHA2_IMPL_STR "neon"
#else
  #include "sha2/transform-portable.h"
  #define SHA2_IMPL_STR "portable"
#endif

//-----------------------------------------------------------------------------

template <bool bswap>
static void SHA256_Update( SHA2_CTX * context, const uint8_t * data, size_t len ) {
    while (len > 0) {
        if ((context->curlen == 0) && (len >= sizeof(context->buf))) {
            SHA256_Transform<bswap>(context->state, data);
            context->length += 64 * 8;
            len  -= 64;
            data += 64;
        } else {
            size_t n = 64 - context->curlen;
            if (n > len) { n = len; }
            memcpy(&context->buf[context->curlen], data, n);
            context->curlen += n;
            len  -= n;
            data += n;
            if (context->curlen == 64) {
                SHA256_Transform<bswap>(context->state, context->buf);
                context->curlen  = 0;
                context->length += 64 * 8;
            }
        }
    }
}

/* Add padding and return len bytes of the message digest. */
template <bool bswap>
static void SHA256_Final( SHA2_CTX * context, uint32_t digest_words, uint8_t * digest ) {
    uint32_t i;
    uint8_t  finalcount[8];
    uint8_t  c;

    context->length += context->curlen * 8;
    for (i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)(context->length >> ((7 - i) * 8)); // Endian independent
    }
    c = 0200;
    SHA256_Update<bswap>(context, &c, 1);
    while ((context->curlen) != 56) {
        c = 0000;
        SHA256_Update<bswap>(context, &c, 1);
    }
    SHA256_Update<bswap>(context, finalcount, 8); /* Should cause a SHA256_Transform() */

    if (digest_words > 8) { digest_words = 8; }
    for (i = 0; i < digest_words; i++) {
        PUT_U32<bswap>(context->state[i], digest, 4 * i);
    }
}

//-----------------------------------------------------------------------------
// Homegrown SHA-2 seeding function
static FORCE_INLINE void SHA256_Seed( SHA2_CTX * ctx, const seed_t seed ) {
    const uint32_t seedlo = seed         & 0xFFFFFFFF;
    const uint32_t seedhi = (seed >> 32) & 0xFFFFFFFF;

    ctx->state[1] ^= seedlo;
    ctx->state[3] += seedlo + seedhi;
    ctx->state[5] ^= seedhi;
}

//-----------------------------------------------------------------------------
template <uint32_t hashbits, bool bswap>
static void SHA256( const void * in, const size_t len, const seed_t seed, void * out ) {
    SHA2_CTX context;

    SHA256_Init(&context);
    SHA256_Seed(&context, seed);
    SHA256_Update<bswap>(&context, (const uint8_t *)in, len);
    SHA256_Final<bswap>(&context, (hashbits + 31) / 32, (uint8_t *)out);
}

template <uint32_t hashbits, bool bswap>
static void SHA224( const void * in, const size_t len, const seed_t seed, void * out ) {
    SHA2_CTX context;

    SHA224_Init(&context);
    SHA256_Seed(&context, seed);
    SHA256_Update<bswap>(&context, (const uint8_t *)in, len);
    SHA256_Final<bswap>(&context, (hashbits + 31) / 32, (uint8_t *)out);
}

//-----------------------------------------------------------------------------
// Self test
//
// Test Vectors
//
//   "" (empty string)
//       e3b0c442 98fc1c14 9afbf4c8 996fb924
//       27ae41e4 649b934c a495991b 7852b855
//   "abc"
//       ba7816bf 8f01cfea 414140de 5dae2223
//       b00361a3 96177a9c b410ff61 f20015ad
//   A million repetitions of "a"
//       cdc76e5c 9914fb92 81a1c7e2 84d73e67
//       f1809a48 a497200e 046d39cc c7112cd0
static const char * const test_data[] = {
    "", "abc",
    "A million repetitions of 'a'"
};
static const char * const test_results[] = {
    "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855",
    "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad",
    "cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0",
};

static void digest_to_hex( const uint8_t digest[32], char * output ) {
    int    i, j;
    char * c = output;

    for (i = 0; i < 32 / 4; i++) {
        for (j = 0; j < 4; j++) {
            sprintf(c, "%02x", digest[i * 4 + j]);
            c += 2;
        }
        *c++ = ' ';
    }
    *(c - 1) = '\0';
}

template <bool bswap>
static bool SHA256_Selftest( void ) {
    int      k;
    SHA2_CTX context;
    uint8_t  digest[32];
    char     output[72];

    for (k = 0; k < 2; k++) {
        SHA256_Init(&context);
        SHA256_Update<bswap>(&context, (uint8_t *)test_data[k], strlen(test_data[k]));
        SHA256_Final<bswap>(&context, 8, digest);
        digest_to_hex(digest, output);

        if (strcmp(output, test_results[k])) {
            fprintf(stdout, "SHA-256 self test FAILED\n"   );
            fprintf(stderr, "* hash of \"%s\" incorrect:\n", test_data[k]);
            fprintf(stderr, "\t%s returned\n", output);
            fprintf(stderr, "\t%s is correct\n", test_results[k]);
            return false;
        }
    }

    /* million 'a' vector we feed separately */
    SHA256_Init(&context);
    for (k = 0; k < 1000000; k++) {
        SHA256_Update<bswap>(&context, (uint8_t *)"a", 1);
    }
    SHA256_Final<bswap>(&context, 8, digest);
    digest_to_hex(digest, output);
    if (strcmp(output, test_results[2])) {
        fprintf(stdout, "SHA-256 self test FAILED\n"   );
        fprintf(stderr, "* hash of \"%s\" incorrect:\n", test_data[2]);
        fprintf(stderr, "\t%s returned\n", output);
        fprintf(stderr, "\t%s is correct\n", test_results[2]);
        return false;
    }

    /* success */
    return true;
}

static bool SHA256_test( void ) {
    if (isBE()) {
        return SHA256_Selftest<false>();
    } else {
        return SHA256_Selftest<true>();
    }
}

REGISTER_FAMILY(sha2,
   $.src_url    = "https://github.com/noloader/SHA-Intrinsics",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(SHA_2_256__64,
   $.desc       = "SHA-256, bits 0-63",
   $.impl       = SHA2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_BE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 64,
   $.verification_LE = 0x31C40E74,
   $.verification_BE = 0x6E81AB0B,
   $.initfn          = SHA256_test,
   $.hashfn_native   = SHA256<64, false>,
   $.hashfn_bswap    = SHA256<64, true>
 );

REGISTER_HASH(SHA_2_256,
   $.desc       = "SHA-256",
   $.impl       = SHA2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_BE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 256,
   $.verification_LE = 0x33BD25DE,
   $.verification_BE = 0x1643B047,
   $.initfn          = SHA256_test,
   $.hashfn_native   = SHA256<256, false>,
   $.hashfn_bswap    = SHA256<256, true>
 );

REGISTER_HASH(SHA_2_224__64,
   $.desc       = "SHA-224, bits 0-63",
   $.impl       = SHA2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_BE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 64,
   $.verification_LE = 0x36C55CA5,
   $.verification_BE = 0x8C3C0B2A,
   $.initfn          = SHA256_test,
   $.hashfn_native   = SHA224<64, false>,
   $.hashfn_bswap    = SHA224<64, true>
 );

REGISTER_HASH(SHA_2_224,
   $.desc       = "SHA-224",
   $.impl       = SHA2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_ENDIAN_INDEPENDENT   |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_BE         |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 224,
   $.verification_LE = 0x6BA219E5,
   $.verification_BE = 0x56F30297,
   $.initfn          = SHA256_test,
   $.hashfn_native   = SHA224<224, false>,
   $.hashfn_bswap    = SHA224<224, true>
 );
