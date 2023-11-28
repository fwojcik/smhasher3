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
#include "Platform.h"
#include "Hashlib.h"
#if defined(HAVE_SSSE_3)
  #include "Intrinsics.h"
#endif

//------------------------------------------------------------
#define KHASH_FINLINE      FORCE_INLINE
#define KHASH_BSWAP32(val) BSWAP32(val)
#define KHASH_ROTR32(x, n) ROTR32(x, n)

static KHASH_FINLINE int khashv_is_little_endian() {
    return isLE() ? 1 : 0;
}

struct khashv_block_s {
    union {
        uint32_t  words[4];
        uint8_t   bytes[16];
#if defined(HAVE_SSSE_3)
        __m128i  vec;
#endif
    };
};

typedef struct khashv_block_s  khashvBlock;
typedef struct khashv_block_s  khashvSeed;

static const khashvBlock khash_v_init = {
    { {
        // Really this could basically be almost anything
        // So just using some bytes of the SHA-256 hashes
        // of 1, 2, 3, and 4
        0x7785459a, // SHA256 of the byte 0x01, using the last 4 bytes
        0x6457d986, // SHA256 of the byte 0x02, using the last 4 bytes
        0xadff29c5, // SHA256 of the byte 0x03, using the last 4 bytes
        0x81c89e71, // SHA256 of the byte 0x04, using the last 4 bytes
    } }
};

//------------------------------------------------------------
// Each implementation provides the following API:
static void khashv_prep_seed32( khashvSeed * seed_prepped, uint32_t seed );
static void khashv_prep_seed64( khashvSeed * seed_prepped, uint64_t seed );
static void khashv_prep_seed128( khashvSeed * seed_prepped, const uint32_t seed[4] );
static uint32_t khashv32( const khashvSeed * seed, const uint8_t * data, size_t data_len );
static uint64_t khashv64( const khashvSeed * seed, const uint8_t * data, size_t data_len );

#if defined(HAVE_SSSE_3)
  #include "khashv/hash-ssse3.h"
  #define KHASH_IMPL_STR "ssse3"
#elif defined(HAVE_GENERIC_VECTOR) && defined(HAVE_GENERIC_VECTOR_SHUFFLE)
  #include "khashv/hash-genericvec.h"
  #define KHASH_IMPL_STR "gccvec"
#else
  #include "khashv/hash-portable.h"
  #define KHASH_IMPL_STR "portable"
#endif

//------------------------------------------------------------

static thread_local khashvSeed khashv_32_seed;
static thread_local khashvSeed khashv_64_seed;

static uintptr_t khashv32_init_seed( const seed_t seed ) {
    khashv_prep_seed64(&khashv_32_seed, (uint64_t)seed);
    return (uintptr_t)(&khashv_32_seed);
}

static uintptr_t khashv64_init_seed( const seed_t seed ) {
    khashv_prep_seed64(&khashv_64_seed, (uint64_t)seed);
    return (uintptr_t)(&khashv_64_seed);
}

static void khashv32_test( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t hash = khashv32((khashvSeed *)(uintptr_t)seed, (const uint8_t *)in, len);

    hash = COND_BSWAP(hash, isBE());
    PUT_U32<false>(hash, (uint8_t *)out, 0);
}

static void khashv64_test( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t hash = khashv64((khashvSeed *)(uintptr_t)seed, (const uint8_t *)in, len);

    hash = COND_BSWAP(hash, isBE());
    PUT_U64<false>(hash, (uint8_t *)out, 0);
}

REGISTER_FAMILY(khashv,
   $.src_url    = "https://github.com/Keith-Cancel/k-hashv",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(khashv_32,
   $.desc       = "K-Hashv vectorizable, 32-bit output",
   $.impl       = KHASH_IMPL_STR,
   $.hash_flags =
        FLAG_HASH_XL_SEED           |
        FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
        FLAG_IMPL_ROTATE            |
        FLAG_IMPL_CANONICAL_BOTH    |
        FLAG_IMPL_LICENSE_MIT       ,
   $.bits = 32,
   $.verification_LE = 0x2FBC65F8,
   $.verification_BE = 0x2FBC65F8,
   $.seedfn          = khashv32_init_seed,
   $.hashfn_native   = khashv32_test,
   $.hashfn_bswap    = khashv32_test
);

REGISTER_HASH(khashv_64,
    $.desc       = "K-Hashv vectorizable, 64-bit output",
    $.impl       = KHASH_IMPL_STR,
    $.hash_flags =
        FLAG_HASH_XL_SEED           |
        FLAG_HASH_ENDIAN_INDEPENDENT,
    $.impl_flags =
        FLAG_IMPL_ROTATE            |
        FLAG_IMPL_CANONICAL_BOTH    |
        FLAG_IMPL_LICENSE_MIT       ,
    $.bits = 64,
    $.verification_LE = 0x8598BACD,
    $.verification_BE = 0x8598BACD,
    $.seedfn          = khashv64_init_seed,
    $.hashfn_native   = khashv64_test,
    $.hashfn_bswap    = khashv64_test
);
