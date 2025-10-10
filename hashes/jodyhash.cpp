/*
 * Jody Bruchon's fast hashing algorithm
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (c) 2014-2023 Jody Bruchon
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

//------------------------------------------------------------
static const uint64_t tail_mask_64[] = {
    UINT64_C(0x0000000000000000),
    UINT64_C(0x00000000000000ff),
    UINT64_C(0x000000000000ffff),
    UINT64_C(0x0000000000ffffff),
    UINT64_C(0x00000000ffffffff),
    UINT64_C(0x000000ffffffffff),
    UINT64_C(0x0000ffffffffffff),
    UINT64_C(0x00ffffffffffffff),
    UINT64_C(0xffffffffffffffff)
};

static const uint32_t tail_mask_32[] = {
    0x00000000,
    0x000000ff,
    0x0000ffff,
    0x00ffffff,
    0xffffffff,
};

//------------------------------------------------------------
// Version increments when algorithm changes incompatibly
// #define JODY_HASH_VERSION 7

#define JODY_HASH_SHIFT     14
#define JH_SHIFT2           28
#define JODY_HASH_CONSTANT  ((sizeof(T) == 4) ? UINT32_C(0x8748ee5d) : UINT64_C(0x71812e0f5463d3c8))

#define JH_ROL(a, x) ((sizeof(T) == 4) ? ROTL32(a, x) : ROTL64(a, x))
#define JH_ROR(a, x) ((sizeof(T) == 4) ? ROTR32(a, x) : ROTR64(a, x))

//------------------------------------------------------------
#if defined(HAVE_AVX2)
  #include "Intrinsics.h"
  #include "jodyhash/block_avx2.c"
  #define JODY_IMPL_STR "avx2"
#elif defined(HAVE_SSE_2)
  #include "Intrinsics.h"
  #include "jodyhash/block_sse2.c"
  #define JODY_IMPL_STR "sse2"
#else
  #define JODY_IMPL_STR "portable"
#endif

//------------------------------------------------------------
template <typename T, bool bswap>
static int jody_block_hash( const uint8_t * RESTRICT data, T * hash, const size_t count ) {
    T      element, element2;
    size_t length = count / sizeof(T);

    const T         jh_s_constant = JH_ROR(JODY_HASH_CONSTANT, JH_SHIFT2);
    const T * const tail_mask     = (sizeof(T) == 4) ? (const T *)tail_mask_32 : (const T *)tail_mask_64;

    /* Don't bother trying to hash a zero-length block */
    if (unlikely(count == 0)) { return 0; }

#if defined(HAVE_AVX2) || defined(HAVE_SSE_2)
    if ((sizeof(T) == 8) && (count >= 32)) {
        size_t done = jody_block_hash_simd<T, bswap>(data, hash, count);
        data  += done;
        length = (count - done) / sizeof(T);
    }
#endif

    for (; length > 0; length--) {
        element   = (sizeof(T) == 4) ? GET_U32<bswap>(data, 0) : GET_U64<bswap>(data, 0);
        element2  = JH_ROR(element, JODY_HASH_SHIFT);
        element2 ^= jh_s_constant;
        element  += JODY_HASH_CONSTANT;

        *hash    += element;
        *hash    ^= element2;
        *hash     = JH_ROL(*hash, JH_SHIFT2);
        *hash    += element;

        data     += sizeof(T);
    }

    /* Handle data tail (for blocks indivisible by sizeof(T)) */
    length = count & (sizeof(T) - 1);
    if (length) {
        element   = (sizeof(T) == 4) ? GET_U32<bswap>(data, 0) : GET_U64<bswap>(data, 0);
        element  &= tail_mask[length];
        element2  = JH_ROR(element, JODY_HASH_SHIFT);
        element2 ^= jh_s_constant;
        element  += JODY_HASH_CONSTANT;

        *hash    += element;
        *hash    ^= element2;
        *hash     = JH_ROL(*hash, JH_SHIFT2);
        *hash    += element2;
    }

    return 0;
}

//------------------------------------------------------------
template <bool bswap>
static void jodyhash32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = (uint32_t)seed;

    jody_block_hash<uint32_t, bswap>((const uint8_t *)in, &h, len);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void jodyhash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = (uint64_t)seed;

    jody_block_hash<uint64_t, bswap>((const uint8_t *)in, &h, len);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(jodyhash,
   $.src_url    = "https://codeberg.org/jbruchon/jodyhash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(jodyhash_32,
   $.desc       = "jodyhash v7.3, 32-bit",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS   | // appending zero bytes might not alter hash!
         FLAG_IMPL_READ_PAST_EOB  |
         FLAG_IMPL_ROTATE         |
         FLAG_IMPL_LICENSE_MIT    |
         FLAG_IMPL_SLOW,
   $.bits = 32,
   $.verification_LE = 0x0B6C88D6,
   $.verification_BE = 0x3CA56359,
   $.hashfn_native   = jodyhash32<false>,
   $.hashfn_bswap    = jodyhash32<true>
 );

REGISTER_HASH(jodyhash_64,
   $.desc       = "jodyhash v7.3, 64-bit",
   $.impl       = JODY_IMPL_STR,
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS   | // appending zero bytes might not alter hash!
         FLAG_IMPL_READ_PAST_EOB  |
         FLAG_IMPL_ROTATE         |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xC1CBFA34,
   $.verification_BE = 0x93494125,
   $.hashfn_native   = jodyhash64<false>,
   $.hashfn_bswap    = jodyhash64<true>
 );
