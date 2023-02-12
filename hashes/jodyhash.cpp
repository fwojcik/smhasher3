/*
 * Jody Bruchon's fast hashing algorithm
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2014-2021 Jody Lee Bruchon
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
// From https://github.com/jbruchon/jodyhash
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
// #define JODY_HASH_VERSION 5

#define JODY_HASH_CONSTANT UINT32_C(0x1f3d5b79)
#define JODY_HASH_SHIFT    14

template <typename T, bool bswap>
static T jody_block_hash( const uint8_t * RESTRICT data, const size_t count, const T start_hash ) {
    T hash = start_hash;
    T element;
    T partial_salt;
    const T * const tail_mask = (sizeof(T) == 4) ?
                (const T *)tail_mask_32 : (const T *)tail_mask_64;
    size_t len;

    /* Don't bother trying to hash a zero-length block */
    if (count == 0) { return hash; }

    len = count / sizeof(T);
    for (; len > 0; len--) {
        element = (sizeof(T) == 4) ?
                    GET_U32<bswap>(data, 0) : GET_U64<bswap>(data, 0);
        hash   += element;
        hash   += JODY_HASH_CONSTANT;
        /* bit rotate left */
        hash    = (hash << JODY_HASH_SHIFT) | hash >> (sizeof(T) * 8 - JODY_HASH_SHIFT);
        hash   ^= element;
        /* bit rotate left */
        hash    = (hash << JODY_HASH_SHIFT) | hash >> (sizeof(T) * 8 - JODY_HASH_SHIFT);
        hash   ^= JODY_HASH_CONSTANT;
        hash   += element;
        data   += sizeof(T);
    }

    /* Handle data tail (for blocks indivisible by sizeof(T)) */
    len = count & (sizeof(T) - 1);
    if (len) {
        partial_salt = JODY_HASH_CONSTANT & tail_mask[len];
        element      = (sizeof(T) == 4) ?
                    GET_U32<bswap>(data, 0) : GET_U64<bswap>(data, 0);
        if (isLE() ^ bswap) {
            element &= tail_mask[len];
        } else {
            element >>= (sizeof(T) - len) * 8;
        }
        hash += element;
        hash += partial_salt;
        hash  = (hash << JODY_HASH_SHIFT) | hash >> (sizeof(T) * 8 - JODY_HASH_SHIFT);
        hash ^= element;
        hash  = (hash << JODY_HASH_SHIFT) | hash >> (sizeof(T) * 8 - JODY_HASH_SHIFT);
        hash ^= partial_salt;
        hash += element;
    }

    return hash;
}

//------------------------------------------------------------
template <bool bswap>
static void jodyhash32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = jody_block_hash<uint32_t, bswap>((const uint8_t *)in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void jodyhash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = jody_block_hash<uint64_t, bswap>((const uint8_t *)in, len, (uint64_t)seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(jodyhash,
   $.src_url    = "https://github.com/jbruchon/jodyhash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(jodyhash_32,
   $.desc       = "jodyhash v5, 32-bit",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB  |
         FLAG_IMPL_ROTATE         |
         FLAG_IMPL_LICENSE_MIT    |
         FLAG_IMPL_SLOW,
   $.bits = 32,
   $.verification_LE = 0xFB47D60D,
   $.verification_BE = 0xB94C9789,
   $.hashfn_native   = jodyhash32<false>,
   $.hashfn_bswap    = jodyhash32<true>
 );

REGISTER_HASH(jodyhash_64,
   $.desc       = "jodyhash v5, 64-bit",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS   | // appending zero bytes might not alter hash!
         FLAG_IMPL_READ_PAST_EOB  |
         FLAG_IMPL_ROTATE         |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x9F09E57F,
   $.verification_BE = 0xF9CDDA2C,
   $.hashfn_native   = jodyhash64<false>,
   $.hashfn_bswap    = jodyhash64<true>,
   $.badseeds        = { 0xffffffffe0c2a486 }
 );
