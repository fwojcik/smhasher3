/*
 * fasthash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (C) 2012 Zilong Tan (eric.zltan@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "Platform.h"
#include "Hashlib.h"

//------------------------------------------------------------
// Compression function for Merkle-Damgard construction.
// This function is generated using the framework provided.
static inline uint64_t mix( uint64_t h ) {
    h ^= h >> 23;
    h *= UINT64_C(0x2127599bf4325c37);
    h ^= h >> 47;
    return h;
}

static inline uint32_t fold( uint64_t h ) {
    // the following trick converts the 64-bit hashcode to Fermat
    // residue, which shall retain information from both the higher
    // and lower parts of hashcode.
    return h - (h >> 32);
}

template <bool bswap>
static uint64_t fasthash_impl( const uint8_t * pos, size_t len, uint64_t seed ) {
    const uint64_t  m   = UINT64_C(0x880355f21e6d1965);
    const uint8_t * end = pos + (len & ~7);

    uint64_t h = seed ^ (len * m);
    uint64_t v;

    while (pos != end) {
        v    = GET_U64<bswap>(pos, 0);
        h   ^= mix(v);
        h   *= m;
        pos += 8;
    }

    v = 0;

    switch (len & 7) {
    case 7: v ^= (uint64_t)pos[6] << 48; // FALLTHROUGH
    case 6: v ^= (uint64_t)pos[5] << 40; // FALLTHROUGH
    case 5: v ^= (uint64_t)pos[4] << 32; // FALLTHROUGH
    case 4: v ^= (uint64_t)pos[3] << 24; // FALLTHROUGH
    case 3: v ^= (uint64_t)pos[2] << 16; // FALLTHROUGH
    case 2: v ^= (uint64_t)pos[1] <<  8; // FALLTHROUGH
    case 1: v ^= (uint64_t)pos[0];
            h ^= mix(v);
            h *= m;
    }

    return mix(h);
}

//------------------------------------------------------------
template <bool bswap>
static void fasthash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = fasthash_impl<bswap>((const uint8_t *)in, len, (uint64_t)seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void fasthash32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = fasthash_impl<bswap>((const uint8_t *)in, len, (uint64_t)seed);

    PUT_U32<bswap>(fold(h), (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(fasthash,
   $.src_url    = "https://github.com/ztanml/fast-hash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(fasthash_32,
   $.desc       = "fast-hash, 32-bit version",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0xE9481AFC,
   $.verification_BE = 0x48BCE1ED,
   $.hashfn_native   = fasthash32<false>,
   $.hashfn_bswap    = fasthash32<true>
 );

REGISTER_HASH(fasthash_64,
   $.desc       = "fast-hash, 64-bit version",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xA16231A7,
   $.verification_BE = 0x82AD8DDB,
   $.hashfn_native   = fasthash64<false>,
   $.hashfn_bswap    = fasthash64<true>
 );
