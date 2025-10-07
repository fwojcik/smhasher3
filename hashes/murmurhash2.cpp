/*
 * Murmur hash, version 2 variants
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2014-2021 Reini Urban
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
 *
 * This is based on:
 * MurmurHash was written by Austin Appleby, and is placed in the public
 * domain. The author hereby disclaims copyright to this source code.
 */
#include "Platform.h"
#include "Hashlib.h"

//-----------------------------------------------------------------------------
template <bool bswap>
static void MurmurHash2_32( const void * in, const size_t olen, const seed_t seed, void * out ) {
    // 'm' and 'r' are mixing constants generated offline.
    // They're not really 'magic', they just happen to work well.
    const uint32_t m   = 0x5bd1e995;
    const uint32_t r   = 24;
    size_t         len = olen;

    // Initialize the hash to a 'random' value
    uint32_t h = seed ^ olen;

    // Mix 4 bytes at a time into the hash
    const uint8_t * data = (const uint8_t *)in;

    while (len >= 4) {
        uint32_t k = GET_U32<bswap>(data, 0);

        k    *= m;
        k    ^= k >> r;
        k    *= m;

        h    *= m;
        h    ^= k;

        data += 4;
        len  -= 4;
    }

    // Handle the last few bytes of the input array
    switch (len) {
    case 3: h ^= data[2] << 16; /* FALLTHROUGH */
    case 2: h ^= data[1] <<  8; /* FALLTHROUGH */
    case 1: h ^= data[0];
            h *= m;
    }

    // Do a few final mixes of the hash to ensure the last few
    // bytes are well-incorporated.
    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

//-----------------------------------------------------------------------------
// MurmurHash2, 64-bit versions, by Austin Appleby

// 64-bit hash for 64-bit platforms
template <bool bswap>
static void MurmurHash2_64( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint64_t m     = UINT64_C(0xc6a4a7935bd1e995);
    const uint32_t r     = 47;

    uint64_t h           = seed ^ (len * m);

    const uint8_t * data = (const uint8_t *)in;
    const uint8_t * end  = data + len - (len & 7);

    while (data != end) {
        uint64_t k = GET_U64<bswap>(data, 0);

        k    *= m;
        k    ^= k >> r;
        k    *= m;

        h    ^= k;
        h    *= m;

        data += 8;
    }

    switch (len & 7) {
    case 7: h ^= uint64_t(data[6]) << 48; /* FALLTHROUGH */
    case 6: h ^= uint64_t(data[5]) << 40; /* FALLTHROUGH */
    case 5: h ^= uint64_t(data[4]) << 32; /* FALLTHROUGH */
    case 4: h ^= uint64_t(data[3]) << 24; /* FALLTHROUGH */
    case 3: h ^= uint64_t(data[2]) << 16; /* FALLTHROUGH */
    case 2: h ^= uint64_t(data[1]) <<  8; /* FALLTHROUGH */
    case 1: h ^= uint64_t(data[0]);
            h *= m;
    }

    h ^= h >> r;
    h *= m;
    h ^= h >> r;

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

// MurmurHash2_32_64() breaks on all-zero keys unless a high bit is set
seed_t MurmurHash2_32_64_seedfix( const HashInfo * hinfo, const seed_t seed ) {
    uint64_t seed64 = (uint64_t)seed;

    unused(hinfo);

    if (seed64 >= 0xffffffff) {
        seed64 |= (seed64 | 1) << 32;
    }
    return (seed_t)seed64;
}

// 64-bit hash for 32-bit platforms
template <bool bswap>
static void MurmurHash2_32_64( const void * in, const size_t olen, const seed_t seed, void * out ) {
    const uint32_t m     = 0x5bd1e995;
    const uint32_t r     = 24;

    uint32_t h1          = (uint32_t)(seed      ) ^ olen;
    uint32_t h2          = (uint32_t)(seed >> 32);
    size_t   len         = olen;

    const uint8_t * data = (const uint8_t *)in;

    while (len >= 8) {
        uint32_t k1 = GET_U32<bswap>(data, 0);
        k1 *= m; k1 ^= k1 >> r; k1 *= m;
        h1 *= m; h1 ^= k1;

        uint32_t k2 = GET_U32<bswap>(data, 4);
        k2 *= m; k2 ^= k2 >> r; k2 *= m;
        h2 *= m; h2 ^= k2;

        len  -= 8;
        data += 8;
    }

    if (len >= 4) {
        uint32_t k1 = GET_U32<bswap>(data, 0);
        k1   *= m; k1 ^= k1 >> r; k1 *= m;
        h1   *= m; h1 ^= k1;
        len  -= 4;
        data += 4;
    }

    switch (len) {
    case 3: h2 ^= data[2] << 16; /* FALLTHROUGH */
    case 2: h2 ^= data[1] <<  8; /* FALLTHROUGH */
    case 1: h2 ^= data[0];
            h2 *= m;
    }

    h1 ^= h2 >> 18; h1 *= m;
    h2 ^= h1 >> 22; h2 *= m;
    h1 ^= h2 >> 17; h1 *= m;
    h2 ^= h1 >> 19; h2 *= m;

    PUT_U32<bswap>(h1, (uint8_t *)out, isBE() ^ bswap ? 0 : 4);
    PUT_U32<bswap>(h2, (uint8_t *)out, isBE() ^ bswap ? 4 : 0);
}

//-----------------------------------------------------------------------------
// MurmurHash2A, by Austin Appleby

// This is a variant of MurmurHash2 modified to use the Merkle-Damgard
// construction. Bulk speed should be identical to Murmur2, small-key speed
// will be 10%-20% slower due to the added overhead at the end of the hash.

// This variant fixes a minor issue where null keys were more likely to
// collide with each other than expected, and also makes the function
// more amenable to incremental implementations.

#define mmix(h, k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }

template <bool bswap>
static void MurmurHash2A_32( const void * in, const size_t olen, const seed_t seed, void * out ) {
    const uint32_t m     = 0x5bd1e995;
    const uint32_t r     = 24;

    size_t   len         = olen;
    uint32_t len32       = olen;
    uint32_t h           = (uint32_t)seed;

    const uint8_t * data = (const uint8_t *)in;

    while (len >= 4) {
        uint32_t k = GET_U32<bswap>(data, 0);

        mmix(h, k);

        data += 4;
        len  -= 4;
    }

    uint32_t t = 0;

    switch (len) {
    case 3: t ^= data[2] << 16; /* FALLTHROUGH */
    case 2: t ^= data[1] <<  8; /* FALLTHROUGH */
    case 1: t ^= data[0];
    }

    mmix(h, t    );
    mmix(h, len32);

    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

REGISTER_FAMILY(murmur2,
   $.src_url    = "https://github.com/aappleby/smhasher/",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(MurmurHash2_32,
   $.desc       = "MurmurHash v2, 32-bit version",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY         |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0x27864C1E,
   $.verification_BE = 0xE87D9B54,
   $.hashfn_native   = MurmurHash2_32<false>,
   $.hashfn_bswap    = MurmurHash2_32<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0x10 }
 );

REGISTER_HASH(MurmurHash2_64,
   $.desc       = "MurmurHash v2, 64-bit version",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x1F0D3804,
   $.verification_BE = 0x8FDA498D,
   $.hashfn_native   = MurmurHash2_64<false>,
   $.hashfn_bswap    = MurmurHash2_64<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0xc6a4a7935bd1e995 }
 );

REGISTER_HASH(MurmurHash2_64__int32,
   $.desc       = "MurmurHash v2, 64-bit version using 32-bit variables",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY        |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xDD537C05,
   $.verification_BE = 0xBF573795,
   $.hashfn_native   = MurmurHash2_32_64<false>,
   $.hashfn_bswap    = MurmurHash2_32_64<true>,
   $.seedfixfn       = MurmurHash2_32_64_seedfix,
   $.badseeddesc     = "If seed==len, then hash of all zeroes is zero. Many seeds collide on varying lengths of all zero bytes."
 );

REGISTER_HASH(MurmurHash2a,
   $.desc       = "MurmurHash v2a, 32-bit version using variant mixing",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY        |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0x7FBD4396,
   $.verification_BE = 0x7D969EB5,
   $.hashfn_native   = MurmurHash2A_32<false>,
   $.hashfn_bswap    = MurmurHash2A_32<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0x2fc301c9 }
 );
