/*
 * Murmur hash, version 3 variants
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
 * MurmurHash3 was written by Austin Appleby, and is placed in the public
 * domain. The author hereby disclaims copyright to this source code.
 */
#include "Platform.h"
#include "Hashlib.h"

static FORCE_INLINE uint32_t fmix32( uint32_t h ) {
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    return h;
}

static FORCE_INLINE uint64_t fmix64( uint64_t k ) {
    k ^= k >> 33;
    k *= UINT64_C(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k *= UINT64_C(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;

    return k;
}

//-----------------------------------------------------------------------------
// Block read - if your platform needs to do endian-swapping or can only
// handle aligned reads, do the conversion here

template <bool bswap>
static FORCE_INLINE uint32_t getblock32( const uint8_t * p, int64_t i ) {
    return GET_U32<bswap>(p + (4 * i), 0);
}

template <bool bswap>
static FORCE_INLINE uint64_t getblock64( const uint8_t * p, int64_t i ) {
    return GET_U64<bswap>(p + (8 * i), 0);
}

//-----------------------------------------------------------------------------
template <bool bswap>
static void MurmurHash3_32( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * data    = (const uint8_t *)in;
    const ssize_t   nblocks = len / 4;

    uint32_t h1       = (uint32_t)seed;

    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    //----------
    // body

    const uint8_t * blocks = data + nblocks * 4;

    for (ssize_t i = -nblocks; i; i++) {
        uint32_t k1 = getblock32<bswap>(blocks, i);

        k1 *= c1;
        k1  = ROTL32(k1, 15);
        k1 *= c2;

        h1 ^= k1;
        h1  = ROTL32(h1, 13);
        h1  = h1 * 5 + 0xe6546b64;
    }

    //----------
    // tail

    const uint8_t * tail = data + nblocks * 4;

    uint32_t k1 = 0;

    switch (len & 3) {
    case 3: k1 ^= tail[2] << 16; /* FALLTHROUGH */
    case 2: k1 ^= tail[1] <<  8; /* FALLTHROUGH */
    case 1: k1 ^= tail[0];
            k1 *= c1; k1 = ROTL32(k1, 15); k1 *= c2; h1 ^= k1;
    }

    //----------
    // finalization

    h1 ^= (uint32_t)len;

    h1  = fmix32(h1);

    PUT_U32<bswap>(h1, (uint8_t *)out, 0);
}

//-----------------------------------------------------------------------------
template <bool bswap>
static void MurmurHash3_32_128( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * data    = (const uint8_t *)in;
    const ssize_t   nblocks = len / 16;

    uint32_t h1       = (uint32_t)seed;
    uint32_t h2       = (uint32_t)seed;
    uint32_t h3       = (uint32_t)seed;
    uint32_t h4       = (uint32_t)seed;

    const uint32_t c1 = 0x239b961b;
    const uint32_t c2 = 0xab0e9789;
    const uint32_t c3 = 0x38b34ae5;
    const uint32_t c4 = 0xa1e38b93;

    //----------
    // body

    const uint8_t * blocks = data + nblocks * 16;

    for (ssize_t i = -nblocks; i; i++) {
        uint32_t k1 = getblock32<bswap>(blocks, i * 4 + 0);
        uint32_t k2 = getblock32<bswap>(blocks, i * 4 + 1);
        uint32_t k3 = getblock32<bswap>(blocks, i * 4 + 2);
        uint32_t k4 = getblock32<bswap>(blocks, i * 4 + 3);

        k1 *= c1; k1 = ROTL32(k1, 15); k1 *= c2; h1 ^= k1;

        h1  = ROTL32(h1,          19); h1 += h2; h1  = h1 * 5 + 0x561ccd1b;

        k2 *= c2; k2 = ROTL32(k2, 16); k2 *= c3; h2 ^= k2;

        h2  = ROTL32(h2,          17); h2 += h3; h2  = h2 * 5 + 0x0bcaa747;

        k3 *= c3; k3 = ROTL32(k3, 17); k3 *= c4; h3 ^= k3;

        h3  = ROTL32(h3,          15); h3 += h4; h3  = h3 * 5 + 0x96cd1c35;

        k4 *= c4; k4 = ROTL32(k4, 18); k4 *= c1; h4 ^= k4;

        h4  = ROTL32(h4,          13); h4 += h1; h4  = h4 * 5 + 0x32ac3b17;
    }

    //----------
    // tail

    const uint8_t * tail = data + nblocks * 16;

    uint32_t k1 = 0;
    uint32_t k2 = 0;
    uint32_t k3 = 0;
    uint32_t k4 = 0;

    switch (len & 15) {
    case 15: k4 ^= tail[14] << 16; /* FALLTHROUGH */
    case 14: k4 ^= tail[13] <<  8; /* FALLTHROUGH */
    case 13: k4 ^= tail[12] <<  0; /* FALLTHROUGH */
             k4 *= c4; k4 = ROTL32(k4, 18); k4 *= c1; h4 ^= k4;
    /* FALLTHROUGH */
    case 12: k3 ^= tail[11] << 24; /* FALLTHROUGH */
    case 11: k3 ^= tail[10] << 16; /* FALLTHROUGH */
    case 10: k3 ^= tail[ 9] <<  8; /* FALLTHROUGH */
    case  9: k3 ^= tail[ 8] <<  0; /* FALLTHROUGH */
             k3 *= c3; k3 = ROTL32(k3, 17); k3 *= c4; h3 ^= k3;
    /* FALLTHROUGH */
    case  8: k2 ^= tail[ 7] << 24; /* FALLTHROUGH */
    case  7: k2 ^= tail[ 6] << 16; /* FALLTHROUGH */
    case  6: k2 ^= tail[ 5] <<  8; /* FALLTHROUGH */
    case  5: k2 ^= tail[ 4] <<  0; /* FALLTHROUGH */
             k2 *= c2; k2 = ROTL32(k2, 16); k2 *= c3; h2 ^= k2;
    /* FALLTHROUGH */
    case  4: k1 ^= tail[ 3] << 24; /* FALLTHROUGH */
    case  3: k1 ^= tail[ 2] << 16; /* FALLTHROUGH */
    case  2: k1 ^= tail[ 1] <<  8; /* FALLTHROUGH */
    case  1: k1 ^= tail[ 0] <<  0;
             k1 *= c1; k1 = ROTL32(k1, 15); k1 *= c2; h1 ^= k1;
    }

    //----------
    // finalization

    h1 ^= (uint32_t)len; h2 ^= (uint32_t)len;
    h3 ^= (uint32_t)len; h4 ^= (uint32_t)len;

    h1 += h2; h1 += h3; h1 += h4;
    h2 += h1; h3 += h1; h4 += h1;

    h1  = fmix32(h1);
    h2  = fmix32(h2);
    h3  = fmix32(h3);
    h4  = fmix32(h4);

    h1 += h2; h1 += h3; h1 += h4;
    h2 += h1; h3 += h1; h4 += h1;

    PUT_U32<bswap>(h1, (uint8_t *)out,  0);
    PUT_U32<bswap>(h2, (uint8_t *)out,  4);
    PUT_U32<bswap>(h3, (uint8_t *)out,  8);
    PUT_U32<bswap>(h4, (uint8_t *)out, 12);
}

//-----------------------------------------------------------------------------
template <bool bswap>
static void MurmurHash3_128( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * data    = (const uint8_t *)in;
    const size_t    nblocks = len / 16;

    uint64_t h1       = (uint32_t)seed;
    uint64_t h2       = (uint32_t)seed;

    const uint64_t c1 = UINT64_C(0x87c37b91114253d5);
    const uint64_t c2 = UINT64_C(0x4cf5ad432745937f);

    //----------
    // body

    const uint8_t * blocks = data;

    for (size_t i = 0; i < nblocks; i++) {
        uint64_t k1 = getblock64<bswap>(blocks, i * 2 + 0);
        uint64_t k2 = getblock64<bswap>(blocks, i * 2 + 1);

        k1 *= c1; k1 = ROTL64(k1, 31); k1 *= c2; h1 ^= k1;

        h1  = ROTL64(h1,          27); h1 += h2; h1  = h1 * 5 + 0x52dce729;

        k2 *= c2; k2 = ROTL64(k2, 33); k2 *= c1; h2 ^= k2;

        h2  = ROTL64(h2,          31); h2 += h1; h2  = h2 * 5 + 0x38495ab5;
    }

    //----------
    // tail

    const uint8_t * tail = data + nblocks * 16;

    uint64_t k1 = 0;
    uint64_t k2 = 0;

    switch (len & 15) {
    case 15: k2 ^= ((uint64_t)tail[14]) << 48; /* FALLTHROUGH */
    case 14: k2 ^= ((uint64_t)tail[13]) << 40; /* FALLTHROUGH */
    case 13: k2 ^= ((uint64_t)tail[12]) << 32; /* FALLTHROUGH */
    case 12: k2 ^= ((uint64_t)tail[11]) << 24; /* FALLTHROUGH */
    case 11: k2 ^= ((uint64_t)tail[10]) << 16; /* FALLTHROUGH */
    case 10: k2 ^= ((uint64_t)tail[ 9]) <<  8; /* FALLTHROUGH */
    case  9: k2 ^= ((uint64_t)tail[ 8]) <<  0;
             k2 *= c2; k2 = ROTL64(k2, 33); k2 *= c1; h2 ^= k2;
    /* FALLTHROUGH */
    case  8: k1 ^= ((uint64_t)tail[ 7]) << 56; /* FALLTHROUGH */
    case  7: k1 ^= ((uint64_t)tail[ 6]) << 48; /* FALLTHROUGH */
    case  6: k1 ^= ((uint64_t)tail[ 5]) << 40; /* FALLTHROUGH */
    case  5: k1 ^= ((uint64_t)tail[ 4]) << 32; /* FALLTHROUGH */
    case  4: k1 ^= ((uint64_t)tail[ 3]) << 24; /* FALLTHROUGH */
    case  3: k1 ^= ((uint64_t)tail[ 2]) << 16; /* FALLTHROUGH */
    case  2: k1 ^= ((uint64_t)tail[ 1]) <<  8; /* FALLTHROUGH */
    case  1: k1 ^= ((uint64_t)tail[ 0]) <<  0;
             k1 *= c1; k1 = ROTL64(k1, 31); k1 *= c2; h1 ^= k1;
    }

    //----------
    // finalization

    h1 ^= (uint32_t)len; h2 ^= (uint32_t)len;

    h1 += h2;
    h2 += h1;

    h1  = fmix64(h1);
    h2  = fmix64(h2);

    h1 += h2;
    h2 += h1;

    PUT_U64<bswap>(h1, (uint8_t *)out, 0);
    PUT_U64<bswap>(h2, (uint8_t *)out, 8);
}

REGISTER_FAMILY(murmur3,
   $.src_url    = "https://github.com/aappleby/smhasher/",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(MurmurHash3_32,
   $.desc       = "MurmurHash v3, 32-bit version",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY         |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0xB0F57EE3,
   $.verification_BE = 0x6213303E,
   $.hashfn_native   = MurmurHash3_32<false>,
   $.hashfn_bswap    = MurmurHash3_32<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0xfca58b2d }
 );

REGISTER_HASH(MurmurHash3_128__int32,
   $.desc       = "MurmurHash v3, 128-bit version using 32-bit variables",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY         |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0xB3ECE62A,
   $.verification_BE = 0xDC26F009,
   $.hashfn_native   = MurmurHash3_32_128<false>,
   $.hashfn_bswap    = MurmurHash3_32_128<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }
 );

REGISTER_HASH(MurmurHash3_128,
   $.desc       = "MurmurHash v3, 128-bit version using 64-bit variables",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x6384BA69,
   $.verification_BE = 0xCC622B6F,
   $.hashfn_native   = MurmurHash3_128<false>,
   $.hashfn_bswap    = MurmurHash3_128<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }
 );
