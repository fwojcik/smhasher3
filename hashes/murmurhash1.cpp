/*
 * Murmur hash, version 1 variants
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
static void MurmurHash1( const void * in, const size_t olen, const seed_t seed, void * out ) {
    // uint32_t MurmurHash1 ( const void * key, int len, uint32_t seed )
    const uint32_t m = 0xc6a4a793;
    const uint32_t r = 16;

    size_t   len     = olen;
    uint32_t h       = seed;

    h ^= len * m;

    //----------
    const uint8_t * data = (const uint8_t *)in;

    while (len >= 4) {
        uint32_t k = GET_U32<bswap>(data, 0);

        h    += k;
        h    *= m;
        h    ^= h >> 16;

        data += 4;
        len  -= 4;
    }

    //----------
    switch (len) {
    case 3:
            h += data[2] << 16; /* FALLTHROUGH */
    case 2:
            h += data[1] <<  8; /* FALLTHROUGH */
    case 1:
            h += data[0];
            h *= m;
            h ^= h >> r;
    }

    //----------
    h *= m;
    h ^= h >> 10;
    h *= m;
    h ^= h >> 17;

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

REGISTER_FAMILY(murmur1,
   $.src_url    = "https://github.com/aappleby/smhasher/",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(MurmurHash1,
   $.desc       = "MurmurHash v1",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY         |
         FLAG_IMPL_LICENSE_MIT      |
         FLAG_IMPL_SLOW,
   $.bits = 32,
   $.verification_LE = 0x9EA7D056,
   $.verification_BE = 0x4B34A47A,
   $.hashfn_native   = MurmurHash1<false>,
   $.hashfn_bswap    = MurmurHash1<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0xc6a4a793 }
 );
