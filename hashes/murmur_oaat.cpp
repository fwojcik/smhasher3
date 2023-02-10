/*
 * One-byte-at-a-time hash based on Murmur's mix
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2016       aappleby
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
static uint32_t MurmurOAAT_impl( const uint8_t * data, size_t len, uint32_t seed ) {
    uint32_t h = seed;

    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x5bd1e995;
        h ^= h >> 15;
    }
    return h;
}

//------------------------------------------------------------
template <bool bswap>
static void MurmurOAAT( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = MurmurOAAT_impl((const uint8_t *)in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(MurmurOAAT,
   $.src_url    = "https://github.com/aappleby/smhasher/blob/master/src/Hashes.cpp",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(MurmurOAAT,
   $.desc       = "OAAT hash based on Murmur's mix",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS  |
         FLAG_IMPL_MULTIPLY      |
         FLAG_IMPL_LICENSE_MIT   |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 32,
   $.verification_LE = 0x5363BD98,
   $.verification_BE = 0x29CCE130,
   $.hashfn_native   = MurmurOAAT<false>,
   $.hashfn_bswap    = MurmurOAAT<true>
 );
