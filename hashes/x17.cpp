/*
 * x17 hash
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
static uint32_t x17_impl( const uint8_t * data, size_t len, uint32_t h ) {
    for (size_t i = 0; i < len; ++i) {
        h = 17 * h + (data[i] - ' ');
    }
    return h ^ (h >> 16);
}

//------------------------------------------------------------
template <bool bswap>
static void x17( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = x17_impl((const uint8_t *)in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(x17,
   $.src_url    = "https://github.com/aappleby/smhasher/blob/master/src/Hashes.cpp",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(x17,
   $.desc       = "x17",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY     |
         FLAG_IMPL_LICENSE_MIT  |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 32,
   $.verification_LE = 0x8128E14C,
   $.verification_BE = 0x9AD0FE22,
   $.hashfn_native   = x17<false>,
   $.hashfn_bswap    = x17<true>
 );
