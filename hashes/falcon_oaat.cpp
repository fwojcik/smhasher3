/*
 * Small One-At-A-Time functions
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2016       Sokolov Yura aka funny_falcon <funny.falcon@gmail.com>
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
static uint32_t GoodOAAT_impl( const uint8_t * str, size_t len, uint32_t seed ) {
    const uint8_t * const end = str + len;
    uint32_t h1 = seed ^ 0x3b00;
    uint32_t h2 = ROTL32(seed, 15);

    for (; str != end; str++) {
        h1 += str[0];
        h1 += h1 << 3; // h1 *= 9
        h2 += h1;
        // the rest could be as in MicroOAAT: h1 = ROTL32(h1, 7)
        // but clang doesn't generate ROTL instruction then.
        h2  = ROTL32(h2, 7);
        h2 += h2 << 2; // h2 *= 5
    }

    h1 ^= h2;
    /*
     * now h1 passes all collision checks,
     * so it is suitable for hash-tables with prime numbers.
     */
    h1 += ROTL32(h2, 14);
    h2 ^= h1; h2 += ROTR32(h1, 6);
    h1 ^= h2; h1 += ROTL32(h2, 5);
    h2 ^= h1; h2 += ROTR32(h1, 8);

    return h2;
}

// MicroOAAT suitable for hash-tables using prime numbers.
// It passes all collision checks.
// Author: Sokolov Yura aka funny-falcon <funny.falcon@gmail.com>
static uint32_t MicroOAAT_impl( const uint8_t * str, size_t len, uint32_t seed ) {
    const uint8_t * const end = str + len;
    uint32_t h1 = seed ^ 0x3b00;
    uint32_t h2 = ROTL32(seed, 15);

    for (; str != end; str++) {
        h1 += str[0];
        h1 += h1 << 3; // h1 *= 9
        h2 -= h1;
        // unfortunately, clang produces bad code here,
        // cause it doesn't generate rotl instruction.
        h1 = ROTL32(h1, 7);
    }
    return h1 ^ h2;
}

//------------------------------------------------------------
template <bool bswap>
static void GoodOAAT( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = GoodOAAT_impl((const uint8_t *)in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void MicroOAAT( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = MicroOAAT_impl((const uint8_t *)in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(falcon_oaat,
   $.src_url    = "https://github.com/rurban/smhasher/commit/3931fd6f723f4fb2afab6ef9a628912220e90ce7",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(GoodOAAT,
   $.desc       = "GoodOAAT (Small non-multiplicative OAAT by funny-falcon)",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT  |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 32,
   $.verification_LE = 0x7B14EEE5,
   $.verification_BE = 0x1A834495,
   $.hashfn_native   = GoodOAAT<false>,
   $.hashfn_bswap    = GoodOAAT<true>
 );

REGISTER_HASH(MicroOAAT,
   $.desc       = "MicroOAAT (Small non-multiplicative OAAT by funny-falcon)",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT  |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 32,
   $.verification_LE = 0x16F1BA97,
   $.verification_BE = 0xDE58061B,
   $.hashfn_native   = MicroOAAT<false>,
   $.hashfn_bswap    = MicroOAAT<true>
 );
