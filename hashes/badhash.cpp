/*
 * BadHash and other simple, bad mock hashes
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2014-2021 Reini Urban
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

template <bool bswap>
static void BadHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t *       data = (const uint8_t *)in;
    const uint8_t * const end  = &data[len];
    uint32_t h = seed;

    while (data < end) {
        h ^= h >> 3;
        h ^= h << 5;
        h ^= *data++;
    }

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void sumhash8( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t *       data = (const uint8_t *)in;
    const uint8_t * const end  = &data[len];
    uint32_t h = seed;

    while (data < end) {
        h += *data++;
    }

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void sumhash32( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint32_t *       data = (const uint32_t *)in;
    const uint32_t * const end  = &data[len / 4];
    uint32_t h = seed;

    while (data < end) {
        h += GET_U32<bswap>((const uint8_t *)data, 0);
        data++;
    }

    if (len & 3) {
        uint8_t * dc = (uint8_t *)data; // byte stepper
        const uint8_t * const endc = &((const uint8_t *)in)[len];
        while (dc < endc) {
            h += *dc++ * UINT64_C(11400714819323198485);
        }
    }

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

REGISTER_FAMILY(badhash,
   $.src_url    = "https://github.com/rurban/smhasher/blob/master/Hashes.cpp",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(badhash,
   $.desc       = "very simple XOR shift",
   $.hash_flags =
         FLAG_HASH_MOCK             |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS     |
         FLAG_IMPL_LICENSE_MIT      |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 32,
   $.verification_LE = 0xAB432E23,
   $.verification_BE = 0x241F49BE,
   $.hashfn_native   = BadHash<false>,
   $.hashfn_bswap    = BadHash<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0 },
   $.sort_order      = 20
 );

REGISTER_HASH(sum8hash,
   $.desc       = "sum all 8-bit bytes",
   $.hash_flags =
         FLAG_HASH_MOCK             |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT      |
         FLAG_IMPL_SANITY_FAILS,
   $.bits = 32,
   $.verification_LE = 0x0000A9AC,
   $.verification_BE = 0xACA90000,
   $.hashfn_native   = sumhash8<false>,
   $.hashfn_bswap    = sumhash8<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0 },
   $.sort_order      = 30
 );

REGISTER_HASH(sum32hash,
   $.desc       = "sum all 32-bit words",
   $.hash_flags =
         FLAG_HASH_MOCK             |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT      |
         FLAG_IMPL_SANITY_FAILS     |
         FLAG_IMPL_MULTIPLY,
   $.bits = 32,
   $.verification_LE = 0x3D6DC280,
   $.verification_BE = 0x00A10D9E,
   $.hashfn_native   = sumhash32<false>,
   $.hashfn_bswap    = sumhash32<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0 },
   $.sort_order      = 31
 );
