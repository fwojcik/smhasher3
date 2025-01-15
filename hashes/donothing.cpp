/*
 * DoNothing hash and DoNothing One-At-A-Time Hash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2014-2021 Reini Urban
 * Copyright (c) 2015      Paul G
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

static void DoNothingHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    unused(in); unused(len); unused(seed); unused(out);
}

template <uint32_t hashlen>
static void DoNothingOAATHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t *       data = (const uint8_t *)in;
    const uint8_t * const end  = &data[len];
    uint32_t h = seed >> 32;

    while (data < end) {
        h &= *data++;
    }
    *(uint8_t *)out = (uint8_t)h;
}

REGISTER_FAMILY(donothing,
   $.src_url    = "https://github.com/rurban/smhasher/blob/master/Hashes.cpp",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(donothing_32,
   $.desc       = "Do-Nothing function (measure call overhead)",
   $.hash_flags =
         FLAG_HASH_MOCK,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS     |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0x0,
   $.verification_BE = 0x0,
   $.hashfn_native   = DoNothingHash,
   $.hashfn_bswap    = DoNothingHash
 );

REGISTER_HASH(donothing_64,
   $.desc       = "Do-Nothing function (measure call overhead)",
   $.hash_flags =
         FLAG_HASH_MOCK,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS     |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x0,
   $.verification_BE = 0x0,
   $.hashfn_native   = DoNothingHash,
   $.hashfn_bswap    = DoNothingHash
 );

REGISTER_HASH(donothing_128,
   $.desc       = "Do-Nothing function (measure call overhead)",
   $.hash_flags =
         FLAG_HASH_MOCK,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS     |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x0,
   $.verification_BE = 0x0,
   $.hashfn_native   = DoNothingHash,
   $.hashfn_bswap    = DoNothingHash
 );

REGISTER_HASH(donothing_256,
   $.desc       = "Do-Nothing function (measure call overhead)",
   $.hash_flags =
         FLAG_HASH_MOCK,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS     |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 256,
   $.verification_LE = 0x0,
   $.verification_BE = 0x0,
   $.hashfn_native   = DoNothingHash,
   $.hashfn_bswap    = DoNothingHash
 );

REGISTER_HASH(donothingOAAT_32,
   $.desc       = "Do-Nothing OAAT function (measure call+OAAT overhead)",
   $.hash_flags =
         FLAG_HASH_MOCK,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS     |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0x0,
   $.verification_BE = 0x0,
   $.hashfn_native   = DoNothingOAATHash<32>,
   $.hashfn_bswap    = DoNothingOAATHash<32>,
   $.sort_order      = 10
 );

REGISTER_HASH(donothingOAAT_64,
   $.desc       = "Do-Nothing OAAT function (measure call+OAAT overhead)",
   $.hash_flags =
         FLAG_HASH_MOCK,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS     |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x0,
   $.verification_BE = 0x0,
   $.hashfn_native   = DoNothingOAATHash<64>,
   $.hashfn_bswap    = DoNothingOAATHash<64>,
   $.sort_order      = 10
 );

REGISTER_HASH(donothingOAAT_128,
   $.desc       = "Do-Nothing OAAT function (measure call+OAAT overhead)",
   $.hash_flags =
         FLAG_HASH_MOCK,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS     |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x0,
   $.verification_BE = 0x0,
   $.hashfn_native   = DoNothingOAATHash<128>,
   $.hashfn_bswap    = DoNothingOAATHash<128>,
   $.sort_order      = 10
 );
