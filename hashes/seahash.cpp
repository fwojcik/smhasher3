/*
 * SeaHash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2019-2020 Reini Urban
 * Copyright (c) 2019 data-man
 * Copyright (c) 2016 Vsevolod Stakhov
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

#include <cassert>

static inline uint64_t diffuse( uint64_t val ) {
    uint64_t a, b;

    val *= UINT64_C(0x6eed0e9da4d94a4f);
    a    = val >> 32;
    b    = val >> 60;
    val ^= a >> b;
    val *= UINT64_C(0x6eed0e9da4d94a4f);
    return val;
}

template <bool bswap>
static uint64_t seahash( const uint8_t * key, size_t len, uint64_t seed ) {
    uint64_t       a, b, c, d;
    uint8_t        pad[8]   = { 0 };
    const uint64_t orig_len = (uint64_t)len;

    a = UINT64_C(0x16f11fe89b0d677c) ^ seed;
    b = UINT64_C(0xb480a793d8e6c86c);
    c = UINT64_C(0x6fe2e5aaf078ebc9);
    d = UINT64_C(0x14f994a4c5259381);

    while (len >= 32) {
        a   ^= GET_U64<bswap>(key,  0);
        b   ^= GET_U64<bswap>(key,  8);
        c   ^= GET_U64<bswap>(key, 16);
        d   ^= GET_U64<bswap>(key, 24);
        a    = diffuse(a);
        b    = diffuse(b);
        c    = diffuse(c);
        d    = diffuse(d);
        len -= 32;
        key += 32;
    }

    switch (len) {
    case 31: case 30: case 29: case 28: case 27: case 26: case 25:
             a ^= GET_U64<bswap>(key,  0);
             b ^= GET_U64<bswap>(key,  8);
             c ^= GET_U64<bswap>(key, 16);
             memcpy(pad, key + 24, len - 24);
             d ^= GET_U64<bswap>(pad, 0);
             a  = diffuse(a);
             b  = diffuse(b);
             c  = diffuse(c);
             d  = diffuse(d);
             break;
    case 24:
             a ^= GET_U64<bswap>(key,  0);
             b ^= GET_U64<bswap>(key,  8);
             c ^= GET_U64<bswap>(key, 16);
             a  = diffuse(a);
             b  = diffuse(b);
             c  = diffuse(c);
             break;
    case 23: case 22: case 21: case 20: case 19: case 18: case 17:
             a ^= GET_U64<bswap>(key, 0);
             b ^= GET_U64<bswap>(key, 8);
             memcpy(pad, key + 16, len - 16);
             c ^= GET_U64<bswap>(pad, 0);
             a  = diffuse(a);
             b  = diffuse(b);
             c  = diffuse(c);
             break;
    case 16:
             a ^= GET_U64<bswap>(key, 0);
             b ^= GET_U64<bswap>(key, 8);
             a  = diffuse(a);
             b  = diffuse(b);
             break;
    case 15: case 14: case 13: case 12: case 11: case 10: case 9:
             a ^= GET_U64<bswap>(key, 0);
             memcpy(pad, key + 8, len - 8);
             b ^= GET_U64<bswap>(pad, 0);
             a  = diffuse(a);
             b  = diffuse(b);
             break;
    case  8:
             a ^= GET_U64<bswap>(key, 0);
             a  = diffuse(a);
             break;
    case  7: case 6: case 5: case 4: case 3: case 2: case 1:
             memcpy(pad, key, len);
             a ^= GET_U64<bswap>(pad, 0);
             a  = diffuse(a);
             break;
    case  0:
             break;
    default:
             unreachable();
             assert(0);
    }

    a ^= b;
    c ^= d;
    a ^= c;
    a ^= orig_len;
    return BSWAP(diffuse(a));
}

template <bool bswap>
static void SeaHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = seahash<bswap>((const uint8_t *)in, len, (uint64_t)seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

REGISTER_FAMILY(seahash,
   $.src_url    = "https://gist.github.com/vstakhov/b58b855532a424cd634b6c7ea7baa1b9",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(seahash,
   $.desc       = "seahash",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64 |
         FLAG_IMPL_ROTATE         |
         FLAG_IMPL_SHIFT_VARIABLE |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xF0374078,
   $.verification_BE = 0x5BD66274,
   $.hashfn_native   = SeaHash<false>,
   $.hashfn_bswap    = SeaHash<true>
 );
