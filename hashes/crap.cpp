/*
 * Hashes from "noncryptohashzoo"
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

#include "Mathmult.h"

//------------------------------------------------------------
// From:
// https://github.com/aappleby/smhasher/blob/master/src/Hashes.cpp, and
// https://web.archive.org/web/20150218010816/http://floodyberry.com/noncryptohashzoo/Crap8.html
// https://web.archive.org/web/20150218011152/http://floodyberry.com/noncryptohashzoo/CrapWow.html
// https://web.archive.org/web/20150218011033/http://floodyberry.com/noncryptohashzoo/CrapWow64.html

template <bool bswap>
static uint32_t Crap8_impl( const uint8_t * key, size_t len, uint32_t seed ) {
#define c8fold( a, b, y, z ) {              \
        p  = (uint32_t)(a) * (uint64_t)(b); \
        y ^= (uint32_t)p;                   \
        z ^= (uint32_t)(p >> 32);           \
}
#define c8mix(in) { h *= m; c8fold(in, m, k, h); }

    const uint32_t m = 0x83d2e73b, n = 0x97e1cc59;
    uint32_t h = (uint32_t)len + seed, k = n + (uint32_t)len;
    uint64_t p;

    while (len >= 8) {
        c8mix(GET_U32<bswap>(key, 0));
        c8mix(GET_U32<bswap>(key, 4));
        key += 8; len -= 8;
    }
    if (len >= 4) {
        c8mix(GET_U32<bswap>(key, 0));
        key += 4; len -= 4;
    }
    if (len) {
        if (isLE() ^ bswap) {
            c8mix(GET_U32<bswap>(key, 0) & ((1 << (len * 8)) - 1));
        } else {
            c8mix(GET_U32<bswap>(key, 0) >> (32 - (len * 8)));
        }
    }
    c8fold(h ^ k, n, k, k);
    return k;
}

#undef c8mix
#undef c8fold

template <bool bswap>
static uint32_t CrapWow_impl( const uint8_t * key, size_t len, uint32_t seed ) {
#define cwfold( a, b, lo, hi) {              \
        p   = (uint32_t)(a) * (uint64_t)(b); \
        lo ^= (uint32_t)p;                   \
        hi ^= (uint32_t)(p >> 32);           \
    }
#define cwmixa(in) { cwfold(in, m, k, h); }
#define cwmixb(in) { cwfold(in, n, h, k); }

    const uint32_t m = 0x57559429, n = 0x5052acdb;
    uint32_t h = (uint32_t)len, k = (uint32_t)len + seed + n;
    uint64_t p;

    while (len >= 8) {
        cwmixb(GET_U32<bswap>(key, 0));
        cwmixa(GET_U32<bswap>(key, 4));
        key += 8; len -= 8;
    }
    if (len >= 4) {
        cwmixb(GET_U32<bswap>(key, 0));
        key += 4; len -= 4;
    }
    if (len) {
        if (isLE() ^ bswap) {
            cwmixa(GET_U32<bswap>(key, 0) & ((1 << (len * 8)) - 1));
        } else {
            cwmixa(GET_U32<bswap>(key, 0) >> (32 - (len * 8)));
        }
    }

    cwmixb(h ^ (k + n));
    return k ^ h;
}

#undef cwmixb
#undef cwmixa
#undef cwfold

template <bool bswap>
static uint64_t CrapWow64_impl( const uint8_t * key, size_t len, uint64_t seed ) {
#define cwfold(a, b, lo, hi) {              \
        MathMult::mult64_128(pl, ph, a, b); \
        lo ^= pl;                           \
        hi ^= ph;                           \
    }
#define cwmixa(in) { cwfold(in, m, k, h); }
#define cwmixb(in) { cwfold(in, n, h, k); }

    const uint64_t m = UINT64_C(0x95b47aa3355ba1a1), n = UINT64_C(0x8a970be7488fda55);
    uint64_t h = (uint64_t)len, k = (uint64_t)len + seed + n;
    uint64_t pl, ph;

    while (len >= 16) {
        cwmixb(GET_U64<bswap>(key, 0));
        cwmixa(GET_U64<bswap>(key, 8));
        key += 16; len -= 16;
    }
    if (len >= 8) {
        cwmixb(GET_U64<bswap>(key, 0));
        key += 8; len -= 8;
    }
    if (len) {
        if (isLE() ^ bswap) {
            cwmixa(GET_U64<bswap>(key, 0) & ((UINT64_C(1) << (len * 8)) - 1));
        } else {
            cwmixa(GET_U64<bswap>(key, 0) >> (64 - (len * 8)));
        }
    }

    cwmixb(h ^ (k + n));
    return k ^ h;
}

#undef cwmixb
#undef cwmixa
#undef cwfold

//------------------------------------------------------------
template <bool bswap>
static void Crap8( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = Crap8_impl<bswap>((const uint8_t *)in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void CrapWow( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = CrapWow_impl<bswap>((const uint8_t *)in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void CrapWow64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = CrapWow64_impl<bswap>((const uint8_t *)in, len, (uint64_t)seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(crap,
   $.src_url    = "https://web.archive.org/web/20150218011033/http://floodyberry.com/noncryptohashzoo/",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(Crap8,
   $.desc       = "Noncryptohashzoo's Crap8 hash",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB  |
         FLAG_IMPL_MULTIPLY       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0x743E97A1,
   $.verification_BE = 0xDFE06AD9,
   $.hashfn_native   = Crap8<false>,
   $.hashfn_bswap    = Crap8<true>
 );

REGISTER_HASH(CrapWow,
   $.desc       = "Noncryptohashzoo's CrapWow hash",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS   |
         FLAG_IMPL_READ_PAST_EOB  |
         FLAG_IMPL_MULTIPLY       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0x49ECB015,
   $.verification_BE = 0x4EF994DF,
   $.hashfn_native   = CrapWow<false>,
   $.hashfn_bswap    = CrapWow<true>
 );

REGISTER_HASH(CrapWow_64,
   $.desc       = "Noncryptohashzoo's CrapWow64 hash",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS    |
         FLAG_IMPL_READ_PAST_EOB   |
         FLAG_IMPL_MULTIPLY_64_128 |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x669D3A9B,
   $.verification_BE = 0xCBB7690C,
   $.hashfn_native   = CrapWow64<false>,
   $.hashfn_bswap    = CrapWow64<true>,
   $.badseeddesc     = "Any keys of len==32*N consisting of repeated 16-byte blocks collide with any seed"
 );
