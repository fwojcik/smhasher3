/*
 * khash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2021 Reini Urban
 * Copyright (c) 2021 Keith-Cancel
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
// "khash" is really *only* these two mathematical functions.
// khash64_fn maps 2 64-bit inputs to a 64-bit output,
// and khash32_fn maps 3 32-bit inputs to a 32-bit output.
static inline uint64_t khash64_fn( uint64_t input, uint64_t func ) {
    uint64_t h = func;

    h ^= input - 7;
    h ^= ROTR64(h, 31);
    h -= ROTR64(h, 11);
    h -= ROTR64(h, 17);

    h ^= input - 13;
    h ^= ROTR64(h, 23);
    h += ROTR64(h, 31);
    h -= ROTR64(h, 13);

    h ^= input - 2;
    h -= ROTR64(h, 19);
    h += ROTR64(h,  5);
    h -= ROTR64(h, 31);
    return h;
}

static inline uint32_t khash32_fn( uint32_t input, uint32_t func1, uint32_t func2 ) {
    uint32_t h = input;

    h  = ROTR32(h, 16);
    h ^= func2;
    h -= 5;
    h  = ROTR32(h, 17);
    h += func1;
    h  = ROTR32(h,  1);

    h += ROTR32(h, 27);
    h ^= ROTR32(h,  3);
    h -= ROTR32(h, 17);
    h -= ROTR32(h, 27);

    h ^= input - 107;
    h -= ROTR32(h, 11);
    h ^= ROTR32(h,  7);
    h -= ROTR32(h,  5);
    return h;
}

// Just initialize with the fractional part of sqrt(2)
// #define khash64(input) khash64_fn(input, 0x6a09e667f3bcc908)
// #define khash32(input) khash32_fn(input, 0x6a09e667, 0xf3bcc908)

//------------------------------------------------------------
// These hash functions operate on any amount of data, and hash it
// using the khash transforms above. However, these are VERY bad
// implementations, and a much better hash could probably be made from
// them. These are kept for the moment for "backwards compatibility"
// with the current SMHasher. The seeding in khash32 was made to
// handle 64-bit seeds but return the existing results when the high
// 32 bits are zero, so that the verification value is unchanged.

template <bool bswap>
static void khash32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t       seedlo      = (uint32_t)(seed      );
    uint32_t       seedhi      = (uint32_t)(seed >> 32);
    uint32_t       hash        = ~seedlo;
    const uint32_t K           = UINT32_C(0xf3bcc908) ^ seedhi;

    const uint8_t * const endw = &((const uint8_t *)in)[len & ~3];
    uint8_t * dw = (uint8_t *)in;

    while (dw < endw) {
        hash ^= khash32_fn(GET_U32<bswap>(dw, 0), seed, K);
        dw   += 4;
    }
    const size_t flen = len & 3;
    if (flen) {
        uint32_t last;
        if (isLE() ^ bswap) {
            last = GET_U32<bswap>(dw, 0) & ((1 << (flen * 8)) - 1);
        } else {
            last = GET_U32<bswap>(dw, 0) >> (32 - (flen * 8));
        }
        hash ^= khash32_fn(last, seed, K);
    }
    PUT_U32<bswap>(hash, (uint8_t *)out, 0);
}

template <bool bswap>
static void khash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t seed64 = ((uint64_t)seed ^ UINT64_C(0x6a09e66700000000));
    uint64_t hash   = ~seed64;

    const uint8_t * const endw = &((const uint8_t *)in)[len & ~7];
    uint8_t * dw = (uint8_t *)in;

    while (dw < endw) {
        hash ^= khash64_fn(GET_U64<bswap>(dw, 0), seed64);
        dw   += 8;
    }
    const size_t flen = len & 7;
    if (flen) {
        uint64_t last;
        if (isLE() ^ bswap) {
            last = GET_U64<bswap>(dw, 0) & ((UINT64_C(1) << (flen * 8)) - 1);
        } else {
            last = GET_U64<bswap>(dw, 0) >> (64 - (flen * 8));
        }
        hash ^= khash64_fn(last, seed64);
    }
    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(khash,
   $.src_url    = "https://github.com/Keith-Cancel/k-hash",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(khash_32,
   $.desc       = "K-Hash 32 bit mixer-based hash",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS  |
         FLAG_IMPL_READ_PAST_EOB |
         FLAG_IMPL_ROTATE        |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0xA17DA29E,
   $.verification_BE = 0x59073F57,
   $.hashfn_native   = khash32<false>,
   $.hashfn_bswap    = khash32<true>
 );

REGISTER_HASH(khash_64,
   $.desc       = "K-Hash 64 bit mixer-based hash",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS  |
         FLAG_IMPL_READ_PAST_EOB |
         FLAG_IMPL_ROTATE        |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x44BD88C4,
   $.verification_BE = 0xCF3003D1,
   $.hashfn_native   = khash64<false>,
   $.hashfn_bswap    = khash64<true>,
   $.badseeddesc     = "All seeds are bad"
 );
