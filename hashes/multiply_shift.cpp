/*
 * Multiply-Shift Hash
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (C) 2023       jason
 * Copyright (C) 2020       Thomas Dybdahl Ahle
 * Copyright (c) 2019       Reini Urban
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

// Multiply shift from
// Thorup "High Speed Hashing for Integers and Strings" 2018
// https://arxiv.org/pdf/1504.06804.pdf

// A randomly-generated table of 128-bit multiplicative constants
const static int MULTIPLY_SHIFT_RANDOM_WORDS = 1 << 8;
static uint64_t  multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS * 2];

// This is just the Xorshift RNG, which was arbitrarily chosen.  This
// hash is labeled as system-dependent, since this would really be
// replaced by *some* kind of srand()/rand() in practice.
static inline void mix( uint32_t & w, uint32_t & x, uint32_t & y, uint32_t & z ) {
    uint32_t t = x ^ (x << 11);

    x = y; y = z; z = w;
    w = w ^ (w >> 19) ^ t ^ (t >> 8);
}

static uintptr_t multiply_shift_seed_init_slow( const seed_t seed ) {
    uint32_t w, x, y, z;

    x = 0x498b3bc5 ^ (uint32_t)(seed      );
    y = 0x5a05089a ^ (uint32_t)(seed >> 32);
    w = z = 0;
    for (int i = 0; i < 10; i++) { mix(w, x, y, z); }

    for (int i = 0; i < MULTIPLY_SHIFT_RANDOM_WORDS; i++) {
        mix(w, x, y, z);
        multiply_shift_random[2 * i + 1] = ((uint64_t)(x) << 32) | y;
        mix(w, x, y, z);
        multiply_shift_random[2 * i + 0] = ((uint64_t)(x) << 32) | y;
        if (!multiply_shift_random[2 * i + 0]) {
            multiply_shift_random[2 * i + 0]++;
        }
    }
    return 0;
}

static bool multiply_shift_init( void ) {
    multiply_shift_seed_init_slow(0);
    return true;
}

// Vector multiply-shift (3.4) from Thorup's notes.
template <bool bswap>
static void multiply_shift32( const void * in, const size_t len_bytes, const seed_t seed, void * out ) {
    const uint8_t * buf = (const uint8_t *)in;
    const size_t    len = len_bytes / 4;

    // We mix in len_bytes in the basis, since smhasher considers two keys
    // of different length to be different, even if all the extra bits are 0.
    // This is needed for the AppendZero test.
    // ">> 16 >> 16" is because ">> 32" is undefined if size_t is 32 bits.
    uint64_t h, t;

    h =     (uint32_t)(seed                 ) * multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 1] +
            (uint32_t)(seed      >> 16 >> 16) * multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 2] +
            (uint32_t)(len_bytes            ) * multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 3] +
            (uint32_t)(len_bytes >> 16 >> 16) * multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 4];

    for (size_t i = 0; i < len; i++, buf += 4) {
        t  = GET_U32<bswap>(buf, 0) *
                multiply_shift_random[i % MULTIPLY_SHIFT_RANDOM_WORDS];
        h += t;
    }

    // Now get the last bytes
    int remaining_bytes = len_bytes & 3;
    if (remaining_bytes) {
        uint64_t last = 0;
        if (remaining_bytes & 2) { last = (last << 16) | GET_U16<bswap>(buf, 0); buf += 2; }
        if (remaining_bytes & 1) { last = (last << 8) | (*buf); }
        t  = last *
                multiply_shift_random[len % MULTIPLY_SHIFT_RANDOM_WORDS];
        h += t;
    }

    PUT_U32<bswap>(h >> 32, (uint8_t *)out, 0);
}

// Pair multiply-shift (3.5) from Thorup's notes.
template <bool bswap>
static void pair_multiply_shift32( const void * in, const size_t len_bytes, const seed_t seed, void * out ) {
    const uint8_t * buf = (const uint8_t *)in;
    const size_t    len = len_bytes / 4;

    // We mix in len_bytes in the basis, since smhasher considers two keys
    // of different length to be different, even if all the extra bits are 0.
    // This is needed for the AppendZero test.
    uint64_t h, t;

    h =     (uint32_t)(seed                 ) * multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 1] +
            (uint32_t)(seed      >> 16 >> 16) * multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 2] +
            (uint32_t)(len_bytes            ) * multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 3] +
            (uint32_t)(len_bytes >> 16 >> 16) * multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 4];

    for (size_t i = 0; i < len / 2; i++, buf += 8) {
        t  = GET_U64<bswap>(buf, 0);
        h +=    (((uint32_t)(t      )) + multiply_shift_random[((2 * i) % MULTIPLY_SHIFT_RANDOM_WORDS) + 1]) *
                (((uint32_t)(t >> 32)) + multiply_shift_random[((2 * i) % MULTIPLY_SHIFT_RANDOM_WORDS) + 0]);
    }

    // Make sure we have the last word, if the number of words is odd
    if (len & 1) {
        t    = GET_U32<bswap>(buf, 0) *
                multiply_shift_random[(len - 1) % MULTIPLY_SHIFT_RANDOM_WORDS];
        h   += t;
        buf += 4;
    }

    // Now get the last bytes
    int remaining_bytes = len_bytes & 3;
    if (remaining_bytes) {
        uint64_t last = 0;
        if (remaining_bytes & 2) { last = (last << 16) | GET_U16<bswap>(buf, 0); buf += 2; }
        if (remaining_bytes & 1) { last = (last << 8) | (*buf); }
        t  = last * multiply_shift_random[len % MULTIPLY_SHIFT_RANDOM_WORDS];
        h += t;
    }

    PUT_U32<bswap>(h >> 32, (uint8_t *)out, 0);
}

// Vector multiply-shift (3.4) from Thorup's notes.
//
// XXX This doesn't seem to quite match the paper, as we are only
// maintaining a sum of the high bits, but for most inputs that will
// only affect a few low bits of the result, so I won't worry about it
// for the moment.
//
// XXX Need to implement fma128_128()
template <bool bswap>
static void multiply_shift64( const void * in, const size_t len_bytes, const seed_t seed, void * out ) {
    const uint8_t * buf = (const uint8_t *)in;
    const size_t    len = len_bytes / 8;

    // We mix in len_bytes in the basis, since smhasher considers two keys
    // of different length to be different, even if all the extra bits are 0.
    // This is needed for the AppendZero test.
    uint64_t h, t, ignored;

    MathMult::mult128_128(ignored, h, (uint64_t)seed     , 0,
            multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 1],
            multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 2]);
    MathMult::mult128_128(ignored, t, (uint64_t)len_bytes, 0,
            multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 3],
            multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 4]);
    h += t;

    for (size_t i = 0; i < len; i++, buf += 8) {
        MathMult::mult128_128(ignored, t, GET_U64<bswap>(buf, 0), 0,
                multiply_shift_random[(i % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 0],
                multiply_shift_random[(i % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 1]);
        h += t;
    }

    // Now get the last bytes
    int remaining_bytes = len_bytes & 7;
    if (remaining_bytes) {
        uint64_t last = 0;
        if (remaining_bytes & 4) { last = GET_U32<bswap>(buf, 0); buf += 4; }
        if (remaining_bytes & 2) { last = (last << 16) | GET_U16<bswap>(buf, 0); buf += 2; }
        if (remaining_bytes & 1) { last = (last << 8) | (*buf); }
        MathMult::mult128_128(ignored, t, last, 0,
                multiply_shift_random[(len % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 0],
                multiply_shift_random[(len % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 1]);
        h += t;
    }

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

// Pair multiply-shift (3.5) from Thorup's notes.
template <bool bswap>
static void pair_multiply_shift64( const void * in, const size_t len_bytes, const seed_t seed, void * out ) {
    const uint8_t * buf = (const uint8_t *)in;
    const size_t    len = len_bytes / 8;

    // We mix in len_bytes in the basis, since smhasher considers two keys
    // of different length to be different, even if all the extra bits are 0.
    // This is needed for the AppendZero test.
    uint64_t h, t, ignored;

    MathMult::mult128_128(ignored, h, (uint64_t)seed     , 0,
            multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 1],
            multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 2]);
    MathMult::mult128_128(ignored, t, (uint64_t)len_bytes, 0,
            multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 3],
            multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS - 4]);
    h += t;
    for (size_t i = 0; i < len / 2; i++, buf += 16) {
        uint64_t blk1lo, blk1hi, blk2lo, blk2hi;
        blk1lo = multiply_shift_random[((2 * i) % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 2];
        blk1hi = multiply_shift_random[((2 * i) % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 3];
        blk2lo = multiply_shift_random[((2 * i) % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 0];
        blk2hi = multiply_shift_random[((2 * i) % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 1];
        MathMult::add128(blk1lo, blk1hi, GET_U64<bswap>(buf, 0));
        MathMult::add128(blk2lo, blk2hi, GET_U64<bswap>(buf, 8));
        MathMult::mult128_128(ignored, t, blk1lo, blk1hi, blk2lo, blk2hi);
        h += t;
    }

    // Make sure we have the last word, if the number of words is odd
    if (len & 1) {
        MathMult::mult128_128(ignored, t, GET_U64<bswap>(buf, 0), 0,
                multiply_shift_random[((len - 1) % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 0],
                multiply_shift_random[((len - 1) % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 1]);
        h   += t;
        buf += 8;
    }

    // Now get the last bytes
    int remaining_bytes = len_bytes & 7;
    if (remaining_bytes) {
        uint64_t last = 0;
        if (remaining_bytes & 4) { last = GET_U32<bswap>(buf, 0); buf += 4; }
        if (remaining_bytes & 2) { last = (last << 16) | GET_U16<bswap>(buf, 0); buf += 2; }
        if (remaining_bytes & 1) { last = (last << 8) | (*buf); }
        MathMult::mult128_128(ignored, t, last, 0,
                multiply_shift_random[(len % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 0],
                multiply_shift_random[(len % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 1]);
        h += t;
    }

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

REGISTER_FAMILY(multiply_shift,
   $.src_url    = "https://github.com/rurban/smhasher/blob/2b5992fe015282c87c9069e3c664771b47555ff3/Hashes.cpp",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(multiply_shift_32,
   $.desc       = "Dietzfelbinger Multiply-shift on strings, 32-bit blocks",
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE      |
         FLAG_HASH_SYSTEM_SPECIFIC,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64    |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0x34BAD85C,
   $.verification_BE = 0x133CC3AC,
   $.hashfn_native   = multiply_shift32<false>,
   $.hashfn_bswap    = multiply_shift32<true>,
// $.seedfn          = multiply_shift_seed_init_slow
   $.initfn          = multiply_shift_init
 );

REGISTER_HASH(pair_multiply_shift_32,
   $.desc       = "Dietzfelbinger Pair-multiply-shift strings, 32-bit blocks",
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE      |
         FLAG_HASH_SYSTEM_SPECIFIC,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64    |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0xFC284F0F,
   $.verification_BE = 0x6E93B706,
   $.hashfn_native   = pair_multiply_shift32<false>,
   $.hashfn_bswap    = pair_multiply_shift32<true>,
// $.seedfn          = multiply_shift_seed_init_slow
   $.initfn          = multiply_shift_init
 );

REGISTER_HASH(multiply_shift,
   $.desc       = "Dietzfelbinger Multiply-shift on strings, 64-bit blocks",
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE      |
         FLAG_HASH_SYSTEM_SPECIFIC,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_128_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xB7A5E66D,
   $.verification_BE = 0x6E3902A6,
   $.hashfn_native   = multiply_shift64<false>,
   $.hashfn_bswap    = multiply_shift64<true>,
// $.seedfn          = multiply_shift_seed_init_slow
   $.initfn          = multiply_shift_init
 );

REGISTER_HASH(pair_multiply_shift,
   $.desc       = "Dietzfelbinger Pair-multiply-shift strings, 64-bit blocks",
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE      |
         FLAG_HASH_SYSTEM_SPECIFIC,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_128_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x4FBA804D,
   $.verification_BE = 0x2B7F643B,
   $.hashfn_native   = pair_multiply_shift64<false>,
   $.hashfn_bswap    = pair_multiply_shift64<true>,
// $.seedfn          = multiply_shift_seed_init_slow
   $.initfn          = multiply_shift_init
 );
