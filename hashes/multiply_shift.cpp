/*
 * DoNothing hash and DoNothing One-At-A-Time Hash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
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
#include "Types.h"
#include "Random.h"
#include "Hashlib.h"

#include "mathmult.h"

// Multiply shift from
// Thorup "High Speed Hashing for Integers and Strings" 2018
// https://arxiv.org/pdf/1504.06804.pdf

// A 128-bit multiplicative constant
const static uint64_t multiply_shift_r_hi = 0x75f17d6b3588f843;
const static uint64_t multiply_shift_r_lo = 0xb13dea7c9c324e51;

// A randomly-generated table of 128-bit multiplicative constants
const static int MULTIPLY_SHIFT_RANDOM_WORDS = 1<<8;
static uint64_t multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS * 2];

static void multiply_shift_seed_init_slow(uint64_t seed) {
    Rand r(seed);
    for (int i = 0; i < MULTIPLY_SHIFT_RANDOM_WORDS; i++) {
        multiply_shift_random[2 * i + 1] = r.rand_u64();
        multiply_shift_random[2 * i + 0] = r.rand_u64();
        if (!multiply_shift_random[2 * i + 0])
            multiply_shift_random[2 * i + 0]++;
    }
}

bool multiply_shift_init(void) {
    multiply_shift_seed_init_slow(0);
    return true;
}

// XXX This modifies a global table, so it will fail on threaded tests!!!
static void multiply_shift_seed_init(seed_t seed) {
    // The seeds we get are not random values, but just something like 1, 2 or 3.
    // So we xor it with a random number to get something slightly more reasonable.
    // But skip really bad seed patterns: 0x...fffffff0
    if ((seed & 0xfffffff0ULL) == 0xfffffff0ULL)
        seed++;
    multiply_shift_random[0] = seed ^ multiply_shift_r_lo;
    multiply_shift_random[1] =        multiply_shift_r_hi;
}

template < bool bswap >
void multiply_shift(const void * in, const size_t len_bytes, const seed_t seed, void * out) {
    const uint8_t * buf = (const uint8_t *)in;
    const size_t len = len_bytes/8;

    multiply_shift_seed_init(seed);

    // The output is 64 bits, and we consider the input 64 bit as well,
    // so our intermediate values are 128.
    // We mix in len_bytes in the basis, since smhasher considers two keys
    // of different length to be different, even if all the extra bits are 0.
    // This is needed for the AppendZero test.
    uint64_t h, t, ignored;
    mult128_128(ignored, h, ((uint64_t)seed) + ((uint64_t)len_bytes), 0,
            multiply_shift_r_lo, multiply_shift_r_hi);
    for (size_t i = 0; i < len; i++, buf += 8) {
        mult128_128(ignored, t, GET_U64<bswap>(buf, 0), 0,
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
        if (remaining_bytes & 1) { last = (last << 8)  | (*buf); }
        mult128_128(ignored, t, last, 0,
                multiply_shift_random[(len % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 0],
                multiply_shift_random[(len % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 1]);
        h += t;
    }

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

// Vector multiply-shift (3.4) from Thorup's notes.
template < bool bswap >
void pair_multiply_shift(const void * in, const size_t len_bytes, const seed_t seed, void * out) {
    const uint8_t * buf = (const uint8_t *)in;
    const size_t len = len_bytes/8;

    multiply_shift_seed_init(seed);

    // The output is 64 bits, and we consider the input 64 bit as well,
    // so our intermediate values are 128.
    // We mix in len_bytes in the basis, since smhasher considers two keys
    // of different length to be different, even if all the extra bits are 0.
    // This is needed for the AppendZero test.
    uint64_t h, t, ignored;
    mult128_128(ignored, h, ((uint64_t)seed) + ((uint64_t)len_bytes), 0,
            multiply_shift_r_lo, multiply_shift_r_hi);
    for (size_t i = 0; i < len/2; i++, buf += 16) {
        uint64_t blk1lo, blk1hi, blk2lo, blk2hi;
        blk1lo = multiply_shift_random[((2 * i) % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 2];
        blk1hi = multiply_shift_random[((2 * i) % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 3];
        blk2lo = multiply_shift_random[((2 * i) % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 0];
        blk2hi = multiply_shift_random[((2 * i) % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 1];
        add128(blk1lo, blk1hi, GET_U64<bswap>(buf, 0));
        add128(blk2lo, blk2hi, GET_U64<bswap>(buf, 8));
        mult128_128(ignored, t, blk1lo, blk1hi, blk2lo, blk2hi);
        h += t;
    }

    // Make sure we have the last word, if the number of words is odd
    if (len & 1) {
        mult128_128(ignored, t, GET_U64<bswap>(buf, 0), 0,
                multiply_shift_random[((len - 1) % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 0],
                multiply_shift_random[((len - 1) % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 1]);
        h += t;
        buf += 8;
    }

    // Now get the last bytes
    int remaining_bytes = len_bytes & 7;
    if (remaining_bytes) {
        uint64_t last = 0;
        if (remaining_bytes & 4) { last = GET_U32<bswap>(buf, 0); buf += 4; }
        if (remaining_bytes & 2) { last = (last << 16) | GET_U16<bswap>(buf, 0); buf += 2; }
        if (remaining_bytes & 1) { last = (last << 8)  | (*buf); }
        mult128_128(ignored, t, last, 0,
                multiply_shift_random[(len % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 0],
                multiply_shift_random[(len % MULTIPLY_SHIFT_RANDOM_WORDS) * 2 + 1]);
        h += t;
    }

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

REGISTER_FAMILY(multiply_shift);

REGISTER_HASH(multiply_shift,
  $.desc = "Dietzfelbinger Multiply-shift on strings",
  $.hash_flags =
        FLAG_HASH_LOOKUP_TABLE      |
        FLAG_HASH_SYSTEM_SPECIFIC,
  $.impl_flags =
        FLAG_IMPL_MULTIPLY_128_128  |
        FLAG_IMPL_LICENSE_MIT,
  $.bits = 64,
  $.verification_LE = 0x6DE70D61,
  $.verification_BE = 0xA025FBD2,
  $.hashfn_native = multiply_shift<false>,
  $.hashfn_bswap = multiply_shift<true>,
  $.initfn = multiply_shift_init
);

REGISTER_HASH(pair_multiply_shift,
  $.desc = "Dietzfelbinger Pair-multiply-shift strings",
  $.hash_flags =
        FLAG_HASH_LOOKUP_TABLE      |
        FLAG_HASH_SYSTEM_SPECIFIC,
  $.impl_flags =
        FLAG_IMPL_MULTIPLY_128_128  |
        FLAG_IMPL_LICENSE_MIT,
  $.bits = 64,
  $.verification_LE = 0x3CB18128,
  $.verification_BE = 0xE10B3234,
  $.hashfn_native = pair_multiply_shift<false>,
  $.hashfn_bswap = pair_multiply_shift<true>,
  $.initfn = multiply_shift_init
);
