/*
 * XMSX
 * Copyright (C) 2025 Frank J. T. Wojcik
 * Copyright (C) 2023 Dmitrii Lebed <lebed.dmitry@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "Platform.h"
#include "Hashlib.h"

//------------------------------------------------------------
// XMSX (XOR - Multiply - Shift - XOR) Hash
// Inspired by MUM and Murmur hashes
//
// Design inputs:
//   - be faster than SW CRC32 on modern 32-bit CPUs (and microcontrollers)
//      (supporting HW 32bx32b->64b multiplication)
//   - be as simple as possible (small code size)
//   - try to reuse the same round function (xor-mul-shift-xor)
//   - provide reasonable hashing quality (pass SMHasher tests)
// XMSX32 passes all SMHasher tests (2 bad seeds)

static uint64_t xmsx32_round( uint64_t h, uint32_t d ) {
    const uint64_t p = UINT64_C(0xcdb32970830fcaa1);

    h  = (h ^ d) * p;
    h ^= h >> 32;

    return h;
}

template <bool bswap>
uint32_t xmsx32( const void * buf, size_t len, uint32_t seed ) {
    const uint8_t * data = (const uint8_t *)buf;
    uint64_t        h    = ((uint64_t)seed << 32) | seed;

    h = xmsx32_round(h, len);

    while (len) {
        uint32_t         d;
        constexpr size_t word_size = sizeof(d);

        memcpy(&d, data, sizeof(d));
        d = COND_BSWAP(d, bswap);

        if (len < word_size) {
            const size_t bits_to_clear = 8 * (word_size - len);

            d <<= bits_to_clear;
            d >>= bits_to_clear;
            len = word_size;
        }

        h     = xmsx32_round(h, d);

        len  -= word_size;
        data += word_size;
    }

    return xmsx32_round(h, h >> 47);
}

//------------------------------------------------------------
template <bool bswap>
static void xmsx( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t hash = xmsx32<bswap>(in, len, (uint32_t)seed);

    PUT_U32<bswap>(hash, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(xmsx,
   $.src_url    = "https://github.com/dlebed/smhasher",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
);

REGISTER_HASH(xmsx,
   $.desc       = "xmsx (XOR - Multiply - Shift - XOR) Hash",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB  |
         FLAG_IMPL_MULTIPLY_64_64 |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 32,
   $.verification_LE = 0x6B54E1D4,
   $.verification_BE = 0x2E9167AB,
   $.hashfn_native   = xmsx<false>,
   $.hashfn_bswap    = xmsx<true>
);
