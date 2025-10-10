/*
 * Falkhash v1 and v2
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
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
 *
 * This file incorporates work from
 * https://github.com/gamozolabs/falkhash covered by the following
 * copyright and permission notice:
 *
 *     This is free and unencumbered software released into the public domain.
 *
 *     Anyone is free to copy, modify, publish, use, compile, sell, or
 *     distribute this software, either in source code form or as a
 *     compiled binary, for any purpose, commercial or non-commercial,
 *     and by any means.
 *
 *     In jurisdictions that recognize copyright laws, the author or
 *     authors of this software dedicate any and all copyright
 *     interest in the software to the public domain. We make this
 *     dedication for the benefit of the public at large and to the
 *     detriment of our heirs and successors. We intend this
 *     dedication to be an overt act of relinquishment in perpetuity
 *     of all present and future rights to this software under
 *     copyright law.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *     NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
 *     ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 *     CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *     CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *     THE SOFTWARE.
 *
 *     For more information, please refer to <http://unlicense.org>
 */
#include "Platform.h"
#include "Hashlib.h"

#if defined(HAVE_X86_64_AES)
  #include "Intrinsics.h"

template <uint32_t version, bool bswap>
static void falkhash( const void * in, const size_t olen, const seed_t seed64, void * out ) {
    const uint8_t * buf = (const uint8_t *)in;
    uint64_t        len = (uint64_t       )olen;
    __m128i         hash, seed;

    // A chunk_size of 0x50 is ideal for AMD fam 15h platforms, which is
    // what this was optimized and designed for. If you change this
    // value, you have to manually add/remove instructions from the core
    // loop below. This must be divisible by 16.
    const uint64_t CHUNK_LEN = 80;

    if (version == 1) {
        // Add the seed to the length. Place the length+seed for both the
        // low and high 64-bits into our hash output.
        seed = _mm_set_epi64x(len + ((uint64_t)seed64), len + ((uint64_t)seed64));
    } else {
        // Create the 128-bit seed. Low 64-bits gets seed, high 64-bits gets
        // seed + len + 1. The +1 ensures that both 64-bits values will never be
        // the same (with the exception of a length of -1. If you have that much
        // ram, send me some).
        seed = _mm_set_epi64x(1 + len + ((uint64_t)seed64), (uint64_t)seed64);
    }

    hash = seed;

    while (len > 0) {
        __m128i piece[5];
        uint8_t tmp[CHUNK_LEN];

        // If the data is smaller than one chunk, pad it with 0xff for v1,
        // or zeroes for v2.
        if (len < CHUNK_LEN) {
            memcpy(tmp, buf, len);
            if (version == 1) {
                memset(tmp + len, 0xff, CHUNK_LEN - len);
            } else {
                memset(tmp + len, 0, CHUNK_LEN - len);
            }
            buf = tmp;
            len = CHUNK_LEN;
        }

        // Read 5 pieces from memory into xmms
        piece[0] = _mm_loadu_si128((__m128i *)(buf + 0 * 0x10));
        piece[1] = _mm_loadu_si128((__m128i *)(buf + 1 * 0x10));
        piece[2] = _mm_loadu_si128((__m128i *)(buf + 2 * 0x10));
        piece[3] = _mm_loadu_si128((__m128i *)(buf + 3 * 0x10));
        piece[4] = _mm_loadu_si128((__m128i *)(buf + 4 * 0x10));

        if (bswap) {
            // Arbitrarily chose 64-bit chunks
            piece[0] = mm_bswap64(piece[0]);
            piece[1] = mm_bswap64(piece[1]);
            piece[2] = mm_bswap64(piece[2]);
            piece[3] = mm_bswap64(piece[3]);
            piece[4] = mm_bswap64(piece[4]);
        }

        if (version == 2) {
            // xor each piece against the seed
            piece[0] = _mm_xor_si128(piece[0], seed);
            piece[1] = _mm_xor_si128(piece[1], seed);
            piece[2] = _mm_xor_si128(piece[2], seed);
            piece[3] = _mm_xor_si128(piece[3], seed);
            piece[4] = _mm_xor_si128(piece[4], seed);
        }

        // Mix all pieces into xmm0
        piece[0] = _mm_aesenc_si128(piece[0], piece[1]);
        piece[0] = _mm_aesenc_si128(piece[0], piece[2]);
        piece[0] = _mm_aesenc_si128(piece[0], piece[3]);
        piece[0] = _mm_aesenc_si128(piece[0], piece[4]);

        if (version == 1) {
            // Finalize xmm0 by mixing with itself
            piece[0] = _mm_aesenc_si128(piece[0], piece[0]);
        } else {
            // Finalize piece[0] by aesencing against seed
            piece[0] = _mm_aesenc_si128(piece[0], seed);
        }

        // Mix in xmm0 to the hash
        hash = _mm_aesenc_si128(hash, piece[0]);

        buf += CHUNK_LEN;
        len -= CHUNK_LEN;
    }

    if (version == 1) {
        // Finalize the hash. This is required at least once to pass
        // Combination 0x8000000 and Combination 0x0000001. Need more than 1 to
        // pass the Seed tests. We do 4 because they're pretty much free.
        // Maybe we should actually use the seed better? Nah, more finalizing!
        hash = _mm_aesenc_si128(hash, hash);
        hash = _mm_aesenc_si128(hash, hash);
        hash = _mm_aesenc_si128(hash, hash);
        hash = _mm_aesenc_si128(hash, hash);
    } else {
        // Finalize hash by aesencing against seed four times
        hash = _mm_aesenc_si128(hash, seed);
        hash = _mm_aesenc_si128(hash, seed);
        hash = _mm_aesenc_si128(hash, seed);
        hash = _mm_aesenc_si128(hash, seed);
    }

    // Write hash to memory
    _mm_storeu_si128((__m128i *)out, hash);
}

#endif

REGISTER_FAMILY(falkhash,
   $.src_url    = "https://github.com/gamozolabs/falkhash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

#if defined(HAVE_X86_64_AES)

// This falkhash v1 code is a re-implementation in C from the original
// ASM. The previous implementation of falkhash in SMHasher
// (verification code 0x2F99B071) had 2 differences from the published
// reference implementation:
//     1) For a hash len of 0, a hash result of 0 was forced, and
//     2) The hash output was truncated to 64 bits.
REGISTER_HASH(falkhash1,
   $.desc            = "Falkhash v1",
   $.impl            = "aesni",
   $.hash_flags      =
         FLAG_HASH_AES_BASED,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.verification_LE = 0xAEF96E69,
   $.verification_BE = 0xDAE2ECE4,
   $.hashfn_native   = falkhash<1, false>,
   $.hashfn_bswap    = falkhash<1, true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0xffffffffffffffb0, 0xffffffffffffffdf }
 );

REGISTER_HASH(falkhash2,
   $.desc            = "Falkhash v2",
   $.impl            = "aesni",
   $.hash_flags      =
         FLAG_HASH_AES_BASED,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits            = 128,
   $.verification_LE = 0x7FA15220,
   $.verification_BE = 0x0A8285F2,
   $.hashfn_native   = falkhash<2, false>,
   $.hashfn_bswap    = falkhash<2, true>
 );

#endif
