/*
 * Goodhart Hashes
 * Copyright (C) 2025 Nathan Vegdahl
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * The hashes in this file are from the article "Hash Design and Goodhart's Law":
 * https://blog.cessen.com/post/2024_07_10_hash_design_and_goodharts_law
 *
 * Note that the hashes here deviate in precisely one way from the those in
 * the article: the hashes in this file are seedable so that they can pass
 * SMHasher's seeding tests. They are otherwise identical to the hashes in the
 * article.
 *
 * Importantly, these hashes are not intended for real use, and some of them
 * are specifically built to deceptively appear high quality in empirical tests
 * while actually having serious issues. Indeed, the purpose of these hashes is
 * to illustrate that empirical test suites should not be depended on as a stamp
 * of quality for large-output hashes. See the article for more details.
 */

#include "Platform.h"
#include "Hashlib.h"

#include <utility>
#include <algorithm>

//------------------------------------------------------------

#define BLOCK_SIZE (128 / 8)

FORCE_INLINE static void mix_state( uint64_t * state, int rounds ) {
    // Rotation constants.
    const static int rots[16] = { 12, 39, 21, 13, 32, 11, 24, 53, 17, 27, 57, 13, 50, 8, 52, 8 };

    for (int i = 0; i < rounds; i++) {
        state[0] += state[1] + 1;
        state[1]  = ROTL64(state[1], rots[i % 16]) ^ state[0];
    }
}

//------------------------------------------------------------

static thread_local uint64_t SEEDED_STATE[2];

static uintptr_t init_seed( seed_t seed ) {
    SEEDED_STATE[0] = (uint64_t)seed;
    SEEDED_STATE[1] = 0;

    if (seed != 0) {
        mix_state(SEEDED_STATE, 12);
    }

    return (uintptr_t)(void *)SEEDED_STATE;
}

//------------------------------------------------------------

template <unsigned hashversion, bool bswap>
static void GoodhartHashAll( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint64_t * seed_state = (const uint64_t *)(void *)(uintptr_t)seed;
    uint64_t         state[2]   = { seed_state[0], seed_state[1] };

    static_assert((hashversion >= 1) && (hashversion <= 6), "Valid GoodhartHash versions are 1-6");

    // Process the input data in 256-bit blocks.
    const uint8_t * data     = (uint8_t *)in;
    uint64_t        data_len = len;
    while (data_len > 0) {
        const size_t process_len = std::min(data_len, uint64_t(BLOCK_SIZE));

        if (process_len == BLOCK_SIZE) {
            state[0] ^= GET_U64<bswap>(data, 0);
            state[1] ^= GET_U64<bswap>(data, 8);
        } else {
            // Copy the data into a zeroed-out buffer. When the data is less than
            // 256 bits this pads it out to 256 bits with zeros.
            uint8_t buffer[BLOCK_SIZE] = { 0 };
            memcpy(buffer, data, process_len);

            state[0] ^= GET_U64<bswap>(buffer, 0);
            state[1] ^= GET_U64<bswap>(buffer, 8);
        }

        if (hashversion == 3) {
            mix_state(state, 12);
        } else if (hashversion == 4) {
            mix_state(state, 4);
        } else if (hashversion >= 5) {
            mix_state(state, 5);
        }

        data_len -= process_len;
        data     += process_len;
    }

    if (hashversion >= 2) {
        // Incorporate input length.
        state[0] ^= len;
    }

    mix_state(state, 12);

    if (hashversion == 6) {
        // Be evil.
        state[1] = 0;
        mix_state(state, 12);
    }

    // Copy the hash state to the output.
    PUT_U64<bswap>(state[0], (uint8_t *)out, 0);
    PUT_U64<bswap>(state[1], (uint8_t *)out, 8);
}

//------------------------------------------------------------

REGISTER_FAMILY(goodhart,
   $.src_url    = "https://blog.cessen.com/post/2024_07_10_hash_design_and_goodharts_law",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(GoodhartHash1,
   $.desc            = "Goodhart Hash 1 (bad)",
   $.hash_flags      =
         FLAG_HASH_NO_SEED,
   $.impl_flags      =
         FLAG_IMPL_SANITY_FAILS |
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.verification_LE = 0x78BE8F44,
   $.verification_BE = 0xE537621E,
   $.seedfn          = init_seed,
   $.hashfn_native   = GoodhartHashAll<1, false>,
   $.hashfn_bswap    = GoodhartHashAll<1, true>
 );

REGISTER_HASH(GoodhartHash2,
   $.desc            = "Goodhart Hash 2 (bad)",
   $.hash_flags      =
         FLAG_HASH_NO_SEED,
   $.impl_flags      =
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.verification_LE = 0x16C82F7A,
   $.verification_BE = 0x5F57974F,
   $.seedfn          = init_seed,
   $.hashfn_native   = GoodhartHashAll<2, false>,
   $.hashfn_bswap    = GoodhartHashAll<2, true>
 );

REGISTER_HASH(GoodhartHash3,
   $.desc            = "Goodhart Hash 3",
   $.hash_flags      =
         FLAG_HASH_NO_SEED,
   $.impl_flags      =
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.verification_LE = 0x504DEE5A,
   $.verification_BE = 0x83DC9414,
   $.seedfn          = init_seed,
   $.hashfn_native   = GoodhartHashAll<3, false>,
   $.hashfn_bswap    = GoodhartHashAll<3, true>
 );

REGISTER_HASH(GoodhartHash4,
   $.desc            = "Goodhart Hash 4 (bad)",
   $.hash_flags      =
         FLAG_HASH_NO_SEED,
   $.impl_flags      =
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.verification_LE = 0xE71EE0DC,
   $.verification_BE = 0xB5176566,
   $.seedfn          = init_seed,
   $.hashfn_native   = GoodhartHashAll<4, false>,
   $.hashfn_bswap    = GoodhartHashAll<4, true>
 );

REGISTER_HASH(GoodhartHash5,
   $.desc            = "Goodhart Hash 5 (bad)",
   $.hash_flags      =
         FLAG_HASH_NO_SEED,
   $.impl_flags      =
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.verification_LE = 0x6F8788F7,
   $.verification_BE = 0x73D864DA,
   $.seedfn          = init_seed,
   $.hashfn_native   = GoodhartHashAll<5, false>,
   $.hashfn_bswap    = GoodhartHashAll<5, true>
 );

REGISTER_HASH(GoodhartHash6,
   $.desc            = "Goodhart Hash 6 (evil)",
   $.hash_flags      =
         FLAG_HASH_NO_SEED,
   $.impl_flags      =
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.verification_LE = 0x7EE56518,
   $.verification_BE = 0x47495960,
   $.seedfn          = init_seed,
   $.hashfn_native   = GoodhartHashAll<6, false>,
   $.hashfn_bswap    = GoodhartHashAll<6, true>
 );
