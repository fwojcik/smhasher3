/*
 * TentHash
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

#include "Platform.h"
#include "Hashlib.h"

#include <utility>

//------------------------------------------------------------

#define TENT_BLOCK_SIZE (256 / 8)

FORCE_INLINE static void mix_state( uint64_t * state ) {
    // Rotation constants.
    const static int rots[7][2] = {
        { 16, 28 }, { 14, 57 }, { 11, 22 }, { 35, 34 },
        { 57, 16 }, { 59, 40 }, { 44, 13 },
    };

    for (int i = 0; i < 7; i++) {
        state[0] += state[2];
        state[1] += state[3];
        state[2]  = ROTL64(state[2], rots[i][0]) ^ state[0];
        state[3]  = ROTL64(state[3], rots[i][1]) ^ state[1];

        std::swap(state[0], state[1]);
    }
}

static thread_local uint64_t SEED_STATE[4];

static uintptr_t init_seed( seed_t seed ) {
    SEED_STATE[0] = seed;
    SEED_STATE[1] = 0;
    SEED_STATE[2] = 0;
    SEED_STATE[3] = 0;

    mix_state(SEED_STATE);

    return (uintptr_t)(void *)SEED_STATE;
}

template <bool bswap>
static void TentHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t  data_len = len;
    uint8_t * data     = (uint8_t *)in;

    uint64_t state[4]  = {
        UINT64_C(0x5d6daffc4411a967),
        UINT64_C(0xe22d4dea68577f34),
        UINT64_C(0xca50864d814cbc2e),
        UINT64_C(0x894e29b9611eb173),
    };

    // Incorporate seed.
    //
    // Note: actual TentHash is not seedable, and this is here just to pass the
    // seeding tests. Unfortunately, this also has a slight negative impact on
    // small key performance, making TentHash look a tiny bit slower than it
    // actually is in the small key performance test.
    const uint64_t * seed_state = (const uint64_t *)(void *)(uintptr_t)seed;

    state[0] ^= seed_state[0];
    state[1] ^= seed_state[1];
    state[2] ^= seed_state[2];
    state[3] ^= seed_state[3];

    // Process the input data in 256-bit blocks.
    while (data_len >= TENT_BLOCK_SIZE) {
        state[0] ^= GET_U64<bswap>(data,  0);
        state[1] ^= GET_U64<bswap>(data,  8);
        state[2] ^= GET_U64<bswap>(data, 16);
        state[3] ^= GET_U64<bswap>(data, 24);

        data     += TENT_BLOCK_SIZE;
        data_len -= TENT_BLOCK_SIZE;

        mix_state(state);
    }

    // Handle any remaining data less than 256 bits.
    if (data_len > 0) {
        // Copy the data into a zeroed-out buffer. When the data is less than
        // 256 bits this pads it out to 256 bits with zeros.
        uint8_t buffer[TENT_BLOCK_SIZE] = { 0 };
        memcpy(buffer, data, data_len);

        state[0] ^= GET_U64<bswap>(buffer,  0);
        state[1] ^= GET_U64<bswap>(buffer,  8);
        state[2] ^= GET_U64<bswap>(buffer, 16);
        state[3] ^= GET_U64<bswap>(buffer, 24);

        mix_state(state);
    }

    // Finalize.
    state[0] ^= len * 8;
    mix_state(state);
    mix_state(state);

    // Copy the hash state to the output.
    PUT_U64<bswap>(state[0], (uint8_t *)out, 0);
    PUT_U64<bswap>(state[1], (uint8_t *)out, 8);
    PUT_U32<bswap>((uint32_t)state[2], (uint8_t *)out, 16);
}

//------------------------------------------------------------

REGISTER_FAMILY(tenthash,
   $.src_url    = "https://github.com/cessen/tenthash",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(TentHash,
   $.desc            = "TentHash",
   $.hash_flags      =
         FLAG_HASH_NO_SEED | FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_ROTATE | FLAG_IMPL_CANONICAL_LE | FLAG_IMPL_LICENSE_MIT,
   $.bits            = 160,
   $.verification_LE = 0x5FDAF416,
   $.verification_BE = 0xB4D751AE,
   $.hashfn_native   = TentHash<false>,
   $.hashfn_bswap    = TentHash<true>,
   $.seedfn          = init_seed
 );
