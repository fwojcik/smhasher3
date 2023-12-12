/*
 * Polynomial Mersenne Hash
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (c) 2020-2021 Reini Urban
 * Copyright (c) 2020      Thomas Dybdahl Ahle
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
// Based on Thorup's "high speed hashing for integers and strings"
// https://arxiv.org/pdf/1504.06804.pdf
#include "Platform.h"
#include "Hashlib.h"

#include "Mathmult.h"

#include <cassert>

//-----------------------------------------------------------------------------
// This code originally used the system's srand()/rand() functions from
// libc. This made the hash unstable across platforms. To rectify this, a
// basic splitmix implementation is included here, just so testing can be
// done consistently.
//
// Hash quality is dependent on the RNG used! If you plan on using this
// hash, it is STRONGLY recommended that you test it with the RNG you plan
// on using to seed it.
static uint32_t splitmix_rand( uint64_t & state ) {
    uint64_t rand;

    rand  = (state += UINT64_C(0x9e3779b97f4a7c15));
    rand ^= rand >> 30;
    rand *= UINT64_C(0xbf58476d1ce4e5b9);
    rand ^= rand >> 27;
    rand *= UINT64_C(0x94d049bb133111eb);
    rand ^= rand >> 31;

    // Return the middle 32-bits
    return (uint32_t)(rand >> 16);
}

static uint64_t tab_rand64( uint64_t & state ) {
    // we don't know how many bits we get from rand(), but it is at least
    // 16, so we concatenate a couple.
    uint64_t r = 0;

    for (int i = 0; i < 4; i++) {
        r <<= 16;
        r  ^= splitmix_rand(state);
    }
    return r;
}

#if defined(HAVE_INT128)

static inline uint128_t tab_rand128( uint64_t & state ) {
    uint128_t r;

    r = tab_rand64(state);
    r = tab_rand64(state) | (r << 64);
    return r;
}

#endif

//-----------------------------------------------------------------------------
// 32 Bit Version
const static uint64_t MERSENNE_31   = (UINT64_C(1) << 31) - 1;
const static int      CHAR_SIZE     = 8;
const static int      BLOCK_SIZE_32 = 1 << 8;

struct seed32_struct {
    uint64_t  multiply_shift_random_64[BLOCK_SIZE_32];
    uint32_t  multiply_shift_a_64;
    uint64_t  multiply_shift_b_64;
    int32_t   tabulation_32[32 / CHAR_SIZE][1 << CHAR_SIZE];
    uint64_t  seed;
};

static thread_local seed32_struct seed32;

static uintptr_t tabulation32_seed( const seed_t seed ) {
    bool     have_broken_rand = false;
    uint64_t splitmix_nextrand     = (uint64_t)seed;

    seed32.seed = (uint64_t)seed;
    // the lazy mersenne combination requires 30 bits values in the polynomial.
    seed32.multiply_shift_a_64 = tab_rand64(splitmix_nextrand) & ((UINT64_C(1) << 30) - 1);
    if (!seed32.multiply_shift_a_64) {
        seed32.multiply_shift_a_64 = tab_rand64(splitmix_nextrand) & ((UINT64_C(1) << 30) - 1);
    }
    if (!seed32.multiply_shift_a_64) {
        have_broken_rand = true;
        seed32.multiply_shift_a_64 = UINT64_C(0xababababbeafcafe) & ((UINT64_C(1) << 30) - 1);
    }
    seed32.multiply_shift_b_64 = tab_rand64(splitmix_nextrand);
    if (!seed32.multiply_shift_b_64) {
        seed32.multiply_shift_b_64 = have_broken_rand ? 0xdeadbeef : tab_rand64(splitmix_nextrand);
    }
    for (int i = 0; i < BLOCK_SIZE_32; i++) {
        seed32.multiply_shift_random_64[i] = tab_rand64(splitmix_nextrand);
        if (!seed32.multiply_shift_random_64[i]) {
            seed32.multiply_shift_random_64[i] = have_broken_rand ? 0xdeadbeef : tab_rand64(splitmix_nextrand);
        }
    }
    for (int i = 0; i < 32 / CHAR_SIZE; i++) {
        for (int j = 0; j < 1 << CHAR_SIZE; j++) {
            seed32.tabulation_32[i][j] = tab_rand64(splitmix_nextrand);
        }
    }
    return (seed_t)(uintptr_t)&seed32;
}

static inline uint32_t combine31( uint32_t h, uint32_t x, uint32_t a ) {
    uint64_t temp = (uint64_t)h * x + a;

    return ((uint32_t)temp & MERSENNE_31) + (uint32_t)(temp >> 31);
}

template <bool bswap>
static void tabulation32( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t *       buf    = (const uint8_t *)in;
    const seed32_struct * seed32 = (const seed32_struct *)(uintptr_t)seed;
    size_t len_words_32          = len / 4;
    size_t len_blocks_32         = len_words_32 / BLOCK_SIZE_32;

    uint32_t h = len ^ (uint32_t)seed32->seed;

    for (size_t b = 0; b < len_blocks_32; b++) {
        uint32_t block_hash = 0;
        for (int i = 0; i < BLOCK_SIZE_32; i++, buf += 4) {
            block_hash ^= seed32->multiply_shift_random_64[i] * GET_U32<bswap>(buf, 0) >> 32;
        }
        h = combine31(h, seed32->multiply_shift_a_64, block_hash >> 2);
    }

    int remaining_words = len_words_32 % BLOCK_SIZE_32;
    for (int i = 0; i < remaining_words; i++, buf += 4) {
        h ^= seed32->multiply_shift_random_64[i] * GET_U32<bswap>(buf, 0) >> 32;
    }

    int remaining_bytes = len % 4;
    if (remaining_bytes) {
        uint32_t last = 0;
        if (remaining_bytes & 2) { last = GET_U16<bswap>(buf, 0); buf += 2; }
        if (remaining_bytes & 1) { last = (last << 8) | (*buf); }
        h ^= seed32->multiply_shift_b_64 * last >> 32;
    }

    // Finalization
    uint32_t tab = 0;
    for (int i = 0; i < 32 / CHAR_SIZE; i++, h >>= CHAR_SIZE) {
        tab ^= seed32->tabulation_32[i][h & ((1 << CHAR_SIZE) - 1)];
    }

    PUT_U32<bswap>(tab, (uint8_t *)out, 0);
}

#if defined(HAVE_INT128)
//-----------------------------------------------------------------------------
// 64 Bit Version
const static uint64_t TAB_MERSENNE_61 = (UINT64_C(1) << 61) - 1;
// multiply shift works on fixed length strings, so we operate in blocks.
// this size can be tuned depending on the system.
const static int TAB_BLOCK_SIZE = 1 << 8;

struct seed64_struct {
    uint128_t  tab_multiply_shift_random[TAB_BLOCK_SIZE];
    uint128_t  tab_multiply_shift_a;
    uint128_t  tab_multiply_shift_b;
    int64_t    tabulation[64 / CHAR_SIZE][1 << CHAR_SIZE];
    uint64_t   seed;
};

static thread_local seed64_struct seed64;

static uintptr_t tabulation64_seed( const seed_t seed ) {
    bool     have_broken_rand = false;
    uint64_t splitmix_nextrand     = (uint64_t)seed;

    seed64.seed = (uint64_t)seed;
    // the lazy mersenne combination requires 60 bits values in the polynomial.
    // rurban: added checks for bad seeds
    seed64.tab_multiply_shift_a = tab_rand128(splitmix_nextrand) & ((UINT64_C(1) << 60) - 1);
    seed64.tab_multiply_shift_b = tab_rand128(splitmix_nextrand);
    if (!seed64.tab_multiply_shift_a) {
        seed64.tab_multiply_shift_a = tab_rand128(splitmix_nextrand) & ((UINT64_C(1) << 60) - 1);
    }
    if (!seed64.tab_multiply_shift_a) {
        have_broken_rand = true;
        seed64.tab_multiply_shift_a = UINT64_C(0xababababbeafcafe) & ((UINT64_C(1) << 60) - 1);
    }
    if (!seed64.tab_multiply_shift_b) {
        seed64.tab_multiply_shift_b = tab_rand128(splitmix_nextrand);
    }
    if (!seed64.tab_multiply_shift_b) {
        have_broken_rand = true;
        seed64.tab_multiply_shift_b++;
    }
    for (int i = 0; i < TAB_BLOCK_SIZE; i++) {
        seed64.tab_multiply_shift_random[i] = tab_rand128(splitmix_nextrand);
        if (!seed64.tab_multiply_shift_random[i]) {
            seed64.tab_multiply_shift_random[i] = 0x12345678;
        }
    }
    if (have_broken_rand) {
        assert(TAB_BLOCK_SIZE >= 64 / CHAR_SIZE);
    }
    for (int i = 0; i < 64 / CHAR_SIZE; i++) {
        for (int j = 0; j < 1 << CHAR_SIZE; j++) {
            seed64.tabulation[i][j] = have_broken_rand ?
                        seed64.tab_multiply_shift_random[i] : tab_rand128(splitmix_nextrand);
        }
    }
    return (seed_t)(uintptr_t)&seed64;
}

static inline uint64_t combine61( uint64_t h, uint64_t x, uint64_t a ) {
    // we assume 2^b-1 >= 2u-1. in other words
    // x <= u-1 <= 2^(b-1)-1 (at most 60 bits)
    // a <= p-1  = 2^b-2     (60 bits suffices)
    // actually, checking the proof, it's fine if a is 61 bits.
    // h <= 2p-1 = 2^62-3. this will also be guaranteed of the output.

    // uint128_t temp = (uint128_t)h * x + a;
    // return ((uint64_t)temp & TAB_MERSENNE_61) + (uint64_t)(temp >> 61);

    uint64_t rhi = 0, rlo = a;

    MathMult::fma64_128(rlo, rhi, h, x);

    rhi <<= (64   - 61);
    rhi  |= (rlo >> 61);
    rlo  &= TAB_MERSENNE_61;

    return rlo + rhi;
}

template <bool bswap>
static void tabulation64( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t *       buf    = (const uint8_t *)in;
    const seed64_struct * seed64 = (const seed64_struct *)(uintptr_t)seed;

    // the idea is to compute a fast "signature" of the string before doing
    // tabulation hashing. this signature only has to be collision resistant,
    // so we can use the variabe-length-hashing polynomial mod-mersenne scheme
    // from thorup.
    // because of the birthday paradox, the signature needs to be around twice
    // as many bits as in the number of keys tested. since smhasher tests
    // collisions in keys in the order of millions, we need the signatures to
    // be at least 40 bits. we settle on 64.

    // we mix in len in the basis, since smhasher considers two keys
    // of different length to be different, even if all the extra bits are 0.
    // this is needed for the appendzero test.

    uint64_t h = len ^ seed64->seed ^ (seed64->seed << 8);

    if (len >= 8) {
        const size_t len_words = len / 8;
        if (len_words >= TAB_BLOCK_SIZE) {
            const size_t len_blocks = len_words / TAB_BLOCK_SIZE;

            // to save time, we partition the string in blocks of ~ 256 words.
            // each word is hashed using a fast strongly-universal multiply-shift,
            // and since the xor of independent strongly-universal hash functions
            // is also universal, we get a unique value for each block.
            for (size_t b = 0; b < len_blocks; b++) {
                uint64_t block_hash = 0;
                for (int i = 0; i < TAB_BLOCK_SIZE; i++, buf += 8) {
                    // we don't have to shift yet, but shifting by 64 allows the
                    // compiler to produce a single "high bits only" multiplication instruction.
                    block_hash ^= (seed64->tab_multiply_shift_random[i] * GET_U64<bswap>(buf, 0)) >> 64;

                    // the following is very fast, basically using mum, but theoretically wrong.
                    // __uint128_t mum = (__uint128_t)tab_multiply_shift_random_64[i] * take64(buf);
                    // block_hash ^= mum ^ (mum >> 64);
                }

                // finally we combine the block hash using variable length hashing.
                // values have to be less than mersenne for the combination to work.
                // we can shift down, since any shift of multiply-shift outputs is
                // strongly-universal.
                h = combine61(h, seed64->tab_multiply_shift_a, block_hash >> 4);
            }

            // in principle we should finish the mersenne modular reduction.
            // however, this isn't be needed, since it can never reduce collisions.
            // if (h >= TAB_MERSENNE_61) h -= TAB_MERSENNE_61;
        }

        // then read the remaining words
        const int remaining_words = len_words % TAB_BLOCK_SIZE;
        for (int i = 0; i < remaining_words; i++, buf += 8) {
            h ^= seed64->tab_multiply_shift_random[i] * GET_U64<bswap>(buf, 0) >> 64;
        }
    }

    // now get the remaining bytes
    const int remaining_bytes = len % 8;
    if (remaining_bytes) {
        uint64_t last = 0;
        if (remaining_bytes & 4) { last = GET_U32<bswap>(buf, 0); buf += 4; }
        if (remaining_bytes & 2) { last = (last << 16) | GET_U16<bswap>(buf, 0); buf += 2; }
        if (remaining_bytes & 1) { last = (last << 8) | (*buf); }
        h ^= seed64->tab_multiply_shift_b * last >> 64;
    }

    uint64_t tab = 0;
    for (int i = 0; i < 64 / CHAR_SIZE; i++, h >>= CHAR_SIZE) {
        tab ^= seed64->tabulation[i][h % (1 << CHAR_SIZE)];
    }

    PUT_U64<bswap>(tab, (uint8_t *)out, 0);
}

#endif

//-----------------------------------------------------------------------------
REGISTER_FAMILY(tabulation,
   $.src_url    = "https://github.com/rurban/smhasher/blob/master/Hashes.cpp",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(tabulation_32,
   $.desc       = "32-bit Tabulation with Multiply-Shift Mixer",
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE         |
         FLAG_HASH_SYSTEM_SPECIFIC,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 32,
   $.verification_LE = 0x0D34E471,
   $.verification_BE = 0x84CD19C4,
   $.seedfn          = tabulation32_seed,
   $.hashfn_native   = tabulation32<false>,
   $.hashfn_bswap    = tabulation32<true>
 );

#if defined(HAVE_INT128)
REGISTER_HASH(tabulation_64,
   $.desc       = "64-bit Tabulation with Multiply-Shift Mixer",
   $.impl       = "int128",
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE         |
         FLAG_HASH_SYSTEM_SPECIFIC,
   $.impl_flags =
         FLAG_IMPL_128BIT               |
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 64,
   $.verification_LE = 0x53B08B2D,
   $.verification_BE = 0x164CA53D,
   $.seedfn          = tabulation64_seed,
   $.hashfn_native   = tabulation64<false>,
   $.hashfn_bswap    = tabulation64<true>,
   $.badseeddesc     = "Many seeds can collide on keys of all zero bytes"
 );
#endif
