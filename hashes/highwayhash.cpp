/*
 * HighwayHash
 * Copyright (C) 2023       Frank J. T. Wojcik
 * Copyright (C) 2016-2019  Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "Platform.h"
#include "Hashlib.h"

//#define FORCE_PORTABLE

#if defined(_MSC_VER)
  #define HH_INLINE FORCE_INLINE
#else
  #define HH_INLINE inline
#endif
#define HH_RESTRICT RESTRICT

//------------------------------------------------------------
// Initialization constants
//
// "Nothing up my sleeve" numbers, concatenated hex digits of Pi from
// http://www.numberworld.org/digits/Pi/, retrieved Feb 22, 2016.
//
// We use this python code to generate the fourth number to have
// more even mixture of bits:
//   def x(a,b,c):
//     retval = 0
//     for i in range(64):
//       count = ((a >> i) & 1) + ((b >> i) & 1) + ((c >> i) & 1)
//       if (count <= 1):
//         retval |= 1 << i
//     return retval
alignas(16) static const uint64_t init0[4] = {
    UINT64_C(0xdbe6d5d5fe4cce2f), UINT64_C(0xa4093822299f31d0),
    UINT64_C(0x13198a2e03707344), UINT64_C(0x243f6a8885a308d3)
};
alignas(16) static const uint64_t init1[4] = {
    UINT64_C(0x3bd39e10cb0ef593), UINT64_C(0xc0acf169b5f18a8c),
    UINT64_C(0xbe5466cf34e90c6c), UINT64_C(0x452821e638d01377)
};

//------------------------------------------------------------
// Reading small tails of input data

// When loading the tail end of the input data, up to 4 preceding bytes may
// be read and returned along with the 0..3 valid bytes, depending on
// various things. The valid bytes are in little-endian order, except that
// the preceding bytes occupy the least-significant bytes.

// It's safe to read before "from", so we can load 32 bits, which is faster
// than individual byte loads. We assume little-endian byte order, so
// big-endian platforms will need to swap.
static HH_INLINE uint32_t Load3LE_AllowReadBefore( const uint8_t * from, const size_t size_mod4 ) {
    from = from + size_mod4 - 4;
    return isLE() ? GET_U32<false>(from, 0) : GET_U32<true>(from, 0);
}

// The bytes need not be loaded in little-endian order. This particular
// order (and the duplication of some bytes depending on "size_mod4") was
// chosen for computational convenience and can no longer be changed
// because it is part of the HighwayHash length padding definition.
static HH_INLINE uint64_t Load3LE_AllowUnordered( const uint8_t * from, const size_t size_mod4 ) {
    uint64_t last3 = 0;

    // Not allowed to read any bytes; early-out is faster than reading from a
    // constant array of zeros.
    if (size_mod4 == 0) {
        return last3;
    }

    // These indices are chosen as an easy-to-compute sequence containing the
    // same elements as [0, size), but repeated and/or reordered. This enables
    // unconditional loads, which outperform conditional 8 or 16+8 bit loads.
    const uint64_t idx0 = 0;
    const uint64_t idx1 = size_mod4 >> 1;
    const uint64_t idx2 = size_mod4 - 1;
    // Store into least significant bytes (avoids one shift).
    last3  = static_cast<uint64_t>(from[idx0]);
    last3 += static_cast<uint64_t>(from[idx1]) <<  8;
    last3 += static_cast<uint64_t>(from[idx2]) << 16;
    return last3;
}

//------------------------------------------------------------
// Platform-specific implementations

#define HH_PORTABLE 0
#define HH_SSE41    1
#define HH_AVX2     2
#define HH_NEON     3
#define HH_VSX      4

static const char * hh_vector_str[] = {
    "portable", // HH_PORTABLE
    "sse41",    // HH_SSE41
    "avx2",     // HH_AVX2
    "neon",     // HH_NEON
    "vsx",      // HH_VSX
};

// The PPC/VSX alternative is disabled here because the implementation
// shipped in the official HighwayHash repo is broken, at least on
// big-endian machines. This may get resolved in the future.
//
// The AVX2 alternative is disabled here because my re-implementation seems
// to be significantly slower than the one in the official repo (e.g. 165
// cycles per hash vs. 90-105), and because even in the offical repo the
// SSE4.1 implementation is faster on my Zen 2 system.
//
// My SSE4.1 re-implementation is mysteriously a little faster than the one
// in the official repo (e.g. 76-81 cycles vs. 76-90). ¯\_(ツ)_/¯
#if defined(FORCE_PORTABLE)
  #define HH_TARGET    HH_PORTABLE
  #define HH_MAX_ALIGN 16
#elif defined(HAVE_ARM_NEON)
  #define HH_TARGET    HH_NEON
  #define HH_MAX_ALIGN 16
  #include "Intrinsics.h"
  #include "highwayhash/hash-neon.h"
#elif 0 && defined(HAVE_PPC_VSX)
  #define HH_TARGET    HH_VSX
  #define HH_MAX_ALIGN 16
  #include "Intrinsics.h"
  #include "highwayhash/hash-vsx.h"
#elif 0 && defined(HAVE_AVX2)
  #define HH_TARGET    HH_AVX2
  #define HH_MAX_ALIGN 32
  #include "Intrinsics.h"
  #include "highwayhash/hash-avx2.h"
#elif defined(HAVE_SSE_4_1)
  #define HH_TARGET    HH_SSE41
  #define HH_MAX_ALIGN 32
  #include "Intrinsics.h"
  #include "highwayhash/hash-sse41.h"
#else
  #define HH_TARGET    HH_PORTABLE
  #define HH_MAX_ALIGN 16
#endif

//------------------------------------------------------------
// Data structures and seeding

#if (HH_TARGET == HH_PORTABLE)

typedef uint64_t block_t[4];

typedef struct state_struct {
    uint64_t  v0[4];
    uint64_t  v1[4];
    uint64_t  mul0[4];
    uint64_t  mul1[4];
} highwayhash_state_t;

void dump_state( const highwayhash_state_t * s ) {
    return;
    printf("\tv0   %016lx %016lx %016lx %016lx\n", s->v0[0]  , s->v0[1]  , s->v0[2]  , s->v0[3]  );
    printf("\tv1   %016lx %016lx %016lx %016lx\n", s->v1[0]  , s->v1[1]  , s->v1[2]  , s->v1[3]  );
    printf("\tmul0 %016lx %016lx %016lx %016lx\n", s->mul0[0], s->mul0[1], s->mul0[2], s->mul0[3]);
    printf("\tmul1 %016lx %016lx %016lx %016lx\n", s->mul1[0], s->mul1[1], s->mul1[2], s->mul1[3]);
    printf("\n");
}

alignas(HH_MAX_ALIGN) static thread_local highwayhash_state_t seeded_state;

static uintptr_t HighwayHashReseed( const seed_t seed ) {
    // This is a totally arbitrary way to generate a 4x64-bit key vector from a
    // single 64-bit seed value.
    static const uint64_t key[4] = { 1, 2, 3, 4 };

    for (uint64_t i = 0; i < 4; i++) {
        uint64_t seededkey   = key[i]   ^ (uint64_t)seed;
        seeded_state.v0[i]   = init0[i] ^ seededkey;
        seeded_state.v1[i]   = init1[i] ^ ROTR64(seededkey, 32);
        seeded_state.mul0[i] = init0[i];
        seeded_state.mul1[i] = init1[i];
    }

    return (uintptr_t)(void *)&seeded_state;
}

//------------------------------------------------------------
// Byte-reading routines
//
// Note that data is always read in little-endian order!

static HH_INLINE void GetBlock( block_t & HH_RESTRICT block, const uint8_t * HH_RESTRICT bytes ) {
    if (isLE()) {
        memcpy(&block[0], bytes, 32);
    } else {
        block[0] = GET_U64<true>(bytes,  0);
        block[1] = GET_U64<true>(bytes,  8);
        block[2] = GET_U64<true>(bytes, 16);
        block[3] = GET_U64<true>(bytes, 24);
    }
}

static HH_INLINE void GetRemainder( block_t & HH_RESTRICT block, const uint8_t * HH_RESTRICT bytes,
        const size_t size_mod32 ) {
    const size_t    size_mod4 = size_mod32 & 3;
    const size_t    rbytes    = size_mod32 & ~3;
    const uint8_t * remainder = bytes + rbytes;
    uint8_t *       block8    = (uint8_t *)block;

    memset(block8, 0, 32);
    for (size_t i = 0; i < rbytes; i++) {
        block8[i] = bytes[i];
    }

    if (size_mod32 & 16) { // 16..31 bytes left
        // Read the last 0..3 bytes and previous 1..4 into the upper bits.
        // Insert into the upper four bytes of packet, which are zero.
        const uint32_t last4 = Load3LE_AllowReadBefore(remainder, size_mod4);
        if (isLE()) {
            PUT_U32<false>(last4, block8, 28);
        } else {
            PUT_U32<true>(last4, block8, 28);
        }
    } else { // size_mod32 < 16
        // Rather than insert at packet + 28, it is faster to initialize
        // the otherwise empty packet + 16 with up to 64 bits of padding.
        const uint64_t last4 = Load3LE_AllowUnordered(remainder, size_mod4);
        if (isLE()) {
            PUT_U64<false>(last4, block8, 16);
        } else {
            PUT_U64<true>(last4, block8, 16);
        }
    }

    if (isBE()) {
        for (unsigned i = 0; i < 4; i++) {
            block[i] = BSWAP64(block[i]);
        }
    }
}

//------------------------------------------------------------
// Core hashing routines

// Clears all bits except one byte at the given offset.
  #define MASK(v, bytes) ((v) & (UINT64_C(0xFF) << ((bytes) * 8)))

// Multiplication mixes/scrambles bytes 0-7 of the 64-bit result to
// varying degrees. In descending order of goodness, bytes
// 3 4 2 5 1 6 0 7 have quality 228 224 164 160 100 96 36 32.
// As expected, the upper and lower bytes are much worse.
// For each 64-bit lane, our objectives are:
// 1) maximizing and equalizing total goodness across the four lanes.
// 2) mixing with bytes from the neighboring lane (AVX-2 makes it difficult
//    to cross the 128-bit wall, but PermuteAndUpdate takes care of that);
// 3) placing the worst bytes in the upper 32 bits because those will not
//    be used in the next 32x32 multiplication.
static HH_INLINE void ZipperMergeAndAdd( const uint64_t v1, const uint64_t v0,
        uint64_t & HH_RESTRICT add1, uint64_t & HH_RESTRICT add0 ) {
    // 16-byte permutation; shifting is about 10% faster than byte loads.
    // Adds zipper-merge result to add*.
    add0 += ((MASK(v0, 3) + MASK(v1, 4)) >> 24) +
            ((MASK(v0, 5) + MASK(v1, 6)) >> 16) + MASK(v0, 2) +
            (MASK(v0, 1) << 32) + (MASK(v1, 7) >> 8) + (v0 << 56);

    add1 += ((MASK(v1, 3) + MASK(v0, 4)) >> 24) + MASK(v1, 2) +
            (MASK(v1, 5) >> 16) + (MASK(v1, 1) << 24) + (MASK(v0, 6) >> 8) +
            (MASK(v1, 0) << 48) + MASK(v0, 7);
}

  #undef MASK

static HH_INLINE void Update( highwayhash_state_t * state, const uint64_t * HH_RESTRICT input ) {
    // printf("\tUPD  %016lx %016lx %016lx %016lx\n", input[0], input[1], input[2], input[3]);

    for (unsigned i = 0; i < 4; i++) {
        state->v1[i] += input[i] + state->mul0[i];
    }

    // (Loop is faster than unrolling)
    for (unsigned lane = 0; lane < 4; lane++) {
        const uint32_t v1_32  = static_cast<uint32_t>(state->v1[lane]);
        state->mul0[lane]    ^= v1_32 * (state->v0[lane] >> 32);
        state->v0[lane]      += state->mul1[lane];
        const uint32_t v0_32  = static_cast<uint32_t>(state->v0[lane]);
        state->mul1[lane]    ^= v0_32 * (state->v1[lane] >> 32);
    }

    ZipperMergeAndAdd(state->v1[1], state->v1[0], state->v0[1], state->v0[0]);
    ZipperMergeAndAdd(state->v1[3], state->v1[2], state->v0[3], state->v0[2]);

    ZipperMergeAndAdd(state->v0[1], state->v0[0], state->v1[1], state->v1[0]);
    ZipperMergeAndAdd(state->v0[3], state->v0[2], state->v1[3], state->v1[2]);
}

// Mix together all lanes. It is slightly better to permute v0 than v1; it
// will be added to v1.
//
// For complete mixing, we need to swap the upper and lower 128-bit halves;
// we also swap all 32-bit halves.
static HH_INLINE void PermuteAndUpdate( highwayhash_state_t * state ) {
    uint64_t permuted[4];

    permuted[0] = ROTR64(state->v0[2], 32);
    permuted[1] = ROTR64(state->v0[3], 32);
    permuted[2] = ROTR64(state->v0[0], 32);
    permuted[3] = ROTR64(state->v0[1], 32);

    Update(state, permuted);
}

// 'Length padding' differentiates zero-valued inputs that have the same
// size/32. mod32 is sufficient because each Update behaves as if a
// counter were injected, because the state is large and mixed thoroughly.
static HH_INLINE void PadState( highwayhash_state_t * state, const size_t size_mod32 ) {
    const uint64_t mod32_pair = (static_cast<uint64_t>(size_mod32) << 32) + size_mod32;

    for (unsigned lane = 0; lane < 4; lane++) {
        state->v0[lane] += mod32_pair;
        uint32_t x = state->v1[lane] & 0xffffffff;
        uint32_t y = state->v1[lane] >> 32;
        x = ROTL32(x, size_mod32);
        y = ROTL32(y, size_mod32);
        state->v1[lane] = static_cast<uint64_t>(x) | (static_cast<uint64_t>(y) << 32);
    }
}

//------------------------------------------------------------
// Extract the hash value(s) from the state

// Computes a << kBits for 128-bit a = (a1, a0).
// Bit shifts are only possible on independent 64-bit lanes. We therefore
// insert the upper bits of a0 that were lost into a1. This is slightly
// shorter than Lemire's (a << 1) | (((a >> 8) << 1) << 8) approach.
template <int kBits>
static HH_INLINE void Shift128Left( uint64_t & HH_RESTRICT a1, uint64_t & HH_RESTRICT a0 ) {
    const uint64_t shifted1 = (a1) << kBits;
    const uint64_t top_bits = (a0) >> (64 - kBits);

    a0 <<= kBits;
    a1   = shifted1 | top_bits;
}

// Modular reduction by the irreducible polynomial (x^128 + x^2 + x).
// Input: a 256-bit number a3210.
static HH_INLINE void ModularReduction( const uint64_t a3_unmasked, const uint64_t a2, const uint64_t a1,
        const uint64_t a0, uint64_t & HH_RESTRICT m1, uint64_t & HH_RESTRICT m0 ) {
    // The upper two bits must be clear, otherwise a3 << 2 would lose bits,
    // in which case we're no longer computing a reduction.
    const uint64_t a3 = a3_unmasked & UINT64_C(0x3FFFFFFFFFFFFFFF);
    // See Lemire, https://arxiv.org/pdf/1503.03465v8.pdf.
    uint64_t a3_shl1  = a3;
    uint64_t a2_shl1  = a2;
    uint64_t a3_shl2  = a3;
    uint64_t a2_shl2  = a2;

    Shift128Left<1>(a3_shl1, a2_shl1);
    Shift128Left<2>(a3_shl2, a2_shl2);
    m1 = a1 ^ a3_shl1 ^ a3_shl2;
    m0 = a0 ^ a2_shl1 ^ a2_shl2;
}

template <bool bswap, unsigned output_words>
static HH_INLINE void Finalize( const highwayhash_state_t * state, uint8_t * out ) {
    uint64_t r1, r2;

    if (output_words == 1) {
        // Each lane is sufficiently mixed, so just truncate to 64 bits.
        r1 = state->v0[0] + state->v1[0] + state->mul0[0] + state->mul1[0];
        PUT_U64<bswap>(r1, out, 0);
    } else if (output_words == 2) {
        r1 = state->v0[0] + state->v1[2] + state->mul0[0] + state->mul1[2];
        r2 = state->v0[1] + state->v1[3] + state->mul0[1] + state->mul1[3];
        PUT_U64<bswap>(r1, out, 0);
        PUT_U64<bswap>(r2, out, 8);
    } else {
        ModularReduction(state->v1[1] + state->mul1[1], state->v1[0] + state->mul1[0],
                state->v0[1] + state->mul0[1], state->v0[0] + state->mul0[0], r2, r1);
        PUT_U64<bswap>(r1, out,  0);
        PUT_U64<bswap>(r2, out,  8);
        uint64_t r3, r4;
        ModularReduction(state->v1[3] + state->mul1[3], state->v1[2] + state->mul1[2],
                state->v0[3] + state->mul0[3], state->v0[2] + state->mul0[2], r4, r3);
        PUT_U64<bswap>(r3, out, 16);
        PUT_U64<bswap>(r4, out, 24);
    }
}

#endif // HH_TARGET == HH_PORTABLE

//------------------------------------------------------------
// Common primary routines

static void HighwayHashUpdate( highwayhash_state_t * state, const uint8_t * HH_RESTRICT bytes, const size_t size ) {
    alignas(HH_MAX_ALIGN) block_t block;
    const size_t remainder = size & 31;
    const size_t truncated = size & ~31;

    for (size_t offset = 0; offset < truncated; offset += 32) {
        GetBlock(block, bytes + offset);
        Update(state, block);
    }
    if (remainder != 0) {
        PadState(state, remainder);
        GetRemainder(block, bytes + truncated, remainder);
        Update(state, block);
    }
}

template <bool bswap, unsigned output_words>
static void HighwayHashFinal( highwayhash_state_t * state, uint8_t * HH_RESTRICT out ) {
    const unsigned permute_rounds = (output_words == 1) ? 4 : (output_words == 2) ? 6 : 10;

    for (unsigned i = 0; i < permute_rounds; i++) {
        PermuteAndUpdate(state);
    }

    Finalize<bswap, output_words>(state, out);
}

//------------------------------------------------------------
template <bool bswap, unsigned output_words>
static void HighwayHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    const highwayhash_state_t * base_state = (const highwayhash_state_t *)(void *)(uintptr_t)seed;

    alignas(HH_MAX_ALIGN) highwayhash_state_t state = *base_state;

    HighwayHashUpdate(&state, (const uint8_t *)in, len);
    HighwayHashFinal<bswap, output_words>(&state, (uint8_t *)out);
}

//------------------------------------------------------------
REGISTER_FAMILY(HighwayHash,
   $.src_url    = "https://github.com/google/highwayhash",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(HighwayHash_64,
   $.desc            = "HighwayHash, 64-bit version",
   $.impl            = hh_vector_str[HH_TARGET],
   $.hash_flags      =
         FLAG_HASH_CRYPTOGRAPHIC       |
         FLAG_HASH_XL_SEED             |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_CANONICAL_LE        |
         FLAG_IMPL_SLOW                |
         FLAG_IMPL_INCREMENTAL         |
         FLAG_IMPL_MULTIPLY_64_64      |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 64,
   $.verification_LE = 0xF3246108,
   $.verification_BE = 0xF41A53FD,
   $.hashfn_native   = HighwayHash<false, 1>,
   $.hashfn_bswap    = HighwayHash<true, 1>,
   $.seedfn          = HighwayHashReseed
 );

REGISTER_HASH(HighwayHash_128,
   $.desc            = "HighwayHash, 128-bit version",
   $.impl            = hh_vector_str[HH_TARGET],
   $.hash_flags      =
         FLAG_HASH_CRYPTOGRAPHIC       |
         FLAG_HASH_XL_SEED             |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_CANONICAL_LE        |
         FLAG_IMPL_SLOW                |
         FLAG_IMPL_INCREMENTAL         |
         FLAG_IMPL_MULTIPLY_64_64      |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 128,
   $.verification_LE = 0x232D434E,
   $.verification_BE = 0xC9665BF9,
   $.hashfn_native   = HighwayHash<false, 2>,
   $.hashfn_bswap    = HighwayHash<true, 2>,
   $.seedfn          = HighwayHashReseed
 );

REGISTER_HASH(HighwayHash_256,
   $.desc            = "HighwayHash, 256-bit version",
   $.impl            = hh_vector_str[HH_TARGET],
   $.hash_flags      =
         FLAG_HASH_CRYPTOGRAPHIC       |
         FLAG_HASH_XL_SEED             |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_CANONICAL_LE        |
         FLAG_IMPL_SLOW                |
         FLAG_IMPL_INCREMENTAL         |
         FLAG_IMPL_MULTIPLY_64_64      |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 256,
   $.verification_LE = 0x0D50D328,
   $.verification_BE = 0x4C737711,
   $.hashfn_native   = HighwayHash<false, 4>,
   $.hashfn_bswap    = HighwayHash<true, 4>,
   $.seedfn          = HighwayHashReseed
 );
