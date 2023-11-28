/*
 * xxHash - Extremely Fast Hash algorithm
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (C) 2012-2023 Yann Collet
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * You can contact the author at xxHash homepage: https://www.xxhash.com.
 */
#include "Platform.h"
#include "Hashlib.h"

#include "Mathmult.h"

// #define FORCE_SCALAR

//------------------------------------------------------------
#define XXH_VERSION_MAJOR    0
#define XXH_VERSION_MINOR    8
#define XXH_VERSION_RELEASE  2
#define XXH_VERSION_NUMBER  (XXH_VERSION_MAJOR * 100 * 100 + XXH_VERSION_MINOR * 100 + XXH_VERSION_RELEASE)

// Used to prevent unwanted optimizations for var.
//
// It uses an empty GCC inline assembly statement with a register
// constraint which forces var into a general purpose register (eg
// eax, ebx, ecx on x86) and marks it as modified.
//
// This is used in a few places to avoid unwanted autovectorization
// (e.g.  XXH32_round()). All vectorization we want is explicit via
// intrinsics, and _usually_ isn't wanted elsewhere.
//
// We also use it to prevent unwanted constant folding for AArch64 in
// XXH3_initCustomSecret_scalar().
#if defined(HAVE_X86_64_ASM) || defined(HAVE_ARM_ASM) || \
    defined(HAVE_ARM64_ASM) || defined(HAVE_PPC_ASM)
  #define XXH_COMPILER_GUARD(var) __asm__("" : "+r" (var))
  #if defined(__clang__) && defined(__ARM_ARCH)
    #define XXH_COMPILER_GUARD_CLANG_NEON(var) __asm__("" : "+w" (var))
  #else
    #define XXH_COMPILER_GUARD_CLANG_NEON(var) ((void)0)
  #endif
#else
  #define XXH_COMPILER_GUARD(var)            ((void)var)
  #define XXH_COMPILER_GUARD_CLANG_NEON(var) ((void)0)
#endif

#if defined(DEBUG)
  #define XXH_ASSERT(x) assert(x)
#else
  #define XXH_ASSERT(x) assume(x)
#endif

#define XXH_ALIASING MAY_ALIAS

//------------------------------------------------------------
// XXH32 family -- functions used in the classic 32-bit xxHash algorithm

// #define instead of static const, to be used as initializers
#define XXH_PRIME32_1  UINT32_C(0x9E3779B1) // 0b10011110001101110111100110110001
#define XXH_PRIME32_2  UINT32_C(0x85EBCA77) // 0b10000101111010111100101001110111
#define XXH_PRIME32_3  UINT32_C(0xC2B2AE3D) // 0b11000010101100101010111000111101
#define XXH_PRIME32_4  UINT32_C(0x27D4EB2F) // 0b00100111110101001110101100101111
#define XXH_PRIME32_5  UINT32_C(0x165667B1) // 0b00010110010101100110011110110001

// Mixes all bits to finalize the hash.
// The final mix ensures that all input bits have a chance to impact
// any bit in the output digest, resulting in an unbiased
// distribution.
static uint32_t XXH32_avalanche( uint32_t hash ) {
    hash ^= hash >> 15;
    hash *= XXH_PRIME32_2;
    hash ^= hash >> 13;
    hash *= XXH_PRIME32_3;
    hash ^= hash >> 16;
    return hash;
}

// Processes the last 0-15 bytes of ptr.
// There may be up to 15 bytes remaining to consume from the input.
// This final stage will digest them to ensure that all input bytes
// are present in the final mix.
template <bool bswap>
static uint32_t XXH32_finalize( uint32_t hash, const uint8_t * ptr, size_t len ) {
    while (len >= 4) {
        hash += GET_U32<bswap>(ptr, 0) * XXH_PRIME32_3;
        ptr  += 4;
        hash  = ROTL32(hash, 17)       * XXH_PRIME32_4;
        len  -= 4;
    }
    while (len > 0) {
        hash += (*ptr++) * XXH_PRIME32_5;
        hash  = ROTL32(hash, 11) * XXH_PRIME32_1;
        --len;
    }
    return XXH32_avalanche(hash);
}

// Normal stripe processing routine.
// This shuffles the bits so that any bit from input impacts several bits in acc.
//
// A compiler fence is the only thing that prevents GCC and Clang from
// autovectorizing the XXH32 loop (pragmas and attributes don't work
// for some reason) without globally disabling SSE4.1.  The reason we
// want to avoid vectorization is because despite working on 4
// integers at a time, there are multiple factors slowing XXH32 down
// on SSE4:
//
// - There's a ridiculous amount of lag from pmulld (10 cycles of
//   latency on newer chips!) making it slightly slower to multiply
//   four integers at once compared to four integers
//   independently. Even when pmulld was fastest, Sandy/Ivy Bridge, it
//   is still not worth it to go into SSE just to multiply unless
//   doing a long operation.
//
// - Four instructions are required to rotate,
//      movqda tmp,  v // not required with VEX encoding
//      pslld  tmp, 13 // tmp <<= 13
//      psrld  v,   19 // x >>= 19
//      por    v,  tmp // x |= tmp
//   compared to one for scalar:
//      roll   v, 13    // reliably fast across the board
//      shldl  v, v, 13 // Sandy Bridge and later prefer this for some reason
//
// - Instruction level parallelism is actually more beneficial here
//   because the SIMD actually serializes this operation: While v1 is
//   rotating, v2 can load data, while v3 can multiply. SSE forces
//   them to operate together.
//
// The compiler guard is also enabled on AArch64, as Clang is *very
// aggressive* in vectorizing the loop. NEON is only faster on the A53, and
// with the newer cores, it is less than half the speed.
static uint32_t XXH32_round( uint32_t acc, uint32_t input ) {
    acc += input * XXH_PRIME32_2;
    acc  = ROTL32(acc, 13);
    acc *= XXH_PRIME32_1;
#if defined(__SSE4_1__) || defined(__aarch64__)
    XXH_COMPILER_GUARD(acc);
#endif
    return acc;
}

template <bool bswap>
static uint32_t XXH32_impl( const uint8_t * input, size_t len, uint32_t seed ) {
    uint32_t h32;

    if (len >= 16) {
        const uint8_t * const bEnd  = input + len;
        const uint8_t * const limit = bEnd - 15;
        uint32_t v1 = seed + XXH_PRIME32_1 + XXH_PRIME32_2;
        uint32_t v2 = seed + XXH_PRIME32_2;
        uint32_t v3 = seed + 0;
        uint32_t v4 = seed - XXH_PRIME32_1;

        do {
            v1     = XXH32_round(v1, GET_U32<bswap>(input,  0));
            v2     = XXH32_round(v2, GET_U32<bswap>(input,  4));
            v3     = XXH32_round(v3, GET_U32<bswap>(input,  8));
            v4     = XXH32_round(v4, GET_U32<bswap>(input, 12));
            input += 16;
        } while (input < limit);

        h32 = ROTL32(v1, 1) + ROTL32(v2, 7) + ROTL32(v3, 12) + ROTL32(v4, 18);
    } else {
        h32 = seed + XXH_PRIME32_5;
    }

    h32 += (uint32_t)len;

    return XXH32_finalize<bswap>(h32, input, len & 15);
}

//------------------------------------------------------------
// XXH64 family -- functions used in the classic 64-bit xxHash algorithm

// #define rather that static const, to be used as initializers
// 0b1001111000110111011110011011000110000101111010111100101010000111
#define XXH_PRIME64_1  UINT64_C(0x9E3779B185EBCA87)
// 0b1100001010110010101011100011110100100111110101001110101101001111
#define XXH_PRIME64_2  UINT64_C(0xC2B2AE3D27D4EB4F)
// 0b0001011001010110011001111011000110011110001101110111100111111001
#define XXH_PRIME64_3  UINT64_C(0x165667B19E3779F9)
// 0b1000010111101011110010100111011111000010101100101010111001100011
#define XXH_PRIME64_4  UINT64_C(0x85EBCA77C2B2AE63)
// 0b0010011111010100111010110010111100010110010101100110011111000101
#define XXH_PRIME64_5  UINT64_C(0x27D4EB2F165667C5)

// 0b0001011001010110011001111001000110011110001101110111100111111001
static const uint64_t PRIME_MX1 = UINT64_C(0x165667919E3779F9);
// 0b1001111110110010000111000110010100011110100110001101111100100101
static const uint64_t PRIME_MX2 = UINT64_C(0x9FB21C651E98DF25);

static uint64_t XXH64_round( uint64_t acc, uint64_t input ) {
    acc += input * XXH_PRIME64_2;
    acc  = ROTL64(acc, 31);
    acc *= XXH_PRIME64_1;
    return acc;
}

static uint64_t XXH64_mergeRound( uint64_t acc, uint64_t val ) {
    val  = XXH64_round(0, val);
    acc ^= val;
    acc  = acc * XXH_PRIME64_1 + XXH_PRIME64_4;
    return acc;
}

static uint64_t XXH64_avalanche( uint64_t hash ) {
    hash ^= hash >> 33;
    hash *= XXH_PRIME64_2;
    hash ^= hash >> 29;
    hash *= XXH_PRIME64_3;
    hash ^= hash >> 32;
    return hash;
}

// Processes the last 0-31 bytes of ptr.
// There may be up to 31 bytes remaining to consume from the input.
// This final stage will digest them to ensure that all input bytes
// are present in the final mix.
template <bool bswap>
static uint64_t XXH64_finalize( uint64_t hash, const uint8_t * ptr, size_t len ) {
    while (len >= 8) {
        uint64_t const k1 = XXH64_round(0, GET_U64<bswap>(ptr, 0));
        ptr  += 8;
        hash ^= k1;
        hash  = ROTL64(hash, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        len  -= 8;
    }
    if (len >= 4) {
        hash ^= (uint64_t)(GET_U32<bswap>(ptr, 0)) * XXH_PRIME64_1;
        ptr  += 4;
        hash  = ROTL64(hash, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        len  -= 4;
    }
    while (len > 0) {
        hash ^= (*ptr++) * XXH_PRIME64_5;
        hash  = ROTL64(hash, 11) * XXH_PRIME64_1;
        --len;
    }
    return XXH64_avalanche(hash);
}

template <bool bswap>
static uint64_t XXH64_impl( const uint8_t * input, size_t len, uint64_t seed ) {
    uint64_t h64;

    if (len >= 32) {
        const uint8_t * const bEnd  = input + len;
        const uint8_t * const limit = bEnd - 31;
        uint64_t v1 = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
        uint64_t v2 = seed + XXH_PRIME64_2;
        uint64_t v3 = seed + 0;
        uint64_t v4 = seed - XXH_PRIME64_1;

        do {
            v1     = XXH64_round(v1, GET_U64<bswap>(input,  0));
            v2     = XXH64_round(v2, GET_U64<bswap>(input,  8));
            v3     = XXH64_round(v3, GET_U64<bswap>(input, 16));
            v4     = XXH64_round(v4, GET_U64<bswap>(input, 24));
            input += 32;
        } while (input < limit);

        h64 = ROTL64(v1, 1) + ROTL64(v2, 7) + ROTL64(v3, 12) + ROTL64(v4, 18);
        h64 = XXH64_mergeRound(h64, v1);
        h64 = XXH64_mergeRound(h64, v2);
        h64 = XXH64_mergeRound(h64, v3);
        h64 = XXH64_mergeRound(h64, v4);
    } else {
        h64 = seed + XXH_PRIME64_5;
    }

    h64 += (uint64_t)len;

    return XXH64_finalize<bswap>(h64, input, len & 31);
}

//------------------------------------------------------------
// XXH3 family -- 64-bit and 128-bit variants.
// New generation hash designed for speed on small keys and vectorization.
//
// XXH3 is a more recent hash algorithm featuring:
//  - Improved speed for both small and large inputs
//  - True 64-bit and 128-bit outputs
//  - SIMD acceleration
//  - Improved 32-bit viability
//
// Speed analysis methodology is explained here:
//    https://fastcompression.blogspot.com/2019/03/presenting-xxh3.html
//
// One goal of XXH3 is to make it fast on both 32-bit and 64-bit, while
// remaining a true 64-bit/128-bit hash function.
//
// This is done by prioritizing a subset of 64-bit operations that can be
// emulated without too many steps on the average 32-bit machine.
//
// For example, these two lines seem similar, and run equally fast on 64-bit:
//
//   xxh_u64 x;
//   x ^= (x >> 47); // good
//   x ^= (x >> 13); // bad
//
// However, to a 32-bit machine, there is a major difference.
//
// x ^= (x >> 47) looks like this:
//
//   x.lo ^= (x.hi >> (47 - 32));
//
// while x ^= (x >> 13) looks like this:
//
//   // note: funnel shifts are not usually cheap.
//   x.lo ^= (x.lo >> 13) | (x.hi << (32 - 13));
//   x.hi ^= (x.hi >> 13);
//
// The first one is significantly faster than the second, simply because the
// shift is larger than 32. This means:
//  - All the bits we need are in the upper 32 bits, so we can ignore the lower
//    32 bits in the shift.
//  - The shift result will always fit in the lower 32 bits, and therefore,
//    we can ignore the upper 32 bits in the xor.
//
// Thanks to this optimization, XXH3 only requires these features to be efficient:
//
//  - Usable unaligned access
//  - A 32-bit or 64-bit ALU
//      - If 32-bit, a decent ADC instruction
//  - A 32 or 64-bit multiply with a 64-bit result
//  - For the 128-bit variant, a decent byteswap helps short inputs.
//
// The first two are already required by XXH32, and almost all 32-bit and 64-bit
// platforms which can run XXH32 can run XXH3 efficiently.
//
// Thumb-1, the classic 16-bit only subset of ARM's instruction set, is one
// notable exception.
//
// First of all, Thumb-1 lacks support for the UMULL instruction which
// performs the important long multiply. This means numerous __aeabi_lmul
// calls.
//
// Second of all, the 8 functional registers are just not enough.
// Setup for __aeabi_lmul, byteshift loads, pointers, and all arithmetic need
// Lo registers, and this shuffling results in thousands more MOVs than A32.
//
// A32 and T32 don't have this limitation. They can access all 14 registers,
// do a 32->64 multiply with UMULL, and the flexible operand allowing free
// shifts is helpful, too.
//
// Credit: large sections of the vectorial and asm source code paths
//         have been contributed by @easyaspi314

#define XXH3_SECRET_DEFAULT_SIZE 192
#define XXH3_SECRET_SIZE_MIN 136
static_assert((XXH3_SECRET_DEFAULT_SIZE & 15) == 0, "valid secret size");

#define XXH_SECRET_CONSUME_RATE 8
#define XXH_STRIPE_LEN 64
#define XXH_ACC_NB (XXH_STRIPE_LEN / sizeof(uint64_t))

// Pseudorandom secret taken directly from FARSH
alignas(64) static const uint8_t XXH3_kSecret[XXH3_SECRET_DEFAULT_SIZE] = {
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe,
    0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb,
    0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78,
    0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e,
    0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb,
    0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e,
    0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f,
    0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31,
    0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3,
    0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49,
    0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc,
    0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28,
    0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
};

//------------------------------------------------------------
// fwojcik: This is NOT true on my Ryzen 2 chip with gcc 9.3. Enabling
// this actually makes xxh3-64 go from 15.5 bytes/cycle down to 7.1!!!
// It's over twice as fast without this!
#if 0 && defined(HAVE_AVX2)
/*
 * UGLY HACK:
 * GCC usually generates the best code with -O3 for xxHash.
 *
 * However, when targeting AVX2, it is overzealous in its unrolling resulting
 * in code roughly 3/4 the speed of Clang.
 *
 * There are other issues, such as GCC splitting _mm256_loadu_si256 into
 * _mm_loadu_si128 + _mm256_inserti128_si256. This is an optimization which
 * only applies to Sandy and Ivy Bridge... which don't even support AVX2.
 *
 * That is why when compiling the AVX2 version, it is recommended to use either
 *   -O2 -mavx2 -march=haswell
 * or
 *   -O2 -mavx2 -mno-avx256-split-unaligned-load
 * for decent performance, or to use Clang instead.
 *
 * Fortunately, we can control the first one with a pragma that forces GCC into
 * -O2, but the other one we can't control without "failed to inline always
 * inline function due to target mismatch" warnings.
 */
  #if defined(__GNUC__) && !defined(__clang__) && /* GCC, not Clang */ \
      defined(__OPTIMIZE__)
    #define XXH3_POP_PRAGMA
    #pragma GCC push_options
    #pragma GCC optimize("-O2")
  #endif
#endif

//------------------------------------------------------------
typedef struct {
    uint64_t  low64;  // value & 0xFFFFFFFFFFFFFFFF
    uint64_t  high64; // value >> 64
} XXH128_hash_t;

static inline uint64_t XXH_mult32to64_add64( uint64_t lhs, uint64_t rhs, uint64_t acc ) {
    MathMult::fma32_64(acc, lhs, rhs);
    return acc;
}

static inline uint64_t XXH_mult32to64( uint32_t lhs, uint32_t rhs ) {
    uint64_t r64;

    MathMult::mult32_64(r64, lhs, rhs);
    return r64;
}

static inline XXH128_hash_t XXH_mult64to128( uint64_t lhs, uint64_t rhs ) {
    XXH128_hash_t r128;

    MathMult::mult64_128(r128.low64, r128.high64, lhs, rhs);
    return r128;
}

static uint64_t XXH3_mul128_fold64( uint64_t lhs, uint64_t rhs ) {
    XXH128_hash_t product = XXH_mult64to128(lhs, rhs);

    return product.low64 ^ product.high64;
}

// Seems to produce slightly better code on GCC for some reason.
static FORCE_INLINE uint64_t XXH_xorshift64( uint64_t v64, const int shift ) {
    // static_assert(0 <= shift && shift < 64, "valid shift value");
    return v64 ^ (v64 >> shift);
}

// This is a fast avalanche stage, suitable when input bits are
// already partially mixed.
static uint64_t XXH3_avalanche( uint64_t h64 ) {
    h64  = XXH_xorshift64(h64, 37);
    h64 *= PRIME_MX1;
    h64  = XXH_xorshift64(h64, 32);
    return h64;
}

// This is a stronger avalanche, inspired by Pelle Evensen's rrmxmx.
// preferable when input has not been previously mixed.
static uint64_t XXH3_rrmxmx( uint64_t h64, uint64_t len ) {
    /* this mix is inspired by Pelle Evensen's rrmxmx */
    h64 ^= ROTL64(h64, 49) ^ ROTL64(h64, 24);
    h64 *= PRIME_MX2;
    h64 ^= (h64 >> 35) + len;
    h64 *= PRIME_MX2;
    return XXH_xorshift64(h64, 28);
}

//------------------------------------------------------------
// One of the shortcomings of XXH32 and XXH64 was that their
// performance was sub-optimal on short lengths. It used an iterative
// algorithm which strongly favored lengths that were a multiple of 4
// or 8.
//
// Instead of iterating over individual inputs, we use a set of single
// shot functions which piece together a range of lengths and operate
// in constant time.
//
// Additionally, the number of multiplies has been significantly
// reduced. This reduces latency, especially when emulating 64-bit
// multiplies on 32-bit.
//
// Depending on the platform, this may or may not be faster than
// XXH32, but it is almost guaranteed to be faster than XXH64.
//
// At very short lengths, there isn't enough input to fully hide
// secrets, or use the entire secret.
//
// There is also only a limited amount of mixing we can do before
// significantly impacting performance.
//
// Therefore, we use different sections of the secret and always mix
// two secret samples with an XOR. This should have no effect on
// performance on the seedless or withSeed variants because everything
// _should_ be constant folded by modern compilers.
//
// The XOR mixing hides individual parts of the secret and increases
// entropy.
//
// This adds an extra layer of strength for custom secrets.

template <bool bswap>
static FORCE_INLINE uint64_t XXH3_len_1to3_64b( const uint8_t * input,
        size_t len, const uint8_t * secret, uint64_t seed ) {
    XXH_ASSERT(1 <= len && len <= 3);
    // len = 1: combined = { input[0], 0x01, input[0], input[0] }
    // len = 2: combined = { input[1], 0x02, input[0], input[1] }
    // len = 3: combined = { input[2], 0x03, input[0], input[1] }
    uint8_t const  c1       = input[0];
    uint8_t const  c2       = input[len >> 1];
    uint8_t const  c3       = input[len  - 1];
    uint32_t const combined = ((uint32_t)c1 << 16) | ((uint32_t)c2 << 24) |
            ((uint32_t)c3 << 0) | ((uint32_t)len << 8);
    uint64_t const bitflip  = (GET_U32<bswap>(secret, 0) ^ GET_U32<bswap>(secret, 4)) + seed;
    uint64_t const keyed    = (uint64_t)combined ^ bitflip;

    return XXH64_avalanche(keyed);
}

template <bool bswap>
static FORCE_INLINE uint64_t XXH3_len_4to8_64b( const uint8_t * input,
        size_t len, const uint8_t * secret, uint64_t seed ) {
    XXH_ASSERT(4 <= len && len <= 8);
    seed ^= (uint64_t)BSWAP((uint32_t)seed) << 32;
    uint32_t const input1  = GET_U32<bswap>(input,   0    );
    uint32_t const input2  = GET_U32<bswap>(input, len - 4);
    uint64_t const input64 = input2 + (((uint64_t)input1) << 32);
    uint64_t const bitflip = (GET_U64<bswap>(secret, 8) ^ GET_U64<bswap>(secret, 16)) - seed;
    uint64_t const keyed   = input64 ^ bitflip;
    return XXH3_rrmxmx(keyed, len);
}

template <bool bswap>
static FORCE_INLINE uint64_t XXH3_len_9to16_64b( const uint8_t * input,
        size_t len, const uint8_t * secret, uint64_t seed ) {
    XXH_ASSERT(9 <= len && len <= 16);
    uint64_t const bitflip1 = (GET_U64<bswap>(secret, 24) ^ GET_U64<bswap>(secret, 32)) + seed;
    uint64_t const bitflip2 = (GET_U64<bswap>(secret, 40) ^ GET_U64<bswap>(secret, 48)) - seed;
    uint64_t const input_lo = GET_U64<bswap>(input,   0    ) ^ bitflip1;
    uint64_t const input_hi = GET_U64<bswap>(input, len - 8) ^ bitflip2;
    uint64_t const acc      = len + input_hi + BSWAP(input_lo) +
            XXH3_mul128_fold64(input_lo, input_hi);

    return XXH3_avalanche(acc);
}

template <bool bswap>
static FORCE_INLINE uint64_t XXH3_len_0to16_64b( const uint8_t * input,
        size_t len, const uint8_t * secret, uint64_t seed ) {
    XXH_ASSERT(len <= 16);
    if (likely(len >  8)) { return XXH3_len_9to16_64b<bswap>(input, len, secret, seed); }
    if (likely(len >= 4)) { return XXH3_len_4to8_64b<bswap>(input, len, secret, seed); }
    if (len) { return XXH3_len_1to3_64b<bswap>(input, len, secret, seed); }
    return XXH64_avalanche(seed ^ GET_U64<bswap>(secret, 56) ^
            GET_U64<bswap>(secret, 64));
}

//------------------------------------------------------------
// For mid range keys, XXH3 uses a Mum-hash variant.
//
// DISCLAIMER: There are known *seed-dependent* multicollisions here
// due to multiplication by 0, affecting hashes of lengths 17 to 240.
//
// However, they are very unlikely.
//
// Keep this in mind when using the unseeded XXH3_64bits() variant: As
// with all unseeded non-cryptographic hashes, it does not attempt to
// defend itself against specially crafted inputs, only random inputs.
//
// Compared to classic UMAC where a 1 in 2^31 chance of 4 consecutive
// bytes cancelling out the secret is taken an arbitrary number of
// times (addressed in XXH3_accumulate_512), this collision is very
// unlikely with random inputs and/or proper seeding:
//
// This only has a 1 in 2^63 chance of 8 consecutive bytes cancelling
// out, in a function that is only called up to 16 times per hash with
// up to 240 bytes of input.
//
// This is not too bad for a non-cryptographic hash function,
// especially with only 64 bit outputs.
//
// The 128-bit variant (which trades some speed for strength) is NOT
// affected by this, although it is always a good idea to use a proper
// seed if you care about strength.
//
// UGLY HACK:
// GCC for x86 tends to autovectorize the 128-bit multiply, resulting in
// slower code.
//
// By forcing seed64 into a register, we disrupt the cost model and
// cause it to scalarize. See `XXH32_round()`
//
// FIXME: Clang's output is still _much_ faster -- On an AMD Ryzen 3600,
// XXH3_64bits @ len=240 runs at 4.6 GB/s with Clang 9, but 3.3 GB/s on
// GCC 9.2, despite both emitting scalar code.
//
// GCC generates much better scalar code than Clang for the rest of XXH3,
// which is why finding a more optimal codepath is an interest.

#define XXH3_MIDSIZE_MAX 240

template <bool bswap>
static FORCE_INLINE uint64_t XXH3_mix16B( const uint8_t * RESTRICT input,
        const uint8_t * RESTRICT secret, uint64_t seed64 ) {
#if defined(__GNUC__) && !defined(__clang__)  /* GCC, not Clang */ \
    && defined(__i386__) && defined(__SSE2__) /* x86 + SSE2 */
    XXH_COMPILER_GUARD(seed64);
#endif
    uint64_t const input_lo = GET_U64<bswap>(input, 0);
    uint64_t const input_hi = GET_U64<bswap>(input, 8);
    return XXH3_mul128_fold64(input_lo ^ (GET_U64<bswap>(secret, 0) + seed64),
            input_hi ^ (GET_U64<bswap>(secret, 8) - seed64));
}

template <bool bswap>
static FORCE_INLINE uint64_t XXH3_len_17to128_64b( const uint8_t * RESTRICT input, size_t len,
        const uint8_t * RESTRICT secret, size_t secretSize, uint64_t seed ) {
    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN); (void)secretSize;
    XXH_ASSERT(16 < len && len <= 128);
    uint64_t acc = len * XXH_PRIME64_1;

    if (len > 32) {
        if (len > 64) {
            if (len > 96) {
                acc += XXH3_mix16B<bswap>(input + 48      , secret +  96, seed);
                acc += XXH3_mix16B<bswap>(input + len - 64, secret + 112, seed);
            }
            acc += XXH3_mix16B<bswap>(input + 32      , secret + 64, seed);
            acc += XXH3_mix16B<bswap>(input + len - 48, secret + 80, seed);
        }
        acc += XXH3_mix16B<bswap>(input + 16      , secret + 32, seed);
        acc += XXH3_mix16B<bswap>(input + len - 32, secret + 48, seed);
    }
    acc += XXH3_mix16B<bswap>(input + 0       , secret +  0, seed);
    acc += XXH3_mix16B<bswap>(input + len - 16, secret + 16, seed);

    return XXH3_avalanche(acc);
}

// UGLY HACK:
// Clang for ARMv7-A tries to vectorize this loop, similar to GCC x86.
// In everywhere else, it uses scalar code.
//
// For 64->128-bit multiplies, even if the NEON was 100% optimal, it
// would still be slower than UMAAL (see XXH_mult64to128).
//
// Unfortunately, Clang doesn't handle the long multiplies properly and
// converts them to the nonexistent "vmulq_u64" intrinsic, which is then
// scalarized into an ugly mess of VMOV.32 instructions.
//
// This mess is difficult to avoid without turning autovectorization
// off completely, but they are usually relatively minor and/or not
// worth it to fix.
//
// This loop is the easiest to fix, as unlike XXH32, this pragma
// _actually works_ because it is a loop vectorization instead of an
// SLP vectorization.
template <bool bswap>
static NEVER_INLINE uint64_t XXH3_len_129to240_64b( const uint8_t * RESTRICT input, size_t len,
        const uint8_t * RESTRICT secret, size_t secretSize, uint64_t seed ) {
    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN); (void)secretSize;
    XXH_ASSERT(128 < len && len <= XXH3_MIDSIZE_MAX);

#define XXH3_MIDSIZE_STARTOFFSET 3
#define XXH3_MIDSIZE_LASTOFFSET  17

    uint64_t acc = len * XXH_PRIME64_1;
    uint64_t acc_end;
    unsigned const nbRounds = (unsigned)len / 16;
    XXH_ASSERT(128 < len && len <= XXH3_MIDSIZE_MAX);

    for (unsigned i = 0; i < 8; i++) {
        acc += XXH3_mix16B<bswap>(input + (16 * i), secret + (16 * i), seed);
    }
    /* last bytes */
    acc_end = XXH3_mix16B<bswap>(input + len - 16, secret + XXH3_SECRET_SIZE_MIN - XXH3_MIDSIZE_LASTOFFSET, seed);
    XXH_ASSERT(nbRounds >= 8);
    acc = XXH3_avalanche(acc);

#if defined(__clang__) && (defined(__ARM_NEON) || defined(__ARM_NEON__))
  #pragma clang loop vectorize(disable)
#endif

    for (unsigned i = 8; i < nbRounds; i++) {
        /*
         * Prevents clang for unrolling the acc loop and interleaving with this one.
         */
        XXH_COMPILER_GUARD(acc);
        acc_end += XXH3_mix16B<bswap>(input + (16 * i), secret + (16 * (i - 8)) + XXH3_MIDSIZE_STARTOFFSET, seed);
    }
    /* last bytes */
    return XXH3_avalanche(acc + acc_end);
}

//------------------------------------------------------------
// XXH3's 128-bit variant has better mixing and strength than the
// 64-bit variant, even without counting the significantly larger
// output size.
//
// For example, extra steps are taken to avoid the seed-dependent
// collisions in 17-240 byte inputs (See XXH3_mix16B and
// XXH128_mix32B).
//
// This strength naturally comes at the cost of some speed, especially
// on short lengths. Note that longer hashes are about as fast as the
// 64-bit version due to it using only a slight modification of the
// 64-bit loop.
//
// XXH128 is also more oriented towards 64-bit machines. It is still
// extremely fast for a _128-bit_ hash on 32-bit (it usually clears
// XXH64).

// A doubled version of 1to3_64b with different constants.
template <bool bswap>
static FORCE_INLINE XXH128_hash_t XXH3_len_1to3_128b( const uint8_t * input,
        size_t len, const uint8_t * secret, uint64_t seed ) {
    XXH_ASSERT(1 <= len && len <= 3);
    /*
     * len = 1: combinedl = { input[0], 0x01, input[0], input[0] }
     * len = 2: combinedl = { input[1], 0x02, input[0], input[1] }
     * len = 3: combinedl = { input[2], 0x03, input[0], input[1] }
     */
    uint8_t const  c1        = input[0];
    uint8_t const  c2        = input[len >> 1];
    uint8_t const  c3        = input[len  - 1];
    uint32_t const combinedl = ((uint32_t)c1 << 16) | ((uint32_t)c2 << 24) |
            ((uint32_t)c3 << 0) | ((uint32_t)len << 8);
    uint32_t const combinedh = ROTL32(BSWAP(combinedl), 13);
    uint64_t const bitflipl  = (GET_U32<bswap>(secret, 0) ^ GET_U32<bswap>(secret,  4)) + seed;
    uint64_t const bitfliph  = (GET_U32<bswap>(secret, 8) ^ GET_U32<bswap>(secret, 12)) - seed;
    uint64_t const keyed_lo  = (uint64_t)combinedl ^ bitflipl;
    uint64_t const keyed_hi  = (uint64_t)combinedh ^ bitfliph;
    XXH128_hash_t  h128      = { XXH64_avalanche(keyed_lo), XXH64_avalanche(keyed_hi) };

    return h128;
}

template <bool bswap>
static FORCE_INLINE XXH128_hash_t XXH3_len_4to8_128b( const uint8_t * input,
        size_t len, const uint8_t * secret, uint64_t seed ) {
    XXH_ASSERT(4 <= len && len <= 8);
    seed ^= (uint64_t)BSWAP((uint32_t)seed) << 32;
    uint32_t const input_lo = GET_U32<bswap>(input,   0    );
    uint32_t const input_hi = GET_U32<bswap>(input, len - 4);
    uint64_t const input_64 = input_lo + ((uint64_t)input_hi << 32);
    uint64_t const bitflip  = (GET_U64<bswap>(secret, 16) ^ GET_U64<bswap>(secret, 24)) + seed;
    uint64_t const keyed    = input_64 ^ bitflip;

    /* Shift len to the left to ensure it is even, this avoids even multiplies. */
    XXH128_hash_t m128 = XXH_mult64to128(keyed, XXH_PRIME64_1 + (len << 2));

    m128.high64 += (m128.low64  << 1);
    m128.low64  ^= (m128.high64 >> 3);

    m128.low64   = XXH_xorshift64(m128.low64, 35);
    m128.low64  *= PRIME_MX2;
    m128.low64   = XXH_xorshift64(m128.low64, 28);
    m128.high64  = XXH3_avalanche(m128.high64);
    return m128;
}

template <bool bswap>
static FORCE_INLINE XXH128_hash_t XXH3_len_9to16_128b( const uint8_t * input,
        size_t len, const uint8_t * secret, uint64_t seed ) {
    XXH_ASSERT(9 <= len && len <= 16);
    uint64_t const bitflipl = (GET_U64<bswap>(secret, 32) ^ GET_U64<bswap>(secret, 40)) - seed;
    uint64_t const bitfliph = (GET_U64<bswap>(secret, 48) ^ GET_U64<bswap>(secret, 56)) + seed;
    uint64_t const input_lo = GET_U64<bswap>(input,   0    );
    uint64_t       input_hi = GET_U64<bswap>(input, len - 8);
    XXH128_hash_t  m128     = XXH_mult64to128(input_lo ^ input_hi ^ bitflipl, XXH_PRIME64_1);

    /*
     * Put len in the middle of m128 to ensure that the length gets mixed to
     * both the low and high bits in the 128x64 multiply below.
     */
    m128.low64 += (uint64_t)(len - 1) << 54;
    input_hi   ^= bitfliph;
    /*
     * Add the high 32 bits of input_hi to the high 32 bits of m128, then
     * add the long product of the low 32 bits of input_hi and XXH_PRIME32_2 to
     * the high 64 bits of m128.
     *
     * The best approach to this operation is different on 32-bit and
     * 64-bit, but the mathematical results are the same.
     */
#if defined(HAVE_32BIT_PLATFORM)
    /*
     * 32-bit optimized version, which is more readable.
     *
     * On 32-bit, it removes an ADC and delays a dependency between the two
     * halves of m128.high64, but it generates an extra mask on 64-bit.
     */
    m128.high64 += (input_hi & UINT64_C(0xFFFFFFFF00000000)) + XXH_mult32to64((uint32_t)input_hi, XXH_PRIME32_2);
#else
    /*
     * 64-bit optimized (albeit more confusing) version.
     *
     * Uses some properties of addition and multiplication to remove the mask:
     *
     * Let:
     *    a = input_hi.lo = (input_hi & 0x00000000FFFFFFFF)
     *    b = input_hi.hi = (input_hi & 0xFFFFFFFF00000000)
     *    c = XXH_PRIME32_2
     *
     *    a + (b * c)
     * Inverse Property: x + y - x == y
     *    a + (b * (1 + c - 1))
     * Distributive Property: x * (y + z) == (x * y) + (x * z)
     *    a + (b * 1) + (b * (c - 1))
     * Identity Property: x * 1 == x
     *    a + b + (b * (c - 1))
     *
     * Substitute a, b, and c:
     *    input_hi.hi + input_hi.lo + ((uint64_t)input_hi.lo * (XXH_PRIME32_2 - 1))
     *
     * Since input_hi.hi + input_hi.lo == input_hi, we get this:
     *    input_hi + ((uint64_t)input_hi.lo * (XXH_PRIME32_2 - 1))
     */
    m128.high64 += input_hi + XXH_mult32to64((uint32_t)input_hi, XXH_PRIME32_2 - 1);
#endif
    /* m128 ^= XXH_swap64(m128 >> 64); */
    m128.low64 ^= BSWAP(m128.high64);

    /* 128x64 multiply: h128 = m128 * XXH_PRIME64_2; */
    XXH128_hash_t h128 = XXH_mult64to128(m128.low64, XXH_PRIME64_2);
    h128.high64 += m128.high64 * XXH_PRIME64_2;

    h128.low64   = XXH3_avalanche(h128.low64 );
    h128.high64  = XXH3_avalanche(h128.high64);
    return h128;
}

// Assumption: `secret` size is >= XXH3_SECRET_SIZE_MIN
template <bool bswap>
static FORCE_INLINE XXH128_hash_t XXH3_len_0to16_128b( const uint8_t * input,
        size_t len, const uint8_t * secret, uint64_t seed ) {
    XXH_ASSERT(len <= 16);
    if (len >  8) { return XXH3_len_9to16_128b<bswap>(input, len, secret, seed); }
    if (len >= 4) { return XXH3_len_4to8_128b<bswap>(input, len, secret, seed); }
    if (len) { return XXH3_len_1to3_128b<bswap>(input, len, secret, seed); }

    uint64_t const bitflipl = GET_U64<bswap>(secret, 64) ^ GET_U64<bswap>(secret, 72);
    uint64_t const bitfliph = GET_U64<bswap>(secret, 80) ^ GET_U64<bswap>(secret, 88);
    XXH128_hash_t  h128     = { XXH64_avalanche(seed ^ bitflipl), XXH64_avalanche(seed ^ bitfliph) };
    return h128;
}

//------------------------------------------------------------
// XXH3-128 mid-range keys

// A bit slower than XXH3_mix16B, but handles multiply by zero better.
template <bool bswap>
static FORCE_INLINE XXH128_hash_t XXH128_mix32B( XXH128_hash_t acc, const uint8_t * input_1,
        const uint8_t * input_2, const uint8_t * secret, uint64_t seed ) {
    acc.low64  += XXH3_mix16B<bswap>(input_1, secret +  0, seed);
    acc.low64  ^= GET_U64<bswap>(input_2, 0) + GET_U64<bswap>(input_2, 8);
    acc.high64 += XXH3_mix16B<bswap>(input_2, secret + 16, seed);
    acc.high64 ^= GET_U64<bswap>(input_1, 0) + GET_U64<bswap>(input_1, 8);
    return acc;
}

template <bool bswap>
static FORCE_INLINE XXH128_hash_t XXH3_len_17to128_128b( const uint8_t * RESTRICT input, size_t len,
        const uint8_t * RESTRICT secret, size_t secretSize, uint64_t seed ) {
    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN); (void)secretSize;
    XXH_ASSERT(16 < len && len <= 128);
    XXH128_hash_t acc = { len * XXH_PRIME64_1, acc.high64 = 0 };

    if (len > 32) {
        if (len > 64) {
            if (len > 96) {
                acc = XXH128_mix32B<bswap>(acc, input + 48, input + len - 64, secret + 96, seed);
            }
            acc = XXH128_mix32B<bswap>(acc, input + 32, input + len - 48, secret + 64, seed);
        }
        acc = XXH128_mix32B<bswap>(acc, input + 16, input + len - 32, secret + 32, seed);
    }
    acc = XXH128_mix32B<bswap>(acc, input, input + len - 16, secret, seed);

    XXH128_hash_t h128;
    h128.low64  = acc.low64 + acc.high64;
    h128.high64 = (acc.low64  * XXH_PRIME64_1) +
                  (acc.high64 * XXH_PRIME64_4) +
                  ((len - seed) * XXH_PRIME64_2);
    h128.low64  = XXH3_avalanche(h128.low64);
    h128.high64 = (uint64_t)0 - XXH3_avalanche(h128.high64);
    return h128;
}

template <bool bswap>
static NEVER_INLINE XXH128_hash_t XXH3_len_129to240_128b( const uint8_t * RESTRICT input, size_t len,
        const uint8_t * RESTRICT secret, size_t secretSize, uint64_t seed ) {
    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN); (void)secretSize;
    XXH_ASSERT(128 < len && len <= XXH3_MIDSIZE_MAX);
    XXH128_hash_t acc;
    unsigned i;

    acc.low64  = len * XXH_PRIME64_1;
    acc.high64 = 0;
    /*
     * We set as `i` as offset + 32. We do this so that unchanged
     * `len` can be used as upper bound. This reaches a sweet spot
     * where both x86 and aarch64 get simple agen and good codegen
     * for the loop.
     */
    for (i = 32; i < 160; i += 32) {
        acc = XXH128_mix32B<bswap>(acc, input + i - 32, input + i - 16, secret + i - 32, seed);
    }
    acc.low64  = XXH3_avalanche(acc.low64 );
    acc.high64 = XXH3_avalanche(acc.high64);

    /*
     * NB: `i <= len` will duplicate the last 32-bytes if
     * len % 32 was zero. This is an unfortunate necessity to keep
     * the hash result stable.
     */
    for (i=160; i <= len; i += 32) {
        acc = XXH128_mix32B<bswap>(acc, input + i - 32, input + i - 16,
                secret + XXH3_MIDSIZE_STARTOFFSET + i - 160, seed);
    }

    /* last bytes */
    acc = XXH128_mix32B<bswap>(acc, input + len - 16, input + len - 32,
            secret + XXH3_SECRET_SIZE_MIN - XXH3_MIDSIZE_LASTOFFSET - 16, UINT64_C(0) - seed);

    XXH128_hash_t h128;
    h128.low64  = acc.low64 + acc.high64;
    h128.high64 = (acc.low64  * XXH_PRIME64_1) +
                  (acc.high64 * XXH_PRIME64_4) +
                  ((len - seed) * XXH_PRIME64_2);
    h128.low64  = XXH3_avalanche(h128.low64);
    h128.high64 = UINT64_C(0) - XXH3_avalanche(h128.high64);
    return h128;
}


//------------------------------------------------------------
// XXH3 and XXH3-128 long keys
// Platform-specific vectorized variants

template <bool bswap>
static FORCE_INLINE void XXH3_scalarRound( void * RESTRICT acc, void const * RESTRICT input,
        void const * RESTRICT secret, size_t lane );
template <bool bswap>
static FORCE_INLINE void XXH3_scalarScrambleRound( void * RESTRICT acc, void const * RESTRICT secret, size_t lane );

#define XXH_SCALAR 0
#define XXH_SSE2   1
#define XXH_AVX2   2
#define XXH_AVX512 3
#define XXH_NEON   4
#define XXH_VSX    5

static const char * xxh_vector_str[] = {
    "scalar", // XXH_SCALAR
    "sse2",   // XXH_SSE2
    "avx2",   // XXH_AVX2
    "avx512", // XXH_AVX512
    "neon",   // XXH_NEON
    "vsx",    // XXH_VSX
};

#if defined(__has_builtin)
  #define XXH_HAS_BUILTIN(x) __has_builtin(x)
#else
  #define XXH_HAS_BUILTIN(x) 0
#endif

#if !defined(FORCE_SCALAR) && defined(HAVE_PPC_VSX) && \
    !defined(HAVE_PPC_ASM) && !defined(__s390x__) &&   \
    !(defined(__clang__) && XXH_HAS_BUILTIN(__builtin_altivec_vmuleuw))
  #warning "PPC mulo/mule compiler support not found; falling back to scalar code"
  #define FORCE_SCALAR
#endif

#if defined(FORCE_SCALAR)
  #define XXH_VECTOR    XXH_SCALAR
  #define XXH_ACC_ALIGN 8
  #define XXH_SEC_ALIGN 8
#elif defined(HAVE_ARM_NEON)
  #define XXH_VECTOR    XXH_NEON
  #define XXH_ACC_ALIGN 16
  #define XXH_SEC_ALIGN 8
  #include "Intrinsics.h"
  #include "xxhash/xxh3-arm.h"
#elif defined(HAVE_PPC_VSX)
  #define XXH_VECTOR    XXH_VSX
  #define XXH_ACC_ALIGN 16
  #define XXH_SEC_ALIGN 8
  #include "Intrinsics.h"
  #include "xxhash/xxh3-ppc.h"
#elif defined(HAVE_AVX512_F)
  #define XXH_VECTOR    XXH_AVX512
  #define XXH_ACC_ALIGN 64
  #define XXH_SEC_ALIGN 64
  #include "Intrinsics.h"
  #include "xxhash/xxh3-avx512.h"
#elif defined(HAVE_AVX2)
  #define XXH_VECTOR    XXH_AVX2
  #define XXH_ACC_ALIGN 32
  #define XXH_SEC_ALIGN 32
  #include "Intrinsics.h"
  #include "xxhash/xxh3-avx2.h"
#elif defined(HAVE_SSE_2)
  #define XXH_VECTOR    XXH_SSE2
  #define XXH_ACC_ALIGN 16
  #define XXH_SEC_ALIGN 16
  #include "Intrinsics.h"
  #include "xxhash/xxh3-sse2.h"
#else
  #define XXH_VECTOR    XXH_SCALAR
  #define XXH_ACC_ALIGN 8
  #define XXH_SEC_ALIGN 8
#endif

//------------------------------------------------------------
// XXH3 and XXH3-128 long keys
// Scalar variants - universal. These are always defined.
//
// XXH3_accumulate_512 is the tightest loop for long inputs, and it is
// the most optimized.
//
// It is a hardened version of UMAC, based off of FARSH's implementation.
//
// This was chosen because it adapts quite well to 32-bit, 64-bit, and
// SIMD implementations, and it is ridiculously fast.
//
// We harden it by mixing the original input to the accumulators as
// well as the product.
//
// This means that in the (relatively likely) case of a multiply by
// zero, the original input is preserved.
//
// On 128-bit inputs, we swap 64-bit pairs when we add the input to
// improve cross-pollination, as otherwise the upper and lower halves
// would be essentially independent.
//
// This doesn't matter on 64-bit hashes since they all get merged
// together in the end, so we skip the extra step.
template <bool bswap>
static FORCE_INLINE void XXH3_scalarRound( void * RESTRICT acc, void const * RESTRICT input,
        void const * RESTRICT secret, size_t lane ) {
    XXH_ASSERT(lane < XXH_ACC_NB);
    XXH_ASSERT(((size_t)acc & (XXH_ACC_ALIGN-1)) == 0);
    uint64_t *      xacc     = (uint64_t *     )acc;
    uint8_t const * xinput   = (uint8_t const *)input;
    uint8_t const * xsecret  = (uint8_t const *)secret;
    uint64_t const  data_val = GET_U64<bswap>(xinput,  lane * 8);
    uint64_t const  data_key = GET_U64<bswap>(xsecret, lane * 8) ^ data_val;

    xacc[lane ^ 1] += data_val; /* swap adjacent lanes */
    xacc[lane]      = XXH_mult32to64_add64(data_key, data_key >> 32, xacc[lane]);
}

template <bool bswap>
static FORCE_INLINE void XXH3_accumulate_512_scalar( void * RESTRICT acc,
        const void * RESTRICT input, const void * RESTRICT secret ) {
    /* ARM GCC refuses to unroll this loop, resulting in a 24% slowdown on ARMv6. */
#if defined(__GNUC__) && !defined(__clang__)     \
    && (defined(__arm__) || defined(__thumb2__)) \
    && defined(__ARM_FEATURE_UNALIGNED) /* no unaligned access just wastes bytes */
  #pragma GCC unroll 8
#endif
    for (size_t i = 0; i < XXH_ACC_NB; i++) {
        XXH3_scalarRound<bswap>(acc, input, secret, i);
    }
}

// XXH3_scrambleAcc: Scrambles the accumulators to improve mixing.
//
// Multiplication isn't perfect, as explained by Google in HighwayHash:
//
//  // Multiplication mixes/scrambles bytes 0-7 of the 64-bit result to
//  // varying degrees. In descending order of goodness, bytes
//  // 3 4 2 5 1 6 0 7 have quality 228 224 164 160 100 96 36 32.
//  // As expected, the upper and lower bytes are much worse.
//
// Source: https://github.com/google/highwayhash/blob/0aaf66b/highwayhash/hh_avx2.h#L291
//
// Since our algorithm uses a pseudorandom secret to add some variance
// into the mix, we don't need to (or want to) mix as often or as much
// as HighwayHash does.
template <bool bswap>
static FORCE_INLINE void XXH3_scalarScrambleRound( void * RESTRICT acc, void const * RESTRICT secret, size_t lane ) {
    XXH_ASSERT((((size_t)acc) & (XXH_ACC_ALIGN-1)) == 0);
    XXH_ASSERT(lane < XXH_ACC_NB);
    uint64_t      * const xacc    = (uint64_t *     )acc;    /* presumed aligned */
    const uint8_t * const xsecret = (const uint8_t *)secret; /* no alignment restriction */
    uint64_t const        key64   = GET_U64<bswap>(xsecret, lane * 8);
    uint64_t acc64 = xacc[lane];

    acc64      = XXH_xorshift64(acc64, 47);
    acc64     ^= key64;
    acc64     *= XXH_PRIME32_1;
    xacc[lane] = acc64;
}

template <bool bswap>
static FORCE_INLINE void XXH3_scrambleAcc_scalar( void * RESTRICT acc, const void * RESTRICT secret ) {
    for (size_t i = 0; i < XXH_ACC_NB; i++) {
        XXH3_scalarScrambleRound<bswap>(acc, secret, i);
    }
}

// UGLY HACK:
// GCC and Clang generate a bunch of MOV/MOVK pairs for aarch64, and they
// are placed sequentially, in order, at the top of the unrolled loop.
//
// While MOVK is great for generating constants (2 cycles for a 64-bit
// constant compared to 4 cycles for LDR), it fights for bandwidth with
// the arithmetic instructions.
//
//   I   L   S
// MOVK
// MOVK
// MOVK
// MOVK
// ADD
// SUB      STR
//          STR
// By forcing loads from memory (as the asm line causes the compiler to
// assume that XXH3_kSecretPtr has been changed), the pipelines are used
// more efficiently:
//   I   L   S
//      LDR
//  ADD LDR
//  SUB     STR
//          STR
//
// See XXH3_NEON_LANES for details on the pipsline.
//
// XXH3_64bits_withSeed, len == 256, Snapdragon 835
//   without hack: 2654.4 MB/s
//   with hack:    3202.9 MB/s
template <bool bswap>
static FORCE_INLINE void XXH3_initCustomSecret_scalar( void * RESTRICT customSecret, uint64_t seed64 ) {
    /*
     * We need a separate pointer for the GUARD hack below,
     * which requires a non-const pointer.
     * Any decent compiler will optimize this out otherwise.
     */
    const uint8_t * kSecretPtr = XXH3_kSecret;

#if defined(__GNUC__) && defined(__aarch64__)
    XXH_COMPILER_GUARD(kSecretPtr);
#endif

    int const nbRounds = XXH3_SECRET_DEFAULT_SIZE / 16;
    for (int i = 0; i < nbRounds; i++) {
        /*
         * The asm hack causes the compiler to assume that kSecretPtr
         * aliases with customSecret, and on aarch64, this prevented LDP
         * from merging two loads together for free. Putting the loads
         * together before the stores properly generates LDP.
         */
        uint64_t lo = GET_U64<bswap>(kSecretPtr, 16 * i    ) + seed64;
        uint64_t hi = GET_U64<bswap>(kSecretPtr, 16 * i + 8) - seed64;
        PUT_U64<bswap>(lo, (uint8_t *)customSecret, 16 * i    );
        PUT_U64<bswap>(hi, (uint8_t *)customSecret, 16 * i + 8);
    }
}

//------------------------------------------------------------
// XXH3 and XXH3-128 long keys
// "Dispatcher" code

template <bool bswap>
static void XXH3_accumulate_512( void * RESTRICT acc, const void * RESTRICT input, const void * RESTRICT secret ) {
#if (XXH_VECTOR == XXH_AVX512)
    XXH3_accumulate_512_avx512<bswap>(acc, input, secret);
#elif (XXH_VECTOR == XXH_AVX2)
    XXH3_accumulate_512_avx2<bswap>(acc, input, secret);
#elif (XXH_VECTOR == XXH_SSE2)
    XXH3_accumulate_512_sse2<bswap>(acc, input, secret);
#elif (XXH_VECTOR == XXH_NEON)
    XXH3_accumulate_512_neon<bswap>(acc, input, secret);
#elif (XXH_VECTOR == XXH_VSX)
    XXH3_accumulate_512_vsx<bswap>(acc, input, secret);
#else /* scalar */
    XXH3_accumulate_512_scalar<bswap>(acc, input, secret);
#endif
}

template <bool bswap>
static void XXH3_scrambleAcc( void * RESTRICT acc, const void * RESTRICT secret ) {
#if (XXH_VECTOR == XXH_AVX512)
    XXH3_scrambleAcc_avx512<bswap>(acc, secret);
#elif (XXH_VECTOR == XXH_AVX2)
    XXH3_scrambleAcc_avx2<bswap>(acc, secret);
#elif (XXH_VECTOR == XXH_SSE2)
    XXH3_scrambleAcc_sse2<bswap>(acc, secret);
#elif (XXH_VECTOR == XXH_NEON)
    XXH3_scrambleAcc_neon<bswap>(acc, secret);
#elif (XXH_VECTOR == XXH_VSX)
    XXH3_scrambleAcc_vsx<bswap>(acc, secret);
#else /* scalar */
    XXH3_scrambleAcc_scalar<bswap>(acc, secret);
#endif
}

template <bool bswap>
static void XXH3_initCustomSecret( void * RESTRICT customSecret, uint64_t seed64 ) {
#if (XXH_VECTOR == XXH_AVX512)
    XXH3_initCustomSecret_avx512<bswap>(customSecret, seed64);
#elif (XXH_VECTOR == XXH_AVX2)
    XXH3_initCustomSecret_avx2<bswap>(customSecret, seed64);
#elif (XXH_VECTOR == XXH_SSE2)
    XXH3_initCustomSecret_sse2<bswap>(customSecret, seed64);
#elif (XXH_VECTOR == XXH_NEON)
    XXH3_initCustomSecret_scalar<bswap>(customSecret, seed64);
#elif (XXH_VECTOR == XXH_VSX)
    XXH3_initCustomSecret_scalar<bswap>(customSecret, seed64);
#else /* scalar */
    XXH3_initCustomSecret_scalar<bswap>(customSecret, seed64);
#endif
}

//------------------------------------------------------------
// XXH3 and XXH3-128 long keys

#if defined(__clang__)
  #define XXH_PREFETCH_DIST 320
#elif (XXH_VECTOR == XXH_AVX512)
  #define XXH_PREFETCH_DIST 512
#else
  #define XXH_PREFETCH_DIST 384
#endif  /* __clang__ */

template <bool bswap>
static FORCE_INLINE void XXH3_accumulate( uint64_t * RESTRICT acc, const uint8_t * RESTRICT input,
        const uint8_t * RESTRICT secret, size_t nbStripes ) {
    for (size_t n = 0; n < nbStripes; n++) {
        const uint8_t * const in = input + n * XXH_STRIPE_LEN;
        prefetch(in + XXH_PREFETCH_DIST);
        XXH3_accumulate_512<bswap>(acc, in, secret + n * XXH_SECRET_CONSUME_RATE);
    }
}

template <bool bswap>
static FORCE_INLINE void XXH3_hashLong_internal_loop( uint64_t * RESTRICT acc, const uint8_t * RESTRICT input,
        size_t len, const uint8_t * RESTRICT secret, size_t secretSize ) {
    XXH_ASSERT(secretSize >= XXH3_SECRET_SIZE_MIN);
    XXH_ASSERT(len > XXH_STRIPE_LEN);
    size_t const nbStripesPerBlock = (secretSize - XXH_STRIPE_LEN) / XXH_SECRET_CONSUME_RATE;
    size_t const block_len         = XXH_STRIPE_LEN * nbStripesPerBlock;
    size_t const nb_blocks         = (len - 1) / block_len;

    for (size_t n = 0; n < nb_blocks; n++) {
        XXH3_accumulate<bswap>(acc, input + n * block_len, secret, nbStripesPerBlock);
        XXH3_scrambleAcc<bswap>(acc, secret + secretSize - XXH_STRIPE_LEN);
    }

    /* last partial block */
    size_t const nbStripes = ((len - 1) - (block_len * nb_blocks)) / XXH_STRIPE_LEN;
    XXH_ASSERT(nbStripes <= (secretSize / XXH_SECRET_CONSUME_RATE));
    XXH3_accumulate<bswap>(acc, input + nb_blocks * block_len, secret, nbStripes);

    /* last stripe */
    const uint8_t * const p = input + len - XXH_STRIPE_LEN;
#define XXH_SECRET_LASTACC_START 7 /* not aligned on 8, last secret is different from acc & scrambler */
    XXH3_accumulate_512<bswap>(acc, p, secret + secretSize - XXH_STRIPE_LEN - XXH_SECRET_LASTACC_START);
}

template <bool bswap>
static FORCE_INLINE uint64_t XXH3_mix2Accs( const uint64_t * RESTRICT acc, const uint8_t * RESTRICT secret ) {
    return XXH3_mul128_fold64(acc[0] ^ GET_U64<bswap>(secret, 0), acc[1] ^ GET_U64<bswap>(secret, 8));
}

// UGLY HACK:
// Prevent autovectorization on Clang ARMv7-a. Exact same problem as
// the one in XXH3_len_129to240_64b. Speeds up shorter keys > 240b.
// XXH3_64bits, len == 256, Snapdragon 835:
//   without hack: 2063.7 MB/s
//   with hack:    2560.7 MB/s
template <bool bswap>
static uint64_t XXH3_mergeAccs( const uint64_t * RESTRICT acc, const uint8_t * RESTRICT secret, uint64_t start ) {
    uint64_t result64 = start;

    for (size_t i = 0; i < 4; i++) {
        result64 += XXH3_mix2Accs<bswap>(acc + 2 * i, secret + 16 * i);
#if defined(__clang__)                                /* Clang */ \
    && (defined(__arm__) || defined(__thumb__))       /* ARMv7 */ \
    && (defined(__ARM_NEON) || defined(__ARM_NEON__)) /* NEON */
        XXH_COMPILER_GUARD(result64);
#endif
    }
    return XXH3_avalanche(result64);
}

#define XXH_SECRET_MERGEACCS_START 11

// It's important for performance that XXH3_hashLong is not inlined. Not sure
// why (uop cache maybe?), but the difference is large and easily measurable.
template <bool bswap>
static NEVER_INLINE uint64_t XXH3_hashLong_64b_internal( const void * RESTRICT input,
        size_t len, const void * RESTRICT secret, size_t secretSize ) {
    alignas(XXH_ACC_ALIGN) uint64_t acc[XXH_ACC_NB] = {
        XXH_PRIME32_3, XXH_PRIME64_1, XXH_PRIME64_2, XXH_PRIME64_3,
        XXH_PRIME64_4, XXH_PRIME32_2, XXH_PRIME64_5, XXH_PRIME32_1,
    };

    XXH3_hashLong_internal_loop<bswap>(acc, (const uint8_t *)input, len, (const uint8_t *)secret, secretSize);

    XXH_ASSERT(secretSize >= sizeof(acc) + XXH_SECRET_MERGEACCS_START);
    return XXH3_mergeAccs<bswap>(acc, (const uint8_t *)secret + XXH_SECRET_MERGEACCS_START,
            (uint64_t)len * XXH_PRIME64_1);
}

template <bool bswap>
static NEVER_INLINE XXH128_hash_t XXH3_hashLong_128b_internal( const void * RESTRICT input,
        size_t len, const void * RESTRICT secret, size_t secretSize ) {
    alignas(XXH_ACC_ALIGN) uint64_t acc[XXH_ACC_NB] = {
        XXH_PRIME32_3, XXH_PRIME64_1, XXH_PRIME64_2, XXH_PRIME64_3,
        XXH_PRIME64_4, XXH_PRIME32_2, XXH_PRIME64_5, XXH_PRIME32_1,
    };

    XXH3_hashLong_internal_loop<bswap>(acc, (const uint8_t *)input, len, (const uint8_t *)secret, secretSize);

    // converge into final hash
    XXH_ASSERT(secretSize >= sizeof(acc) + XXH_SECRET_MERGEACCS_START);
    const XXH128_hash_t h128 = {
        /* .low64 = */ XXH3_mergeAccs <bswap>(acc, (const uint8_t *)secret + XXH_SECRET_MERGEACCS_START,
                (uint64_t)len * XXH_PRIME64_1),
        /* .high64 = */ XXH3_mergeAccs<bswap>(acc, (const uint8_t *)secret + secretSize                -
                sizeof(acc) - XXH_SECRET_MERGEACCS_START, ~((uint64_t)len * XXH_PRIME64_2)),
    };
    return h128;
}

//------------------------------------------------------------
// XXH3 and XXH3-128 top-level functions

template <bool bswap>
static FORCE_INLINE uint64_t XXH3_64bits_withSecretandSeed( const void * input, size_t len,
         uint64_t seed, const uint8_t * RESTRICT secret, const size_t secretLen ) {
    if (len <= 16) {
        return XXH3_len_0to16_64b<bswap>((const uint8_t *)input, len, secret, seed);
    }
    if (len <= 128) {
        return XXH3_len_17to128_64b<bswap>((const uint8_t *)input, len, secret, secretLen, seed);
    }
    if (len <= XXH3_MIDSIZE_MAX) {
        return XXH3_len_129to240_64b<bswap>((const uint8_t *)input, len, secret, secretLen, seed);
    }

    if (seed == 0) {
        return XXH3_hashLong_64b_internal<bswap>(input, len, secret, secretLen);
    }

    alignas(XXH_SEC_ALIGN) uint8_t secretbuf[XXH3_SECRET_DEFAULT_SIZE];
    XXH3_initCustomSecret<bswap>(secretbuf, seed);
    return XXH3_hashLong_64b_internal<bswap>(input, len, secretbuf, sizeof(secretbuf));
}

template <bool bswap>
static FORCE_INLINE XXH128_hash_t XXH3_128bits_withSecretandSeed( const void * input, size_t len,
         uint64_t seed, const uint8_t * RESTRICT secret, const size_t secretLen ) {
    if (len <= 16) {
        return XXH3_len_0to16_128b<bswap>((const uint8_t *)input, len, secret, seed);
    }
    if (len <= 128) {
        return XXH3_len_17to128_128b<bswap>((const uint8_t *)input, len, secret, secretLen, seed);
    }
    if (len <= XXH3_MIDSIZE_MAX) {
        return XXH3_len_129to240_128b<bswap>((const uint8_t *)input, len, secret, secretLen, seed);
    }

    if (seed == 0) {
        return XXH3_hashLong_128b_internal<bswap>(input, len, secret, secretLen);
    }

    alignas(XXH_SEC_ALIGN) uint8_t secretbuf[XXH3_SECRET_DEFAULT_SIZE];
    XXH3_initCustomSecret<bswap>(secretbuf, seed);
    return XXH3_hashLong_128b_internal<bswap>(input, len, secretbuf, sizeof(secretbuf));
}


template <bool bswap>
static uint64_t XXH3_64bits_withSeed( const void * input, size_t len, uint64_t seed ) {
    return XXH3_64bits_withSecretandSeed<bswap>(input, len, seed, (const uint8_t *)XXH3_kSecret, sizeof(XXH3_kSecret));
}

template <bool bswap>
static XXH128_hash_t XXH3_128bits_withSeed( const void * input, size_t len, uint64_t seed ) {
    return XXH3_128bits_withSecretandSeed<bswap>(input, len, seed, (const uint8_t *)XXH3_kSecret, sizeof(XXH3_kSecret));
}

#if defined(XXH3_POP_PRAGMA)
  #pragma GCC pop_options
#endif

//------------------------------------------------------------
template <bool bswap>
static void XXH32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = XXH32_impl<bswap>((const uint8_t *)in, len, (uint32_t)seed);

    // Output in "canonical" BE format
    if (isLE()) {
        PUT_U32<true>(h, (uint8_t *)out, 0);
    } else {
        PUT_U32<false>(h, (uint8_t *)out, 0);
    }
}

template <bool bswap>
static void XXH64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = XXH64_impl<bswap>((const uint8_t *)in, len, (uint64_t)seed);

    // Output in "canonical" BE format
    if (isLE()) {
        PUT_U64<true>(h, (uint8_t *)out, 0);
    } else {
        PUT_U64<false>(h, (uint8_t *)out, 0);
    }
}

//------------------------------------------------------------
template <bool bswap>
static void XXH3_64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = XXH3_64bits_withSeed<bswap>(in, len, seed);

    // Output in "canonical" BE format
    if (isLE()) {
        PUT_U64<true>(h, (uint8_t *)out, 0);
    } else {
        PUT_U64<false>(h, (uint8_t *)out, 0);
    }
}

template <bool bswap>
static void XXH3_128( const void * in, const size_t len, const seed_t seed, void * out ) {
    XXH128_hash_t h = XXH3_128bits_withSeed<bswap>(in, len, seed);

    // Output in "canonical" BE format
    if (isLE()) {
        PUT_U64<true>(h.high64, (uint8_t *)out, 0);
        PUT_U64<true>(h.low64 , (uint8_t *)out, 8);
    } else {
        PUT_U64<false>(h.high64, (uint8_t *)out, 0);
        PUT_U64<false>(h.low64 , (uint8_t *)out, 8);
    }
}

//------------------------------------------------------------
struct xxh3_gensecret {
    uint8_t secret[XXH3_SECRET_DEFAULT_SIZE];
};

alignas(XXH_SEC_ALIGN) static thread_local struct xxh3_gensecret gensecret;

static uintptr_t xxh3_initsecret( const seed_t seed ) {
    if (isLE()) {
        XXH3_initCustomSecret<false>(gensecret.secret, (uint64_t)seed);
    } else {
        XXH3_initCustomSecret<true>(gensecret.secret, (uint64_t)seed);
    }
    return (seed_t)(uintptr_t)&gensecret;
}

template <bool bswap>
static uintptr_t xxh3_generatesecret_impl( const seed_t seed ) {
    const uint64_t seed64 = (uint64_t)seed;
    const uint64_t seedLE = COND_BSWAP(seed64, bswap);

    uint8_t scrambler[16];
    XXH3_128<bswap>(&seedLE, sizeof(seedLE), 0, scrambler);

    size_t const nbSeg16 = sizeof(gensecret.secret) / 16;
    for (size_t n = 0; n < nbSeg16; n++) {
        const XXH128_hash_t h128 = XXH3_128bits_withSeed<bswap>(scrambler, sizeof(scrambler), n);
        PUT_U64<bswap>(h128.low64  ^ seed64, gensecret.secret, n * 16);
        PUT_U64<bswap>(h128.high64 ^ seed64, gensecret.secret, n * 16 + 8);
    }
    for (size_t i = 0; i < 8; i++) {
        gensecret.secret[XXH3_SECRET_DEFAULT_SIZE - 16 + i] ^= scrambler[15 - i];
        gensecret.secret[XXH3_SECRET_DEFAULT_SIZE -  8 + i] ^= scrambler[ 7 - i];
    }

    return (seed_t)(uintptr_t)&gensecret;
}

static uintptr_t xxh3_generatesecret( const seed_t seed ) {
    if (isLE()) {
        return xxh3_generatesecret_impl<false>(seed);
    } else {
        return xxh3_generatesecret_impl<true>(seed);
    }
}

// These hash entry points both emulate XXH3_NNbits_withSecret(), and not
// XXH3_NNbits_withSecretandSeed(). The latter, bizarrely, does not used
// the supplied secret data with inputs lengths <= XXH3_MIDSIZE_MAX. The
// former always uses a seed value of 0 explicitly, so that is done
// here. This does sidestep certain destructive interferences in the
// XXH3_initCustomSecret() case which would happen if the same seed value
// was given, which is good.

template <bool bswap>
static void XXH3_64_reseed( const void * in, const size_t len, const seed_t seed, void * out ) {
    const struct xxh3_gensecret * gs = (const struct xxh3_gensecret *)(uintptr_t)seed;
    uint64_t h = XXH3_64bits_withSecretandSeed<bswap>(in, len, 0, gs->secret, XXH3_SECRET_DEFAULT_SIZE);

    // Output in "canonical" BE format
    if (isLE()) {
        PUT_U64<true>(h, (uint8_t *)out, 0);
    } else {
        PUT_U64<false>(h, (uint8_t *)out, 0);
    }
}

template <bool bswap>
static void XXH3_128_reseed( const void * in, const size_t len, const seed_t seed, void * out ) {
    const struct xxh3_gensecret * gs = (const struct xxh3_gensecret *)(uintptr_t)seed;
    XXH128_hash_t h = XXH3_128bits_withSecretandSeed<bswap>(in, len, 0, gs->secret, XXH3_SECRET_DEFAULT_SIZE);

    // Output in "canonical" BE format
    if (isLE()) {
        PUT_U64<true>(h.high64, (uint8_t *)out, 0);
        PUT_U64<true>(h.low64 , (uint8_t *)out, 8);
    } else {
        PUT_U64<false>(h.high64, (uint8_t *)out, 0);
        PUT_U64<false>(h.low64 , (uint8_t *)out, 8);
    }
}

//------------------------------------------------------------
REGISTER_FAMILY(xxhash,
   $.src_url    = "https://github.com/Cyan4973/xxHash",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(XXH_32,
   $.desc       = "xxHash, 32-bit version",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED          |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE        |
         FLAG_IMPL_MULTIPLY            |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 32,
   $.verification_LE = 0x6FD78385,
   $.verification_BE = 0x2BC79298,
   $.hashfn_native   = XXH32<false>,
   $.hashfn_bswap    = XXH32<true>
 );

REGISTER_HASH(XXH_64,
   $.desc       = "xxHash, 64-bit version",
   $.hash_flags =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE        |
         FLAG_IMPL_MULTIPLY_64_64      |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 64,
   $.verification_LE = 0x8F8224C4,
   $.verification_BE = 0xB96ABE81,
   $.hashfn_native   = XXH64<false>,
   $.hashfn_bswap    = XXH64<true>
 );

REGISTER_HASH(XXH3_64,
   $.desc       = "xxh3, 64-bit version",
   $.impl       = xxh_vector_str[XXH_VECTOR],
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE        |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE        |
         FLAG_IMPL_MULTIPLY            |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 64,
   $.verification_LE = 0x1AAEE62C,
   $.verification_BE = 0xF8DBB4DD,
   $.hashfn_native   = XXH3_64<false>,
   $.hashfn_bswap    = XXH3_64<true>,
   // Seems to be simpler-than-expected relationship between seed and hash
   // for keys of 1-3 bytes.
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0x58b7a744, 0x58b7a844, 0x58b7a944, 0x70cfa75c, 0x70cfa85c, 0x70cfa95c,
                         0x76d5a762, 0x76d5a862, 0x76d5a962, 0x78d7a764, 0x78d7a864, 0x78d7a964,
                         0xffffffff78d8a665, 0xffffffff78d8a765, 0xffffffff78d8a865,
                         0xffffffff7adaa667, 0xffffffff7adaa767, 0xffffffff7adaa867,
                         0xffffffff80e0a66d, 0xffffffff80e0a76d, 0xffffffff80e0a86d,
                         0xffffffff98f8a685, 0xffffffff98f8a785, 0xffffffff98f8a885,
                         0xfffffffff857a6e4, 0xfffffffff857a7e4, 0xfffffffff857a8e4,
                         0xfffffffff958a6e5, 0xfffffffff958a7e5, 0xfffffffff958a8e5 }
 );

REGISTER_HASH(XXH3_64__reinit,
   $.desc       = "xxh3, 64-bit version with secret initialized per-seed",
   $.impl       = xxh_vector_str[XXH_VECTOR],
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE        |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS        |
         FLAG_IMPL_CANONICAL_LE        |
         FLAG_IMPL_MULTIPLY            |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 64,
   $.verification_LE = 0x1D70522D,
   $.verification_BE = 0x853C024D,
   $.hashfn_native   = XXH3_64_reseed<false>,
   $.hashfn_bswap    = XXH3_64_reseed<true>,
   $.seedfn          = xxh3_initsecret
 );

REGISTER_HASH(XXH3_64__regen,
   $.desc       = "xxh3, 64-bit version with secret regenerated per-seed",
   $.impl       = xxh_vector_str[XXH_VECTOR],
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE        |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE        |
         FLAG_IMPL_MULTIPLY            |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 64,
   $.verification_LE = 0xD9D35F29,
   $.verification_BE = 0x6A66F3AD,
   $.hashfn_native   = XXH3_64_reseed<false>,
   $.hashfn_bswap    = XXH3_64_reseed<true>,
   $.seedfn          = xxh3_generatesecret
 );

REGISTER_HASH(XXH3_128,
   $.desc       = "xxh3, 128-bit version",
   $.impl       = xxh_vector_str[XXH_VECTOR],
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE        |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE        |
         FLAG_IMPL_MULTIPLY            |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 128,
   $.verification_LE = 0x288DAA94,
   $.verification_BE = 0x6C82FA25,
   $.hashfn_native   = XXH3_128<false>,
   $.hashfn_bswap    = XXH3_128<true>
 );

REGISTER_HASH(XXH3_128__reinit,
   $.desc       = "xxh3, 128-bit version with secret initialized per-seed",
   $.impl       = xxh_vector_str[XXH_VECTOR],
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE        |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS        |
         FLAG_IMPL_CANONICAL_LE        |
         FLAG_IMPL_MULTIPLY            |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 128,
   $.verification_LE = 0x73E0E58E,
   $.verification_BE = 0xDF32C7F9,
   $.hashfn_native   = XXH3_128_reseed<false>,
   $.hashfn_bswap    = XXH3_128_reseed<true>,
   $.seedfn          = xxh3_initsecret
 );

REGISTER_HASH(XXH3_128__regen,
   $.desc       = "xxh3, 128-bit version with secret regenerated per-seed",
   $.impl       = xxh_vector_str[XXH_VECTOR],
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE        |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE        |
         FLAG_IMPL_MULTIPLY            |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 128,
   $.verification_LE = 0xCB11C866,
   $.verification_BE = 0x93EA1B6C,
   $.hashfn_native   = XXH3_128_reseed<false>,
   $.hashfn_bswap    = XXH3_128_reseed<true>,
   $.seedfn          = xxh3_generatesecret
 );
