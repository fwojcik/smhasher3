/*
 * Abseil (absl) hashes
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

#include "Intrinsics.h"
#include "Mathmult.h"

//------------------------------------------------------------
// Import the existing CityHash implementations
namespace CityHash {
    #define IMPORT_CITY
    #include "cityhash.cpp"
}

//------------------------------------------------------------
// Explicitly defines the size of the L1 cache for purposes of alignment.
//
// NOTE: this macro should be replaced with the following C++17 features, when
// those are generally available:
//
//   * `std::hardware_constructive_interference_size`
//   * `std::hardware_destructive_interference_size`
//
// See http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2016/p0154r1.html
// for more information.
//
// For aarch64, we would need to read special register ctr_el0 to find out
// L1 dcache size. The below value is a good estimate based on a real
// aarch64 machine.
//
// For ARM, these values are not strictly correct since cache line sizes
// depend on implementations, not architectures. There are even
// implementations with cache line sizes configurable at boot time.
#if defined(__GNUC__)
  #if defined(__i386__) || defined(__x86_64__)
    #define ABSL_CACHELINE_SIZE 64
  #elif defined(__powerpc64__)
    #define ABSL_CACHELINE_SIZE 128
  #elif defined(__aarch64__)
    #define ABSL_CACHELINE_SIZE 64
  #elif defined(__arm__)
    #if defined(__ARM_ARCH_5T__)
      #define ABSL_CACHELINE_SIZE 32
    #elif defined(__ARM_ARCH_7A__)
      #define ABSL_CACHELINE_SIZE 64
    #endif
  #endif
#endif

// A reasonable default guess.  Note that overestimates tend to waste more
// space, while underestimates tend to waste more time.
#ifndef ABSL_CACHELINE_SIZE
  #define ABSL_CACHELINE_SIZE 64
#endif

//------------------------------------------------------------
// The salt array used by LowLevelHash.
//
// Any random values are fine. These values are just digits from the
// decimal part of pi.
// https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number
static constexpr uint64_t kHashSalt[5] = {
    UINT64_C(0x243f6a8885a308d3), UINT64_C(0x13198a2e03707344),
    UINT64_C(0xa4093822299f31d0), UINT64_C(0x082efa98ec4e6c89),
    UINT64_C(0x452821e638d01377),
};

//------------------------------------------------------------

static uint64_t Mix( uint64_t v0, uint64_t v1 ) {
    uint64_t rlo, rhi;

    MathMult::mult64_128(rlo, rhi, v0, v1);
    return rlo ^ rhi;
}

static FORCE_INLINE uint64_t Mix32( uint64_t state, uint64_t v ) {
    const uint64_t kMul = UINT64_C(0xcc9e2d51);
    uint64_t m = state + v;
    m *= kMul;
    return static_cast<uint64_t>(m ^ (m >> (sizeof(m) * 8 / 2)));
}

static FORCE_INLINE uint64_t Mix64( uint64_t state, uint64_t v ) {
    // We do the addition in 64-bit space to make sure the 128-bit
    // multiplication is fast. If we were to do it as 128 bits, then
    // the compiler has to assume that the high word is non-zero and
    // needs to perform 2 multiplications instead of one.
    const uint64_t kMul = UINT64_C(0x9ddfea08eb382d69);
    uint64_t mlo, mhi;
    MathMult::mult64_128(mlo, mhi, state + v, kMul);
    return mlo ^ mhi;
}

//------------------------------------------------------------
// Chunksize for AbslHashValue()

static constexpr size_t PiecewiseChunkSize() { return 1024; }

//------------------------------------------------------------

template <bool bswap>
static void LowLevelHash( const void * in, const size_t starting_length, const seed_t seed, void * out ) {
    // Prefetch the cacheline that data resides in.
    prefetch(in);

    const uint8_t * ptr = static_cast<const uint8_t *>(in             );
    uint64_t        len = static_cast<uint64_t       >(starting_length);
    uint64_t        current_state = seed ^ kHashSalt[0];

    if (len > 64) {
        // If we have more than 64 bytes, we're going to handle chunks of 64
        // bytes at a time. We're going to build up two separate hash states
        // which we will then hash together.
        uint64_t duplicated_state = current_state;

        do {
            // Always prefetch the next cacheline.
            prefetch(ptr + ABSL_CACHELINE_SIZE);

            uint64_t a   = GET_U64<bswap>(ptr,  0);
            uint64_t b   = GET_U64<bswap>(ptr,  8);
            uint64_t c   = GET_U64<bswap>(ptr, 16);
            uint64_t d   = GET_U64<bswap>(ptr, 24);
            uint64_t e   = GET_U64<bswap>(ptr, 32);
            uint64_t f   = GET_U64<bswap>(ptr, 40);
            uint64_t g   = GET_U64<bswap>(ptr, 48);
            uint64_t h   = GET_U64<bswap>(ptr, 56);

            uint64_t cs0 = Mix(a ^ kHashSalt[1], b ^ current_state);
            uint64_t cs1 = Mix(c ^ kHashSalt[2], d ^ current_state);
            current_state = (cs0 ^ cs1);

            uint64_t ds0 = Mix(e ^ kHashSalt[3], f ^ duplicated_state);
            uint64_t ds1 = Mix(g ^ kHashSalt[4], h ^ duplicated_state);
            duplicated_state = (ds0 ^ ds1);

            ptr += 64;
            len -= 64;
        } while (len > 64);

        current_state = current_state ^ duplicated_state;
    }

    // We now have a data `ptr` with at most 64 bytes and the current state
    // of the hashing state machine stored in current_state.
    while (len > 16) {
        uint64_t a = GET_U64<bswap>(ptr, 0);
        uint64_t b = GET_U64<bswap>(ptr, 8);

        current_state = Mix(a ^ kHashSalt[1], b ^ current_state);

        ptr += 16;
        len -= 16;
    }

    // We now have a data `ptr` with at most 16 bytes.
    uint64_t a = 0;
    uint64_t b = 0;
    if (len > 8) {
        // When we have at least 9 and at most 16 bytes, set A to the first 64
        // bits of the input and B to the last 64 bits of the input. Yes, they will
        // overlap in the middle if we are working with less than the full 16
        // bytes.
        a = GET_U64<bswap>(ptr, 0);
        b = GET_U64<bswap>(ptr, len - 8);
    } else if (len > 3) {
        // If we have at least 4 and at most 8 bytes, set A to the first 32
        // bits and B to the last 32 bits.
        a = GET_U32<bswap>(ptr, 0);
        b = GET_U32<bswap>(ptr, len - 4);
    } else if (len > 0) {
        // If we have at least 1 and at most 3 bytes, read all of the provided
        // bits into A, with some adjustments.
        a = static_cast<uint64_t>((ptr[0] << 16) | (ptr[len >> 1] << 8) | ptr[len - 1]);
        b = 0;
    } else {
        a = 0;
        b = 0;
    }

    uint64_t w = Mix(a ^ kHashSalt[1], b ^ current_state);
    uint64_t z = kHashSalt[1] ^ starting_length;
    uint64_t h = Mix(w, z);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------

template <bool bswap>
static std::pair<uint64_t, uint64_t> Read9To16( const uint8_t * p, const size_t len ) {
    uint64_t low_mem  = GET_U64<bswap>(p,           0);
    uint64_t high_mem = GET_U64<bswap>(p + len - 8, 0);
    uint64_t most_significant, least_significant;

    if (isLE() ^ bswap) {
        most_significant  = high_mem;
        least_significant = low_mem;
    } else {
        most_significant  = low_mem;
        least_significant = high_mem;
    }

    return {least_significant, most_significant};
}

template <bool bswap>
static uint64_t Read4To8( const uint8_t * p, size_t len ) {
    uint32_t low_mem  = GET_U32<bswap>(p,           0);
    uint32_t high_mem = GET_U32<bswap>(p + len - 4, 0);
    uint32_t most_significant, least_significant;

    if (isLE() ^ bswap) {
        most_significant  = high_mem;
        least_significant = low_mem;
    } else {
        most_significant  = low_mem;
        least_significant = high_mem;
    }

    return (static_cast<uint64_t>(most_significant) << (len - 4) * 8) | least_significant;
}

template <bool bswap>
static uint32_t Read1To3( const uint8_t * p, size_t len ) {
    // The trick used by this implementation is to avoid branches if possible.
    uint8_t mem0 = p[0];
    uint8_t mem1 = p[len / 2];
    uint8_t mem2 = p[len - 1];
    uint8_t significant0, significant1, significant2;

    if (isLE() ^ bswap) {
        significant2 = mem2;
        significant1 = mem1;
        significant0 = mem0;
    } else {
        significant2 = mem0;
        significant1 = len == 2 ? mem0 : mem1;
        significant0 = mem2;
    }

    return static_cast<uint32_t>(significant0                      |
                                 (significant1 << (len / 2 * 8))   |
                                 (significant2 << ((len - 1) * 8)));
}

//------------------------------------------------------------
// 32-bit version of AbslHashValue() for a string

template <bool bswap>
static inline uint64_t CombineContiguousImpl32( uint64_t state, const uint8_t * first, const size_t len );

template <bool bswap>
static uint32_t CityHash32( const uint8_t * s, const size_t len ) {
    return CityHash::CityHash32WithSeed<bswap>(s, len, 0);
}

template <bool bswap>
static uint64_t CombineLargeContiguousImpl32( uint64_t state, const uint8_t * first, size_t len ) {
    while (len >= PiecewiseChunkSize()) {
        if (isLE()) {
            state = Mix32(state, CityHash32<false>(first, PiecewiseChunkSize()));
        } else {
            state = Mix32(state, CityHash32<true>(first, PiecewiseChunkSize()));
        }
        len -= PiecewiseChunkSize();
        first += PiecewiseChunkSize();
    }
    // Handle the remainder.
    return CombineContiguousImpl32<bswap>(state, first, len);
}

template <bool bswap>
static inline uint64_t CombineContiguousImpl32( uint64_t state, const uint8_t * first, const size_t len ) {
    // For large values we use CityHash, for small ones we just use a
    // multiplicative hash.
    uint64_t v;
    if (len > 8) {
        if (unlikely(len > PiecewiseChunkSize())) {
            return CombineLargeContiguousImpl32<bswap>(state, first, len);
        }
        if (isLE()) {
            v = CityHash32<false>(first, len);
        } else {
            v = CityHash32<true>(first, len);
        }
    } else if (len >= 4) {
        v = Read4To8<bswap>(first, len);
    } else if (len > 0) {
        v = Read1To3<bswap>(first, len);
    } else {
        // Empty ranges have no effect.
        return state;
    }
    return Mix32(state, v);
}

template <bool bswap>
static void ABSL32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = Mix32(CombineContiguousImpl32<bswap>(seed, (const uint8_t *)in, len), len);
    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
// 64-bit version of AbslHashValue() for a string

template <bool bswap, bool use_llh>
static inline uint64_t CombineContiguousImpl64( uint64_t state, uint64_t seed, const uint8_t * first, size_t len );

template <bool bswap>
static uint64_t CityHash64( const uint8_t * s, const size_t len ) {
    return CityHash::CityHash64<bswap>(s, len);
}

template <bool bswap, bool use_llh>
static inline uint64_t Hash64( uint64_t seed, const uint8_t * first, size_t len ) {
    if (use_llh) {
        uint64_t h;
        LowLevelHash<bswap>(first, len, seed, &h);
        h = COND_BSWAP(h, bswap);
        return h;
    } else {
        if (isLE()) {
            return CityHash64<false>(first, len);
        } else {
            return CityHash64<true>(first, len);
        }
    }
}

template <bool bswap, bool use_llh>
static inline uint64_t CombineLargeContiguousImpl64( uint64_t state, uint64_t seed, const uint8_t * first, size_t len ) {
    while (len >= PiecewiseChunkSize()) {
        state = Mix64(state, Hash64<bswap, use_llh>(seed, first, PiecewiseChunkSize()));
        len -= PiecewiseChunkSize();
        first += PiecewiseChunkSize();
    }
    // Handle the remainder.
    return CombineContiguousImpl64<bswap, use_llh>(state, seed, first, len);
}

template <bool bswap, bool use_llh>
static inline uint64_t CombineContiguousImpl64( uint64_t state, uint64_t seed, const uint8_t * first, size_t len ) {
    // For large values we use LowLevelHash or CityHash depending on the platform,
    // for small ones we just use a multiplicative hash.
    uint64_t v;
    if (len > 16) {
        if (unlikely(len > PiecewiseChunkSize())) {
            return CombineLargeContiguousImpl64<bswap, use_llh>(state, seed, first, len);
        }
        v = Hash64<bswap, use_llh>(seed, first, len);
    } else if (len > 8) {
        // This hash function was constructed by the ML-driven algorithm discovery
        // using reinforcement learning. We fed the agent lots of inputs from
        // microbenchmarks, SMHasher, low hamming distance from generated inputs and
        // picked up the one that was good on micro and macrobenchmarks.
        auto p = Read9To16<bswap>(first, len);
        uint64_t lo = p.first;
        uint64_t hi = p.second;
        // Rotation by 53 was found to be most often useful when discovering these
        // hashing algorithms with ML techniques.
        lo = ROTR64(lo, 53);
        state += UINT64_C(0x9ddfea08eb382d69);
        lo    += state;
        state ^= hi;
        uint64_t rlo, rhi;
        MathMult::mult64_128(rlo, rhi, state, lo);
        uint64_t h = rlo ^ rhi;
        return h;
    } else if (len >= 4) {
        v = Read4To8<bswap>(first, len);
    } else if (len > 0) {
        v = Read1To3<bswap>(first, len);
    } else {
        // Empty ranges have no effect.
        return state;
    }
    return Mix64(state, v);
}

template <bool bswap, bool use_llh>
static void ABSL64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = Mix64(CombineContiguousImpl64<bswap, use_llh>(seed, seed, (const uint8_t *)in, len), len);
    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(AbseilHashes,
   $.src_url    = "https://github.com/abseil/abseil-cpp",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

// Also all-zero seed?
// Also golden seed?

REGISTER_HASH(Abseil_lowlevel,
   $.desc            = "Abseil internal low-level hash",
   $.hash_flags      =
         0,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 64,
   $.verification_LE = 0xD3CF7B11,
   $.verification_BE = 0x5515DFEE,
   $.hashfn_native   = LowLevelHash<false>,
   $.hashfn_bswap    = LowLevelHash<true>
 );

REGISTER_HASH(Abseil32,
   $.desc            = "Abseil hash (for 32-bit environments)",
   $.hash_flags      =
         0,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 64,
   $.verification_LE = 0x45D6E7B0,
   $.verification_BE = 0x2C90699F,
   $.hashfn_native   = ABSL32<false>,
   $.hashfn_bswap    = ABSL32<true>
 );

REGISTER_HASH(Abseil64_llh,
   $.desc            = "Abseil hash (for 64-bit environments, with 128-bit intrinsics)",
   $.hash_flags      =
         0,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 64,
   $.verification_LE = 0x301C73CB,
   $.verification_BE = 0x38206C0E,
   $.hashfn_native   = ABSL64<false, true>,
   $.hashfn_bswap    = ABSL64<true, true>
 );

REGISTER_HASH(Abseil64_city,
   $.desc            = "Abseil hash (for 64-bit environments, without 128-bit intrinsics)",
   $.hash_flags      =
         0,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 64,
   $.verification_LE = 0xA80E05DA,
   $.verification_BE = 0xCA7890B6,
   $.hashfn_native   = ABSL64<false, false>,
   $.hashfn_bswap    = ABSL64<true, false>
 );
