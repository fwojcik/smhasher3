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
   $.hashfn_bswap    = LowLevelHash<true>,
   $.badseeddesc     = "Many bad seeds, unsure of details; see abseil.cpp for examples",
   $.badseeds        = {
            0x030de468, 0x197ba2fe, 0x2c0e2fc1, 0x394c9e50, 0x3fb038b6, 0x458a6ffe, 0x58b25934, 0x5b48b660,
            0x600df26a, 0x6af5461f, 0x7143e148, 0x7470957e, 0x7902d968, 0x7d1253f7, 0x7f6d84c0, 0x810e65f4,
            0x81b968d0, 0x90b8c47f, 0xac31277c, 0xc52498f6, 0xee281ac8, 0xf70bb998, 0xfacc778f,
            0xffffffff026ed87f, 0xffffffff03aa7ce8, 0xffffffff03d08483, 0xffffffff0473948f,
            0xffffffff04f687ab, 0xffffffff059e7564, 0xffffffff060c9467, 0xffffffff0723a2a4,
            0xffffffff072f4778, 0xffffffff092705f8, 0xffffffff092f0f0b, 0xffffffff0a1bb8ad,
            0xffffffff0b3924e6, 0xffffffff0b3f0b1a, 0xffffffff0d332c11, 0xffffffff10a707fb,
            0xffffffff14ac159e, 0xffffffff14ec8c48, 0xffffffff1730841c, 0xffffffff178e3498,
            0xffffffff19392113, 0xffffffff199ee464, 0xffffffff1cb0adef, 0xffffffff1e744ae7,
            0xffffffff219f85e0, 0xffffffff233283da, 0xffffffff29f4951a, 0xffffffff30b37e64,
            0xffffffff3328d8a6, 0xffffffff392be46c, 0xffffffff392fd7a8, 0xffffffff3986ccab,
            0xffffffff3a378408, 0xffffffff3a5360e0, 0xffffffff3a591046, 0xffffffff3bb9b728,
            0xffffffff422e2550, 0xffffffff45cd8d7c, 0xffffffff490a37a3, 0xffffffff490dd988,
            0xffffffff4a20e2e4, 0xffffffff4e0b90b4, 0xffffffff500b965a, 0xffffffff512c0a54,
            0xffffffff570b6465, 0xffffffff5b0c59ee, 0xffffffff5c9c8a98, 0xffffffff5dd70508,
            0xffffffff5e083bb7, 0xffffffff5e128593, 0xffffffff684c74f4, 0xffffffff6860ad8d,
            0xffffffff692e6346, 0xffffffff6a09647c, 0xffffffff71ddddbe, 0xffffffff7863cf10,
            0xffffffff788eb7b9, 0xffffffff792c2610, 0xffffffff7933aef2, 0xffffffff793d5811,
            0xffffffff79677fd7, 0xffffffff79f58a54, 0xffffffff7a2c0d5e, 0xffffffff7b05b406,
            0xffffffff7b331847, 0xffffffff7b33199a, 0xffffffff7bc38564, 0xffffffff7c38ce5d,
            0xffffffff7d2ee53e, 0xffffffff7e490011, 0xffffffff804b2f44, 0xffffffff80cb61f0,
            0xffffffff8124c663, 0xffffffff81359a16, 0xffffffff816c848b, 0xffffffff8205b456,
            0xffffffff83648b1c, 0xffffffff836d9a68, 0xffffffff83c28f28, 0xffffffff83d94d2b,
            0xffffffff84af1064, 0xffffffff84b124a4, 0xffffffff84b48c7e, 0xffffffff84ef66f8,
            0xffffffff85b82834, 0xffffffff872498d8, 0xffffffff8725646a, 0xffffffff873087d0,
            0xffffffff87b47385, 0xffffffff8b240418, 0xffffffff8ba81338, 0xffffffff8c482988,
            0xffffffff8d0882e8, 0xffffffff8dedcdd1, 0xffffffff8dfd7398, 0xffffffff8ece9910,
            0xffffffff8f35eb5e, 0xffffffff8ffd9997, 0xffffffff98b451d0, 0xffffffff9e089d68,
            0xffffffffa12a8468, 0xffffffffa52f8445, 0xffffffffa58b1e9d, 0xffffffffa911856a,
            0xffffffffa946aee8, 0xffffffffa9c444e3, 0xffffffffa9ee1be4, 0xffffffffadc0a817,
            0xffffffffb12f9816, 0xffffffffb13044b4, 0xffffffffb32edc3d, 0xffffffffb3b1957c,
            0xffffffffb58ec81e, 0xffffffffb61093ff, 0xffffffffb82b4b1a, 0xffffffffb92f9bf7,
            0xffffffffb9e1d22e, 0xffffffffba3c24be, 0xffffffffbabb97d7, 0xffffffffbc295fcb,
            0xffffffffbc2c0d44, 0xffffffffbde0da40, 0xffffffffbe3bcc45, 0xffffffffc230bbe0,
            0xffffffffc8e8706d, 0xffffffffc9217320, 0xffffffffcb8c648f, 0xffffffffd0308366,
            0xffffffffd1ec5568, 0xffffffffd7fce448, 0xffffffffd8f26c7c, 0xffffffffd9d194eb,
            0xffffffffd9dc5412, 0xffffffffda119874, 0xffffffffda638511, 0xffffffffdcd0cb30,
            0xffffffffdd33864a, 0xffffffffe0aee5f0, 0xffffffffe2357bb2, 0xffffffffe631d37f,
            0xffffffffe665b97b, 0xffffffffe6ad97f6, 0xffffffffe6ed9233, 0xffffffffe73405e6,
            0xffffffffe77e1f48, 0xffffffffe7d8a272, 0xffffffffe8eb4400, 0xffffffffe90c77be,
            0xffffffffe9606ef4, 0xffffffffea4c2848, 0xffffffffeacd4479, 0xffffffffeb3fe607,
            0xffffffffecb81f80, 0xffffffffedcf8430, 0xffffffffef982f09, 0xfffffffff09893e8,
            0xfffffffff0bc87d0, 0xfffffffff0ecf28c, 0xfffffffff1609292, 0xfffffffff1aa7cbc,
            0xfffffffff1da84e8, 0xfffffffff22c9b10, 0xfffffffff5d85c63, 0xfffffffff5f31698,
            0xfffffffff60005e5, 0xfffffffff824026f, 0xfffffffff8fa9ad0, 0xfffffffff90dcc64,
            0xfffffffff934827c, 0xfffffffff9420a3a, 0xfffffffff97ed86b, 0xfffffffffa8676e4,
            0xfffffffffbc82068, 0xfffffffffbf89578, 0xfffffffffd409df7, 0xfffffffffdd83310,
            0xfffffffffdded588, 0xfffffffffddf85e6, 0xfffffffffe349023, 0xfffffffffe7c9734
   }
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
   $.hashfn_bswap    = ABSL32<true>,
   $.badseeds        = { 0xffffffff }
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
   $.hashfn_bswap    = ABSL64<true, true>,
   $.badseeds        = { // For 1-byte keys, if keybyte+seed == UINT64_C(-1), hash is always 0
            0xffffffffffffff00, 0xffffffffffffff01, 0xffffffffffffff02, 0xffffffffffffff03,
            0xffffffffffffff04, 0xffffffffffffff05, 0xffffffffffffff06, 0xffffffffffffff07,
            0xffffffffffffff08, 0xffffffffffffff09, 0xffffffffffffff0a, 0xffffffffffffff0b,
            0xffffffffffffff0c, 0xffffffffffffff0d, 0xffffffffffffff0e, 0xffffffffffffff0f,
            0xffffffffffffff10, 0xffffffffffffff11, 0xffffffffffffff12, 0xffffffffffffff13,
            0xffffffffffffff14, 0xffffffffffffff15, 0xffffffffffffff16, 0xffffffffffffff17,
            0xffffffffffffff18, 0xffffffffffffff19, 0xffffffffffffff1a, 0xffffffffffffff1b,
            0xffffffffffffff1c, 0xffffffffffffff1d, 0xffffffffffffff1e, 0xffffffffffffff1f,
            0xffffffffffffff20, 0xffffffffffffff21, 0xffffffffffffff22, 0xffffffffffffff23,
            0xffffffffffffff24, 0xffffffffffffff25, 0xffffffffffffff26, 0xffffffffffffff27,
            0xffffffffffffff28, 0xffffffffffffff29, 0xffffffffffffff2a, 0xffffffffffffff2b,
            0xffffffffffffff2c, 0xffffffffffffff2d, 0xffffffffffffff2e, 0xffffffffffffff2f,
            0xffffffffffffff30, 0xffffffffffffff31, 0xffffffffffffff32, 0xffffffffffffff33,
            0xffffffffffffff34, 0xffffffffffffff35, 0xffffffffffffff36, 0xffffffffffffff37,
            0xffffffffffffff38, 0xffffffffffffff39, 0xffffffffffffff3a, 0xffffffffffffff3b,
            0xffffffffffffff3c, 0xffffffffffffff3d, 0xffffffffffffff3e, 0xffffffffffffff3f,
            0xffffffffffffff40, 0xffffffffffffff41, 0xffffffffffffff42, 0xffffffffffffff43,
            0xffffffffffffff44, 0xffffffffffffff45, 0xffffffffffffff46, 0xffffffffffffff47,
            0xffffffffffffff48, 0xffffffffffffff49, 0xffffffffffffff4a, 0xffffffffffffff4b,
            0xffffffffffffff4c, 0xffffffffffffff4d, 0xffffffffffffff4e, 0xffffffffffffff4f,
            0xffffffffffffff50, 0xffffffffffffff51, 0xffffffffffffff52, 0xffffffffffffff53,
            0xffffffffffffff54, 0xffffffffffffff55, 0xffffffffffffff56, 0xffffffffffffff57,
            0xffffffffffffff58, 0xffffffffffffff59, 0xffffffffffffff5a, 0xffffffffffffff5b,
            0xffffffffffffff5c, 0xffffffffffffff5d, 0xffffffffffffff5e, 0xffffffffffffff5f,
            0xffffffffffffff60, 0xffffffffffffff61, 0xffffffffffffff62, 0xffffffffffffff63,
            0xffffffffffffff64, 0xffffffffffffff65, 0xffffffffffffff66, 0xffffffffffffff67,
            0xffffffffffffff68, 0xffffffffffffff69, 0xffffffffffffff6a, 0xffffffffffffff6b,
            0xffffffffffffff6c, 0xffffffffffffff6d, 0xffffffffffffff6e, 0xffffffffffffff6f,
            0xffffffffffffff70, 0xffffffffffffff71, 0xffffffffffffff72, 0xffffffffffffff73,
            0xffffffffffffff74, 0xffffffffffffff75, 0xffffffffffffff76, 0xffffffffffffff77,
            0xffffffffffffff78, 0xffffffffffffff79, 0xffffffffffffff7a, 0xffffffffffffff7b,
            0xffffffffffffff7c, 0xffffffffffffff7d, 0xffffffffffffff7e, 0xffffffffffffff7f,
            0xffffffffffffff80, 0xffffffffffffff81, 0xffffffffffffff82, 0xffffffffffffff83,
            0xffffffffffffff84, 0xffffffffffffff85, 0xffffffffffffff86, 0xffffffffffffff87,
            0xffffffffffffff88, 0xffffffffffffff89, 0xffffffffffffff8a, 0xffffffffffffff8b,
            0xffffffffffffff8c, 0xffffffffffffff8d, 0xffffffffffffff8e, 0xffffffffffffff8f,
            0xffffffffffffff90, 0xffffffffffffff91, 0xffffffffffffff92, 0xffffffffffffff93,
            0xffffffffffffff94, 0xffffffffffffff95, 0xffffffffffffff96, 0xffffffffffffff97,
            0xffffffffffffff98, 0xffffffffffffff99, 0xffffffffffffff9a, 0xffffffffffffff9b,
            0xffffffffffffff9c, 0xffffffffffffff9d, 0xffffffffffffff9e, 0xffffffffffffff9f,
            0xffffffffffffffa0, 0xffffffffffffffa1, 0xffffffffffffffa2, 0xffffffffffffffa3,
            0xffffffffffffffa4, 0xffffffffffffffa5, 0xffffffffffffffa6, 0xffffffffffffffa7,
            0xffffffffffffffa8, 0xffffffffffffffa9, 0xffffffffffffffaa, 0xffffffffffffffab,
            0xffffffffffffffac, 0xffffffffffffffad, 0xffffffffffffffae, 0xffffffffffffffaf,
            0xffffffffffffffb0, 0xffffffffffffffb1, 0xffffffffffffffb2, 0xffffffffffffffb3,
            0xffffffffffffffb4, 0xffffffffffffffb5, 0xffffffffffffffb6, 0xffffffffffffffb7,
            0xffffffffffffffb8, 0xffffffffffffffb9, 0xffffffffffffffba, 0xffffffffffffffbb,
            0xffffffffffffffbc, 0xffffffffffffffbd, 0xffffffffffffffbe, 0xffffffffffffffbf,
            0xffffffffffffffc0, 0xffffffffffffffc1, 0xffffffffffffffc2, 0xffffffffffffffc3,
            0xffffffffffffffc4, 0xffffffffffffffc5, 0xffffffffffffffc6, 0xffffffffffffffc7,
            0xffffffffffffffc8, 0xffffffffffffffc9, 0xffffffffffffffca, 0xffffffffffffffcb,
            0xffffffffffffffcc, 0xffffffffffffffcd, 0xffffffffffffffce, 0xffffffffffffffcf,
            0xffffffffffffffd0, 0xffffffffffffffd1, 0xffffffffffffffd2, 0xffffffffffffffd3,
            0xffffffffffffffd4, 0xffffffffffffffd5, 0xffffffffffffffd6, 0xffffffffffffffd7,
            0xffffffffffffffd8, 0xffffffffffffffd9, 0xffffffffffffffda, 0xffffffffffffffdb,
            0xffffffffffffffdc, 0xffffffffffffffdd, 0xffffffffffffffde, 0xffffffffffffffdf,
            0xffffffffffffffe0, 0xffffffffffffffe1, 0xffffffffffffffe2, 0xffffffffffffffe3,
            0xffffffffffffffe4, 0xffffffffffffffe5, 0xffffffffffffffe6, 0xffffffffffffffe7,
            0xffffffffffffffe8, 0xffffffffffffffe9, 0xffffffffffffffea, 0xffffffffffffffeb,
            0xffffffffffffffec, 0xffffffffffffffed, 0xffffffffffffffee, 0xffffffffffffffef,
            0xfffffffffffffff0, 0xfffffffffffffff1, 0xfffffffffffffff2, 0xfffffffffffffff3,
            0xfffffffffffffff4, 0xfffffffffffffff5, 0xfffffffffffffff6, 0xfffffffffffffff7,
            0xfffffffffffffff8, 0xfffffffffffffff9, 0xfffffffffffffffa, 0xfffffffffffffffb,
            0xfffffffffffffffc, 0xfffffffffffffffd, 0xfffffffffffffffe, 0xffffffffffffffff
   }
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
   $.hashfn_bswap    = ABSL64<true, false>,
   $.badseeds        = { // For 1-byte keys, if keybyte+seed == UINT64_C(-1), hash is always 0
            0xffffffffffffff00, 0xffffffffffffff01, 0xffffffffffffff02, 0xffffffffffffff03,
            0xffffffffffffff04, 0xffffffffffffff05, 0xffffffffffffff06, 0xffffffffffffff07,
            0xffffffffffffff08, 0xffffffffffffff09, 0xffffffffffffff0a, 0xffffffffffffff0b,
            0xffffffffffffff0c, 0xffffffffffffff0d, 0xffffffffffffff0e, 0xffffffffffffff0f,
            0xffffffffffffff10, 0xffffffffffffff11, 0xffffffffffffff12, 0xffffffffffffff13,
            0xffffffffffffff14, 0xffffffffffffff15, 0xffffffffffffff16, 0xffffffffffffff17,
            0xffffffffffffff18, 0xffffffffffffff19, 0xffffffffffffff1a, 0xffffffffffffff1b,
            0xffffffffffffff1c, 0xffffffffffffff1d, 0xffffffffffffff1e, 0xffffffffffffff1f,
            0xffffffffffffff20, 0xffffffffffffff21, 0xffffffffffffff22, 0xffffffffffffff23,
            0xffffffffffffff24, 0xffffffffffffff25, 0xffffffffffffff26, 0xffffffffffffff27,
            0xffffffffffffff28, 0xffffffffffffff29, 0xffffffffffffff2a, 0xffffffffffffff2b,
            0xffffffffffffff2c, 0xffffffffffffff2d, 0xffffffffffffff2e, 0xffffffffffffff2f,
            0xffffffffffffff30, 0xffffffffffffff31, 0xffffffffffffff32, 0xffffffffffffff33,
            0xffffffffffffff34, 0xffffffffffffff35, 0xffffffffffffff36, 0xffffffffffffff37,
            0xffffffffffffff38, 0xffffffffffffff39, 0xffffffffffffff3a, 0xffffffffffffff3b,
            0xffffffffffffff3c, 0xffffffffffffff3d, 0xffffffffffffff3e, 0xffffffffffffff3f,
            0xffffffffffffff40, 0xffffffffffffff41, 0xffffffffffffff42, 0xffffffffffffff43,
            0xffffffffffffff44, 0xffffffffffffff45, 0xffffffffffffff46, 0xffffffffffffff47,
            0xffffffffffffff48, 0xffffffffffffff49, 0xffffffffffffff4a, 0xffffffffffffff4b,
            0xffffffffffffff4c, 0xffffffffffffff4d, 0xffffffffffffff4e, 0xffffffffffffff4f,
            0xffffffffffffff50, 0xffffffffffffff51, 0xffffffffffffff52, 0xffffffffffffff53,
            0xffffffffffffff54, 0xffffffffffffff55, 0xffffffffffffff56, 0xffffffffffffff57,
            0xffffffffffffff58, 0xffffffffffffff59, 0xffffffffffffff5a, 0xffffffffffffff5b,
            0xffffffffffffff5c, 0xffffffffffffff5d, 0xffffffffffffff5e, 0xffffffffffffff5f,
            0xffffffffffffff60, 0xffffffffffffff61, 0xffffffffffffff62, 0xffffffffffffff63,
            0xffffffffffffff64, 0xffffffffffffff65, 0xffffffffffffff66, 0xffffffffffffff67,
            0xffffffffffffff68, 0xffffffffffffff69, 0xffffffffffffff6a, 0xffffffffffffff6b,
            0xffffffffffffff6c, 0xffffffffffffff6d, 0xffffffffffffff6e, 0xffffffffffffff6f,
            0xffffffffffffff70, 0xffffffffffffff71, 0xffffffffffffff72, 0xffffffffffffff73,
            0xffffffffffffff74, 0xffffffffffffff75, 0xffffffffffffff76, 0xffffffffffffff77,
            0xffffffffffffff78, 0xffffffffffffff79, 0xffffffffffffff7a, 0xffffffffffffff7b,
            0xffffffffffffff7c, 0xffffffffffffff7d, 0xffffffffffffff7e, 0xffffffffffffff7f,
            0xffffffffffffff80, 0xffffffffffffff81, 0xffffffffffffff82, 0xffffffffffffff83,
            0xffffffffffffff84, 0xffffffffffffff85, 0xffffffffffffff86, 0xffffffffffffff87,
            0xffffffffffffff88, 0xffffffffffffff89, 0xffffffffffffff8a, 0xffffffffffffff8b,
            0xffffffffffffff8c, 0xffffffffffffff8d, 0xffffffffffffff8e, 0xffffffffffffff8f,
            0xffffffffffffff90, 0xffffffffffffff91, 0xffffffffffffff92, 0xffffffffffffff93,
            0xffffffffffffff94, 0xffffffffffffff95, 0xffffffffffffff96, 0xffffffffffffff97,
            0xffffffffffffff98, 0xffffffffffffff99, 0xffffffffffffff9a, 0xffffffffffffff9b,
            0xffffffffffffff9c, 0xffffffffffffff9d, 0xffffffffffffff9e, 0xffffffffffffff9f,
            0xffffffffffffffa0, 0xffffffffffffffa1, 0xffffffffffffffa2, 0xffffffffffffffa3,
            0xffffffffffffffa4, 0xffffffffffffffa5, 0xffffffffffffffa6, 0xffffffffffffffa7,
            0xffffffffffffffa8, 0xffffffffffffffa9, 0xffffffffffffffaa, 0xffffffffffffffab,
            0xffffffffffffffac, 0xffffffffffffffad, 0xffffffffffffffae, 0xffffffffffffffaf,
            0xffffffffffffffb0, 0xffffffffffffffb1, 0xffffffffffffffb2, 0xffffffffffffffb3,
            0xffffffffffffffb4, 0xffffffffffffffb5, 0xffffffffffffffb6, 0xffffffffffffffb7,
            0xffffffffffffffb8, 0xffffffffffffffb9, 0xffffffffffffffba, 0xffffffffffffffbb,
            0xffffffffffffffbc, 0xffffffffffffffbd, 0xffffffffffffffbe, 0xffffffffffffffbf,
            0xffffffffffffffc0, 0xffffffffffffffc1, 0xffffffffffffffc2, 0xffffffffffffffc3,
            0xffffffffffffffc4, 0xffffffffffffffc5, 0xffffffffffffffc6, 0xffffffffffffffc7,
            0xffffffffffffffc8, 0xffffffffffffffc9, 0xffffffffffffffca, 0xffffffffffffffcb,
            0xffffffffffffffcc, 0xffffffffffffffcd, 0xffffffffffffffce, 0xffffffffffffffcf,
            0xffffffffffffffd0, 0xffffffffffffffd1, 0xffffffffffffffd2, 0xffffffffffffffd3,
            0xffffffffffffffd4, 0xffffffffffffffd5, 0xffffffffffffffd6, 0xffffffffffffffd7,
            0xffffffffffffffd8, 0xffffffffffffffd9, 0xffffffffffffffda, 0xffffffffffffffdb,
            0xffffffffffffffdc, 0xffffffffffffffdd, 0xffffffffffffffde, 0xffffffffffffffdf,
            0xffffffffffffffe0, 0xffffffffffffffe1, 0xffffffffffffffe2, 0xffffffffffffffe3,
            0xffffffffffffffe4, 0xffffffffffffffe5, 0xffffffffffffffe6, 0xffffffffffffffe7,
            0xffffffffffffffe8, 0xffffffffffffffe9, 0xffffffffffffffea, 0xffffffffffffffeb,
            0xffffffffffffffec, 0xffffffffffffffed, 0xffffffffffffffee, 0xffffffffffffffef,
            0xfffffffffffffff0, 0xfffffffffffffff1, 0xfffffffffffffff2, 0xfffffffffffffff3,
            0xfffffffffffffff4, 0xfffffffffffffff5, 0xfffffffffffffff6, 0xfffffffffffffff7,
            0xfffffffffffffff8, 0xfffffffffffffff9, 0xfffffffffffffffa, 0xfffffffffffffffb,
            0xfffffffffffffffc, 0xfffffffffffffffd, 0xfffffffffffffffe, 0xffffffffffffffff
   }
 );
