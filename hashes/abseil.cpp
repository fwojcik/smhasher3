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
static constexpr uint64_t kStaticRandomData[5] = {
    UINT64_C(0x243f6a8885a308d3), UINT64_C(0x13198a2e03707344),
    UINT64_C(0xa4093822299f31d0), UINT64_C(0x082efa98ec4e6c89),
    UINT64_C(0x452821e638d01377),
};

// The same table, but with byte-swapped items. This will match the
// contents of the real kStaticRandomData[] array on opposite-endian
// platforms, so that we can compute PrecombineLengthMix() for each
// endianness, regardless of native endianness. That is the only place this
// array is used at the byte-level; word-level access never needs this
// version of the table.
static constexpr uint64_t kStaticRandomDataBSWP[5] = {
    UINT64_C(0xd308a385886a3f24), UINT64_C(0x447370032e8a1913),
    UINT64_C(0xd0319f29223809a4), UINT64_C(0x896c4eec98fa2e08),
    UINT64_C(0x7713d038e6212845),
};

static constexpr uint64_t kMul = UINT64_C(0x79d5f9e0de1e8cf5);

//------------------------------------------------------------
// Chunksize for AbslHashValue()

static constexpr size_t PiecewiseChunkSize() { return 1024; }

//------------------------------------------------------------
// Common data reading routines

template <bool bswap>
static std::pair<uint64_t, uint64_t> Read9To16( const uint8_t * p, const size_t len ) {
    uint64_t low_mem  = GET_U64<bswap>(p          , 0);
    uint64_t high_mem = GET_U64<bswap>(p + len - 8, 0);

    return { low_mem, high_mem };
}

template <bool bswap>
static uint64_t Read4To8( const uint8_t * p, size_t len ) {
    uint32_t low_mem  = GET_U32<bswap>(p          , 0);
    uint32_t high_mem = GET_U32<bswap>(p + len - 4, 0);

    return (static_cast<uint64_t>(low_mem) << 32) | high_mem;
}

static uint32_t Read1To3( const uint8_t * p, size_t len ) {
    // The trick used by this implementation is to avoid branches if possible.
    uint32_t mem0 = p[0];
    uint32_t mem1 = p[len / 2];
    uint32_t mem2 = p[len - 1];

    return (mem0 << 16) | mem2 | (mem1 << 8);
}

template <bool bswap>
static uint64_t Read8( const uint8_t * p ) {
    return GET_U64<bswap>(p, 0);
}

//------------------------------------------------------------
// Some common hashing routines

static uint64_t Mix( uint64_t v0, uint64_t v1 ) {
    uint64_t rlo, rhi;

    MathMult::mult64_128(rlo, rhi, v0, v1);
    return rlo ^ rhi;
}

static FORCE_INLINE uint64_t CombineRawImpl( uint64_t state, uint64_t value ) {
    return Mix(state ^ value, kMul);
}

template <bool bswap>
static inline uint64_t PrecombineLengthMix( uint64_t state, size_t len ) {
    assume(len + sizeof(uint64_t) <= sizeof(kStaticRandomData));
    uint64_t data;

    if (isLE()) {
        data = GET_U64<bswap>((const uint8_t *)(&kStaticRandomData[0]), len);
    } else {
        data = GET_U64<bswap>((const uint8_t *)(&kStaticRandomDataBSWP[0]), len);
    }
    return state ^ data;
}

template <bool bswap>
static FORCE_INLINE uint64_t CombineSmallContiguousImpl( uint64_t state, const uint8_t * first, size_t len ) {
    uint64_t v;

    assume(len <= 8);
    if (len >= 4) {
        v = Read4To8<bswap>(first, len);
    } else if (len > 0) {
        v = Read1To3(first, len);
    } else {
        // Empty string must modify the state.
        v = 0x57;
    }
    return CombineRawImpl(state, v);
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
static FORCE_INLINE uint64_t HashBlockOn32Bit( uint64_t state, const uint8_t * data, size_t len ) {
    // TODO(b/417141985): expose and use CityHash32WithSeed.
    // Note: we can't use PrecombineLengthMix here because len can be up to 1024.
    return CombineRawImpl(state + len, CityHash32<bswap>(data, len));
}

template <bool bswap>
static NEVER_INLINE uint64_t SplitAndCombineOn32Bit( uint64_t state, const uint8_t * first, size_t len ) {
    while (len >= PiecewiseChunkSize()) {
        state  = HashBlockOn32Bit<bswap>(state, first, PiecewiseChunkSize());
        len   -= PiecewiseChunkSize();
        first += PiecewiseChunkSize();
    }
    // Do not call CombineContiguousImpl for empty range since it is
    // modifying state.
    if (len == 0) {
        return state;
    }
    // Handle the remainder.
    return CombineContiguousImpl32<bswap>(state, first, len);
}

template <bool bswap>
static uint64_t CombineLargeContiguousImpl32( uint64_t state, const uint8_t * first, size_t len ) {
    assume(len > 8);

    if (likely(len <= PiecewiseChunkSize())) {
        return HashBlockOn32Bit<bswap>(state, first, len);
    }
    return SplitAndCombineOn32Bit<bswap>(state, first, len);
}

template <bool bswap>
static inline uint64_t CombineContiguousImpl32( uint64_t state, const uint8_t * first, const size_t len ) {
    // For large values we use CityHash, for small ones we use custom low
    // latency hash.
    if (len <= 8) {
        return CombineSmallContiguousImpl<bswap>(PrecombineLengthMix<bswap>(state, len), first, len);
    }
    return CombineLargeContiguousImpl32<bswap>(state, first, len);
}

template <bool bswap>
static void ABSL32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = CombineContiguousImpl32<bswap>(seed, (const uint8_t *)in, len);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
// 64-bit version of AbslHashValue() for a string

template <bool bswap, bool use_llh>
static inline uint64_t CombineContiguousImpl64( uint64_t state, const uint8_t * first, const size_t len );

template <bool bswap>
static uint64_t CityHash64( uint64_t state, const uint8_t * s, const size_t len ) {
#if 0
    if (isLE()) {
        return CityHash::CityHash64WithSeed<false>(s, len, state);
    } else {
        return CityHash::CityHash64WithSeed<true>(s, len, state);
    }
#else
    return CityHash::CityHash64WithSeed<bswap>(s, len, state);
#endif
}

template <bool bswap>
static uint64_t Mix32Bytes( uint64_t current_state, const uint8_t * ptr ) {
    uint64_t a   = Read8<bswap>(ptr     );
    uint64_t b   = Read8<bswap>(ptr +  8);
    uint64_t c   = Read8<bswap>(ptr + 16);
    uint64_t d   = Read8<bswap>(ptr + 24);

    uint64_t cs0 = Mix(a ^ kStaticRandomData[1], b ^ current_state);
    uint64_t cs1 = Mix(c ^ kStaticRandomData[2], d ^ current_state);

    return cs0 ^ cs1;
}

template <bool bswap>
static uint64_t LowLevelHashLenGt32( uint64_t seed, const uint8_t * ptr, size_t len ) {
    assume(len > 32);
    uint64_t        current_state = seed ^ kStaticRandomData[0] ^ len;
    const uint8_t * last_32_ptr   = ptr + len - 32;

    if (len > 64) {
        // If we have more than 64 bytes, we're going to handle chunks of
        // 64 bytes at a time. We're going to build up four separate hash
        // states which we will then hash together. This avoids short
        // dependency chains.
        uint64_t duplicated_state0 = current_state;
        uint64_t duplicated_state1 = current_state;
        uint64_t duplicated_state2 = current_state;

        do {
            prefetch(ptr + 5 * ABSL_CACHELINE_SIZE);

            uint64_t a = Read8<bswap>(ptr     );
            uint64_t b = Read8<bswap>(ptr +  8);
            uint64_t c = Read8<bswap>(ptr + 16);
            uint64_t d = Read8<bswap>(ptr + 24);
            uint64_t e = Read8<bswap>(ptr + 32);
            uint64_t f = Read8<bswap>(ptr + 40);
            uint64_t g = Read8<bswap>(ptr + 48);
            uint64_t h = Read8<bswap>(ptr + 56);

            current_state     = Mix(a ^ kStaticRandomData[1], b ^ current_state    );
            duplicated_state0 = Mix(c ^ kStaticRandomData[2], d ^ duplicated_state0);
            duplicated_state1 = Mix(e ^ kStaticRandomData[3], f ^ duplicated_state1);
            duplicated_state2 = Mix(g ^ kStaticRandomData[4], h ^ duplicated_state2);

            ptr += 64;
            len -= 64;
        } while (len > 64);

        current_state = (current_state ^ duplicated_state0) ^ (duplicated_state1 + duplicated_state2);
    }

    // We now have a data `ptr` with at most 64 bytes and the current state
    // of the hashing state machine stored in current_state.
    if (len > 32) {
        current_state = Mix32Bytes<bswap>(current_state, ptr);
    }

    // We now have a data `ptr` with at most 32 bytes and the current state
    // of the hashing state machine stored in current_state. But we can
    // safely read from `ptr + len - 32`.
    return Mix32Bytes<bswap>(current_state, last_32_ptr);
}

template <bool bswap, bool use_llh>
static FORCE_INLINE uint64_t HashBlockOn64Bit( uint64_t state, const uint8_t * data, size_t len ) {
    if (use_llh) {
        return LowLevelHashLenGt32<bswap>(state, data, len);
    } else {
        return CityHash64<bswap>(state, data, len);
    }
}

template <bool bswap, bool use_llh>
static NEVER_INLINE uint64_t SplitAndCombineOn64Bit( uint64_t state, const uint8_t * first, size_t len ) {
    while (len >= PiecewiseChunkSize()) {
        state  = HashBlockOn64Bit<bswap, use_llh>(state, first, PiecewiseChunkSize());
        len   -= PiecewiseChunkSize();
        first += PiecewiseChunkSize();
    }
    // Do not call CombineContiguousImpl for empty range since it is
    // modifying state.
    if (len == 0) {
        return state;
    }
    // Handle the remainder.
    return CombineContiguousImpl64<bswap, use_llh>(state, first, len);
}

template <bool bswap, bool use_llh>
static uint64_t CombineLargeContiguousImpl64( uint64_t state, const uint8_t * first, size_t len ) {
    assume(len > 32);

    if (likely(len <= PiecewiseChunkSize())) {
        return HashBlockOn64Bit<bswap, use_llh>(state, first, len);
    }
    return SplitAndCombineOn64Bit<bswap, use_llh>(state, first, len);
}

template <bool bswap>
static FORCE_INLINE uint64_t CombineContiguousImpl17to32( uint64_t state, const uint8_t * first, size_t len ) {
    assume(len >= 17);
    assume(len <= 32);
    // Do two mixes of overlapping 16-byte ranges in parallel to minimize
    // latency.
    const uint8_t * tail = first + (len - 16);
    const uint64_t  m0   = Mix(Read8<bswap>(first) ^ kStaticRandomData[1], Read8<bswap>(first + 8) ^ state);
    const uint64_t  m1   = Mix(Read8<bswap>(tail)  ^ kStaticRandomData[3], Read8<bswap>(tail  + 8) ^ state);
    return m0 ^ m1;
}

template <bool bswap>
static FORCE_INLINE uint64_t CombineContiguousImpl9to16( uint64_t state, const uint8_t * first, size_t len ) {
    assume(len >= 9);
    assume(len <= 16);
    // Note: any time one half of the mix function becomes zero it will
    // fail to incorporate any bits from the other half. However, there is
    // exactly 1 in 2^64 values for each side that achieve this, and only
    // when the size is exactly 16 -- for smaller sizes there is an
    // overlapping byte that makes this impossible unless the seed is
    // *also* incredibly unlucky.
    auto p = Read9To16<bswap>(first, len);
    return Mix(state ^ p.first, kMul ^ p.second);
}

template <bool bswap, bool use_llh>
static inline uint64_t CombineContiguousImpl64( uint64_t state, const uint8_t * first, const size_t len ) {
    // For large values we use LowLevelHash or CityHash depending on the platform,
    // for small ones we use custom low latency hash.
    if (len <= 8) {
        return CombineSmallContiguousImpl<bswap>(PrecombineLengthMix<bswap>(state, len), first, len);
    }
    if (len <= 16) {
        return CombineContiguousImpl9to16<bswap>(PrecombineLengthMix<bswap>(state, len), first, len);
    }
    if (len <= 32) {
        return CombineContiguousImpl17to32<bswap>(PrecombineLengthMix<bswap>(state, len), first, len);
    }
    // We must not mix length into the state here because calling
    // CombineContiguousImpl twice with PiecewiseChunkSize() must be equivalent
    // to calling CombineLargeContiguousImpl once with 2 * PiecewiseChunkSize().
    return CombineLargeContiguousImpl64<bswap, use_llh>(state, first, len);
}

template <bool bswap, bool use_llh>
static void ABSL64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = CombineContiguousImpl64<bswap, use_llh>(seed, (const uint8_t *)in, len);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(AbseilHashes,
   $.src_url    = "https://github.com/abseil/abseil-cpp",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(Abseil32,
   $.desc            = "Abseil hash (for 32-bit environments)",
   $.hash_flags      =
         0,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_MULTIPLY_64_128 |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 64,
   $.verification_LE = 0x9C56A962,
   $.verification_BE = 0x4CEEA989,
   $.hashfn_native   = ABSL32<false>,
   $.hashfn_bswap    = ABSL32<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = {
            0x04dff984, 0x07e179cd, 0x0d61dc56, 0x0df1d3ab, 0x1061b386, 0x12de1c38, 0x13e458fd, 0x1693edc5,
            0x1bcf794d, 0x20b9a223, 0x22360df3, 0x23209dca, 0x240d3c4b, 0x2a8cf2cc, 0x2babe4dd, 0x2c60fd68,
            0x3907d5be, 0x396ff30a, 0x3b3c0dc4, 0x3c42ab0a, 0x40d7eff8, 0x4399e7e6, 0x48219ca9, 0x4d9ebb2d,
            0x50aefabc, 0x52f72f78, 0x543c79b7, 0x555391af, 0x56f21429, 0x5b8ee0a8, 0x5bdba59e, 0x5c44ac6e,
            0x611bedd3, 0x621a4848, 0x62801812, 0x63a4c28f, 0x64cb6abb, 0x69e7fb84, 0x6a11bca8, 0x6acc181c,
            0x6ad54355, 0x6bf5f13c, 0x73fedc73, 0x75e368a1, 0x778d979c, 0x782afcf3, 0x78e27d91, 0x7ac6ad8d,
            0x7c8db815, 0x7df34ef5, 0x7eefe1b7, 0x85877240, 0x86132110, 0x8a265023, 0x8b48834a, 0x8b55844c,
            0x8bcb4a33, 0x8c77c65c, 0x8d7a5d3e, 0x8f120ab4, 0x9d5cfe5e, 0xa020397b, 0xa02efbb5, 0xa11aaa15,
            0xa1499aa8, 0xa2f5d350, 0xa308e84d, 0xa37e3914, 0xa43df127, 0xa96bbf90, 0xaad0f8b0, 0xab170515,
            0xabe7bcbb, 0xad738701, 0xad917285, 0xaddfd3ec, 0xaec53194, 0xb391fd3b, 0xb6df3830, 0xb71709e2,
            0xb8a95cee, 0xb902f1ec, 0xbca4a607, 0xbce16238, 0xc0670d36, 0xc5cbffb6, 0xc8e3ef4a, 0xc9fd8bee,
            0xcc6b6568, 0xce087006, 0xcf39d40e, 0xd1fd2d50, 0xd35e2d85, 0xd63b3d68, 0xdec094e2, 0xdfd16106,
            0xe3dda8b9, 0xed8c7854, 0xeef1fc3e, 0xf01a4b27, 0xf0d96d4c, 0xf13c328e, 0xf38a9d99, 0xf4fcb39f,
            0xf7f085a3, 0xfa262aa1, 0xfb4173b6, 0xfe5586fc,
            0xffffffff01aa7903, 0xffffffff0f2692b3, 0xffffffff127387ab, 0xffffffff1c225746,
            0xffffffff202e9ef9, 0xffffffff213f6b1d, 0xffffffff29c4c297, 0xffffffff2ca1d27a,
            0xffffffff2e02d2af, 0xffffffff33949a97, 0xffffffff36027411, 0xffffffff371c10b5,
            0xffffffff3a340049, 0xffffffff431e9dc7, 0xffffffff46fd0e13, 0xffffffff48e8f61d,
            0xffffffff4920c7cf, 0xffffffff4c6e02c4, 0xffffffff513ace6b, 0xffffffff552f074f,
            0xffffffff5c81c6eb, 0xffffffff5cf717b2, 0xffffffff5ee555ea, 0xffffffff5fd1044a,
            0xffffffff62a301a1, 0xffffffff7434b5cc, 0xffffffff74aa7bb3, 0xffffffff74b77cb5,
            0xffffffff81101e48, 0xffffffff820cb10a, 0xffffffff837247ea, 0xffffffff85395272,
            0xffffffff88726863, 0xffffffff940a0ec3, 0xffffffff952abcaa, 0xffffffff95ee4357,
            0xffffffff9618047b, 0xffffffff9c5b3d70, 0xffffffff9d7fe7ed, 0xffffffff9de5b7b7,
            0xffffffff9ee4122c, 0xffffffffa4245a61, 0xffffffffa4711f57, 0xffffffffa90debd6,
            0xffffffffabc38648, 0xffffffffad08d087, 0xffffffffb26144d2, 0xffffffffb7de6356,
            0xffffffffbc661819, 0xffffffffc4c3f23b, 0xffffffffc6900cf5, 0xffffffffd39f0297,
            0xffffffffddc9f20c, 0xffffffffdf465ddc, 0xffffffffe43086b2, 0xffffffffed21e3c7,
            0xfffffffff29e23a9, 0xfffffffffb20067b,
   }
);

REGISTER_HASH(Abseil64_llh,
   $.desc            = "Abseil hash (for 64-bit environments, with 128-bit intrinsics)",
   $.hash_flags      =
         0,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128 |
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 64,
   $.verification_LE = 0x07203CDB,
   $.verification_BE = 0x68AA434B,
   $.hashfn_native   = ABSL64<false, true>,
   $.hashfn_bswap    = ABSL64<true, true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = {
            0x0340676a, 0x04dff984, 0x04ffe39d, 0x08677e59, 0x09104b9b, 0x0ad4b645, 0x0d61dc56, 0x0ed0ac11,
            0x0eee231a, 0x12de1c38, 0x17d1c332, 0x19193e5d, 0x1bcf794d, 0x1ce4e11d, 0x1d507e3c, 0x1ebfbb5f,
            0x1f7f88fa, 0x203cb978, 0x20b9a223, 0x22360df3, 0x23327a07, 0x25fb45b7, 0x2a96e741, 0x2c60fd68,
            0x2e158318, 0x3050bec1, 0x37d8a4c9, 0x396ff30a, 0x3ac0c0bf, 0x3b3c0dc4, 0x3ca01d05, 0x3d11d0f4,
            0x3fd5e275, 0x412f2f09, 0x4296a911, 0x4399e7e6, 0x45107895, 0x48219ca9, 0x4869437a, 0x49566ec3,
            0x4996a255, 0x4d9ebb2d, 0x51ed8ac9, 0x52f72f78, 0x543c79b7, 0x56f21429, 0x585223d9, 0x5a7c5704,
            0x5b8ee0a8, 0x5bdba59e, 0x5dd8beaf, 0x5eecf749, 0x5ff35335, 0x5ff4a656, 0x611bedd3, 0x616c5243,
            0x621a4848, 0x62801812, 0x63a4c28f, 0x6942a715, 0x69e7fb84, 0x6a11bca8, 0x6ad54355, 0x6bf5f13c,
            0x6caa4239, 0x6dd002da, 0x6ed15576, 0x76cb2a15, 0x778d979c, 0x78da2935, 0x7ac6ad8d, 0x7aca5c71,
            0x7b1263f3, 0x7b36a991, 0x7c8db815, 0x7df34ef5, 0x7ed0811d, 0x7eefe1b7, 0x838906e9, 0x84328645,
            0x86ecbb4f, 0x874b1fda, 0x892c91c5, 0x89949eb9, 0x8b48834a, 0x8b55844c, 0x8bcb4a33, 0x8bea89de,
            0x8e114e2a, 0x8e283f29, 0x8f096066, 0x90815695, 0x936861b1, 0x949d38d7, 0x94c03819, 0x96a58cc2,
            0x96e79d16, 0x96e9bf1a, 0x99ea5a63, 0x9a947ac7, 0x9aa0bc21, 0x9b6c7451, 0x9c13e2f1, 0x9c1fee85,
            0x9d5cfe5e, 0x9d67691a, 0x9ed32326, 0xa02efbb5, 0xa0a3f452, 0xa11aaa15, 0xa212a391, 0xa2f83ffa,
            0xa308e84d, 0xa37e3914, 0xa8524503, 0xa8e49721, 0xa9145d59, 0xa91d500e, 0xa9d28d65, 0xaad0a3e3,
            0xaad0f8b0, 0xade5d259, 0xae5622ec, 0xae8d2115, 0xae911f3a, 0xaec53194, 0xaeca63e7, 0xb2ae3215,
            0xb391fd3b, 0xb398323f, 0xb39898c7, 0xb3dc2361, 0xb62fcb31, 0xb65caaa1, 0xb6c3b399, 0xb6df3830,
            0xb71709e2, 0xb793736b, 0xb7e81395, 0xb7fe285f, 0xb810fd66, 0xb902f1ec, 0xb994a8d9, 0xba80a5c3,
            0xbae93511, 0xbce16238, 0xbd35e910, 0xbd383d8a, 0xbd50131b, 0xbd72bc14, 0xbda91a07, 0xbe1182d9,
            0xbe28a15a, 0xbe5bde8a, 0xbe67a10f, 0xbe80b0b9, 0xbec0a2e1, 0xbed6cee6, 0xbee652e1, 0xbee8a319,
            0xbeedb2e5, 0xbfd0aef6, 0xc0f8be51, 0xc5cbffb6, 0xc6009cb7, 0xc6d18f59, 0xc8e3ef4a, 0xc9fd8bee,
            0xcba4a363, 0xcc6b6568, 0xcd184c5d, 0xcee4eaef, 0xd1fd2d50, 0xd35e2d85, 0xd480a74a, 0xd63b3d68,
            0xd6e00f8f, 0xdcd5bae2, 0xdcfac90e, 0xddd02255, 0xde7ba384, 0xdec094e2, 0xded1bbd1, 0xdfb6944a,
            0xdfd16106, 0xe3d44285, 0xe3dda8b9, 0xe9411b16, 0xeb01b359, 0xeb547077, 0xed8c7854, 0xf0d96d4c,
            0xf85166de, 0xfc925739, 0xfdf03c91, 0xfe532907, 0xfe5586fc,
            0xffffffff0169bb15, 0xffffffff01aa7903, 0xffffffff01d1bd45, 0xffffffff0530ff9d,
            0xffffffff05502219, 0xffffffff06cf5b95, 0xffffffff07d087a1, 0xffffffff0a2f7a95,
            0xffffffff0da10d01, 0xffffffff0eb456ad, 0xffffffff0f2692b3, 0xffffffff12531b12,
            0xffffffff127387ab, 0xffffffff16663b1a, 0xffffffff18389717, 0xffffffff193df3b4,
            0xffffffff1a28151c, 0xffffffff1c225746, 0xffffffff1d2c89cc, 0xffffffff1d83b3a1,
            0xffffffff1d8cd0ad, 0xffffffff1ea9ad29, 0xffffffff1ec0ae8e, 0xffffffff1f256f7c,
            0xffffffff202e9ef9, 0xffffffff2030701f, 0xffffffff213f6b1d, 0xffffffff21dc8f09,
            0xffffffff23509c89, 0xffffffff26c1bb19, 0xffffffff27e82121, 0xffffffff297d5c83,
            0xffffffff29c4c297, 0xffffffff2beea35d, 0xffffffff2ca1d27a, 0xffffffff2d9ce69f,
            0xffffffff2e02d2af, 0xffffffff2eb0b3e3, 0xffffffff2ef53d77, 0xffffffff3353e1f9,
            0xffffffff33949a97, 0xffffffff33dccd1e, 0xffffffff35533ffd, 0xffffffff36027411,
            0xffffffff371c10b5, 0xffffffff392cdbdb, 0xffffffff3a340049, 0xffffffff3b01637a,
            0xffffffff3b44d2b7, 0xffffffff3ba8ab98, 0xffffffff3cdaa354, 0xffffffff3d07a999,
            0xffffffff3d228d51, 0xffffffff3e48af5a, 0xffffffff3ea8e50a, 0xffffffff3ed005d9,
            0xffffffff3feaeb37, 0xffffffff4131d79d, 0xffffffff41a18402, 0xffffffff42e06619,
            0xffffffff431e9dc7, 0xffffffff46bc9d4d, 0xffffffff46fd0e13, 0xffffffff47082b19,
            0xffffffff48e8f61d, 0xffffffff4920c7cf, 0xffffffff4ae822ba, 0xffffffff4c6e02c4,
            0xffffffff4d9f830d, 0xffffffff4e3ec5d1, 0xffffffff4ea4a31b, 0xffffffff4ea6ad2a,
            0xffffffff4ec0fa9a, 0xffffffff4ed1e26e, 0xffffffff4ed32066, 0xffffffff513ace6b,
            0xffffffff53d8e327, 0xffffffff53ec77ae, 0xffffffff54a6039e, 0xffffffff552f074f,
            0xffffffff55918446, 0xffffffff56afd819, 0xffffffff5c81c6eb, 0xffffffff5cd294df,
            0xffffffff5cf717b2, 0xffffffff5da0bbfd, 0xffffffff5e1ac3c9, 0xffffffff5ec0096f,
            0xffffffff5ecfbd48, 0xffffffff5ee555ea, 0xffffffff5f305bb3, 0xffffffff5fd1044a,
            0xffffffff62a301a1, 0xffffffff6586ff19, 0xffffffff6835b116, 0xffffffff6d055d05,
            0xffffffff6ed52eda, 0xffffffff6ed8fc49, 0xffffffff7434b5cc, 0xffffffff746e0309,
            0xffffffff74aa7bb3, 0xffffffff74b77cb5, 0xffffffff761386eb, 0xffffffff7d143fc1,
            0xffffffff7e58bbbf, 0xffffffff7e60e312, 0xffffffff7eacbd99, 0xffffffff7f67bb32,
            0xffffffff7f6cfdc7, 0xffffffff81101e48, 0xffffffff820cb10a, 0xffffffff837247ea,
            0xffffffff8496e35d, 0xffffffff85395272, 0xffffffff8693bcf7, 0xffffffff86e08fd9,
            0xffffffff88726863, 0xffffffff8ec0538a, 0xffffffff92c5031f, 0xffffffff940a0ec3,
            0xffffffff952abcaa, 0xffffffff95ee4357, 0xffffffff9618047b, 0xffffffff9669bf9f,
            0xffffffff96b0bbd2, 0xffffffff9ad4a2cd, 0xffffffff9c5b3d70, 0xffffffff9d7fe7ed,
            0xffffffff9de5b7b7, 0xffffffff9ee4122c, 0xffffffffa0308dd9, 0xffffffffa12080ce,
            0xffffffffa4245a61, 0xffffffffa4711f57, 0xffffffffa760c391, 0xffffffffa8d1ac22,
            0xffffffffa90debd6, 0xffffffffab797aac, 0xffffffffabc38648, 0xffffffffad08d087,
            0xffffffffad304307, 0xffffffffae57bf76, 0xffffffffaf44a319, 0xffffffffb26144d2,
            0xffffffffb2cefddb, 0xffffffffb2fce2c1, 0xffffffffb33f1749, 0xffffffffb7de6356,
            0xffffffffb890401f, 0xffffffffb8c4a2d9, 0xffffffffb8ee7915, 0xffffffffb9d18460,
            0xffffffffbae6a222, 0xffffffffbc661819, 0xffffffffbc68bd95, 0xffffffffbdc1b743,
            0xffffffffbe20bfa7, 0xffffffffbe40e126, 0xffffffffbe69dce4, 0xffffffffbea8990a,
            0xffffffffbec8a59e, 0xffffffffbef02911, 0xffffffffbfddb5df, 0xffffffffbfe8a304,
            0xffffffffc0afee19, 0xffffffffc116ccfd, 0xffffffffc150bb15, 0xffffffffc1ec1ce7,
            0xffffffffc2abd6b9, 0xffffffffc2eb6d67, 0xffffffffc3e6f301, 0xffffffffc4c3f23b,
            0xffffffffc55f3ee0, 0xffffffffc668b894, 0xffffffffc6900cf5, 0xffffffffc786941a,
            0xffffffffcc6bd584, 0xffffffffccd84f99, 0xffffffffd17e5816, 0xffffffffd21fc8bd,
            0xffffffffd39f0297, 0xffffffffd552061d, 0xffffffffd55bf4f7, 0xffffffffd916c30a,
            0xffffffffda50bf1b, 0xffffffffda50db59, 0xffffffffdbd48954, 0xffffffffdd2e831a,
            0xffffffffdd95c72f, 0xffffffffddc9f20c, 0xffffffffdf465ddc, 0xffffffffe43086b2,
            0xffffffffea284b19, 0xffffffffea511287, 0xffffffffed219889, 0xffffffffed21e3c7,
            0xffffffffefe6fa9e, 0xfffffffff1689795, 0xfffffffff29e23a9, 0xfffffffff45323e6,
            0xfffffffff9f02259, 0xfffffffffb20067b, 0xfffffffffcbf17c5, 0xfffffffffd31fc02,
            0xfffffffffd90df14, 0xfffffffffdd5c535, 0xfffffffffe07a2b7, 0xfffffffffed0511d,
            0xffffffffff50aaac,
   }
);

REGISTER_HASH(Abseil64_city,
   $.desc            = "Abseil hash (for 64-bit environments, without 128-bit intrinsics)",
   $.hash_flags      =
         0,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_MULTIPLY_64_128 |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 64,
   $.verification_LE = 0xBCA82904,
   $.verification_BE = 0x3DE6C260,
   $.hashfn_native   = ABSL64<false, false>,
   $.hashfn_bswap    = ABSL64<true, false>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = {
            0x0340676a, 0x04dff984, 0x04ffe39d, 0x08677e59, 0x09104b9b, 0x0ad4b645, 0x0d61dc56, 0x0ed0ac11,
            0x0eee231a, 0x12de1c38, 0x17d1c332, 0x19193e5d, 0x1bcf794d, 0x1ce4e11d, 0x1d507e3c, 0x1ebfbb5f,
            0x1f7f88fa, 0x203cb978, 0x20b9a223, 0x22360df3, 0x23327a07, 0x25fb45b7, 0x2a96e741, 0x2c60fd68,
            0x2e158318, 0x3050bec1, 0x37d8a4c9, 0x396ff30a, 0x3ac0c0bf, 0x3b3c0dc4, 0x3ca01d05, 0x3d11d0f4,
            0x3fd5e275, 0x412f2f09, 0x4296a911, 0x4399e7e6, 0x45107895, 0x48219ca9, 0x4869437a, 0x49566ec3,
            0x4996a255, 0x4d9ebb2d, 0x51ed8ac9, 0x52f72f78, 0x543c79b7, 0x56f21429, 0x585223d9, 0x5a7c5704,
            0x5b8ee0a8, 0x5bdba59e, 0x5dd8beaf, 0x5eecf749, 0x5ff35335, 0x5ff4a656, 0x611bedd3, 0x616c5243,
            0x621a4848, 0x62801812, 0x63a4c28f, 0x6942a715, 0x69e7fb84, 0x6a11bca8, 0x6ad54355, 0x6bf5f13c,
            0x6caa4239, 0x6dd002da, 0x6ed15576, 0x76cb2a15, 0x778d979c, 0x78da2935, 0x7ac6ad8d, 0x7aca5c71,
            0x7b1263f3, 0x7b36a991, 0x7c8db815, 0x7df34ef5, 0x7ed0811d, 0x7eefe1b7, 0x838906e9, 0x84328645,
            0x86ecbb4f, 0x874b1fda, 0x892c91c5, 0x89949eb9, 0x8b48834a, 0x8b55844c, 0x8bcb4a33, 0x8bea89de,
            0x8e114e2a, 0x8e283f29, 0x8f096066, 0x90815695, 0x936861b1, 0x949d38d7, 0x94c03819, 0x96a58cc2,
            0x96e79d16, 0x96e9bf1a, 0x99ea5a63, 0x9a947ac7, 0x9aa0bc21, 0x9b6c7451, 0x9c13e2f1, 0x9c1fee85,
            0x9d5cfe5e, 0x9d67691a, 0x9ed32326, 0xa02efbb5, 0xa0a3f452, 0xa11aaa15, 0xa212a391, 0xa2f83ffa,
            0xa308e84d, 0xa37e3914, 0xa8524503, 0xa8e49721, 0xa9145d59, 0xa91d500e, 0xa9d28d65, 0xaad0a3e3,
            0xaad0f8b0, 0xade5d259, 0xae5622ec, 0xae8d2115, 0xae911f3a, 0xaec53194, 0xaeca63e7, 0xb2ae3215,
            0xb391fd3b, 0xb398323f, 0xb39898c7, 0xb3dc2361, 0xb62fcb31, 0xb65caaa1, 0xb6c3b399, 0xb6df3830,
            0xb71709e2, 0xb793736b, 0xb7e81395, 0xb7fe285f, 0xb810fd66, 0xb902f1ec, 0xb994a8d9, 0xba80a5c3,
            0xbae93511, 0xbce16238, 0xbd35e910, 0xbd383d8a, 0xbd50131b, 0xbd72bc14, 0xbda91a07, 0xbe1182d9,
            0xbe28a15a, 0xbe5bde8a, 0xbe67a10f, 0xbe80b0b9, 0xbec0a2e1, 0xbed6cee6, 0xbee652e1, 0xbee8a319,
            0xbeedb2e5, 0xbfd0aef6, 0xc0f8be51, 0xc5cbffb6, 0xc6009cb7, 0xc6d18f59, 0xc8e3ef4a, 0xc9fd8bee,
            0xcba4a363, 0xcc6b6568, 0xcd184c5d, 0xcee4eaef, 0xd1fd2d50, 0xd35e2d85, 0xd480a74a, 0xd63b3d68,
            0xd6e00f8f, 0xdcd5bae2, 0xdcfac90e, 0xddd02255, 0xde7ba384, 0xdec094e2, 0xded1bbd1, 0xdfb6944a,
            0xdfd16106, 0xe3d44285, 0xe3dda8b9, 0xe9411b16, 0xeb01b359, 0xeb547077, 0xed8c7854, 0xf0d96d4c,
            0xf85166de, 0xfc925739, 0xfdf03c91, 0xfe532907, 0xfe5586fc,
            0xffffffff0169bb15, 0xffffffff01aa7903, 0xffffffff01d1bd45, 0xffffffff0530ff9d,
            0xffffffff05502219, 0xffffffff06cf5b95, 0xffffffff07d087a1, 0xffffffff0a2f7a95,
            0xffffffff0da10d01, 0xffffffff0eb456ad, 0xffffffff0f2692b3, 0xffffffff12531b12,
            0xffffffff127387ab, 0xffffffff16663b1a, 0xffffffff18389717, 0xffffffff193df3b4,
            0xffffffff1a28151c, 0xffffffff1c225746, 0xffffffff1d2c89cc, 0xffffffff1d83b3a1,
            0xffffffff1d8cd0ad, 0xffffffff1ea9ad29, 0xffffffff1ec0ae8e, 0xffffffff1f256f7c,
            0xffffffff202e9ef9, 0xffffffff2030701f, 0xffffffff213f6b1d, 0xffffffff21dc8f09,
            0xffffffff23509c89, 0xffffffff26c1bb19, 0xffffffff27e82121, 0xffffffff297d5c83,
            0xffffffff29c4c297, 0xffffffff2beea35d, 0xffffffff2ca1d27a, 0xffffffff2d9ce69f,
            0xffffffff2e02d2af, 0xffffffff2eb0b3e3, 0xffffffff2ef53d77, 0xffffffff3353e1f9,
            0xffffffff33949a97, 0xffffffff33dccd1e, 0xffffffff35533ffd, 0xffffffff36027411,
            0xffffffff371c10b5, 0xffffffff392cdbdb, 0xffffffff3a340049, 0xffffffff3b01637a,
            0xffffffff3b44d2b7, 0xffffffff3ba8ab98, 0xffffffff3cdaa354, 0xffffffff3d07a999,
            0xffffffff3d228d51, 0xffffffff3e48af5a, 0xffffffff3ea8e50a, 0xffffffff3ed005d9,
            0xffffffff3feaeb37, 0xffffffff4131d79d, 0xffffffff41a18402, 0xffffffff42e06619,
            0xffffffff431e9dc7, 0xffffffff46bc9d4d, 0xffffffff46fd0e13, 0xffffffff47082b19,
            0xffffffff48e8f61d, 0xffffffff4920c7cf, 0xffffffff4ae822ba, 0xffffffff4c6e02c4,
            0xffffffff4d9f830d, 0xffffffff4e3ec5d1, 0xffffffff4ea4a31b, 0xffffffff4ea6ad2a,
            0xffffffff4ec0fa9a, 0xffffffff4ed1e26e, 0xffffffff4ed32066, 0xffffffff513ace6b,
            0xffffffff53d8e327, 0xffffffff53ec77ae, 0xffffffff54a6039e, 0xffffffff552f074f,
            0xffffffff55918446, 0xffffffff56afd819, 0xffffffff5c81c6eb, 0xffffffff5cd294df,
            0xffffffff5cf717b2, 0xffffffff5da0bbfd, 0xffffffff5e1ac3c9, 0xffffffff5ec0096f,
            0xffffffff5ecfbd48, 0xffffffff5ee555ea, 0xffffffff5f305bb3, 0xffffffff5fd1044a,
            0xffffffff62a301a1, 0xffffffff6586ff19, 0xffffffff6835b116, 0xffffffff6d055d05,
            0xffffffff6ed52eda, 0xffffffff6ed8fc49, 0xffffffff7434b5cc, 0xffffffff746e0309,
            0xffffffff74aa7bb3, 0xffffffff74b77cb5, 0xffffffff761386eb, 0xffffffff7d143fc1,
            0xffffffff7e58bbbf, 0xffffffff7e60e312, 0xffffffff7eacbd99, 0xffffffff7f67bb32,
            0xffffffff7f6cfdc7, 0xffffffff81101e48, 0xffffffff820cb10a, 0xffffffff837247ea,
            0xffffffff8496e35d, 0xffffffff85395272, 0xffffffff8693bcf7, 0xffffffff86e08fd9,
            0xffffffff88726863, 0xffffffff8ec0538a, 0xffffffff92c5031f, 0xffffffff940a0ec3,
            0xffffffff952abcaa, 0xffffffff95ee4357, 0xffffffff9618047b, 0xffffffff9669bf9f,
            0xffffffff96b0bbd2, 0xffffffff9ad4a2cd, 0xffffffff9c5b3d70, 0xffffffff9d7fe7ed,
            0xffffffff9de5b7b7, 0xffffffff9ee4122c, 0xffffffffa0308dd9, 0xffffffffa12080ce,
            0xffffffffa4245a61, 0xffffffffa4711f57, 0xffffffffa760c391, 0xffffffffa8d1ac22,
            0xffffffffa90debd6, 0xffffffffab797aac, 0xffffffffabc38648, 0xffffffffad08d087,
            0xffffffffad304307, 0xffffffffae57bf76, 0xffffffffaf44a319, 0xffffffffb26144d2,
            0xffffffffb2cefddb, 0xffffffffb2fce2c1, 0xffffffffb33f1749, 0xffffffffb7de6356,
            0xffffffffb890401f, 0xffffffffb8c4a2d9, 0xffffffffb8ee7915, 0xffffffffb9d18460,
            0xffffffffbae6a222, 0xffffffffbc661819, 0xffffffffbc68bd95, 0xffffffffbdc1b743,
            0xffffffffbe20bfa7, 0xffffffffbe40e126, 0xffffffffbe69dce4, 0xffffffffbea8990a,
            0xffffffffbec8a59e, 0xffffffffbef02911, 0xffffffffbfddb5df, 0xffffffffbfe8a304,
            0xffffffffc0afee19, 0xffffffffc116ccfd, 0xffffffffc150bb15, 0xffffffffc1ec1ce7,
            0xffffffffc2abd6b9, 0xffffffffc2eb6d67, 0xffffffffc3e6f301, 0xffffffffc4c3f23b,
            0xffffffffc55f3ee0, 0xffffffffc668b894, 0xffffffffc6900cf5, 0xffffffffc786941a,
            0xffffffffcc6bd584, 0xffffffffccd84f99, 0xffffffffd17e5816, 0xffffffffd21fc8bd,
            0xffffffffd39f0297, 0xffffffffd552061d, 0xffffffffd55bf4f7, 0xffffffffd916c30a,
            0xffffffffda50bf1b, 0xffffffffda50db59, 0xffffffffdbd48954, 0xffffffffdd2e831a,
            0xffffffffdd95c72f, 0xffffffffddc9f20c, 0xffffffffdf465ddc, 0xffffffffe43086b2,
            0xffffffffea284b19, 0xffffffffea511287, 0xffffffffed219889, 0xffffffffed21e3c7,
            0xffffffffefe6fa9e, 0xfffffffff1689795, 0xfffffffff29e23a9, 0xfffffffff45323e6,
            0xfffffffff9f02259, 0xfffffffffb20067b, 0xfffffffffcbf17c5, 0xfffffffffd31fc02,
            0xfffffffffd90df14, 0xfffffffffdd5c535, 0xfffffffffe07a2b7, 0xfffffffffed0511d,
            0xffffffffff50aaac,
   }
);
