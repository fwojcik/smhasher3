/*
 * Rust FxHash v2.1.1
 * Copyright (C) 2023 Frank J. T. Wojcik
 * Copyright (C) 2015 The Rust Project Developers
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
 */
#include "Platform.h"
#include "Hashlib.h"

#include "Mathmult.h"

//------------------------------------------------------------
// A speedy, non-cryptographic hashing algorithm used by `rustc`. The
// hash map in `std` (https://doc.rust-lang.org/std/collections/struct.HashMap.html)
// uses SipHash by default, which provides resistance against DOS attacks.
// These attacks aren't a concern in the compiler so we prefer to use a
// quicker, non-cryptographic hash algorithm.
//
// The original hash algorithm provided by this crate was one taken from
// Firefox, hence the hasher it provides is called FxHasher. This name is
// kept for backwards compatibility, but the underlying hash has since been
// replaced. The current design for the hasher is a polynomial hash
// finished with a single bit rotation, together with a wyhash-inspired
// compression function for strings/slices, both designed by Orson Peters.
//
// For `rustc` we have tried many different hashing algorithms. Hashing
// speed is critical, especially for single integers. Spending more CPU
// cycles on a higher quality hash does not reduce hash collisions enough
// to make the compiler faster on real-world benchmarks.

//------------------------------------------------------------
// One might view a polynomial hash
//    m[0] * k    + m[1] * k^2  + m[2] * k^3  + ...
// as a multilinear hash with keystream k[..]
//    m[0] * k[0] + m[1] * k[1] + m[2] * k[2] + ...
// where keystream k just happens to be generated using a multiplicative
// congruential pseudorandom number generator (MCG). For that reason we chose a
// constant that was found to be good for a MCG in:
//     "Computationally Easy, Spectrally Good Multipliers for Congruential
//     Pseudorandom Number Generators" by Guy Steele and Sebastiano Vigna.
const uint64_t K64 = UINT64_C(0xf1357aea2e62a9c5);
const uint32_t K32 = 0x93d765dd;

// Nothing special, digits of pi.
const uint64_t SEED1 = UINT64_C(0x243f6a8885a308d3);
const uint64_t SEED2 = UINT64_C(0x13198a2e03707344);
const uint64_t PREVENT_TRIVIAL_ZERO_COLLAPSE = UINT64_C(0xa4093822299f31d0);

//------------------------------------------------------------
static inline void add_to_hash_64( uint64_t & hash, uint64_t val ) {
    hash = (hash + val) * K64;
}

static inline void add_to_hash_32( uint32_t & hash, uint32_t val ) {
    hash = (hash + val) * K32;
}

template <bool mul64>
static inline uint64_t multiply_mix( uint64_t x, uint64_t y ) {
    uint64_t rlo, rhi;

    if (mul64) {
        MathMult::mult64_128(rlo, rhi, x, y);
        return rlo ^ rhi;
    } else {
        // If u64 x u64 -> u128 product is prohibitively expensive, then
        // decompose into 32-bit parts...
        uint64_t lx = (uint32_t)x;
        uint64_t ly = (uint32_t)y;
        uint64_t hx = (uint32_t)(x >> 32);
        uint64_t hy = (uint32_t)(y >> 32);

        // u32 x u32 -> u64 the low bits of one with the high bits of the other.
        uint64_t afull = lx * hy;
        uint64_t bfull = hx * ly;

        // Combine, swapping low/high of one of them so the upper bits of the
        // product of one combine with the lower bits of the other.
        return afull ^ ROTR64(bfull, 32);
    }
}

/// A wyhash-inspired non-collision-resistant hash for strings/slices designed
/// by Orson Peters, with a focus on small strings and small codesize.
template <bool bswap, bool mul64>
static uint64_t hash_bytes( const uint8_t * bytes, const size_t len ) {
    uint64_t s0 = SEED1;
    uint64_t s1 = SEED2;

    if (len <= 16) {
        // XOR the input into s0, s1.
        if (len >= 8) {
            s0 ^= GET_U64<bswap>(bytes, 0);
            s1 ^= GET_U64<bswap>(bytes, len - 8);
        } else if (len >= 4) {
            s0 ^= GET_U32<bswap>(bytes, 0);
            s1 ^= GET_U32<bswap>(bytes, len - 4);
        } else if (len > 0) {
            uint64_t  lo = bytes[0];
            uint64_t mid = bytes[len / 2];
            uint64_t  hi = bytes[len - 1];
            s0 ^= lo;
            s1 ^= (hi << 8) | mid;
        }
    } else {
        // Handle bulk (can partially overlap with suffix).
        size_t off = 0;
        while (off < (len - 16)) {
            uint64_t x = GET_U64<bswap>(bytes, off    );
            uint64_t y = GET_U64<bswap>(bytes, off + 8);

            // Replace s1 with a mix of s0, x, and y, and s0 with s1.
            // This ensures the compiler can unroll this loop into two
            // independent streams, one operating on s0, the other on s1.
            //
            // Since zeroes are a common input we prevent an immediate trivial
            // collapse of the hash function by XOR'ing a constant with y.
            uint64_t t = multiply_mix<mul64>(s0 ^ x, PREVENT_TRIVIAL_ZERO_COLLAPSE ^ y);
            s0   = s1;
            s1   = t;
            off += 16;
        }

        s0 ^= GET_U64<bswap>(bytes, len - 16);
        s1 ^= GET_U64<bswap>(bytes, len -  8);
    }

    return multiply_mix<mul64>(s0, s1) ^ (uint64_t)len;
}

//------------------------------------------------------------
// "[S]ome good avalanching permutation[s]", borrowed from MurmurHash3.
// This is an unofficial variant, suggested by the comments in the original
// in src/lib.rs.
static uint64_t f64( uint64_t val ) {
    val ^= val >> 33;
    val *= UINT64_C(0xff51afd7ed558ccd);
    val ^= val >> 33;
    val *= UINT64_C(0xc4ceb9fe1a85ec53);
    val ^= val >> 33;

    return val;
}

static uint32_t f32( uint32_t val ) {
    val ^= val >> 16;
    val *= 0x85ebca6b;
    val ^= val >> 13;
    val *= 0xc2b2ae35;
    val ^= val >> 16;

    return val;
}

//------------------------------------------------------------
template <bool bswap, bool avalanche, bool mul64>
static void FxHash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * ptr  = (const uint8_t *)in;
    uint64_t        hash = (uint64_t       )seed;
    uint64_t        hb   = hash_bytes<bswap, mul64>(ptr, len);

    if (avalanche) {
        hash  = f64(hash);
        hash ^= hb;
        hash  = f64(hash);
    } else {
        add_to_hash_64(hash, hb);
        hash = ROTL64(hash, 26);
    }

    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}

template <bool bswap, bool avalanche>
static void FxHash32( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * ptr  = (const uint8_t *)in;
    uint32_t        hash = (uint32_t       )seed;
    uint64_t        hb   = hash_bytes<bswap, false>(ptr, len);

    if (avalanche) {
        hash  = f32(hash);
        hash ^= hb;
        hash ^= hb >> 32;
        hash  = f32(hash);
    } else {
        add_to_hash_32(hash, (uint32_t)hb);
        add_to_hash_32(hash, (uint32_t)(hb >> 32));
        hash = ROTL32(hash, 15);
    }

    PUT_U32<bswap>(hash, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(rust_fxhash,
   $.src_url    = "https://github.com/rust-lang/rustc-hash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(rust_fxhash64,
   $.desc            = "Rust FxHash v2.1.1 64-bit version",
   $.hash_flags      =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128 |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_CANONICAL_LE    |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.verification_LE = 0x8F177350,
   $.verification_BE = 0xDA24B5D0,
   $.hashfn_native   = FxHash64<false, false, true>,
   $.hashfn_bswap    = FxHash64<true, false, true>
);

REGISTER_HASH(rust_fxhash64__mix,
   $.desc            = "Rust FxHash v2.1.1 64-bit version, with unofficial extra mixing",
   $.hash_flags      =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128 |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_CANONICAL_LE    |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.verification_LE = 0xFC662413,
   $.verification_BE = 0x0B8B6821,
   $.hashfn_native   = FxHash64<false, true, true>,
   $.hashfn_bswap    = FxHash64<true, true, true>
);

REGISTER_HASH(rust_fxhash64__mult32,
   $.desc            = "Rust FxHash v2.1.1 64-bit version",
   $.hash_flags      =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_CANONICAL_LE    |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.verification_LE = 0x686292BD,
   $.verification_BE = 0xF10008B1,
   $.hashfn_native   = FxHash64<false, false, false>,
   $.hashfn_bswap    = FxHash64<true, false, false>
);

REGISTER_HASH(rust_fxhash64__mult32__mix,
   $.desc            = "Rust FxHash v2.1.1 64-bit version, with unofficial extra mixing",
   $.hash_flags      =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_CANONICAL_LE    |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.verification_LE = 0x9CF6B62E,
   $.verification_BE = 0x23CEDC0E,
   $.hashfn_native   = FxHash64<false, true, false>,
   $.hashfn_bswap    = FxHash64<true, true, false>
);

REGISTER_HASH(rust_fxhash32,
   $.desc            = "Rust FxHash v2.1.1 32-bit version",
   $.hash_flags      =
         FLAG_HASH_SMALL_SEED      |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY        |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_CANONICAL_LE    |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 32,
   $.verification_LE = 0xC8D7717D,
   $.verification_BE = 0x0209B465,
   $.hashfn_native   = FxHash32<false, false>,
   $.hashfn_bswap    = FxHash32<true, false>
);

REGISTER_HASH(rust_fxhash32__mix,
   $.desc            = "Rust FxHash v2.1.1 32-bit version, with unofficial extra mixing",
   $.hash_flags      =
         FLAG_HASH_SMALL_SEED      |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY        |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_CANONICAL_LE    |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 32,
   $.verification_LE = 0xD2DC6A74,
   $.verification_BE = 0x6202E4AD,
   $.hashfn_native   = FxHash32<false, true>,
   $.hashfn_bswap    = FxHash32<true, true>
);
