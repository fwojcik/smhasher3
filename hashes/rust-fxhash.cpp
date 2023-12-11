/*
 * Rust FxHash
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

//------------------------------------------------------------
// A speedy hash algorithm for use within rustc. The hashmap in liballoc
// by default uses SipHash which isn't quite as speedy as we want. In the
// compiler we're not really worried about DOS attempts, so we use a fast
// non-cryptographic hash.
//
// This is the same as the algorithm used by Firefox -- which is a homespun
// one not based on any widely-known algorithm -- though modified to produce
// 64-bit hash values instead of 32-bit hash values. It consistently
// out-performs an FNV-based hash within rustc itself -- the collision rate is
// similar or slightly worse than FNV, but the speed of the hash function
// itself is much higher because it works on up to 8 bytes at a time.

const uint64_t K64 = UINT64_C(0x517cc1b727220a95);
const uint32_t K32 = 0x9e3779b9;

static inline void add_to_hash_64( uint64_t & hash, uint64_t val ) {
    hash = (ROTL64(hash, 5) ^ val) * K64;
}

static inline void add_to_hash_32( uint32_t & hash, uint32_t val ) {
    hash = (ROTL32(hash, 5) ^ val) * K32;
}

//------------------------------------------------------------
template <bool bswap>
static void FxHash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * ptr = (const uint8_t *)in;
    uint64_t hash = (uint64_t)seed;
    size_t   l    = len;

    while (l >= 8) {
        add_to_hash_64(hash, GET_U64<bswap>(ptr, 0));
        ptr += 8;
        l -= 8;
    }
    if (l >= 4) {
        add_to_hash_64(hash, GET_U32<bswap>(ptr, 0));
        ptr += 4;
        l -= 4;
    }
    if (l >= 2) {
        add_to_hash_64(hash, GET_U16<bswap>(ptr, 0));
        ptr += 2;
        l -= 2;
    }
    if (l >= 1) {
        add_to_hash_64(hash, *ptr);
    }
    
    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}

template <bool bswap>
static void FxHash32( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * ptr = (const uint8_t *)in;
    uint32_t hash = (uint32_t)seed;
    size_t   l    = len;

    while (l >= 4) {
        add_to_hash_32(hash, GET_U32<bswap>(ptr, 0));
        ptr += 4;
        l -= 4;
    }
    if (l >= 2) {
        add_to_hash_32(hash, GET_U16<bswap>(ptr, 0));
        ptr += 2;
        l -= 2;
    }
    if (l >= 1) {
        add_to_hash_32(hash, *ptr);
    }
    
    PUT_U32<bswap>(hash, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(rust_fxhash,
   $.src_url    = "https://github.com/rust-lang/rustc-hash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(rust_fxhash32,
   $.desc            = "Rust FxHash 32-bit version",
   $.hash_flags      =         
         FLAG_HASH_NO_SEED        |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags      =
         FLAG_IMPL_SANITY_FAILS   |
         FLAG_IMPL_MULTIPLY       |
         FLAG_IMPL_ROTATE         |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 32,
   $.verification_LE = 0x80176895,
   $.verification_BE = 0x06DDB589,
   $.hashfn_native   = FxHash32<false>,
   $.hashfn_bswap    = FxHash32<true>
 );

REGISTER_HASH(rust_fxhash64,
   $.desc            = "Rust FxHash 64-bit version",
   $.hash_flags      =
         FLAG_HASH_NO_SEED,
   $.impl_flags      =
         FLAG_IMPL_SANITY_FAILS   |
         FLAG_IMPL_MULTIPLY_64_64 |
         FLAG_IMPL_ROTATE         |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.verification_LE = 0x32408FE5,
   $.verification_BE = 0x57249883,
   $.hashfn_native   = FxHash64<false>,
   $.hashfn_bswap    = FxHash64<true>,
   $.badseeddesc     = "All seeds are bad, as varying lengths of all-zeros can always cause collisions"
 );
