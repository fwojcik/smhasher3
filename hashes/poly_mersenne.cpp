/*
 * Polynomial Mersenne Hash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
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
#include "Platform.h"
#include "Hashlib.h"

#include "Mathmult.h"

#if defined(HAVE_INT128)

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

const static uint64_t MERSENNE_61         = (1ull << 61) - 1;
const static uint32_t POLY_MERSENNE_MAX_K = 4;

struct poly_mersenne_struct {
    uint64_t  poly_mersenne_random[POLY_MERSENNE_MAX_K + 1];
    uint64_t  poly_mersenne_a;
    uint64_t  poly_mersenne_b;
};
static thread_local struct poly_mersenne_struct poly_mersenne_data;

static uint128_t rand_u128( uint64_t & state ) {
    // We don't know how many bits we get from rand(), but it is at least
    // 16, so we concatenate a couple.
    uint128_t r = splitmix_rand(state);

    for (int i = 0; i < 7; i++) {
        r <<= 16;
        r  ^= splitmix_rand(state);
    }
    return r;
}

static uintptr_t poly_mersenne_seed_init( const seed_t seed ) {
    uint64_t splitmix_nextrand = (uint64_t)seed;    

    // a has be at most 2^60, or the lazy modular reduction won't work.
    poly_mersenne_data.poly_mersenne_a = rand_u128(splitmix_nextrand) % (MERSENNE_61 / 2);
    poly_mersenne_data.poly_mersenne_b = rand_u128(splitmix_nextrand) % MERSENNE_61;
    for (uint32_t i = 0; i < POLY_MERSENNE_MAX_K + 1; i++) {
        // The random values should be at most 2^61-2, or the lazy
        // modular reduction won't work.
        poly_mersenne_data.poly_mersenne_random[i] = rand_u128(splitmix_nextrand) % MERSENNE_61;
    }
    return (seed_t)(uintptr_t)&poly_mersenne_data;
}

static uint64_t mult_combine61( uint64_t h, uint64_t x, uint64_t a ) {
    uint64_t rhi = 0, rlo = a;

    MathMult::fma64_128(rlo, rhi, h, x);

    rhi <<= (64   - 61);
    rhi  |= (rlo >> 61);
    rlo  &= MERSENNE_61;

    return rlo + rhi;
}

// This function ignores the seed, because it uses a separate seeding function.
template <uint32_t K, bool bswap>
static void Poly_Mersenne( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * buf = (const uint8_t *)in;
    const struct poly_mersenne_struct * data = (const struct poly_mersenne_struct *)(uintptr_t)seed;

    // We first combine hashes using a polynomial in `a`:
    // hash = x1 + x2 * a + x3 * a^2 + ... (mod p)
    // This hash has collision probability len/p, since the polynomial is
    // degree and so can have at most len roots (values of a that make it zero).
    const uint64_t a = data->poly_mersenne_a;

    // We use the length as the first character.
    uint64_t h = len;

    for (size_t i = 0; i < len / 4; i++, buf += 4) {
        // Partial modular reduction. Since each round adds 32 bits, and this
        // subtracts (up to) 61 bits, we make sure to never overflow.
        h = mult_combine61(h, a, GET_U32<bswap>(buf, 0));
    }

    // Get the last character
    int remaining_bytes = len % 4;
    if (remaining_bytes) {
        uint32_t last = 0;
        if (remaining_bytes & 2) { last = GET_U16<bswap>(buf, 0); buf += 2; }
        if (remaining_bytes & 1) { last = (last << 8) | (*buf); }
        h = mult_combine61(h, a, last);
    }

    // Increase hash strength from low collision rate to K-independence.
    // hash = a1 + a2 * h + a3 * h^2 + ... (mod p)
    if (K != 0) {
        uint64_t h0 = h;
        h = data->poly_mersenne_random[0];
        for (uint32_t i = 1; i <= std::min(K, POLY_MERSENNE_MAX_K); i++) {
            h = mult_combine61(h, h0, data->poly_mersenne_random[i]);
        }
    }

    // Finally complete the modular reduction
    if (h >= MERSENNE_61) { h -= MERSENNE_61; }

    h = COND_BSWAP(h, bswap);
    memcpy(out, &h, 4);
}

REGISTER_FAMILY(poly_mersenne,
   $.src_url    = "https://github.com/rurban/smhasher/blob/master/Hashes.cpp",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(poly_mersenne__deg0,
   $.desc       = "Degree 0 Hashing mod 2^61-1",
   $.impl       = "int128",
   $.hash_flags =
         FLAG_HASH_SYSTEM_SPECIFIC,
   $.impl_flags =
         FLAG_IMPL_128BIT               |
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_LICENSE_BSD          |
         FLAG_IMPL_SLOW,
   $.bits = 32,
   $.verification_LE = 0x5D4B947A,
   $.verification_BE = 0x79E0F01B,
   $.seedfn          = poly_mersenne_seed_init,
   $.hashfn_native   = Poly_Mersenne<0, false>,
   $.hashfn_bswap    = Poly_Mersenne<0, true>
 );

REGISTER_HASH(poly_mersenne__deg1,
   $.desc       = "Degree 1 Hashing mod 2^61-1",
   $.impl       = "int128",
   $.hash_flags =
         FLAG_HASH_SYSTEM_SPECIFIC,
   $.impl_flags =
         FLAG_IMPL_128BIT               |
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_LICENSE_BSD          |
         FLAG_IMPL_SLOW,
   $.bits = 32,
   $.verification_LE = 0x2C5C1B0E,
   $.verification_BE = 0xE85E0414,
   $.seedfn          = poly_mersenne_seed_init,
   $.hashfn_native   = Poly_Mersenne<1, false>,
   $.hashfn_bswap    = Poly_Mersenne<1, true>
 );

REGISTER_HASH(poly_mersenne__deg2,
   $.desc       = "Degree 2 Hashing mod 2^61-1",
   $.impl       = "int128",
   $.hash_flags =
         FLAG_HASH_SYSTEM_SPECIFIC,
   $.impl_flags =
         FLAG_IMPL_128BIT               |
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_LICENSE_BSD          |
         FLAG_IMPL_SLOW,
   $.bits = 32,
   $.verification_LE = 0x35AF4EA2,
   $.verification_BE = 0xEA3BFB05,
   $.seedfn          = poly_mersenne_seed_init,
   $.hashfn_native   = Poly_Mersenne<2, false>,
   $.hashfn_bswap    = Poly_Mersenne<2, true>
 );

REGISTER_HASH(poly_mersenne__deg3,
   $.desc       = "Degree 3 Hashing mod 2^61-1",
   $.impl       = "int128",
   $.hash_flags =
         FLAG_HASH_SYSTEM_SPECIFIC,
   $.impl_flags =
         FLAG_IMPL_128BIT               |
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_LICENSE_BSD          |
         FLAG_IMPL_SLOW,
   $.bits = 32,
   $.verification_LE = 0x8197A37D,
   $.verification_BE = 0x601CF718,
   $.seedfn          = poly_mersenne_seed_init,
   $.hashfn_native   = Poly_Mersenne<3, false>,
   $.hashfn_bswap    = Poly_Mersenne<3, true>
 );

REGISTER_HASH(poly_mersenne__deg4,
   $.desc       = "Degree 4 Hashing mod 2^61-1",
   $.impl       = "int128",
   $.hash_flags =
         FLAG_HASH_SYSTEM_SPECIFIC,
   $.impl_flags =
         FLAG_IMPL_128BIT               |
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_LICENSE_BSD          |
         FLAG_IMPL_SLOW,
   $.bits = 32,
   $.verification_LE = 0x27C2F53B,
   $.verification_BE = 0x6857DC31,
   $.seedfn          = poly_mersenne_seed_init,
   $.hashfn_native   = Poly_Mersenne<4, false>,
   $.hashfn_bswap    = Poly_Mersenne<4, true>
 );

#else
REGISTER_FAMILY(poly_mersenne);
#endif
