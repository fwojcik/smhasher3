/*
 * Polymur hash
 * Copyright (C) 2023 Frank J. T. Wojcik
 * Copyright (C) 2023 Orson Peters
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would
 *    be appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source distribution.
 *
 * This software has been modified for use in SMHasher3.
 */
#include "Platform.h"
#include "Hashlib.h"
#include "Mathmult.h"

//------------------------------------------------------------
typedef struct {
    uint64_t  k, k2, k7, s, seed;
} PolymurHashParams;

static inline uint32_t polymur_load_le_u32( const uint8_t * p ) {
    uint32_t v = GET_U32<false>(p, 0);

    v = COND_BSWAP(v, isBE());
    return v;
}

static inline uint64_t polymur_load_le_u64( const uint8_t * p ) {
    uint64_t v = GET_U64<false>(p, 0);

    v = COND_BSWAP(v, isBE());
    return v;
}

// Loads 0 to 8 bytes from buf with length len as a 64-bit little-endian integer.
static inline uint64_t polymur_load_le_u64_0_8( const uint8_t * buf, size_t len ) {
    if (len < 4) {
        if (len == 0) { return 0; }
        uint64_t v = buf[0];
        v |= buf[len / 2] << 8 * (len / 2);
        v |= buf[len - 1] << 8 * (len - 1);
        return v;
    }

    uint64_t lo = polymur_load_le_u32(buf);
    uint64_t hi = polymur_load_le_u32(buf + len - 4);
    return lo | (hi << 8 * (len - 4));
}

//------------------------------------------------------------
// Integer arithmetic

#define POLYMUR_P611 ((UINT64_C(1) << 61) - 1)

typedef struct {
    uint64_t  lo;
    uint64_t  hi;
} polymur_u128_t;

static inline polymur_u128_t polymur_add128( polymur_u128_t a, polymur_u128_t b ) {
    MathMult::add128(a.lo, a.hi, b.lo, b.hi);
    return a;
}

static inline polymur_u128_t polymur_mul128( uint64_t a, uint64_t b ) {
    polymur_u128_t r;

    MathMult::mult64_128(r.lo, r.hi, a, b);
    return r;
}

static inline uint64_t polymur_red611( polymur_u128_t x ) {
#if defined(_MSC_VER) && defined(_M_X64)
    return (((uint64_t)x.lo) & POLYMUR_P611) + __shiftright128(x.lo, x.hi, 61);
#else
    return (x.lo & POLYMUR_P611) + ((x.lo >> 61) | (x.hi << 3));
#endif
}

static inline uint64_t polymur_extrared611( uint64_t x ) {
    return (x & POLYMUR_P611) + (x >> 61);
}

//------------------------------------------------------------
// Hash function initialization

#define POLYMUR_ARBITRARY1 UINT64_C(0x6a09e667f3bcc908) // Completely arbitrary, these
#define POLYMUR_ARBITRARY2 UINT64_C(0xbb67ae8584caa73b) // are taken from SHA-2, and
#define POLYMUR_ARBITRARY3 UINT64_C(0x3c6ef372fe94f82b) // are the fractional bits of
#define POLYMUR_ARBITRARY4 UINT64_C(0xa54ff53a5f1d36f1) // sqrt(p), p = 2, 3, 5, 7.

static inline uint64_t polymur_mix( uint64_t x ) {
    // Mixing function from https://jonkagstrom.com/mx3/mx3_rev2.html.
    x ^= x >> 32;
    x *= UINT64_C(0xe9846af9b1a615d);
    x ^= x >> 32;
    x *= UINT64_C(0xe9846af9b1a615d);
    x ^= x >> 28;
    return x;
}

static inline void polymur_init_params( PolymurHashParams * p, uint64_t k_seed, uint64_t s_seed ) {
    p->s = s_seed ^ POLYMUR_ARBITRARY1; // People love to pass zero.

    // POLYMUR_POW37[i] = 37^(2^i) mod (2^61 - 1)
    // Could be replaced by a 512 byte LUT, costs ~400 byte overhead but 2x
    // faster seeding. However, seeding is rather rare, so I chose not to.
    uint64_t POLYMUR_POW37[64];
    POLYMUR_POW37[0] = 37; POLYMUR_POW37[32] = UINT64_C(559096694736811184);
    for (int i = 0; i < 31; ++i) {
        POLYMUR_POW37[i +  1] =
            polymur_extrared611(polymur_red611(polymur_mul128(POLYMUR_POW37[i     ], POLYMUR_POW37[i     ])));
        POLYMUR_POW37[i + 33] =
            polymur_extrared611(polymur_red611(polymur_mul128(POLYMUR_POW37[i + 32], POLYMUR_POW37[i + 32])));
    }

    while (1) {
        // Choose a random exponent coprime to 2^61 - 2. ~35.3% success rate.
        k_seed += POLYMUR_ARBITRARY2;
        uint64_t e = (k_seed >> 3) | 1; // e < 2^61, odd.
        if (e % 3 == 0) { continue; }
        if (!(e % 5 && e % 7)) { continue; }
        if (!(e % 11 && e % 13 && e % 31)) { continue; }
        if (!(e % 41 && e % 61 && e % 151 && e % 331 && e % 1321)) { continue; }

        // Compute k = 37^e mod 2^61 - 1. Since e is coprime with the order of
        // the multiplicative group mod 2^61 - 1 and 37 is a generator, this
        // results in another generator of the group.
        uint64_t ka = 1, kb = 1;
        for (int i = 0; e; i += 2, e >>= 2) {
            if (e & 1) { ka = polymur_extrared611(polymur_red611(polymur_mul128(ka, POLYMUR_POW37[i]))); }
            if (e & 2) { kb = polymur_extrared611(polymur_red611(polymur_mul128(kb, POLYMUR_POW37[i + 1]))); }
        }
        uint64_t k = polymur_extrared611(polymur_red611(polymur_mul128(ka, kb)));

        // ~46.875% success rate. Bound on k^7 needed for efficient reduction.
        p->k  = polymur_extrared611(k);
        p->k2 = polymur_extrared611(polymur_red611(polymur_mul128(p->k,  p->k)));
        uint64_t k3 = polymur_red611(polymur_mul128(p->k,  p->k2));
        uint64_t k4 = polymur_red611(polymur_mul128(p->k2, p->k2));
        p->k7 = polymur_extrared611(polymur_red611(polymur_mul128(k3, k4)));
        if (p->k7 < ((UINT64_C(1) << 60) - (UINT64_C(1) << 56))) { break; }
        // Our key space is log2(totient(2^61 - 2) * (2^60-2^56)/2^61) ~= 57.4 bits.
    }
}

static thread_local PolymurHashParams params;
static PolymurHashParams params_0;

static uintptr_t polymur_init_params_from_seed( uint64_t seed ) {
    polymur_init_params(&params, polymur_mix(seed + POLYMUR_ARBITRARY3), polymur_mix(seed + POLYMUR_ARBITRARY4));
    return (uintptr_t)(void *)&params;
}

static bool polymur_init_params_from_zero( void ) {
    polymur_init_params(&params_0, polymur_mix(POLYMUR_ARBITRARY3), polymur_mix(POLYMUR_ARBITRARY4));
    return true;
}

//------------------------------------------------------------
// Hash function

static inline uint64_t polymur_hash_poly611( const uint8_t * buf, size_t len,
        const PolymurHashParams * p, uint64_t tweak ) {
    uint64_t m[7];
    uint64_t poly_acc = tweak;

    if (likely(len <= 7)) {
        m[0] = polymur_load_le_u64_0_8(buf, len);
        return poly_acc + polymur_red611(polymur_mul128(p->k + m[0], p->k2 + len));
    }

    uint64_t k3 = polymur_red611(polymur_mul128(p->k, p->k2) );
    uint64_t k4 = polymur_red611(polymur_mul128(p->k2, p->k2));
    if (unlikely(len >= 50)) {
        const uint64_t k5 = polymur_extrared611(polymur_red611(polymur_mul128(p->k,  k4)));
        const uint64_t k6 = polymur_extrared611(polymur_red611(polymur_mul128(p->k2, k4)));
        k3 = polymur_extrared611(k3);
        k4 = polymur_extrared611(k4);
        uint64_t h = 0;
        do {
            for (int i = 0; i < 7; ++i) { m[i] = polymur_load_le_u64(buf + 7 * i) & UINT64_C(0x00ffffffffffffff); }
            polymur_u128_t t0 = polymur_mul128(p->k  + m[0], k6 + m[1]);
            polymur_u128_t t1 = polymur_mul128(p->k2 + m[2], k5 + m[3]);
            polymur_u128_t t2 = polymur_mul128(k3    + m[4], k4 + m[5]);
            polymur_u128_t t3 = polymur_mul128(h     + m[6], p->k7    );
            polymur_u128_t s  = polymur_add128(polymur_add128(t0, t1), polymur_add128(t2, t3));
            h    = polymur_red611(s);
            len -= 49;
            buf += 49;
        } while (len >= 50);
        const uint64_t k14  = polymur_red611(polymur_mul128(p->k7, p->k7));
        uint64_t       hk14 = polymur_red611(polymur_mul128(polymur_extrared611(h), k14));
        poly_acc += polymur_extrared611(hk14);
    }

    if (likely(len >= 8)) {
        m[0] = polymur_load_le_u64(buf     )            & UINT64_C(0x00ffffffffffffff);
        m[1] = polymur_load_le_u64(buf + (len - 7) / 2) & UINT64_C(0x00ffffffffffffff);
        m[2] = polymur_load_le_u64(buf + len - 8) >> 8;
        polymur_u128_t t0 = polymur_mul128(p->k2 + m[0], p->k7 + m[1]);
        polymur_u128_t t1 = polymur_mul128(p->k  + m[2], k3    + len );
        if (likely(len <= 21)) { return poly_acc + polymur_red611(polymur_add128(t0, t1)); }
        m[3] = polymur_load_le_u64(buf +  7)       & UINT64_C(0x00ffffffffffffff);
        m[4] = polymur_load_le_u64(buf + 14)       & UINT64_C(0x00ffffffffffffff);
        m[5] = polymur_load_le_u64(buf + len - 21) & UINT64_C(0x00ffffffffffffff);
        m[6] = polymur_load_le_u64(buf + len - 14) & UINT64_C(0x00ffffffffffffff);
        uint64_t       t0r = polymur_red611(t0);
        polymur_u128_t t2  = polymur_mul128(p->k2 + m[3], p->k7 + m[4]);
        polymur_u128_t t3  = polymur_mul128(t0r   + m[5], k4    + m[6]);
        polymur_u128_t s   = polymur_add128(polymur_add128(t1, t2), t3);
        return poly_acc + polymur_red611(s);
    }

    m[0] = polymur_load_le_u64_0_8(buf, len);
    return poly_acc + polymur_red611(polymur_mul128(p->k + m[0], p->k2 + len));
}

//------------------------------------------------------------
template <bool bswap, bool tweak_seed>
static void PolymurHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    const PolymurHashParams * p     = tweak_seed ? &params_0 : (const PolymurHashParams *)(void *)(uintptr_t)seed;
    const uint64_t            tweak = tweak_seed ? (uint64_t)seed : 0;
    uint64_t hash = polymur_hash_poly611((const uint8_t *)in, len, p, tweak);

    hash = polymur_mix(hash) + p->s;
    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(polymur,
   $.src_url    = "https://github.com/orlp/polymur-hash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(polymurhash,
   $.desc            = "Polymur Hash (using polymur_init_params_from_seed)",
   $.hash_flags      =
         FLAG_HASH_XL_SEED,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128 |
         FLAG_IMPL_LICENSE_ZLIB,
   $.bits            = 64,
   $.verification_LE = 0x0722B1A7,
   $.verification_BE = 0x830CF404,
   $.seedfn          = polymur_init_params_from_seed,
   $.hashfn_native   = PolymurHash<false, false>,
   $.hashfn_bswap    = PolymurHash<true, false>
 );

REGISTER_HASH(polymurhash_tweakseed,
   $.desc            = "Polymur Hash (using seed as tweak)",
   $.hash_flags      =
         FLAG_HASH_XL_SEED,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128 |
         FLAG_IMPL_LICENSE_ZLIB,
   $.bits            = 64,
   $.verification_LE = 0x95CFB54D,
   $.verification_BE = 0xEE893701,
   $.initfn          = polymur_init_params_from_zero,
   $.hashfn_native   = PolymurHash<false, true>,
   $.hashfn_bswap    = PolymurHash<true, true>
 );
