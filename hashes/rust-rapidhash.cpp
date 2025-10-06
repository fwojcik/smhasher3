/*
 * rapidhash - Very fast, high quality, platform independant hashing algorithm.
 * Copyright (C) 2025 Nicolas De Carli
 * Copyright (C) 2025 Frank J. T. Wojcik
 *
 * Based on 'wyhash', by Wang Yi <godspeed_china@yeah.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * You can contact the author at:
 *   - rapidhash source repository: https://github.com/Nicoshev/rapidhash
 */

#include "Platform.h"
#include "Hashlib.h"

#include "Mathmult.h"

//-----------------------------------------------------------------------------
template <bool bswap>
static inline uint64_t rapid_read64( const uint8_t * p ) {
    return GET_U64<bswap>(p, 0);
}

template <bool bswap>
static inline uint64_t rapid_read32( const uint8_t * p ) {
    return GET_U32<bswap>(p, 0);
}

//-----------------------------------------------------------------------------
template <bool PROTECTED, bool PORTABLE>
static inline void rapid_mum( uint64_t * A, uint64_t * B ) {
    uint64_t rlo, rhi;

    if (PORTABLE) {
        // If u64 x u64 -> u128 product is quite expensive, then
        // we approximate it by expanding the multiplication and eliminating
        // carries by replacing additions with XORs:
        //    (2^32 hx + lx)*(2^32 hy + ly) =
        //    2^64 hx*hy + 2^32 (hx*ly + lx*hy) + lx*ly ~=
        //    2^64 hx*hy ^ 2^32 (hx*ly ^ lx*hy) ^ lx*ly
        // Which when folded becomes:
        //    (hx*hy ^ lx*ly) ^ (hx*ly ^ lx*hy).rotate_right(32)
        uint64_t lx = (uint32_t)*A;
        uint64_t ly = (uint32_t)*B;
        uint64_t hx = (uint32_t)(*A >> 32);
        uint64_t hy = (uint32_t)(*B >> 32);

        // u32 x u32 -> u64 the low bits of one with the high bits of the other.
        uint64_t ll = lx * ly;
        uint64_t lh = lx * hy;
        uint64_t hl = hx * ly;
        uint64_t hh = hx * hy;

        if (PROTECTED) {
            // If protected, we XOR the inputs with the results.
            // This is to ensure that the inputs are not recoverable from the output.
            *A ^= hh ^ ll;
            *B ^= ROTR64(hl ^ lh, 32);
        } else {
            *A  = hh ^ ll;
            *B  = ROTR64(hl ^ lh, 32);
        }
    } else {
        MathMult::mult64_128(rlo, rhi, *A, *B);
        if (PROTECTED) {
            *A ^= rlo; *B ^= rhi;
        } else {
            *A  = rlo; *B  = rhi;
        }
    }
}

// Folded 64-bit multiply. [rapid_mum] then XOR the results together.
template <bool PROTECTED, bool PORTABLE>
static inline uint64_t rapid_mix( uint64_t A, uint64_t B ) {
    rapid_mum<PROTECTED, PORTABLE>(&A, &B);
    return A ^ B;
}

static const uint64_t DEFAULT_RAPID_SECRETS[7] = {
    UINT64_C(0x2d358dccaa6c78a5), UINT64_C(0x8bb84b93962eacc9),
    UINT64_C(0x4b33a62ed433d4a3), UINT64_C(0x4d5a2da51de1aa47),
    UINT64_C(0xa0761d6478bd642f), UINT64_C(0xe7037ed1a0b428db),
    UINT64_C(0x90ed1765281c388c),
};

// rapid_secrets[7] is used for storing the seed
static thread_local uint64_t rapid_secrets[8] = { 0 };

//-----------------------------------------------------------------------------
// Seed mixing/initialization routines

// This seeding matches the RapidHasher::new() interface
static uintptr_t rapidhash_seed( const seed_t seed ) {
    uint64_t s = (uint64_t)seed;

    // rapidhash_seed() calls rapid_mix::<false>, so it's never the
    // PROTECTED version and it's never the PORTABLE version
    s ^= rapid_mix<false, false>(seed ^ DEFAULT_RAPID_SECRETS[2], DEFAULT_RAPID_SECRETS[1]);
    return (uintptr_t)s;
}

// This routine from GlobalSecrets::create_secrets() is very similar to,
// but NOT the same as, RapidSecrets::premix_seed().
static uint64_t premix_seed( uint64_t seed, const size_t i ) {
    const uint64_t hi = UINT64_C(0xFFFF) << 48;
    const uint64_t mi = UINT64_C(0xFFFF) << 24;
    const uint64_t lo = UINT64_C(0xFFFF);

    // GlobalSecrets::create_secrets() calls rapid_mix::<true>, so it's
    // always the PROTECTED version, and it's never the PORTABLE version
    seed ^= rapid_mix<true, false>(seed ^ DEFAULT_RAPID_SECRETS[0], DEFAULT_RAPID_SECRETS[i]);

    // Ensure the seeds are of reasonable non-zero quality
    if ((seed & hi) == 0) {
        seed |= UINT64_C(1) << 63;
    }
    if ((seed & mi) == 0) {
        seed |= UINT64_C(1) << 31;
    }
    if ((seed & lo) == 0) {
        seed |= UINT64_C(1);
    }

    return seed;
}

// This seeding is _analogous_ to SeedableState::new(). The hashing seed
// value is generated from the user-supplied seed in the same way. The
// secrets values are generated here using the method in
// GlobalSecrets::create_secrets(), which is what SeedableState::new()
// calls, except that the seed value for secret generation is not
// randomly-generated outside the user's control, but is instead derived
// from the hashing seed.
static uintptr_t create_secrets_from_seed( const seed_t s ) {
    const uint64_t seed = rapidhash_seed(s);

    rapid_secrets[0] = premix_seed(seed, 0);
    rapid_secrets[1] = premix_seed(rapid_secrets[0], 1);
    rapid_secrets[2] = premix_seed(rapid_secrets[1], 2);
    rapid_secrets[3] = premix_seed(rapid_secrets[2], 3);
    rapid_secrets[4] = premix_seed(rapid_secrets[3], 4);
    rapid_secrets[5] = premix_seed(rapid_secrets[4], 5);
    rapid_secrets[6] = premix_seed(rapid_secrets[5], 6);
    rapid_secrets[7] = seed;

    return (uintptr_t)(void *)&rapid_secrets;
}

//-----------------------------------------------------------------------------
// Core rust-rapidhash routines

// This is a somewhat arbitrary cutoff for the long path.
//
// It's dependent on the cost of the function call, register clobbering, setup/teardown of the 7
// independent lanes etc. The current value should be reached by testing against the
// hash/rapidhash-f/medium benchmarks, and may benefit from being tuned per target platform.
constexpr size_t COLD_PATH_CUTOFF = 400;

template <bool PROTECTED, bool PORTABLE, bool AVALANCHE>
static FORCE_INLINE uint64_t rapidhash_finish( uint64_t a, uint64_t b, uint64_t seed, const uint64_t * secrets ) {
    a ^= secrets[0];
    b ^= seed;
    rapid_mum<PROTECTED, PORTABLE>(&a, &b);

    if (AVALANCHE) {
        return rapid_mix<PROTECTED, PORTABLE>(a ^ UINT64_C(0xaaaaaaaaaaaaaaaa) ^ seed, b ^ secrets[1]);
    } else {
        return a ^ b;
    }
}

// This routine may read from addresses BEFORE &p[0], but this is
// guaranteed only to be called when such data is guaranteed to be valid.
template <bool bswap, bool PROTECTED, bool PORTABLE, bool AVALANCHE>
static FORCE_INLINE uint64_t rapidhash_final_48( const uint8_t * p, size_t len,
        uint64_t seed, const uint64_t * secrets, size_t origlen ) {
    assume(origlen > 16);

    if (likely(len > 16)) {
        seed = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p) ^ secrets[0],
                rapid_read64<bswap>(p + 8) ^ seed);
        if (likely(len > 32)) {
            seed = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p + 16) ^ secrets[0],
                    rapid_read64<bswap>(p + 24) ^ seed);
        }
    }

    uint64_t a = rapid_read64<bswap>(p + len - 16);
    uint64_t b = rapid_read64<bswap>(p + len -  8);
    seed += (uint64_t)origlen;
    return rapidhash_finish<PROTECTED, PORTABLE, AVALANCHE>(a, b, seed, secrets);
}

template <bool bswap, bool UNROLLED, bool PROTECTED, bool PORTABLE, bool AVALANCHE>
static NEVER_INLINE uint64_t rapidhash_core_cold( const uint8_t * p, const size_t len,
        uint64_t seed, const uint64_t * secrets ) {
    uint64_t see1 = seed, see2 = seed;
    uint64_t see3 = seed, see4 = seed;
    uint64_t see5 = seed, see6 = seed;
    size_t   i    = len;

    assume(len > COLD_PATH_CUTOFF);

    if (UNROLLED) {
        while (i >= 224) {
            seed = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p      ) ^ secrets[0],
                    rapid_read64<bswap>(p +   8) ^ seed);
            see1 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  16) ^ secrets[1],
                    rapid_read64<bswap>(p +  24) ^ see1);
            see2 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  32) ^ secrets[2],
                    rapid_read64<bswap>(p +  40) ^ see2);
            see3 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  48) ^ secrets[3],
                    rapid_read64<bswap>(p +  56) ^ see3);
            see4 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  64) ^ secrets[4],
                    rapid_read64<bswap>(p +  72) ^ see4);
            see5 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  80) ^ secrets[5],
                    rapid_read64<bswap>(p +  88) ^ see5);
            see6 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  96) ^ secrets[6],
                    rapid_read64<bswap>(p + 104) ^ see6);

            seed = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p + 112) ^ secrets[0],
                    rapid_read64<bswap>(p + 120) ^ seed);
            see1 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p + 128) ^ secrets[1],
                    rapid_read64<bswap>(p + 136) ^ see1);
            see2 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p + 144) ^ secrets[2],
                    rapid_read64<bswap>(p + 152) ^ see2);
            see3 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p + 160) ^ secrets[3],
                    rapid_read64<bswap>(p + 168) ^ see3);
            see4 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p + 176) ^ secrets[4],
                    rapid_read64<bswap>(p + 184) ^ see4);
            see5 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p + 192) ^ secrets[5],
                    rapid_read64<bswap>(p + 200) ^ see5);
            see6 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p + 208) ^ secrets[6],
                    rapid_read64<bswap>(p + 216) ^ see6);
            p   += 224; i -= 224;
        }
        if (likely(i >= 112)) {
            seed = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p      ) ^ secrets[0],
                    rapid_read64<bswap>(p +   8) ^ seed);
            see1 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  16) ^ secrets[1],
                    rapid_read64<bswap>(p +  24) ^ see1);
            see2 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  32) ^ secrets[2],
                    rapid_read64<bswap>(p +  40) ^ see2);
            see3 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  48) ^ secrets[3],
                    rapid_read64<bswap>(p +  56) ^ see3);
            see4 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  64) ^ secrets[4],
                    rapid_read64<bswap>(p +  72) ^ see4);
            see5 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  80) ^ secrets[5],
                    rapid_read64<bswap>(p +  88) ^ see5);
            see6 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  96) ^ secrets[6],
                    rapid_read64<bswap>(p + 104) ^ see6);
            p   += 112; i -= 112;
        }
    } else {
        do {
            seed = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p      ) ^ secrets[0],
                    rapid_read64<bswap>(p +   8) ^ seed);
            see1 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  16) ^ secrets[1],
                    rapid_read64<bswap>(p +  24) ^ see1);
            see2 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  32) ^ secrets[2],
                    rapid_read64<bswap>(p +  40) ^ see2);
            see3 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  48) ^ secrets[3],
                    rapid_read64<bswap>(p +  56) ^ see3);
            see4 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  64) ^ secrets[4],
                    rapid_read64<bswap>(p +  72) ^ see4);
            see5 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  80) ^ secrets[5],
                    rapid_read64<bswap>(p +  88) ^ see5);
            see6 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  96) ^ secrets[6],
                    rapid_read64<bswap>(p + 104) ^ see6);
            p   += 112; i -= 112;
        } while (i > 112);
    }

    if (UNROLLED) {
        if (i >= 48) {
            seed = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p      ) ^ secrets[0],
                    rapid_read64<bswap>(p +   8) ^ seed);
            see1 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  16) ^ secrets[1],
                    rapid_read64<bswap>(p +  24) ^ see1);
            see2 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  32) ^ secrets[2],
                    rapid_read64<bswap>(p +  40) ^ see2);
            p   += 48; i -= 48;

            if (i >= 48) {
                seed = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p      ) ^ secrets[0],
                        rapid_read64<bswap>(p +   8) ^ seed);
                see1 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  16) ^ secrets[1],
                        rapid_read64<bswap>(p +  24) ^ see1);
                see2 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  32) ^ secrets[2],
                        rapid_read64<bswap>(p +  40) ^ see2);
                p   += 48; i -= 48;
            }
        }
    } else {
        while (i >= 48) {
            seed = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p      ) ^ secrets[0],
                    rapid_read64<bswap>(p +   8) ^ seed);
            see1 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  16) ^ secrets[1],
                    rapid_read64<bswap>(p +  24) ^ see1);
            see2 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  32) ^ secrets[2],
                    rapid_read64<bswap>(p +  40) ^ see2);
            p   += 48; i -= 48;
        }
    }

    see3 ^= see4;
    see5 ^= see6;
    seed ^= see1;
    see3 ^= see2;
    seed ^= see5;
    seed ^= see3;

    return rapidhash_final_48<bswap, PROTECTED, PORTABLE, AVALANCHE>(p, i, seed, secrets, len);
}

template <bool bswap, bool UNROLLED, bool PROTECTED, bool PORTABLE, bool AVALANCHE>
static NEVER_INLINE uint64_t rapidhash_core_17_plus( const uint8_t * p, const size_t len,
        uint64_t seed, const uint64_t * secrets ) {
    assume(len > 16);

    if (likely(len <= 48)) {
        return rapidhash_final_48<bswap, PROTECTED, PORTABLE, AVALANCHE>(p, len, seed, secrets, len);
    }

    if (unlikely(len > COLD_PATH_CUTOFF)) {
        return rapidhash_core_cold<bswap, UNROLLED, PROTECTED, PORTABLE, AVALANCHE>(p, len, seed, secrets);
    }

    uint64_t see1 = seed, see2 = seed;
    size_t remain = len;

    do {
        seed = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p      ) ^ secrets[0],
                rapid_read64<bswap>(p +   8) ^ seed);
        see1 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  16) ^ secrets[1],
                rapid_read64<bswap>(p +  24) ^ see1);
        see2 = rapid_mix<PROTECTED, PORTABLE>(rapid_read64<bswap>(p +  32) ^ secrets[2],
                rapid_read64<bswap>(p +  40) ^ see2);
        p   += 48; remain -= 48;
    } while (remain >= 48);

    seed ^= see1 ^ see2;

    return rapidhash_final_48<bswap, PROTECTED, PORTABLE, AVALANCHE>(p, remain, seed, secrets, len);
}

template <bool bswap, bool UNROLLED, bool PROTECTED, bool PORTABLE, bool AVALANCHE>
static inline uint64_t rapidhash_core( const uint8_t * p, size_t len, uint64_t seed, const uint64_t * secrets ) {
    uint64_t a, b;

    if (likely(len <= 16)) {
        if (likely(len >= 8)) {
            const uint8_t * plast = p + len - 8;
            a = rapid_read64<bswap>(p);
            b = rapid_read64<bswap>(plast);
        } else if (likely(len >= 4)) {
            const uint8_t * plast = p + len - 4;
            a = rapid_read32<bswap>(p);
            b = rapid_read32<bswap>(plast);
        } else if (likely(len > 0)) {
            a = (((uint64_t)p[0]) << 45) | p[len - 1];
            b = p[len >> 1];
        } else {
            a = b = 0;
        }

        seed += (uint64_t)len;

        return rapidhash_finish<PROTECTED, PORTABLE, AVALANCHE>(a, b, seed, secrets);
    } else {
        return rapidhash_core_17_plus<bswap, UNROLLED, PROTECTED, PORTABLE, AVALANCHE>(p, len, seed, secrets);
    }
}

//-----------------------------------------------------------------------------
template <bool bswap, bool UNROLLED, bool PROTECTED, bool PORTABLE, bool AVALANCHE, bool SEEDED>
static void RustRapidHash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint64_t * secrets = SEEDED ? (const uint64_t *)(void *)(uintptr_t)seed : DEFAULT_RAPID_SECRETS;
    const uint64_t   seedval = SEEDED ? secrets[7] : (uint64_t)seed;
    const uint8_t *  data    = (const uint8_t *)in;
    uint64_t         h;

    h = rapidhash_core<bswap, UNROLLED, PROTECTED, PORTABLE, AVALANCHE>(data, len, seedval, secrets);
    if (AVALANCHE) {
        h = rapid_mix<PROTECTED, PORTABLE>(h, DEFAULT_RAPID_SECRETS[1]);
    }
    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//-----------------------------------------------------------------------------
REGISTER_FAMILY(rust_rapidhash,
   $.src_url    = "https://github.com/hoxxep/rapidhash",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

// All of these implementations are unrolled, as that seems to provide a
// uniform, modest performance boost
constexpr bool UNROLLED_FLAG = true;
// All of these implementations are not in PROTECTED mode, since there
// seems to be no non-internal way of setting that flag for users of the
// Rust crate
constexpr bool PROTECTED_FLAG = false;

REGISTER_HASH(rust_rapidhash,
   $.desc       = "rapidhash rust, quality::RapidHasher::new()",
   $.sort_order = 0,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x562EF848,
   $.verification_BE = 0x714A6798,
   $.hashfn_native   = RustRapidHash64<false, UNROLLED_FLAG, PROTECTED_FLAG, false, true, false>,
   $.hashfn_bswap    = RustRapidHash64<true, UNROLLED_FLAG, PROTECTED_FLAG, false, true, false>,
   $.seedfn          = rapidhash_seed
);

REGISTER_HASH(rust_rapidhash__seed,
   $.desc       = "rapidhash rust, quality::SeedableState::new()",
   $.sort_order = 10,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x9E0838C9,
   $.verification_BE = 0x1C2AC079,
   $.hashfn_native   = RustRapidHash64<false, UNROLLED_FLAG, PROTECTED_FLAG, false, true, true>,
   $.hashfn_bswap    = RustRapidHash64<true, UNROLLED_FLAG, PROTECTED_FLAG, false, true, true>,
   $.seedfn          = create_secrets_from_seed
);

REGISTER_HASH(rust_rapidhash__fast,
   $.desc       = "rapidhash rust, fast::RapidHasher::new()",
   $.sort_order = 20,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xB891F260,
   $.verification_BE = 0x7B75C39E,
   $.hashfn_native   = RustRapidHash64<false, UNROLLED_FLAG, PROTECTED_FLAG, false, false, false>,
   $.hashfn_bswap    = RustRapidHash64<true, UNROLLED_FLAG, PROTECTED_FLAG, false, false, false>,
   $.seedfn          = rapidhash_seed,
   $.badseeddesc     = "Many bad seeds; see rust-rapidhash.cpp for known list",
   $.badseeds        = {
            0x006091b0, 0x00e0c55d, 0x01478255, 0x01ec81ac, 0x02e4a803, 0x03c933b3, 0x046acbda, 0x04ad8a93,
            0x05f3ddd5, 0x06039935, 0x070a4c1b, 0x078e80cb, 0x07bc7d65, 0x091f8f97, 0x0a863af8, 0x0b589405,
            0x0e18b6b2, 0x0f676061, 0x1075f5c4, 0x111672b7, 0x11f9c5e9, 0x129c16ba, 0x13277adb, 0x1762a99f,
            0x17d8fb3c, 0x19975ef4, 0x19a5441a, 0x1b4e344f, 0x1cafd2e0, 0x1e2ead63, 0x1f494a44, 0x1fffd470,
            0x2021bd35, 0x208872f7, 0x23c6a285, 0x27e441f9, 0x28b55059, 0x2ac93903, 0x2c77bb8c, 0x2e0c6201,
            0x2f3be950, 0x30fe2ffe, 0x318f5fea, 0x33c1595e, 0x34975250, 0x368c3ed8, 0x38404ad2, 0x39c895a9,
            0x3acf00e0, 0x3bc4ebd6, 0x3bce27f8, 0x3bf8695e, 0x3dcec869, 0x3ef97476, 0x3f04e611, 0x3f05237f,
            0x3f120003, 0x3f74d662, 0x3ff798b8, 0x4305c20f, 0x4770073c, 0x479243d7, 0x47d17e77, 0x4807af00,
            0x4809299d, 0x484b0bd0, 0x49b4bd9c, 0x4b102850, 0x4cc5e0fa, 0x4dfe94a8, 0x4e8d2f4c, 0x4fe82f84,
            0x5097a007, 0x50a4129a, 0x5176ae27, 0x51a703ee, 0x5313d90f, 0x54c75b97, 0x5684ad3f, 0x570c13b6,
            0x57397e5c, 0x57af7d68, 0x595a4e7c, 0x5a5a5960, 0x5e3927d2, 0x5e59388d, 0x5fc06386, 0x6174688f,
            0x61b33fe7, 0x621c4ab2, 0x630a29a1, 0x65c98e42, 0x664719a6, 0x66953d54, 0x6a18b9c4, 0x6b078e1e,
            0x707defb2, 0x718f35a6, 0x74f64aff, 0x76d0cd3b, 0x7a95d765, 0x7a9d6ed0, 0x7b362944, 0x7b8de12a,
            0x7dbe1bc4, 0x811684be, 0x876755dd, 0x87729579, 0x8897dd8e, 0x896a0120, 0x89dd2818, 0x8ab18982,
            0x8abd49e6, 0x8bc0b8da, 0x8d9ccbf1, 0x90559b9b, 0x9130a2c5, 0x92353cd0, 0x9563da70, 0x966e10cf,
            0x96f717f1, 0x983bca81, 0x98a57a5a, 0x9a17c9f2, 0x9ad93c3a, 0x9b19c002, 0x9bc11f2a, 0x9c2736af,
            0x9da3d125, 0x9e29bedf, 0x9e4cfb24, 0x9fa5a30d, 0x9ffb6796, 0xa14d99e6, 0xa277a48e, 0xa31dab49,
            0xa43233c9, 0xa4c56836, 0xa5286d19, 0xa562c81d, 0xa61c5526, 0xa691db21, 0xa8bcbbd7, 0xa90e048d,
            0xaacceac1, 0xaca37850, 0xb3040889, 0xb546ff8c, 0xb60c0eed, 0xb647af3f, 0xb69eabaf, 0xb6b8c16c,
            0xb9e69d89, 0xb9f355df, 0xbba90dab, 0xbca434f9, 0xbd39c7f2, 0xc464d83c, 0xc69d0e42, 0xc932cb08,
            0xca78f43f, 0xcd7d879f, 0xcf0a6a0a, 0xcf5424c8, 0xcf580fd6, 0xd0b41933, 0xd0dc5dfc, 0xd10c2288,
            0xd1f49c21, 0xd2a5d96d, 0xd2e43950, 0xd45f4239, 0xd98d7707, 0xd9c53771, 0xd9e5b4a9, 0xda0eadad,
            0xdc997cc7, 0xdcbd4663, 0xdce54b18, 0xdd24b884, 0xdd562528, 0xdfdb4af6, 0xe0e442f7, 0xe1aef272,
            0xe4b55a34, 0xe4d53f83, 0xe535f642, 0xe5cf27e6, 0xe72db555, 0xe75ee1a7, 0xe8265e42, 0xea994d3d,
            0xeaaf72f9, 0xeb585260, 0xec6fc1d6, 0xec6fd214, 0xee9d27f8, 0xeef6cb11, 0xf05f4efc, 0xf2d6d683,
            0xf2e5d6d3, 0xf39ab966, 0xf3ab4da0, 0xf4192b4b, 0xf428d555, 0xf441ace9, 0xf786c710, 0xf7e3b622,
            0xf8bdc795, 0xf8d1066b, 0xf9d9b0f7, 0xfb1f5813, 0xfbc10367, 0xfbd7d460, 0xfddefd49, 0xfeb08a75,
            0xfefb2dfe, 0xffffffff00daff1f, 0xffffffff011f2554, 0xffffffff0352eb83, 0xffffffff0493393b,
            0xffffffff08f7fd3c, 0xffffffff0a530476, 0xffffffff0ccff3b6, 0xffffffff0cf28bf6,
            0xffffffff0d5e51d0, 0xffffffff0d8cf236, 0xffffffff104d78ac, 0xffffffff10f011c1,
            0xffffffff116ee4ec, 0xffffffff14934997, 0xffffffff14ba3231, 0xffffffff15c991cb,
            0xffffffff16ad48c2, 0xffffffff16f1544c, 0xffffffff18ba60f7, 0xffffffff192cbfa0,
            0xffffffff1d388935, 0xffffffff1deda067, 0xffffffff20fe702c, 0xffffffff21650829,
            0xffffffff2175e692, 0xffffffff21857de0, 0xffffffff22ebb0f5, 0xffffffff230c5c64,
            0xffffffff23230b5a, 0xffffffff26b54fd6, 0xffffffff274a3c51, 0xffffffff279e5744,
            0xffffffff27c36508, 0xffffffff2839810b, 0xffffffff289f3c28, 0xffffffff2a5bbde9,
            0xffffffff2b061b72, 0xffffffff2ca15138, 0xffffffff3054e364, 0xffffffff3123259a,
            0xffffffff3257f065, 0xffffffff3348a78b, 0xffffffff338ea163, 0xffffffff3532cba1,
            0xffffffff36349bdd, 0xffffffff3667b83c, 0xffffffff3a07ce4f, 0xffffffff3a7e2030,
            0xffffffff3b2dc859, 0xffffffff3b95fcc8, 0xffffffff3bc5031e, 0xffffffff3f994c60,
            0xffffffff405af3ab, 0xffffffff421898fa, 0xffffffff43545695, 0xffffffff44184311,
            0xffffffff443d617e, 0xffffffff4829e519, 0xffffffff488c5716, 0xffffffff48986588,
            0xffffffff48f0c679, 0xffffffff490772a0, 0xffffffff49708c13, 0xffffffff4b38b47c,
            0xffffffff4b6f3e66, 0xffffffff4b86ac21, 0xffffffff4c3dcc69, 0xffffffff4f87aaeb,
            0xffffffff52455614, 0xffffffff52d19434, 0xffffffff54b73287, 0xffffffff56f2f62d,
            0xffffffff57d70c5c, 0xffffffff58e0305e, 0xffffffff58ed9522, 0xffffffff5a0f3f59,
            0xffffffff5ac6dac1, 0xffffffff5b2c9834, 0xffffffff5cac8a93, 0xffffffff5d1c7398,
            0xffffffff5e71e2c5, 0xffffffff5e88a1b1, 0xffffffff5f1f269a, 0xffffffff5fc92832,
            0xffffffff5fd170e0, 0xffffffff604a8acc, 0xffffffff65ed839a, 0xffffffff661c78ec,
            0xffffffff66d29d9f, 0xffffffff6883e1b5, 0xffffffff68f22cb2, 0xffffffff6a41931e,
            0xffffffff6a8671f3, 0xffffffff6b2cdc1f, 0xffffffff6b5ddfd0, 0xffffffff6b9fc369,
            0xffffffff6bae49b9, 0xffffffff6c57b51f, 0xffffffff6e325565, 0xffffffff714e348b,
            0xffffffff717730a1, 0xffffffff726cb66c, 0xffffffff7528a7ce, 0xffffffff764315eb,
            0xffffffff7a00520a, 0xffffffff7a4aa491, 0xffffffff7afd058d, 0xffffffff7b498fde,
            0xffffffff7b52c8c7, 0xffffffff7b769086, 0xffffffff7b78cc93, 0xffffffff7c94024a,
            0xffffffff7dc37f07, 0xffffffff7dd2befa, 0xffffffff7e433a0b, 0xffffffff7e730d03,
            0xffffffff7ea0b4fc, 0xffffffff7f807381, 0xffffffff81152679, 0xffffffff81b6a801,
            0xffffffff8227c170, 0xffffffff8286ba70, 0xffffffff838c1414, 0xffffffff83d0e436,
            0xffffffff83eb7e49, 0xffffffff8407954c, 0xffffffff846f634d, 0xffffffff85c0dbcd,
            0xffffffff869a2ecd, 0xffffffff89912b00, 0xffffffff8b4b6fd3, 0xffffffff8d00d9dd,
            0xffffffff8e2cab94, 0xffffffff909777bf, 0xffffffff914a2ac4, 0xffffffff9173c42d,
            0xffffffff9350a593, 0xffffffff9362cc3f, 0xffffffff93969835, 0xffffffff942d9214,
            0xffffffff94f79935, 0xffffffff97588898, 0xffffffff97740a54, 0xffffffff97937fc1,
            0xffffffff9b71c57b, 0xffffffff9c841728, 0xffffffff9cd8c9fd, 0xffffffff9e4d0a45,
            0xffffffff9eaa8988, 0xffffffffa02d0e41, 0xffffffffa255e2bb, 0xffffffffa4441bd9,
            0xffffffffa80f85b5, 0xffffffffaa599dd4, 0xffffffffaa605ff9, 0xffffffffafc7b019,
            0xffffffffb3b247d1, 0xffffffffb4430cf2, 0xffffffffb4764b68, 0xffffffffb5945d74,
            0xffffffffb5a46157, 0xffffffffb90e644b, 0xffffffffbaec046d, 0xffffffffbd50d72b,
            0xffffffffbdc52bed, 0xffffffffbdebc076, 0xffffffffbea5be85, 0xffffffffc0468f41,
            0xffffffffc17b7515, 0xffffffffc410f051, 0xffffffffc557348a, 0xffffffffc6bd8f83,
            0xffffffffc7736d73, 0xffffffffcbcfd0a5, 0xffffffffcbd55602, 0xffffffffcc75dc74,
            0xffffffffce6a11ee, 0xffffffffce90bdc8, 0xffffffffceb21440, 0xffffffffd0c53142,
            0xffffffffd1e1090c, 0xffffffffd382ef36, 0xffffffffd3fd5596, 0xffffffffd42f1abc,
            0xffffffffd4387d1f, 0xffffffffd4764e98, 0xffffffffd494a106, 0xffffffffd624bb1f,
            0xffffffffd7337c7a, 0xffffffffd8703faa, 0xffffffffd99ed440, 0xffffffffd9bd0b3a,
            0xffffffffda6764f3, 0xffffffffdb03266a, 0xffffffffdb4c2eef, 0xffffffffdcfb9bd2,
            0xffffffffdd64d4cf, 0xffffffffde7a9574, 0xffffffffdf4073d4, 0xffffffffdf5cb774,
            0xffffffffdf9d4c29, 0xffffffffe0b16dcd, 0xffffffffe45d405d, 0xffffffffe5689cb4,
            0xffffffffe595e78f, 0xffffffffe609983c, 0xffffffffe6d4984e, 0xffffffffe84379ee,
            0xffffffffe89d46ef, 0xffffffffea26fe56, 0xffffffffecf33496, 0xffffffffed644ea2,
            0xffffffffed9443e7, 0xffffffffee4ee4b8, 0xffffffffeeb4df72, 0xffffffffef3cf9e7,
            0xffffffffef71d6ba, 0xfffffffff00a401b, 0xfffffffff01eeb0f, 0xfffffffff09bcb5a,
            0xfffffffff2951685, 0xfffffffff469d078, 0xfffffffff506ad9d, 0xfffffffff507891f,
            0xfffffffff5af211d, 0xfffffffff6305f88, 0xfffffffff67616c0, 0xfffffffff8a44825,
            0xfffffffff8caa1fb, 0xfffffffff95d1c06, 0xfffffffffbdf73fc, 0xfffffffffbff89f3,
            0xfffffffffc5e0ba5, 0xfffffffffca53082, 0xffffffffff894ead,
   }
);

REGISTER_HASH(rust_rapidhash__fast__seed,
   $.desc       = "rapidhash rust, fast::SeedableState::new()",
   $.sort_order = 30,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xC3100741,
   $.verification_BE = 0x62C5E469,
   $.hashfn_native   = RustRapidHash64<false, UNROLLED_FLAG, PROTECTED_FLAG, false, false, true>,
   $.hashfn_bswap    = RustRapidHash64<true, UNROLLED_FLAG, PROTECTED_FLAG, false, false, true>,
   $.seedfn          = create_secrets_from_seed
);

REGISTER_HASH(rust_rapidhash__p,
   $.desc       = "rapidhash rust, quality::RapidHasher::new(), no wide mult",
   $.sort_order = 40,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x77BCDA91,
   $.verification_BE = 0xF30CC344,
   $.hashfn_native   = RustRapidHash64<false, UNROLLED_FLAG, PROTECTED_FLAG, true, true, false>,
   $.hashfn_bswap    = RustRapidHash64<true, UNROLLED_FLAG, PROTECTED_FLAG, true, true, false>,
   $.seedfn          = rapidhash_seed
);

REGISTER_HASH(rust_rapidhash__p__seed,
   $.desc       = "rapidhash rust, quality::SeedableState::new(), no wide mult",
   $.sort_order = 50,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xC31AF1C5,
   $.verification_BE = 0x617E996C,
   $.hashfn_native   = RustRapidHash64<false, UNROLLED_FLAG, PROTECTED_FLAG, true, true, true>,
   $.hashfn_bswap    = RustRapidHash64<true, UNROLLED_FLAG, PROTECTED_FLAG, true, true, true>,
   $.seedfn          = create_secrets_from_seed
);

REGISTER_HASH(rust_rapidhash__p__fast,
   $.desc       = "rapidhash rust, fast::RapidHasher::new(), no wide mult",
   $.sort_order = 60,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x2955B659,
   $.verification_BE = 0x9D0F120C,
   $.hashfn_native   = RustRapidHash64<false, UNROLLED_FLAG, PROTECTED_FLAG, true, false, false>,
   $.hashfn_bswap    = RustRapidHash64<true, UNROLLED_FLAG, PROTECTED_FLAG, true, false, false>,
   $.seedfn          = rapidhash_seed
);

REGISTER_HASH(rust_rapidhash__p__fast__seed,
   $.desc       = "rapidhash rust, fast::SeedableState::new(), no wide mult",
   $.sort_order = 70,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xDB1D8A21,
   $.verification_BE = 0x64BAB88E,
   $.hashfn_native   = RustRapidHash64<false, UNROLLED_FLAG, PROTECTED_FLAG, true, false, true>,
   $.hashfn_bswap    = RustRapidHash64<true, UNROLLED_FLAG, PROTECTED_FLAG, true, false, true>,
   $.seedfn          = create_secrets_from_seed
);
