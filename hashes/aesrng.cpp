/*
 * AES(CTR-mode)-based strong RNG
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
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

// This uses bog-standard AES encryption
#include "AES.h"

#include <cassert>

//------------------------------------------------------------
// This is not strictly AES CTR mode, it is based on that plus the ARS
// RNG constructions.

static thread_local uint64_t ctr[2], oldctr[2];
static const uint64_t        incr[2] = { UINT64_C(1), UINT64_C(-1) };
static uint32_t round_keys[44]; // only modified on main thread

// A little ugly...
extern seed_t g_seed;

/* K1 is golden ratio - 1, K2 is sqrt(3) - 1 */
#define K1 UINT64_C(0x9E3779B97F4A7C15)
#define K2 UINT64_C(0xBB67AE8584CAA73B)

static bool aesrng_init( void ) {
    uint8_t key[16];

    if (isLE()) {
        PUT_U64<false>(g_seed + K2, key, 0);
        PUT_U64<false>(g_seed + K1, key, 8);
    } else {
        PUT_U64<true>(g_seed + K2, key, 0);
        PUT_U64<true>(g_seed + K1, key, 8);
    }
    AES_KeySetup_Enc(round_keys, key, 128);
    ctr[0] = incr[0]; ctr[1] = incr[1];
    return true;
}

static uint64_t rnd64( void ) {
    uint8_t result[16];

    if (isLE()) {
        PUT_U64<false>(ctr[0], result, 0);
        PUT_U64<false>(ctr[1], result, 8);
    } else {
        PUT_U64<true>(ctr[0], result, 0);
        PUT_U64<true>(ctr[1], result, 8);
    }
    AES_Encrypt<10>(round_keys, result, result);
    ctr[0] += incr[0]; ctr[1] += incr[1];
    // The result will get put into the output buffer from this return
    // value via memcpy(), so just using native endianness is fine.
    return GET_U64<false>(result, 0);
}

static void rng_ffwd( int64_t ffwd ) {
    ctr[0] += ffwd; ctr[1] -= ffwd;
}

static void rng_setctr( uint64_t stream, uint64_t seq ) {
    ctr[0] = seq; ctr[1] = stream;
}

// This variable is _not_ thread-local
static uint64_t hash_mode;

// These complications are intended to make this "hash" return the
// same results if threading is enabled or not. It makes the following
// assumptions about the rest of the code:
//
// 1) aesrng_seedfix() will always be called (at the least) before
//    each group of tests, before any hash() invocation is made in
//    those tests.
// 2) aesrng_seedfix() may be called in each worker thread or the main
//    thread.
// 3) The hint passed to aesrng_seedfix() will indicate the start of a
//    possibly-threaded set of tests.
// 4) If threading is being used, the main thread WILL NOT call hash()
//    until another aesrng_seedfix() call with hint set appropriately.
// 5) The work done by threaded tests is identical to the work done if
//    threading is disabled, but threading may arbitrarily re-order
//    that work.
//
// In this way, the main thread's ctr value just after a set of
// possibly-threaded tests will match the ctr value from just before
// the tests. The value provided during the possibly-threaded tests
// will depend upon the length and first 64 bytes of data being hashed
// and the seed, and not upon the previous ctr value. So the main
// thread's results should be unaffected if threading is enabled or
// disabled, or if the possibly-threaded tests are skipped, and the
// per-thread results should be unaffected by the number of threads.
static seed_t aesrng_seedfix( const HashInfo * hinfo, const seed_t hint ) {
    if (hash_mode == hint) {
        oldctr[0] = ctr[0];
        oldctr[1] = ctr[1];
    } else {
        hash_mode = hint;
        ctr[0]    = oldctr[0];
        ctr[1]    = oldctr[1];
    }
    return 0;
}

// This makes the RNG depend on the data to "hash". It is only used
// for possibly-threaded tests.
//
// For hash_mode 1, this just makes random numbers returned be based
// on the seed and first block of data.
//
// Hash_mode 2 is for Avalanche, which is very hard to fool in a
// consistent way, so we have some magic knowledge of how it calls us.
//
// Hash mode 3 is for BIC, where we also have some magic knowledge of
// how it calls us. BIC could work with hash mode 1 if we wanted to
// quickly mix together all the input words for a seed, but we don't.
static thread_local uint64_t callcount;

static void rng_keyseq( const void * key, size_t len, uint64_t seed ) {
    if (hash_mode == 3) {
        if (callcount-- != 0) {
            return;
        }
        callcount = 1;
    } else if (hash_mode == 2) {
        if (callcount-- != 0) {
            return;
        }
        callcount = (8 * len);
    }
    uint64_t s = 0;
    memcpy(&s, key, len > 8 ? 8 : len);
    s     = COND_BSWAP(s, isBE());
    s    ^= len * K2;
    seed ^= s * K1;
    s    ^= seed * K2;
    rng_setctr(s, seed);
}

template <uint32_t nbytes>
static void rng_impl( void * out ) {
    assert((nbytes >= 0) && (nbytes <= 39));
    uint8_t * result = (uint8_t *)out;
    if (nbytes >= 8) {
        uint64_t r = rnd64();
        memcpy(result, &r, 8);
        result += 8;
    }
    if (nbytes >= 16) {
        uint64_t r = rnd64();
        memcpy(result, &r, 8);
        result += 8;
    }
    if (nbytes >= 24) {
        uint64_t r = rnd64();
        memcpy(result, &r, 8);
        result += 8;
    }
    if (nbytes >= 32) {
        uint64_t r = rnd64();
        memcpy(result, &r, 8);
        result += 8;
    }
    if ((nbytes % 8) != 0) {
        uint64_t r = rnd64();
        memcpy(result, &r, nbytes % 8);
    }
}

template <uint32_t hashbits>
static void aesrng( const void * in, const size_t len, const seed_t seed, void * out ) {
    if (hash_mode != 0) {
        rng_keyseq(in, len, seed);
    }
    rng_impl<(hashbits >> 3)>(out);
}

REGISTER_FAMILY(aesrng,
   $.src_url    = "https://gitlab.com/fwojcik/smhasher3/-/blob/main/hashes/aesrng.cpp",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(aesrng_32,
   $.desc       = "32-bit RNG using AES in CTR mode; not a hash",
   $.impl       = AES_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_MOCK                |
         FLAG_HASH_AES_BASED           |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS        |
         FLAG_IMPL_SEED_WITH_HINT      |
         FLAG_IMPL_CANONICAL_BOTH      |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0xED1590AC,
   $.verification_BE = 0xED1590AC,
   $.hashfn_native   = aesrng<32>,
   $.hashfn_bswap    = aesrng<32>,
   $.initfn          = aesrng_init,
   $.seedfixfn       = aesrng_seedfix,
   $.sort_order      = 50
 );

REGISTER_HASH(aesrng_64,
   $.desc       = "64-bit RNG using AES in CTR mode; not a hash",
   $.impl       = AES_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_MOCK                |
         FLAG_HASH_AES_BASED           |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS        |
         FLAG_IMPL_SEED_WITH_HINT      |
         FLAG_IMPL_CANONICAL_BOTH      |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xAE36B667,
   $.verification_BE = 0xAE36B667,
   $.hashfn_native   = aesrng<64>,
   $.hashfn_bswap    = aesrng<64>,
   $.initfn          = aesrng_init,
   $.seedfixfn       = aesrng_seedfix,
   $.sort_order      = 50
 );

REGISTER_HASH(aesrng_128,
   $.desc       = "128-bit RNG using AES in CTR mode; not a hash",
   $.impl       = AES_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_MOCK                |
         FLAG_HASH_AES_BASED           |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS        |
         FLAG_IMPL_SEED_WITH_HINT      |
         FLAG_IMPL_CANONICAL_BOTH      |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x2D1A1DB5,
   $.verification_BE = 0x2D1A1DB5,
   $.hashfn_native   = aesrng<128>,
   $.hashfn_bswap    = aesrng<128>,
   $.initfn          = aesrng_init,
   $.seedfixfn       = aesrng_seedfix,
   $.sort_order      = 50
 );

REGISTER_HASH(aesrng_160,
   $.desc       = "160-bit RNG using AES in CTR mode; not a hash",
   $.impl       = AES_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_MOCK                |
         FLAG_HASH_AES_BASED           |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS        |
         FLAG_IMPL_SEED_WITH_HINT      |
         FLAG_IMPL_CANONICAL_BOTH      |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 160,
   $.verification_LE = 0x3FC284C3,
   $.verification_BE = 0x3FC284C3,
   $.hashfn_native   = aesrng<160>,
   $.hashfn_bswap    = aesrng<160>,
   $.initfn          = aesrng_init,
   $.seedfixfn       = aesrng_seedfix,
   $.sort_order      = 50
 );

REGISTER_HASH(aesrng_224,
   $.desc       = "224-bit RNG using AES in CTR mode; not a hash",
   $.impl       = AES_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_MOCK                |
         FLAG_HASH_AES_BASED           |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS        |
         FLAG_IMPL_SEED_WITH_HINT      |
         FLAG_IMPL_CANONICAL_BOTH      |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 224,
   $.verification_LE = 0x9288A516,
   $.verification_BE = 0x9288A516,
   $.hashfn_native   = aesrng<224>,
   $.hashfn_bswap    = aesrng<224>,
   $.initfn          = aesrng_init,
   $.seedfixfn       = aesrng_seedfix,
   $.sort_order      = 50
 );

REGISTER_HASH(aesrng_256,
   $.desc       = "256-bit RNG using AES in CTR mode; not a hash",
   $.impl       = AES_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_MOCK                |
         FLAG_HASH_AES_BASED           |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS        |
         FLAG_IMPL_SEED_WITH_HINT      |
         FLAG_IMPL_CANONICAL_BOTH      |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 256,
   $.verification_LE = 0x2816EEC1,
   $.verification_BE = 0x2816EEC1,
   $.hashfn_native   = aesrng<256>,
   $.hashfn_bswap    = aesrng<256>,
   $.initfn          = aesrng_init,
   $.seedfixfn       = aesrng_seedfix,
   $.sort_order      = 50
 );
