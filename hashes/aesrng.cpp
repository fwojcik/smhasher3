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

#include "AES.h"

#include <algorithm>
#include <cassert>

//------------------------------------------------------------
// This uses bog-standard AES encryption to generate random numbers. This
// is not strictly AES CTR mode, it is based on that plus the ARS RNG
// constructions.

/* K1 is golden ratio - 1, K2 is sqrt(3) - 1 */
#define K1    UINT64_C(0x9E3779B97F4A7C15)
#define K2    UINT64_C(0xBB67AE8584CAA73B)
#define INCR1 UINT64_C(+1)
#define INCR2 UINT64_C(-1)

//------------------------------------------------------------
// RNG global state initialization

static uint8_t round_keys[44 * 4]; // only modified on main thread

// A little ugly...
extern seed_t g_seed;

static bool aesrng_init( void ) {
    uint8_t key[16];

    if (isLE()) {
        PUT_U64<false>(g_seed + K1, key, 0);
        PUT_U64<false>(g_seed + K2, key, 8);
    } else {
        PUT_U64<true>(g_seed + K1, key, 0);
        PUT_U64<true>(g_seed + K2, key, 8);
    }

    AES_KeySetup_Enc(round_keys, key, 128);

    return true;
}

//------------------------------------------------------------
// RNG state management for threaded testing
//
// These complications are intended to make this "hash" return the same
// results if threading is enabled or not. For non-threaded tests, the RNG
// just increments the global counters for each "hash". When tests _might_
// be threaded, it switches to an alternate mode where the RNG is
// frequently re-keyed based on the input parameters and data, and so the
// output values instead depend upon the thread-local ctr[] values in the
// content_t struct, no matter which thread is running.
//
// In this way, the main thread's ctr value just after a set of
// possibly-threaded tests will match the ctr value from just before the
// tests. So the main thread's results should be unaffected if threading is
// enabled or disabled, or if the possibly-threaded tests are skipped, and
// the per-thread results should be unaffected by the number of threads, or
// by whatever tests happened before.
//
// It makes the following assumptions about the rest of the code:
//
// 1) aesrng_seedfix() will always be called (at the least) before
//    each group of tests, before any hash() invocation is made in
//    those tests.
// 2) For each group of tests, aesrng_seedfix() may be called in each
//    worker thread or the main thread, or even both.
// 3) The hint passed to aesrng_seedfix() will indicate the start of a
//    possibly-threaded set of tests. A hint value of 1 means
//    possibly-threaded, and 0 means definitely-unthreaded.
// 4) If threading is being used, the main thread WILL NOT call hash()
//    until another aesrng_seedfix() call with hint set appropriately.
// 5) The work done by possibly-threaded tests is identical to the work
//    done if threading is disabled, but threading may arbitrarily
//    re-order that work.
// 6) There is enough time such that writes to hash_mode from the main
//    thread become visible to worker threads by the time they start, and
//    that writes in a worker_thread are visible to the main thread by the
//    time it starts the following test suite.

// NB: these variables are _not_ thread-local
static seed_t hash_mode;
static uint64_t ctr[2];

struct content_t {
    uint64_t ctr[2];
    uint64_t prev_blk;
    uint64_t prev_seed;
    size_t   prev_len = UINT32_C(-1);
};
static thread_local struct content_t cstate;

// Note that HashInfo::getFixedSeed() can call this with a real hinfo
// value; if it does, just return the seed unchanged. Note also that
// because the hint value is supplied by HashInfo::Seed(), it ignores the
// return value of this function.
static seed_t aesrng_seedfix( const HashInfo * hinfo, const seed_t hint ) {
    if (hinfo == NULL) {
        hash_mode = hint;
        // Just in case we're on the main thread about to do hashing
        if (hint != 0) {
            cstate.prev_len = UINT32_C(-1);
        }
    }

    return hint;
}

// This makes the RNG depend on the data to be "hashed". It is only used
// for possibly-threaded tests.
//
// Since the whole goal here is to cheat and not examine every byte of the
// input data, yet still return consistent hash values even if we are
// threaded and can't know what the hypothetical "global" counter value
// would be for this call to hash(), something clever needs to be done.
//
// This code detects if any of the hash() input parameters changed in an
// important way, and, if they have, saves all the new parameters and
// rekeys the RNG based on an arbitrary mashup of the 64-bit seed value,
// the length of the input data, and the first up-to-8 bytes of that data.
//
// The test for "changed in an important way" takes advantage of the
// (recently true) property of the possibly-threaded tests where, if a
// batch of similar keys of the same length are being tested with the same
// seed, then a baseline key is hash()ed first, and only 1 key bit is
// altered from that baseline for each subsequent call to hash(), until a
// new baseline key is used, which must differ from the previous baseline
// key by at least 2 bits. This is what the popcount8() test is for. In
// this way, even if the test is currently testing a bit far beyond the
// 64th, the first 8 bytes will still match the baseline, so the rekey
// won't happen spuriously.
//
// Note that using atomic values for a real global counter wouldn't
// substitute for this, because there could be arbitrary delays between a
// given thread taking the next work item off of the existing global queue
// and that same thread calling hash() for even the first time on that
// item. We could maybe cheat if we had access to the existing global
// counter, but setting that up that access would be more API-breaking than
// even this "seed hint" / alternate mode mess.
static void rng_keyseq( struct content_t * s, const void * key, size_t len, uint64_t seed ) {
    uint64_t blk = 0;
    memcpy(&blk, key, std::min(len, (size_t)8));

    if ((s->prev_len != len) || (s->prev_seed != seed) || (popcount8(s->prev_blk ^ blk) > 1)) {
        s->prev_len   = len;
        s->prev_blk   = blk;
        s->prev_seed  = seed;

        blk           = COND_BSWAP(blk, isBE());
        blk          ^= len  * K2;
        seed         ^= blk  * K1;
        blk          ^= seed * K2;
        s->ctr[0]     = seed;
        s->ctr[1]     = blk;
    }
}

//------------------------------------------------------------
// The RNG core code

static uint64_t aesrng64( uint64_t * ctrs ) {
    uint8_t result[16];

    ctrs[0] += INCR1;
    ctrs[1] += INCR2;

    if (isLE()) {
        PUT_U64<false>(ctrs[0], result, 0);
        PUT_U64<false>(ctrs[1], result, 8);
    } else {
        PUT_U64<true>(ctrs[0], result, 0);
        PUT_U64<true>(ctrs[1], result, 8);
    }

    AES_Encrypt<10>(round_keys, result, result);

    // The result will get put into the output buffer from this return
    // value via memcpy(), so just using native endianness is fine.
    return GET_U64<false>(result, 0);
}

template <uint32_t nbytes>
static void rng_impl( uint64_t * ctrs, void * out ) {
    assert((nbytes >= 0) && (nbytes <= 39));
    uint8_t * result = (uint8_t *)out;
    if (nbytes >= 8) {
        uint64_t r = aesrng64(ctrs);
        memcpy(result, &r, 8);
        result += 8;
    }
    if (nbytes >= 16) {
        uint64_t r = aesrng64(ctrs);
        memcpy(result, &r, 8);
        result += 8;
    }
    if (nbytes >= 24) {
        uint64_t r = aesrng64(ctrs);
        memcpy(result, &r, 8);
        result += 8;
    }
    if (nbytes >= 32) {
        uint64_t r = aesrng64(ctrs);
        memcpy(result, &r, 8);
        result += 8;
    }
    if ((nbytes % 8) != 0) {
        uint64_t r = aesrng64(ctrs);
        memcpy(result, &r, nbytes % 8);
    }
}

// Note that this _cannot_ use the seed-as-uintptr trick because Seed()
// might have been called on the main thread, which would give the same
// pointer to each worker thread. That doesn't work for this hash because
// the contents of cstate are written to, and are therefore different,
// per-thread. So the thread-local pointer must be looked up every time.
template <uint32_t hashbits>
static void aesrng( const void * in, const size_t len, const seed_t seed, void * out ) {
    if (hash_mode == 0) {
        rng_impl<(hashbits >> 3)>(ctr, out);
    } else {
        rng_keyseq(&cstate, in, len, seed);
        rng_impl<(hashbits >> 3)>(cstate.ctr, out);
    }
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
   $.verification_LE = 0x7FBE21B3,
   $.verification_BE = 0x7FBE21B3,
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
   $.verification_LE = 0x0176B234,
   $.verification_BE = 0x0176B234,
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
   $.verification_LE = 0xF09383D0,
   $.verification_BE = 0xF09383D0,
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
   $.verification_LE = 0xD0BF5177,
   $.verification_BE = 0xD0BF5177,
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
   $.verification_LE = 0x902F4DF3,
   $.verification_BE = 0x902F4DF3,
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
   $.verification_LE = 0xE54E472C,
   $.verification_BE = 0xE54E472C,
   $.hashfn_native   = aesrng<256>,
   $.hashfn_bswap    = aesrng<256>,
   $.initfn          = aesrng_init,
   $.seedfixfn       = aesrng_seedfix,
   $.sort_order      = 50
 );
