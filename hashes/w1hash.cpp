/*
 * w1hash
 * Copyright (C) 2025  Frank J. T. Wojcik
 * Copyright (c) 2024, 阮坤良
 * Copyright (c) 2024, Ruan Kunliang.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "Platform.h"
#include "Hashlib.h"
#include "Mathmult.h"

//------------------------------------------------------------
// This is a variant of wyhash
// (https://github.com/wangyi-fudan/wyhash). It's optimized for short
// input, and faster than wyhash in such workflows.

//------------------------------------------------------------
// Data-reading functions
#if defined(__amd64__) || defined(__aarch64__) || defined(_M_AMD64) || defined(_M_ARM64)
  #define SM3_W1_UB_READS 1
#else
  #define SM3_W1_UB_READS 0
#endif

static const char * w1_readimpl_str[] = {
    "portable",
    "ub_reads",
};

static inline uint64_t _w1r1( const uint8_t * p ) { return *p; }

#if SM3_W1_UB_READS == 1
  #define W1_PAGE_SIZE 4096

static inline uint64_t _w1r2( const uint8_t * p ) { return *(uint16_t *)p; }

static inline uint64_t _w1r4( const uint8_t * p ) { return *(uint32_t *)p; }

static inline uint64_t _w1r8( const uint8_t * p ) { return *(uint64_t *)p; }

static inline uint64_t _w1r3( const uint8_t * p ) {
    if (((uintptr_t)p & (W1_PAGE_SIZE - 1)) <= W1_PAGE_SIZE - 4) {
        return _w1r4(p) & ((UINT64_C(1) << 24) - 1);
    }
    return _w1r2(p) | (_w1r1(p + 2) << 16);
}

static inline uint64_t _w1r5( const uint8_t * p ) {
    if (((uintptr_t)p & (W1_PAGE_SIZE - 1)) <= W1_PAGE_SIZE - 8) {
        return _w1r8(p) & ((UINT64_C(1) << 40) - 1);
    }
    return _w1r4(p) | (_w1r1(p + 4) << 32);
}

static inline uint64_t _w1r6( const uint8_t * p ) {
    if (((uintptr_t)p & (W1_PAGE_SIZE - 1)) <= W1_PAGE_SIZE - 8) {
        return _w1r8(p) & ((UINT64_C(1) << 48) - 1);
    }
    return _w1r4(p) | (_w1r2(p + 4) << 32);
}

static inline uint64_t _w1r7( const uint8_t * p ) {
    if (((uintptr_t)p & (W1_PAGE_SIZE - 1)) <= W1_PAGE_SIZE - 8) {
        return _w1r8(p) & ((UINT64_C(1) << 56) - 1);
    }
    return _w1r4(p) | (_w1r2(p + 4) << 32) | (_w1r1(p + 6) << 48);
}

  #undef W1_PAGE_SIZE
#else

static inline uint64_t _w1r2( const uint8_t * p ) { return _w1r1(p) | (_w1r1(p + 1) <<  8); }

static inline uint64_t _w1r3( const uint8_t * p ) { return _w1r2(p) | (_w1r1(p + 2) << 16); }

static inline uint64_t _w1r4( const uint8_t * p ) { return _w1r2(p) | (_w1r2(p + 2) << 16); }

static inline uint64_t _w1r5( const uint8_t * p ) { return _w1r4(p) | (_w1r1(p + 4) << 32); }

static inline uint64_t _w1r6( const uint8_t * p ) { return _w1r4(p) | (_w1r2(p + 4) << 32); }

static inline uint64_t _w1r7( const uint8_t * p ) { return _w1r4(p) | (_w1r2(p + 4) << 32)  | (_w1r1(p + 6) << 48); }

static inline uint64_t _w1r8( const uint8_t * p ) { return _w1r4(p) | (_w1r4(p + 4) << 32); }

#endif

//------------------------------------------------------------
// Hash implementation
typedef struct {
    uint64_t  a;
    uint64_t  b;
} _w1u128;

static inline _w1u128 _w1mum( uint64_t a, uint64_t b ) {
    _w1u128 x;

    MathMult::mult64_128(x.a, x.b, a, b);
    return x;
}

static inline uint64_t _w1mix( uint64_t a, uint64_t b ) {
    _w1u128 t = _w1mum(a, b);

    return t.a ^ t.b;
}

static inline uint64_t w1hash_with_seed( const void * key, size_t len, uint64_t seed ) {
    const uint64_t s0 = UINT64_C(0x2d358dccaa6c78a5);
    const uint64_t s1 = UINT64_C(0x8bb84b93962eacc9);
    const uint64_t s2 = UINT64_C(0x4b33a62ed433d4a3);
    const uint64_t s3 = UINT64_C(0x4d5a2da51de1aa47);

    seed ^= _w1mix(seed ^ s0, len ^ s1);

    _w1u128         t;
    const uint8_t * p = (const uint8_t *)key;
    size_t          l = len;
  _w1_tail:
    switch (l) {
    case  0: t.a = 0;        t.b = 0; break;
    case  1: t.a = _w1r1(p); t.b = 0; break;
    case  2: t.a = _w1r2(p); t.b = 0; break;
    case  3: t.a = _w1r3(p); t.b = 0; break;
    case  4: t.a = _w1r4(p); t.b = 0; break;
    case  5: t.a = _w1r5(p); t.b = 0; break;
    case  6: t.a = _w1r6(p); t.b = 0; break;
    case  7: t.a = _w1r7(p); t.b = 0; break;
    case  8: t.a = _w1r8(p); t.b = 0; break;
    case  9: t.a = _w1r8(p); t.b = _w1r1(p + 8); break;
    case 10: t.a = _w1r8(p); t.b = _w1r2(p + 8); break;
    case 11: t.a = _w1r8(p); t.b = _w1r3(p + 8); break;
    case 12: t.a = _w1r8(p); t.b = _w1r4(p + 8); break;
    case 13: t.a = _w1r8(p); t.b = _w1r5(p + 8); break;
    case 14: t.a = _w1r8(p); t.b = _w1r6(p + 8); break;
    case 15: t.a = _w1r8(p); t.b = _w1r7(p + 8); break;
    case 16: t.a = _w1r8(p); t.b = _w1r8(p + 8); break;
    default:
             if (l > 64) {
                 uint64_t x = seed;
                 uint64_t y = seed;
                 uint64_t z = seed;
                 do {
                     seed = _w1mix(_w1r8(p)      ^ s0, _w1r8(p +  8) ^ seed);
                     x    = _w1mix(_w1r8(p + 16) ^ s1, _w1r8(p + 24) ^ x   );
                     y    = _w1mix(_w1r8(p + 32) ^ s2, _w1r8(p + 40) ^ y   );
                     z    = _w1mix(_w1r8(p + 48) ^ s3, _w1r8(p + 56) ^ z   );
                     p   += 64;
                     l   -= 64;
                 } while (l > 64);
                 seed ^= x ^ y ^ z;
             }
             if (l > 32) {
                 uint64_t x = seed;
                 seed  = _w1mix(_w1r8(p)      ^ s0, _w1r8(p +  8) ^ seed);
                 x     = _w1mix(_w1r8(p + 16) ^ s1, _w1r8(p + 24) ^ x   );
                 seed ^= x;
                 p    += 32;
                 l    -= 32;
             }
             if (l > 16) {
                 seed = _w1mix(_w1r8(p) ^ s0, _w1r8(p + 8) ^ seed);
                 p   += 16;
                 l   -= 16;
             }
             goto _w1_tail;
    }
    t = _w1mum(t.a ^ s1, t.b ^ seed);
    return _w1mix(t.a ^ (s0 ^ len), t.b ^ s1);
}

//------------------------------------------------------------
template <bool bswap>
static void w1hash( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t hash = w1hash_with_seed(in, len, (uint64_t)seed);

    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(w1hash,
   $.src_url    = "https://github.com/peterrk/w1hash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(w1hash,
   $.desc            = "w1hash",
   $.impl            = w1_readimpl_str[SM3_W1_UB_READS],
   $.hash_flags      =
         0,
   $.impl_flags      =
         FLAG_IMPL_READ_PAST_EOB   |
         FLAG_IMPL_MULTIPLY_64_128 |
         FLAG_IMPL_LICENSE_BSD,
   $.bits            = 64,
   $.verification_LE = 0x648948F1,
   $.verification_BE = 0xD69F31A0,
   $.hashfn_native   = w1hash<false>,
   $.hashfn_bswap    = w1hash<true>
);
