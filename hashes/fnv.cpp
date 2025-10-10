/*
 * FNV and similar hashes
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2014-2021 Reini Urban
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
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of Google Inc. nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "Platform.h"
#include "Hashlib.h"

#include "Mathmult.h"

static seed_t excludeLow32Zero( const HashInfo * hinfo, const seed_t seed ) {
    (void)hinfo; // To mark as used
    if (((uint64_t)seed & 0xFFFFFFFF) == 0x0) {
        return (seed_t)((uint64_t)seed ^ 0xA5A5A5A5);
    }
    return seed;
}

template <typename hashT, bool bswap>
static void fibonacci( const void * in, const size_t len, const seed_t seed, void * out ) {
    hashT         h          = (hashT)seed;
    const hashT * dw         = (const hashT *)in;
    const hashT * const endw = &dw[len / sizeof(hashT)];
    const uint64_t      C    = UINT64_C(11400714819323198485);
    hashT w;

    // word stepper
    while (dw < endw) {
        memcpy(&w, dw++, sizeof(w));
        w  = COND_BSWAP(w, bswap);
        h += w * C;
    }
    // byte stepper
    if (len & (sizeof(hashT) - 1)) {
        uint8_t * dc = (uint8_t *)dw;
        const uint8_t * const endc = &((const uint8_t *)in)[len];
        while (dc < endc) {
            h += *dc++ * C;
        }
    }

    h = COND_BSWAP(h, bswap);
    memcpy(out, &h, sizeof(h));
}

// All seeding below this is homegrown for SMHasher3

template <typename hashT, bool bswap>
static void FNV1a( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * data = (const uint8_t *)in;
    const hashT     C1   = (sizeof(hashT) == 4) ? UINT32_C(2166136261) :
                                                  UINT64_C(0xcbf29ce484222325);
    const hashT     C2   = (sizeof(hashT) == 4) ? UINT32_C(  16777619) :
                                                  UINT64_C(0x100000001b3);
    hashT h = (hashT)seed;

    h ^= C1;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= C2;
    }

    h = COND_BSWAP(h, bswap);
    memcpy(out, &h, sizeof(h));
}

static void FNV1a_128( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * data = (const uint8_t *)in;
    const uint64_t  C1lo = UINT64_C(0x62b821756295c58d);
    const uint64_t  C1hi = UINT64_C(0x6c62272e07bb0142);
    const uint64_t  C2   = UINT64_C(0x13b);

    uint64_t s0, s1;
    uint64_t hash[2] = { seed, seed };

    hash[0] ^= C1hi;
    hash[1] ^= C1lo;
    for (size_t i = 0; i < len; i++) {
        hash[1] ^= data[i];
        MathMult::mult64_128(s1, s0, C2, hash[1]);
        s0 += (hash[1] << 24) + C2 * hash[0];
        hash[0] = s0;
        hash[1] = s1;
    }

    if (isLE()) {
        PUT_U64<true>(hash[0], (uint8_t *)out, 0);
        PUT_U64<true>(hash[1], (uint8_t *)out, 8);
    } else {
        PUT_U64<false>(hash[0], (uint8_t *)out, 0);
        PUT_U64<false>(hash[1], (uint8_t *)out, 8);
    }
}

template <typename hashT, bool bswap>
static void FNV2( const void * in, const size_t len, const seed_t seed, void * out ) {
    const hashT *       dw   = (const hashT *)in;
    const hashT * const endw = &dw[len / sizeof(hashT)];
    const uint64_t      C1   = (sizeof(hashT) == 4) ? UINT32_C(2166136261) :
                                                      UINT64_C(0xcbf29ce484222325);
    const uint64_t C2        = (sizeof(hashT) == 4) ? UINT32_C(  16777619) :
                                                      UINT64_C(0x100000001b3);
    hashT h = C1 ^ (hashT)seed;
    hashT w;

    // word stepper
    while (dw < endw) {
        memcpy(&w, dw++, sizeof(w));
        h ^= COND_BSWAP(w, bswap);
        h *= C2;
    }
    // byte stepper
    if (len & (sizeof(hashT) - 1)) {
        uint8_t * dc = (uint8_t *)dw;
        const uint8_t * const endc = &((const uint8_t *)in)[len];
        while (dc < endc) {
            h ^= *dc++;
            h *= C2;
        }
    }

    h = COND_BSWAP(h, bswap);
    memcpy(out, &h, sizeof(h));
}

template <bool bswap>
static void FNV_YoshimitsuTRIAD( const void * in, const size_t olen, const seed_t seed, void * out ) {
    const uint8_t * p       = (const uint8_t *)in;
    const uint32_t  PRIME   = 709607;
    uint32_t        hash32A = UINT32_C(2166136261) ^ seed;
    uint32_t        hash32B = UINT32_C(2166136261) + olen;
    uint32_t        hash32C = UINT32_C(2166136261);
    size_t          len     = olen;

    for (; len >= 3 * 2 * sizeof(uint32_t); len -= 3 * 2 * sizeof(uint32_t), p += 3 * 2 * sizeof(uint32_t)) {
        hash32A = (hash32A ^ (ROTL32(GET_U32<bswap>(p,  0), 5) ^ GET_U32<bswap>(p,  4))) * PRIME;
        hash32B = (hash32B ^ (ROTL32(GET_U32<bswap>(p,  8), 5) ^ GET_U32<bswap>(p, 12))) * PRIME;
        hash32C = (hash32C ^ (ROTL32(GET_U32<bswap>(p, 16), 5) ^ GET_U32<bswap>(p, 20))) * PRIME;
    }
    if (p != (const uint8_t *)in) {
        hash32A = (hash32A ^ ROTL32(hash32C, 5)) * PRIME;
    }
    // Cases 0. .31
    if (len & (4 * sizeof(uint32_t))) {
        hash32A = (hash32A ^ (ROTL32(GET_U32<bswap>(p, 0), 5) ^ GET_U32<bswap>(p,  4))) * PRIME;
        hash32B = (hash32B ^ (ROTL32(GET_U32<bswap>(p, 8), 5) ^ GET_U32<bswap>(p, 12))) * PRIME;
        p      += 8 * sizeof(uint16_t);
    }
    // Cases 0. .15
    if (len & (2 * sizeof(uint32_t))) {
        hash32A = (hash32A ^ GET_U32<bswap>(p, 0)) * PRIME;
        hash32B = (hash32B ^ GET_U32<bswap>(p, 4)) * PRIME;
        p      += 4 * sizeof(uint16_t);
    }
    // Cases:0. .7
    if (len & sizeof(uint32_t)) {
        hash32A = (hash32A ^ GET_U16<bswap>(p, 0)) * PRIME;
        hash32B = (hash32B ^ GET_U16<bswap>(p, 2)) * PRIME;
        p      += 2 * sizeof(uint16_t);
    }
    // Cases:0. .3
    if (len & sizeof(uint16_t)) {
        hash32A = (hash32A ^ GET_U16<bswap>(p, 0)) * PRIME;
        p      += sizeof(uint16_t);
    }
    if (len & 1) {
        hash32A = (hash32A ^ *p) * PRIME;
    }

    hash32A  = (hash32A ^ ROTL32(hash32B, 5)) * PRIME;
    hash32A ^= (hash32A >> 16);

    hash32A  = COND_BSWAP(hash32A, bswap);
    memcpy(out, &hash32A, 4);
}

template <bool keeplsb>
static FORCE_INLINE uint64_t _PADr_KAZE( uint64_t x, int n ) {
    if (n >= 64) { return 0; }
    if (keeplsb) {
        return (x << n) >> n;
    } else {
        return x >> n;
    }
}

template <bool bswap>
static void FNV_Totenschiff( const void * in, const size_t olen, const seed_t seed, void * out ) {
    const uint8_t * p      = (uint8_t *)in;
    const uint32_t  PRIME  = 591798841;
    uint32_t        hash32;
    uint64_t        hash64 = (uint64_t)seed ^ UINT64_C(14695981039346656037);
    uint64_t        PADDEDby8;
    size_t          len    = olen;

    for (; len > 8; len -= 8, p += 8) {
        PADDEDby8 = GET_U64<bswap>(p, 0);
        hash64    = (hash64 ^ PADDEDby8) * PRIME;
    }

    // Here len is 1..8. when (8-8) the QWORD remains intact
    if (isLE() ^ bswap) {
        PADDEDby8 = _PADr_KAZE<true>(GET_U64<bswap>(p, 0), (8 - len) << 3);
    } else {
        PADDEDby8 = _PADr_KAZE<false>(GET_U64<bswap>(p, 0), (8 - len) << 3);
    }
    hash64 = (hash64 ^ PADDEDby8) * PRIME;

    hash32 = (uint32_t)(hash64 ^ (hash64 >> 32));
    hash32 = hash32 ^ (hash32 >> 16);

    hash32 = COND_BSWAP(hash32, bswap);
    memcpy(out, &hash32, 4);
}

// Dedicated to Pippip, the main character in the 'Das Totenschiff'
// roman, actually the B.Traven himself, his real name was Hermann
// Albert Otto Maksymilian Feige.
//
// CAUTION: Add 8 more bytes to the buffer being hashed, usually
// malloc(...+8) - to prevent out of boundary reads!
//
// Many thanks go to Yurii 'Hordi' Hordiienko, he lessened with 3
// instructions the original 'Pippip', thus:
template <bool bswap>
static void FNV_Pippip_Yurii( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * str    = (uint8_t *)in;
    const uint32_t  PRIME  = 591798841;
    uint32_t        hash32;
    uint64_t        hash64 = (uint64_t)seed ^ UINT64_C(14695981039346656037);
    size_t          Cycles, NDhead;

    if (len > 8) {
        Cycles = ((len - 1) >> 4) + 1;
        NDhead = len - (Cycles << 3);
#pragma nounroll
        for (; Cycles--; str += 8) {
            hash64 = (hash64 ^ (GET_U64<bswap>(str, 0)     )) * PRIME;
            hash64 = (hash64 ^ (GET_U64<bswap>(str, NDhead))) * PRIME;
        }
    } else {
        if (isLE() ^ bswap) {
            hash64 = (hash64 ^ _PADr_KAZE<true >(GET_U64<bswap>(str, 0), (8 - len) << 3)) * PRIME;
        } else {
            hash64 = (hash64 ^ _PADr_KAZE<false>(GET_U64<bswap>(str, 0), (8 - len) << 3)) * PRIME;
        }
    }
    hash32 = (uint32_t)(hash64 ^ (hash64 >> 32));
    hash32 = hash32 ^ (hash32 >> 16);

    hash32 = COND_BSWAP(hash32, bswap);
    memcpy(out, &hash32, 4);
} // Last update: 2019-Oct-30, 14 C lines strong, Kaze.

// https://papa.bretmulvey.com/post/124027987928/hash-functions
template <bool bswap>
static void FNV_Mulvey( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * data = (const uint8_t *)in;
    uint32_t h = (uint32_t)seed;

    h ^= 2166136261;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 16777619;
    }

    h += h << 13;
    h ^= h >> 7;
    h += h << 3;
    h ^= h >> 17;
    h += h << 5;

    h = COND_BSWAP(h, bswap);
    memcpy(out, &h, sizeof(h));
}

// Also https://www.codeproject.com/articles/716530/fastest-hash-function-for-table-lookups-in-c
// Also https://github.com/golang/go/, src/hash/fnv/fnv.go
REGISTER_FAMILY(fnv,
   $.src_url    = "http://www.sanmayce.com/Fastest_Hash/index.html",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(fibonacci_32,
   $.desc       = "32-bit wordwise Fibonacci hash (Knuth)",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS |
         FLAG_IMPL_MULTIPLY     |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0x09952480,
   $.verification_BE = 0x006F7705,
   $.hashfn_native   = fibonacci<uint32_t, false>,
   $.hashfn_bswap    = fibonacci<uint32_t, true>,
   $.seedfixfn       = excludeLow32Zero,
   $.badseeds        = { 0, UINT64_C (0xffffffff00000000) } /* !! all keys ending with 0x0000_0000 */
 );

REGISTER_HASH(fibonacci_64,
   $.desc       = "64-bit wordwise Fibonacci hash (Knuth)",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS   |
         FLAG_IMPL_MULTIPLY_64_64 |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xFE3BD380,
   $.verification_BE = 0x3E67D58C,
   $.hashfn_native   = fibonacci<uint64_t, false>,
   $.hashfn_bswap    = fibonacci<uint64_t, true>,
   $.badseeddesc     = "All keys of zero bytes produce the seed as the hash."
 );

REGISTER_HASH(FNV_1a_32,
   $.desc       = "32-bit bytewise FNV-1a (Fowler-Noll-Vo)",
   $.hash_flags =
         FLAG_HASH_NO_SEED      |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY     |
         FLAG_IMPL_LICENSE_MIT  |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 32,
   $.verification_LE = 0xE3CBBE91,
   $.verification_BE = 0x656F95A0,
   $.hashfn_native   = FNV1a<uint32_t, false>,
   $.hashfn_bswap    = FNV1a<uint32_t, true>
 );

REGISTER_HASH(FNV_1a_64,
   $.desc       = "64-bit bytewise FNV-1a (Fowler-Noll-Vo)",
   $.hash_flags =
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64 |
         FLAG_IMPL_LICENSE_MIT    |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 64,
   $.verification_LE = 0x103455FC,
   $.verification_BE = 0x4B032B63,
   $.hashfn_native   = FNV1a<uint64_t, false>,
   $.hashfn_bswap    = FNV1a<uint64_t, true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0xcbf29ce484222325 }
 );

REGISTER_HASH(FNV_1a_128,
   $.desc       = "128-bit bytewise FNV-1a (Fowler-Noll-Vo), from Golang",
   $.hash_flags =
         FLAG_HASH_ENDIAN_INDEPENDENT |
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128    |
         FLAG_IMPL_LICENSE_BSD        |
         FLAG_IMPL_VERY_SLOW          |
         FLAG_IMPL_CANONICAL_BOTH,
   $.bits = 128,
   $.verification_LE = 0x0269D36F,
   $.verification_BE = 0x0269D36F,
   $.hashfn_native   = FNV1a_128,
   $.hashfn_bswap    = FNV1a_128
 );

REGISTER_HASH(FNV_1a_32__wordwise,
   $.desc       = "32-bit wordwise hash based on FNV-1a",
   $.hash_flags =
         FLAG_HASH_NO_SEED      |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS |
         FLAG_IMPL_MULTIPLY     |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0x739801C5,
   $.verification_BE = 0xC5999647,
   $.hashfn_native   = FNV2<uint32_t, false>,
   $.hashfn_bswap    = FNV2<uint32_t, true>
 );

REGISTER_HASH(FNV_1a_64__wordwise,
   $.desc       = "64-bit wordwise hash based on FNV1-a",
   $.hash_flags =
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS    |
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x1967C625,
   $.verification_BE = 0x06F5053E,
   $.hashfn_native   = FNV2<uint64_t, false>,
   $.hashfn_bswap    = FNV2<uint64_t, true>,
   $.badseeddesc     = "All seeds collide on keys of all zero bytes of varying lengths (e.g. 18 vs. 32 bytes, 52 vs. 80)."
 );

REGISTER_HASH(FNV_YoshimitsuTRIAD,
   $.desc       = "FNV-YoshimitsuTRIAD 32-bit (sanmayce)",
   $.hash_flags =
         FLAG_HASH_NO_SEED      |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY     |
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0xD8AFFD71,
   $.verification_BE = 0x85C2EC2F,
   $.hashfn_native   = FNV_YoshimitsuTRIAD<false>,
   $.hashfn_bswap    = FNV_YoshimitsuTRIAD<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0x811c9dc5, 0x23d4a49d }
 );

REGISTER_HASH(FNV_Totenschiff,
   $.desc       = "FNV-Totenschiff 32-bit (sanmayce)",
   $.hash_flags =
         FLAG_HASH_NO_SEED       |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS  |
         FLAG_IMPL_MULTIPLY      |
         FLAG_IMPL_READ_PAST_EOB |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0x95D95ACF,
   $.verification_BE = 0xC16E2C8F,
   $.hashfn_native   = FNV_Totenschiff<false>,
   $.hashfn_bswap    = FNV_Totenschiff<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0x811c9dc5 }
 );

REGISTER_HASH(FNV_PippipYurii,
   $.desc       = "FNV-Pippip-Yurii 32-bit (sanmayce)",
   $.hash_flags =
         FLAG_HASH_NO_SEED       |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS  |
         FLAG_IMPL_MULTIPLY      |
         FLAG_IMPL_READ_PAST_EOB |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0xE79AE3E4,
   $.verification_BE = 0x90C8C706,
   $.hashfn_native   = FNV_Pippip_Yurii<false>,
   $.hashfn_bswap    = FNV_Pippip_Yurii<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0x811c9dc5 }
 );

REGISTER_HASH(FNV_Mulvey,
   $.desc       = "FNV-Mulvey 32-bit",
   $.hash_flags =
         FLAG_HASH_NO_SEED     |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
        FLAG_IMPL_MULTIPLY     |
        FLAG_IMPL_VERY_SLOW    |
        FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0x0E256555,
   $.verification_BE = 0xAC12B951,
   $.hashfn_native   = FNV_Mulvey<false>,
   $.hashfn_bswap    = FNV_Mulvey<true>
 );
