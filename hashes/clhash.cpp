/*
 * clhash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (C) 2017       Daniel Lemire
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 */
/*
 * This code is based on https://github.com/lemire/clhash, and has
 * been sublicensed as GPL3 from the original Apache-2.0 license.
 */
#include "Platform.h"
#include "Hashlib.h"

#if defined(HAVE_X86_64_CLMUL)

  #include "Intrinsics.h"
  #include <cassert>

/*
 * CLHash is a very fast hashing function that uses the
 * carry-less multiplication and SSE instructions.
 *
 * Daniel Lemire, Owen Kaser, Faster 64-bit universal hashing
 * using carry-less multiplications, Journal of Cryptographic Engineering (to appear)
 *
 * Best used on recent x64 processors (Haswell or better).
 *
 * Template option: if you define BITMIX during compilation, extra
 * work is done to pass smhasher's avalanche test succesfully.
 *
 */

//------------------------------------------------------------
// xoshift RNG for turning uint seeds into random bytes.
//
// Keys for scalar xorshift128. Must be non-zero. These are modified
// by xorshift128plus.
typedef struct xorshift128plus_key_s {
    uint64_t  part1;
    uint64_t  part2;
} xorshift128plus_key_t;

static uint64_t xorshift128plus( xorshift128plus_key_t * key ) {
    uint64_t       s1 = key->part1;
    const uint64_t s0 = key->part2;

    key->part1 = s0;
    s1        ^= s1 << 23;                         // a
    key->part2 = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5); // b, c
    return key->part2 + s0;
}

// key must be aligned to 16 bytes!
static void get_random_key_for_clhash( uint64_t seed1, uint64_t seed2, size_t keycnt, uint64_t * key ) {
    xorshift128plus_key_t k;

    k.part1 = seed1;
    k.part2 = seed2;

    for (size_t i = 0; i < keycnt; ++i) {
        key[i] = xorshift128plus(&k);
    }
    while ((key[128] == 0) && (key[129] == 1)) {
        key[128] = xorshift128plus(&k);
        key[129] = xorshift128plus(&k);
    }
}

//------------------------------------------------------------
enum {
    CLHASH_64BITWORDS_CHUNK_SIZE        = 128,
    CLHASH_64BITWORDS_EXTRA             = 5,
    RANDOM_64BITWORDS_NEEDED_FOR_CLHASH = CLHASH_64BITWORDS_CHUNK_SIZE + CLHASH_64BITWORDS_EXTRA,
};
// static_assert((CLHASH_64BITWORDS_CHUNK_SIZE % 4) == 0)

alignas(16) static thread_local uint64_t clhash_random[RANDOM_64BITWORDS_NEEDED_FOR_CLHASH];

static uintptr_t clhash_init( const seed_t seed ) {
    uint64_t s64 = (uint64_t)seed;

    get_random_key_for_clhash(s64, ~s64, RANDOM_64BITWORDS_NEEDED_FOR_CLHASH, clhash_random);
    return (seed_t)(uintptr_t)(void *)clhash_random;
}

//------------------------------------------------------------
// computes a << 1
static inline __m128i leftshift1( __m128i a ) {
    const int x        = 1;
    __m128i   u64shift = _mm_slli_epi64(a, x);
    __m128i   topbits  = _mm_slli_si128(_mm_srli_epi64(a, 64 - x), sizeof(uint64_t));

    return _mm_or_si128(u64shift, topbits);
}

// computes a << 2
static inline __m128i leftshift2( __m128i a ) {
    const int x        = 2;
    __m128i   u64shift = _mm_slli_epi64(a, x);
    __m128i   topbits  = _mm_slli_si128(_mm_srli_epi64(a, 64 - x), sizeof(uint64_t));

    return _mm_or_si128(u64shift, topbits);
}

//////////////////
// compute the "lazy" modulo with 2^127 + 2 + 1, actually we compute the
// modulo with (2^128 + 4 + 2) = 2 * (2^127 + 2 + 1) ,
// though  (2^128 + 4 + 2) is not
// irreducible, we have that
//     (x mod (2^128 + 4 + 2)) mod (2^127 + 2 + 1) == x mod (2^127 + 2 + 1)
// That's true because, in general ( x mod k y ) mod y = x mod y.
//
// Precondition:  given that Ahigh|Alow represents a 254-bit value
//                  (two highest bits of Ahigh must be zero)
//////////////////
static inline __m128i lazymod127( __m128i Alow, __m128i Ahigh ) {
    ///////////////////////////////////////////////////
    // CHECKING THE PRECONDITION:
    // Important: we are assuming that the two highest bits of Ahigh
    // are zero. This could be checked by adding a line such as this one:
    // if(_mm_extract_epi64(Ahigh,1) >= (1ULL<<62)){printf("bug\n");abort();}
    //                       (this assumes SSE4.1 support)
    ///////////////////////////////////////////////////
    // The answer is Alow XOR  (  Ahigh <<1 ) XOR (  Ahigh <<2 )
    // This is correct because the two highest bits of Ahigh are
    // assumed to be zero.
    ///////////////////////////////////////////////////
    // credit for simplified implementation : Jan Wassenberg
    __m128i shift1 = leftshift1(Ahigh);
    __m128i shift2 = leftshift2(Ahigh);
    __m128i final = _mm_xor_si128(_mm_xor_si128(Alow, shift1), shift2);

    return final;
}

// multiplication with lazy reduction
// assumes that the two highest bits of the 256-bit multiplication are zeros
// returns a lazy reduction
static inline __m128i mul128by128to128_lazymod127( __m128i A, __m128i B ) {
    __m128i Amix1 = _mm_clmulepi64_si128(A, B, 0x01);
    __m128i Amix2 = _mm_clmulepi64_si128(A, B, 0x10);
    __m128i Alow  = _mm_clmulepi64_si128(A, B, 0x00);
    __m128i Ahigh = _mm_clmulepi64_si128(A, B, 0x11);
    __m128i Amix  = _mm_xor_si128(Amix1, Amix2);

    Amix1 = _mm_slli_si128(Amix, 8);
    Amix2 = _mm_srli_si128(Amix, 8);
    Alow  = _mm_xor_si128(Alow , Amix1);
    Ahigh = _mm_xor_si128(Ahigh, Amix2);
    return lazymod127(Alow, Ahigh);
}

// multiply the length and the some key, no modulo
static __m128i lazyLengthHash( uint64_t keylength, uint64_t length ) {
    const __m128i lengthvector = _mm_set_epi64x(keylength, length);
    const __m128i clprod1      = _mm_clmulepi64_si128(lengthvector, lengthvector, 0x10);

    return clprod1;
}

// modulo reduction to 64-bit value. The high 64 bits contain garbage,
// see precompReduction64
static inline __m128i precompReduction64_si128( __m128i A ) {
    // const __m128i C = _mm_set_epi64x(1U,(1U<<4)+(1U<<3)+(1U<<1)+(1U<<0)); // C is the irreducible poly. (64,4,3,1,0)
    const __m128i C  = _mm_cvtsi64_si128((1 << 4) + (1 << 3) + (1 << 1) + (1 << 0));
    __m128i       Q2 = _mm_clmulepi64_si128(A, C, 0x01);
    __m128i       Q3 = _mm_shuffle_epi8(_mm_setr_epi8(0, 27, 54, 45, 108, 119, 90, 65, (uint8_t)216, (uint8_t)195,
            (uint8_t)238, (uint8_t)245, (uint8_t)180, (uint8_t)175, (uint8_t)130, (uint8_t)153), _mm_srli_si128(Q2, 8));
    __m128i Q4       = _mm_xor_si128(Q2, A);
    const __m128i final = _mm_xor_si128(Q3, Q4);

    return final; /// WARNING: HIGH 64 BITS CONTAIN GARBAGE
}

static inline uint64_t precompReduction64( __m128i A ) {
    return _mm_cvtsi128_si64(precompReduction64_si128(A));
}

// hashing the bits in value using the keys key1 and key2 (only the
// first 64 bits of key2 are used).  This is basically (a xor k1) * (b
// xor k2) mod p with length component.
static uint64_t simple128to64hashwithlength( const __m128i value, const __m128i key,
        uint64_t keylength, uint64_t length ) {
    const __m128i add     = _mm_xor_si128(value, key);
    const __m128i clprod1 = _mm_clmulepi64_si128(add, add, 0x10);
    const __m128i total   = _mm_xor_si128(clprod1, lazyLengthHash(keylength, length));

    return precompReduction64(total);
}

// we expect length to have value 128 or, at least, to be divisible by 4.
template <bool bswap>
static __m128i clmulhalfscalarproductwithoutreduction( const __m128i * randomsource,
        const uint64_t * string, const size_t length ) {
    const uint64_t * const endstring = string + length;
    __m128i acc = _mm_setzero_si128();

    // we expect length = 128
    for (; string + 3 < endstring; randomsource += 2, string += 4) {
        const __m128i temp1    = _mm_load_si128(randomsource);
        const __m128i temp2    = _mm_lddqu_si128((const __m128i *)string);
        const __m128i temp3    = bswap ? mm_bswap64(temp2) : temp2;
        const __m128i add1     = _mm_xor_si128(temp1, temp3);
        const __m128i clprod1  = _mm_clmulepi64_si128(add1, add1, 0x10);
        acc = _mm_xor_si128(clprod1 , acc);
        const __m128i temp12   = _mm_load_si128(randomsource + 1);
        const __m128i temp22   = _mm_lddqu_si128((const __m128i *)(string + 2));
        const __m128i temp32   = bswap ? mm_bswap64(temp22) : temp22;
        const __m128i add12    = _mm_xor_si128(temp12, temp32);
        const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
        acc = _mm_xor_si128(clprod12, acc);
    }
    return acc;
}

template <bool bswap>
static __m128i clmulhalfscalarproductwithtailwithoutreduction( const __m128i * randomsource,
        const uint64_t * string, const size_t length ) {
    const uint64_t * const endstring = string + length;
    __m128i acc = _mm_setzero_si128();

    for (; string + 3 < endstring; randomsource += 2, string += 4) {
        const __m128i temp1    = _mm_load_si128(randomsource);
        const __m128i temp2    = _mm_lddqu_si128((const __m128i *)string);
        const __m128i temp3    = bswap ? mm_bswap64(temp2) : temp2;
        const __m128i add1     = _mm_xor_si128(temp1, temp3);
        const __m128i clprod1  = _mm_clmulepi64_si128(add1, add1, 0x10);
        acc = _mm_xor_si128(clprod1 , acc);
        const __m128i temp12   = _mm_load_si128(randomsource + 1);
        const __m128i temp22   = _mm_lddqu_si128((const __m128i *)(string + 2));
        const __m128i temp32   = bswap ? mm_bswap64(temp22) : temp22;
        const __m128i add12    = _mm_xor_si128(temp12, temp32);
        const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
        acc = _mm_xor_si128(clprod12, acc);
    }
    if (string + 1 < endstring) {
        const __m128i temp1   = _mm_load_si128(randomsource);
        const __m128i temp2   = _mm_lddqu_si128((const __m128i *)string);
        const __m128i temp3   = bswap ? mm_bswap64(temp2) : temp2;
        const __m128i add1    = _mm_xor_si128(temp1, temp3);
        const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
        acc           = _mm_xor_si128(clprod1, acc);
        randomsource += 1;
        string       += 2;
    }
    if (string < endstring) {
        const __m128i temp1   = _mm_load_si128(randomsource);
        const __m128i temp2   = _mm_loadl_epi64((const __m128i *)string);
        const __m128i temp3   = bswap ? mm_bswap64(temp2) : temp2;
        const __m128i add1    = _mm_xor_si128(temp1, temp3);
        const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
        acc = _mm_xor_si128(clprod1, acc);
    }
    return acc;
}

template <bool bswap>
static __m128i clmulhalfscalarproductwithtailwithoutreductionWithExtraWord( const __m128i * randomsource,
        const uint64_t * string, const size_t length, const uint64_t extraword ) {
    const uint64_t * const endstring = string + length;
    __m128i acc = _mm_setzero_si128();

    for (; string + 3 < endstring; randomsource += 2, string += 4) {
        const __m128i temp1    = _mm_load_si128(randomsource);
        const __m128i temp2    = _mm_lddqu_si128((const __m128i *)string);
        const __m128i temp3    = bswap ? mm_bswap64(temp2) : temp2;
        const __m128i add1     = _mm_xor_si128(temp1, temp3);
        const __m128i clprod1  = _mm_clmulepi64_si128(add1, add1, 0x10);
        acc = _mm_xor_si128(clprod1 , acc);
        const __m128i temp12   = _mm_load_si128(randomsource + 1);
        const __m128i temp22   = _mm_lddqu_si128((const __m128i *)(string + 2));
        const __m128i temp32   = bswap ? mm_bswap64(temp22) : temp22;
        const __m128i add12    = _mm_xor_si128(temp12, temp32);
        const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
        acc = _mm_xor_si128(clprod12, acc);
    }
    if (string + 1 < endstring) {
        const __m128i temp1   = _mm_load_si128(randomsource);
        const __m128i temp2   = _mm_lddqu_si128((const __m128i *)string);
        const __m128i temp3   = bswap ? mm_bswap64(temp2) : temp2;
        const __m128i add1    = _mm_xor_si128(temp1, temp3);
        const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
        acc           = _mm_xor_si128(clprod1, acc);
        randomsource += 1;
        string       += 2;
    }
    // we have to append an extra 1
    if (string < endstring) {
        const __m128i temp1   = _mm_load_si128(randomsource);
        const __m128i temp2   = _mm_set_epi64x(extraword, GET_U64<bswap>((const uint8_t *)string, 0));
        const __m128i temp3   = bswap ? mm_bswap64(temp2) : temp2;
        const __m128i add1    = _mm_xor_si128(temp1, temp3);
        const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
        acc = _mm_xor_si128(clprod1, acc);
    } else {
        const __m128i temp1   = _mm_load_si128(randomsource);
        const __m128i temp2   = _mm_loadl_epi64((const __m128i *)&extraword);
        const __m128i temp3   = bswap ? mm_bswap64(temp2) : temp2;
        const __m128i add1    = _mm_xor_si128(temp1, temp3);
        const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x01);
        acc = _mm_xor_si128(clprod1, acc);
    }
    return acc;
}

template <bool bswap>
static __m128i clmulhalfscalarproductOnlyExtraWord( const __m128i * randomsource, const uint64_t extraword ) {
    const __m128i temp1   = _mm_load_si128(randomsource);
    const __m128i temp2   = _mm_loadl_epi64((const __m128i *)&extraword);
    const __m128i temp3   = bswap ? mm_bswap64(temp2) : temp2;
    const __m128i add1    = _mm_xor_si128(temp1, temp3);
    const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x01);

    return clprod1;
}

////////
// an invertible function used to mix the bits
// borrowed directly from murmurhash
////////
static inline uint64_t fmix64( uint64_t k ) {
    k ^= k >> 33;
    k *= UINT64_C(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k *= UINT64_C(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;
    return k;
}

// there always remain an incomplete word that has 1,2, 3, 4, 5, 6, 7
// used bytes.  we append 0s to it. The result is really a fancy 8-byte buffer, so
// this routine does not care about byteswapping.
static inline uint64_t createLastWord( const size_t lengthbyte, const uint64_t * lastw ) {
    const int significantbytes = lengthbyte % sizeof(uint64_t);
    uint64_t  lastword         = 0;

    memcpy(&lastword, lastw, significantbytes); // could possibly be faster?
    return lastword;
}

// The seeding here is homegrown for SMHasher3
template <bool bitmix, bool bswap>
static uint64_t clhash( const void * random, const uint8_t * stringbyte, const size_t lengthbyte ) {
    assert(((uintptr_t)random & 15) == 0); // we expect cache line alignment for the keys

    // We process the data in chunks of 16 cache lines (m should be divisible by 4).
    const uint32_t m = CLHASH_64BITWORDS_CHUNK_SIZE;
    const uint32_t m128neededperblock = m / 2; // How many 128-bit words of random bits we use per block.

    const uint64_t * string = (const uint64_t *)stringbyte;

    const size_t length     = lengthbyte / sizeof(uint64_t);                          // # of complete words
    const size_t lengthinc  = (lengthbyte + sizeof(uint64_t) - 1) / sizeof(uint64_t); // # of words, including partial
                                                                                      // ones

    const __m128i * rs64 = (__m128i *)random;

    // to preserve alignment on cache lines for main loop, we pick random bits at the end
    __m128i polyvalue = _mm_load_si128(rs64 + m128neededperblock);
    // setting two highest bits to zero
    polyvalue = _mm_and_si128(polyvalue, _mm_setr_epi32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x3fffffff));
    // we should check that polyvalue is non-zero, though this is best done outside the function and highly unlikely

    // long strings // modified from length to lengthinc to address issue #3 raised by Eik List
    if (m < lengthinc) {
        __m128i acc = clmulhalfscalarproductwithoutreduction<bswap>(rs64, string, m);

        size_t t = m;
        for (; t + m <= length; t += m) {
            // we compute something like
            // acc+= polyvalue * acc + h1
            acc = mul128by128to128_lazymod127(polyvalue, acc);
            const __m128i h1 = clmulhalfscalarproductwithoutreduction<bswap>(rs64, string + t, m);
            acc = _mm_xor_si128(acc, h1);
        }
        const uint32_t remain = length - t; // number of completely filled words

        if (remain != 0) {
            // we compute something like
            // acc+= polyvalue * acc + h1
            acc = mul128by128to128_lazymod127(polyvalue, acc);
            if ((lengthbyte % sizeof(uint64_t)) == 0) {
                const __m128i h1 =
                        clmulhalfscalarproductwithtailwithoutreduction<bswap>(rs64, string + t, remain);
                acc = _mm_xor_si128(acc, h1);
            } else {
                const uint64_t lastword = createLastWord(lengthbyte, (string + length));
                const __m128i  h1       =
                        clmulhalfscalarproductwithtailwithoutreductionWithExtraWord<bswap>(
                        rs64, string + t, remain, lastword);
                acc = _mm_xor_si128(acc, h1);
            }
        } else if ((lengthbyte % sizeof(uint64_t)) != 0) { // added to address issue #2 raised by Eik List
            // there are no completely filled words left, but there is one partial word.
            acc = mul128by128to128_lazymod127(polyvalue, acc);
            const uint64_t lastword = createLastWord(lengthbyte, (string + length));
            const __m128i  h1       = clmulhalfscalarproductOnlyExtraWord<bswap>(rs64, lastword);
            acc = _mm_xor_si128(acc, h1);
        }

        const __m128i  finalkey  = _mm_load_si128(rs64 + m128neededperblock + 1);
        const uint64_t keylength = ((const uint64_t *)(rs64 + m128neededperblock + 2))[0];
        return simple128to64hashwithlength(acc, finalkey, keylength, (uint64_t)lengthbyte);
    } else {
        // short strings
        __m128i acc;

        if ((lengthbyte % sizeof(uint64_t)) == 0) {
            acc = clmulhalfscalarproductwithtailwithoutreduction             <bswap>(rs64, string, length);
        } else {
            const uint64_t lastword = createLastWord(lengthbyte, (string + length));
            acc = clmulhalfscalarproductwithtailwithoutreductionWithExtraWord<bswap>(rs64, string, length, lastword);
        }

        const uint64_t keylength = ((const uint64_t *)(rs64 + m128neededperblock + 2))[0];
        acc = _mm_xor_si128(acc, lazyLengthHash(keylength, (uint64_t)lengthbyte));
        return bitmix ? fmix64(precompReduction64(acc)) : precompReduction64(acc);
    }
}

//------------------------------------------------------------
template <bool bswap>
static void CLHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    void *   random = (void *)(uintptr_t)seed;
    uint64_t h      = clhash<true, bswap>(random, (const uint8_t *)in, len);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void CLHashNomix( const void * in, const size_t len, const seed_t seed, void * out ) {
    void *   random = (void *)(uintptr_t)seed;
    uint64_t h      = clhash<false, bswap>(random, (const uint8_t *)in, len);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

#endif

//------------------------------------------------------------
REGISTER_FAMILY(clhash,
   $.src_url    = "https://github.com/lemire/clhash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

#if defined(HAVE_X86_64_CLMUL)

REGISTER_HASH(CLhash__bitmix,
   $.desc       = "Carryless multiplication hash, with -DBITMIX",
   $.impl       = "hwclmul",
   $.hash_flags =
         FLAG_HASH_CLMUL_BASED      |
         FLAG_HASH_LOOKUP_TABLE     |
         FLAG_HASH_NO_SEED          ,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_LICENSE_GPL3,
   $.bits = 64,
   $.verification_LE = 0xAAC87C33,
   $.verification_BE = 0x26D0DD6C,
   $.hashfn_native   = CLHash<false>,
   $.hashfn_bswap    = CLHash<true>,
   $.seedfn          = clhash_init
 );

REGISTER_HASH(CLhash,
   $.desc       = "Carryless multiplication hash, without -DBITMIX",
   $.impl       = "hwclmul",
   $.hash_flags =
         FLAG_HASH_CLMUL_BASED      |
         FLAG_HASH_LOOKUP_TABLE     |
         FLAG_HASH_NO_SEED          ,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_LICENSE_GPL3,
   $.bits = 64,
   $.verification_LE = 0x2E554CB4,
   $.verification_BE = 0x4F2B76A1,
   $.hashfn_native   = CLHashNomix<false>,
   $.hashfn_bswap    = CLHashNomix<true>,
   $.seedfn          = clhash_init
 );

#endif
