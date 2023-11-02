/*
 * Spookyhash v1 and v2
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
 *
 * This file incorporates work by Bob Jenkins from
 * https://www.burtleburtle.net/bob/hash/spooky.html covered by the
 * following copyright and permission notice:
 *
 *     This is free and unencumbered software released into the public domain.
 *
 *     Anyone is free to copy, modify, publish, use, compile, sell, or
 *     distribute this software, either in source code form or as a
 *     compiled binary, for any purpose, commercial or non-commercial,
 *     and by any means.
 *
 *     In jurisdictions that recognize copyright laws, the author or
 *     authors of this software dedicate any and all copyright
 *     interest in the software to the public domain. We make this
 *     dedication for the benefit of the public at large and to the
 *     detriment of our heirs and successors. We intend this
 *     dedication to be an overt act of relinquishment in perpetuity
 *     of all present and future rights to this software under
 *     copyright law.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *     NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
 *     ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 *     CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *     CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *     THE SOFTWARE.
 *
 *     For more information, please refer to <http://unlicense.org>
 */
#include "Platform.h"
#include "Hashlib.h"

// SpookyHash: a 128-bit noncryptographic hash function
// By Bob Jenkins, public domain

class SpookyHash {
  public:
    //
    // SpookyHash: hash a single message in one call, produce 128-bit output
    //
    template <uint32_t version, bool bswap>
    static void Hash128( const void * message, // message to hash
            size_t length,                     // length of message in bytes
            uint64_t * hash1,                  // in/out: in seed 1, out hash value 1
            uint64_t * hash2 );                // in/out: in seed 2, out hash value 2

    //
    // This is used if the input is 96 bytes long or longer.
    //
    // The internal state is fully overwritten every 96 bytes.
    // Every input bit appears to cause at least 128 bits of entropy
    // before 96 other bytes are combined, when run forward or backward
    //   For every input bit,
    //   Two inputs differing in just that input bit
    //   Where "differ" means xor or subtraction
    //   And the base value is random
    //   When run forward or backwards one Mix
    // I tried 3 pairs of each; they all differed by at least 212 bits.
    //
    template <bool bswap>
    static FORCE_INLINE void Mix( const uint8_t * data, uint64_t & s0, uint64_t & s1, uint64_t & s2,
            uint64_t & s3, uint64_t & s4, uint64_t & s5, uint64_t & s6, uint64_t & s7, uint64_t & s8,
            uint64_t & s9, uint64_t & s10, uint64_t & s11 ) {
        s0  += GET_U64<bswap>(data, 8 *  0);      s2 ^= s10;  s11 ^= s0;    s0  = ROTL64(s0, 11);   s11 += s1;
        s1  += GET_U64<bswap>(data, 8 *  1);      s3 ^= s11;   s0 ^= s1;    s1  = ROTL64(s1, 32);    s0 += s2;
        s2  += GET_U64<bswap>(data, 8 *  2);      s4 ^= s0;    s1 ^= s2;    s2  = ROTL64(s2, 43);    s1 += s3;
        s3  += GET_U64<bswap>(data, 8 *  3);      s5 ^= s1;    s2 ^= s3;    s3  = ROTL64(s3, 31);    s2 += s4;
        s4  += GET_U64<bswap>(data, 8 *  4);      s6 ^= s2;    s3 ^= s4;    s4  = ROTL64(s4, 17);    s3 += s5;
        s5  += GET_U64<bswap>(data, 8 *  5);      s7 ^= s3;    s4 ^= s5;    s5  = ROTL64(s5, 28);    s4 += s6;
        s6  += GET_U64<bswap>(data, 8 *  6);      s8 ^= s4;    s5 ^= s6;    s6  = ROTL64(s6, 39);    s5 += s7;
        s7  += GET_U64<bswap>(data, 8 *  7);      s9 ^= s5;    s6 ^= s7;    s7  = ROTL64(s7, 57);    s6 += s8;
        s8  += GET_U64<bswap>(data, 8 *  8);     s10 ^= s6;    s7 ^= s8;    s8  = ROTL64(s8, 55);    s7 += s9;
        s9  += GET_U64<bswap>(data, 8 *  9);     s11 ^= s7;    s8 ^= s9;    s9  = ROTL64(s9, 54);    s8 += s10;
        s10 += GET_U64<bswap>(data, 8 * 10);      s0 ^= s8;    s9 ^= s10;   s10 = ROTL64(s10, 22);   s9 += s11;
        s11 += GET_U64<bswap>(data, 8 * 11);      s1 ^= s9;   s10 ^= s11;   s11 = ROTL64(s11, 46);  s10 += s0;
    }

    //
    // Mix all 12 inputs together so that h0, h1 are a hash of them all.
    //
    // For two inputs differing in just the input bits
    // Where "differ" means xor or subtraction
    // And the base value is random, or a counting value starting at that bit
    // The final result will have each bit of h0, h1 flip
    // For every input bit,
    // with probability 50 +- .3%
    // For every pair of input bits,
    // with probability 50 +- 3%
    //
    // This does not rely on the last Mix() call having already mixed some.
    // Two iterations was almost good enough for a 64-bit result, but a
    // 128-bit result is reported, so End() does three iterations.
    //
    static FORCE_INLINE void EndPartial( uint64_t & h0, uint64_t & h1, uint64_t & h2, uint64_t & h3, uint64_t & h4,
            uint64_t & h5, uint64_t & h6, uint64_t & h7, uint64_t & h8,
            uint64_t & h9, uint64_t & h10, uint64_t & h11 ) {
        h11 += h1;    h2 ^= h11;   h1 = ROTL64(h1 , 44);
        h0  += h2;    h3 ^= h0;    h2 = ROTL64(h2 , 15);
        h1  += h3;    h4 ^= h1;    h3 = ROTL64(h3 , 34);
        h2  += h4;    h5 ^= h2;    h4 = ROTL64(h4 , 21);
        h3  += h5;    h6 ^= h3;    h5 = ROTL64(h5 , 38);
        h4  += h6;    h7 ^= h4;    h6 = ROTL64(h6 , 33);
        h5  += h7;    h8 ^= h5;    h7 = ROTL64(h7 , 10);
        h6  += h8;    h9 ^= h6;    h8 = ROTL64(h8 , 13);
        h7  += h9;   h10 ^= h7;    h9 = ROTL64(h9 , 38);
        h8  += h10;  h11 ^= h8;   h10 = ROTL64(h10, 53);
        h9  += h11;   h0 ^= h9;   h11 = ROTL64(h11, 42);
        h10 += h0;    h1 ^= h10;   h0 = ROTL64(h0 , 54);
    }

    template <uint32_t version, bool bswap>
    static FORCE_INLINE void End( uint64_t & h0, uint64_t & h1, uint64_t & h2, uint64_t & h3,
            uint64_t & h4, uint64_t & h5, uint64_t & h6, uint64_t & h7, uint64_t & h8, uint64_t & h9,
            uint64_t & h10, uint64_t & h11, const uint8_t * data ) {
        if (version == 2) {
            h0  += GET_U64<bswap>(data, 8 *  0);    h1 += GET_U64<bswap>(data, 8 *  1);
            h2  += GET_U64<bswap>(data, 8 *  2);    h3 += GET_U64<bswap>(data, 8 *  3);
            h4  += GET_U64<bswap>(data, 8 *  4);    h5 += GET_U64<bswap>(data, 8 *  5);
            h6  += GET_U64<bswap>(data, 8 *  6);    h7 += GET_U64<bswap>(data, 8 *  7);
            h8  += GET_U64<bswap>(data, 8 *  8);    h9 += GET_U64<bswap>(data, 8 *  9);
            h10 += GET_U64<bswap>(data, 8 * 10);   h11 += GET_U64<bswap>(data, 8 * 11);
        } else {
            Mix<bswap>(data, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        }
        EndPartial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        EndPartial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        EndPartial(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
    }

    //
    // The goal is for each bit of the input to expand into 128 bits of
    //   apparent entropy before it is fully overwritten.
    // n trials both set and cleared at least m bits of h0 h1 h2 h3
    //   n: 2   m: 29
    //   n: 3   m: 46
    //   n: 4   m: 57
    //   n: 5   m: 107
    //   n: 6   m: 146
    //   n: 7   m: 152
    // when run forwards or backwards
    // for all 1-bit and 2-bit diffs
    // with diffs defined by either xor or subtraction
    // with a base of all zeros plus a counter, or plus another bit, or random
    //
    static FORCE_INLINE void ShortMix( uint64_t & h0, uint64_t & h1, uint64_t & h2, uint64_t & h3 ) {
        h2 = ROTL64(h2, 50);  h2 += h3;  h0 ^= h2;
        h3 = ROTL64(h3, 52);  h3 += h0;  h1 ^= h3;
        h0 = ROTL64(h0, 30);  h0 += h1;  h2 ^= h0;
        h1 = ROTL64(h1, 41);  h1 += h2;  h3 ^= h1;
        h2 = ROTL64(h2, 54);  h2 += h3;  h0 ^= h2;
        h3 = ROTL64(h3, 48);  h3 += h0;  h1 ^= h3;
        h0 = ROTL64(h0, 38);  h0 += h1;  h2 ^= h0;
        h1 = ROTL64(h1, 37);  h1 += h2;  h3 ^= h1;
        h2 = ROTL64(h2, 62);  h2 += h3;  h0 ^= h2;
        h3 = ROTL64(h3, 34);  h3 += h0;  h1 ^= h3;
        h0 = ROTL64(h0,  5);  h0 += h1;  h2 ^= h0;
        h1 = ROTL64(h1, 36);  h1 += h2;  h3 ^= h1;
    }

    //
    // Mix all 4 inputs together so that h0, h1 are a hash of them all.
    //
    // For two inputs differing in just the input bits
    // Where "differ" means xor or subtraction
    // And the base value is random, or a counting value starting at that bit
    // The final result will have each bit of h0, h1 flip
    // For every input bit,
    // with probability 50 +- .3% (it is probably better than that)
    // For every pair of input bits,
    // with probability 50 +- .75% (the worst case is approximately that)
    //
    static FORCE_INLINE void ShortEnd( uint64_t & h0, uint64_t & h1, uint64_t & h2, uint64_t & h3 ) {
        h3 ^= h2;  h2 = ROTL64(h2, 15);  h3 += h2;
        h0 ^= h3;  h3 = ROTL64(h3, 52);  h0 += h3;
        h1 ^= h0;  h0 = ROTL64(h0, 26);  h1 += h0;
        h2 ^= h1;  h1 = ROTL64(h1, 51);  h2 += h1;
        h3 ^= h2;  h2 = ROTL64(h2, 28);  h3 += h2;
        h0 ^= h3;  h3 = ROTL64(h3,  9);  h0 += h3;
        h1 ^= h0;  h0 = ROTL64(h0, 47);  h1 += h0;
        h2 ^= h1;  h1 = ROTL64(h1, 54);  h2 += h1;
        h3 ^= h2;  h2 = ROTL64(h2, 32);  h3 += h2;
        h0 ^= h3;  h3 = ROTL64(h3, 25);  h0 += h3;
        h1 ^= h0;  h0 = ROTL64(h0, 63);  h1 += h0;
    }

  private:
    //
    // Short is used for messages under 192 bytes in length
    // Short has a low startup cost, the normal mode is good for long
    // keys, the cost crossover is at about 192 bytes.  The two modes were
    // held to the same quality bar.
    //
    template <uint32_t version, bool bswap>
    static void Short( const void * message, // message (array of bytes, not necessarily aligned)
            size_t length,                   // length of message (in bytes)
            uint64_t * hash1,                // in/out: in the seed, out the hash value
            uint64_t * hash2 );              // in/out: in the seed, out the hash value

    // number of uint64_t's in internal state
    static const size_t  sc_numVars = 12;

    // size of the internal state
    static const size_t  sc_blockSize = sc_numVars * 8;

    // size of buffer of unhashed data, in bytes
    static const size_t  sc_bufSize = 2 * sc_blockSize;

    //
    // sc_const: a constant which:
    //  * is not zero
    //  * is odd
    //  * is a not-very-regular mix of 1's and 0's
    //  * does not need any other special mathematical properties
    //
    static const uint64_t  sc_const = UINT64_C(0xdeadbeefdeadbeef);
}; // class SpookyHash

template <uint32_t version, bool bswap>
void SpookyHash::Short( const void * message, size_t length, uint64_t * hash1, uint64_t * hash2 ) {
    size_t          remainder = length % 32;
    uint64_t        a         = *hash1;
    uint64_t        b         = *hash2;
    uint64_t        c         = sc_const;
    uint64_t        d         = sc_const;
    const uint8_t * ptr       = (const uint8_t *)message;

    if (length > 15) {
        const uint8_t * end = ptr + (length / 32) * 32;

        // handle all complete sets of 32 bytes
        for (; ptr < end; ptr += 32) {
            c += GET_U64<bswap>(ptr, 0);
            d += GET_U64<bswap>(ptr, 8);
            ShortMix(a, b, c, d);
            a += GET_U64<bswap>(ptr, 16);
            b += GET_U64<bswap>(ptr, 24);
        }

        // Handle the case of 16+ remaining bytes.
        if (remainder >= 16) {
            c         += GET_U64<bswap>(ptr, 0);
            d         += GET_U64<bswap>(ptr, 8);
            ShortMix(a, b, c, d);
            ptr       += 16;
            remainder -= 16;
        }
    }

    // Handle the last 0..15 bytes, and its length
    if (version == 1) {
        d = ((uint64_t)length) << 56;
    } else {
        d += ((uint64_t)length) << 56;
    }
    switch (remainder) {
    case 15: d += ((uint64_t)ptr[14]) << 48; // FALLTHROUGH
    case 14: d += ((uint64_t)ptr[13]) << 40; // FALLTHROUGH
    case 13: d += ((uint64_t)ptr[12]) << 32; // FALLTHROUGH
    case 12: d += GET_U32<bswap>(ptr, 8); c += GET_U64<bswap>(ptr, 0); break;
    case 11: d += ((uint64_t)ptr[10]) << 16; // FALLTHROUGH
    case 10: d += ((uint64_t)ptr[ 9]) <<  8; // FALLTHROUGH
    case  9: d +=  (uint64_t)ptr[ 8];        // FALLTHROUGH
    case  8: c += GET_U64<bswap>(ptr, 0); break;
    case  7: c += ((uint64_t)ptr[ 6]) << 48; // FALLTHROUGH
    case  6: c += ((uint64_t)ptr[ 5]) << 40; // FALLTHROUGH
    case  5: c += ((uint64_t)ptr[ 4]) << 32; // FALLTHROUGH
    case  4: c += GET_U32<bswap>(ptr, 0); break;
    case  3: c += ((uint64_t)ptr[ 2]) << 16; // FALLTHROUGH
    case  2: c += ((uint64_t)ptr[ 1]) <<  8; // FALLTHROUGH
    case  1: c += (uint64_t)ptr[0]; break;
    case  0: c += sc_const; d += sc_const; break;
    }
    ShortEnd(a, b, c, d);
    *hash1 = a;
    *hash2 = b;
}

// do the whole hash in one call
template <uint32_t version, bool bswap>
void SpookyHash::Hash128( const void * message, size_t length, uint64_t * hash1, uint64_t * hash2 ) {
    if (length < sc_bufSize) {
        Short<version, bswap>(message, length, hash1, hash2);
        return;
    }

    uint64_t        h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11;
    const uint8_t * ptr = (const uint8_t *)message;
    const uint8_t * end = ptr + (length / sc_blockSize) * sc_blockSize;
    size_t          remainder;

    h0 = h3 = h6 = h9  = *hash1;
    h1 = h4 = h7 = h10 = *hash2;
    h2 = h5 = h8 = h11 = sc_const;

    // handle all whole sc_blockSize blocks of bytes
    while (ptr < end) {
        Mix<bswap>(ptr, h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11);
        ptr += sc_blockSize;
    }

    // handle the last partial block of sc_blockSize bytes
    alignas(16) uint8_t buf[sc_blockSize];
    remainder = (length - (ptr - (const uint8_t *)message));
    memcpy(buf, ptr, remainder);
    memset(buf + remainder, 0, sc_blockSize - remainder - 1);
    buf[sc_blockSize - 1] = remainder;

    // do some final mixing
    End<version, bswap>(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, buf);
    *hash1 = h0;
    *hash2 = h1;
}

template <uint32_t version, uint32_t hashlen, bool bswap>
static void spookyhash( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h1, h2;

    h1 = h2 = (uint64_t)seed;

    SpookyHash::Hash128<version, bswap>(in, len, &h1, &h2);

    h1 = COND_BSWAP(h1, bswap);
    h2 = COND_BSWAP(h2, bswap);

    if (hashlen > 64) {
        memcpy(out, &h1, 8);
        memcpy(((uint8_t *)out) + 8, &h2, hashlen / 8 - 8);
    } else {
        memcpy(out, &h1, hashlen / 8);
    }
}

REGISTER_FAMILY(spookyhash,
   $.src_url    = "https://www.burtleburtle.net/bob/hash/spooky.html",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

// { 0x111af082, 0x26bb3cda, 0x94c4f96c, 0xec24c166 }
REGISTER_HASH(SpookyHash1_32,
   $.desc       = "SpookyHash v1, 32-bit result",
   $.hash_flags =
         0,
   $.impl_flags =
       FLAG_IMPL_ROTATE                 |
       FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 32,
   $.verification_LE = 0x3F798BBB,
   $.verification_BE = 0x32C8248C,
   $.hashfn_native   = spookyhash<1, 32, false>,
   $.hashfn_bswap    = spookyhash<1, 32, true>
 );

REGISTER_HASH(SpookyHash1_64,
   $.desc       = "SpookyHash v1, 64-bit result",
   $.hash_flags =
         0,
   $.impl_flags =
       FLAG_IMPL_ROTATE                 |
       FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 64,
   $.verification_LE = 0xA7F955F1,
   $.verification_BE = 0xD6BD6D2B,
   $.hashfn_native   = spookyhash<1, 64, false>,
   $.hashfn_bswap    = spookyhash<1, 64, true>
 );

REGISTER_HASH(SpookyHash1_128,
   $.desc       = "SpookyHash v1, 128-bit result",
   $.hash_flags =
         0,
   $.impl_flags =
       FLAG_IMPL_ROTATE                 |
       FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 128,
   $.verification_LE = 0x8D263080,
   $.verification_BE = 0xE9E5572C,
   $.hashfn_native   = spookyhash<1, 128, false>,
   $.hashfn_bswap    = spookyhash<1, 128, true>
 );

REGISTER_HASH(SpookyHash2_32,
   $.desc       = "SpookyHash v2, 32-bit result",
   $.hash_flags =
         0,
   $.impl_flags =
       FLAG_IMPL_ROTATE                 |
       FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 32,
   $.verification_LE = 0xA48BE265,
   $.verification_BE = 0x9742FF7D,
   $.hashfn_native   = spookyhash<2, 32, false>,
   $.hashfn_bswap    = spookyhash<2, 32, true>,
   $.sort_order      = 10
 );

REGISTER_HASH(SpookyHash2_64,
   $.desc       = "SpookyHash v2, 64-bit result",
   $.hash_flags =
         0,
   $.impl_flags =
       FLAG_IMPL_ROTATE                 |
       FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 64,
   $.verification_LE = 0x972C4BDC,
   $.verification_BE = 0x6B914F15,
   $.hashfn_native   = spookyhash<2, 64, false>,
   $.hashfn_bswap    = spookyhash<2, 64, true>,
   $.sort_order      = 10
 );

REGISTER_HASH(SpookyHash2_128,
   $.desc       = "SpookyHash v2, 128-bit result",
   $.hash_flags =
         0,
   $.impl_flags =
       FLAG_IMPL_ROTATE                 |
       FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 128,
   $.verification_LE = 0x893CFCBE,
   $.verification_BE = 0x7C1EA273,
   $.hashfn_native   = spookyhash<2, 128, false>,
   $.hashfn_bswap    = spookyhash<2, 128, true>,
   $.sort_order      = 10
 );
