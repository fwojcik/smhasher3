/*
 * Farmhash v1.1, by Geoff Pike
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2014 Google, Inc.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "Platform.h"
#include "Hashlib.h"

#include <cassert>

#if defined(HAVE_SSE_4_1) || defined(HAVE_X86_64_CRC32C) || defined(HAVE_X86_64_AES)
  #include "Intrinsics.h"
  #define FARMHASH_USE_INTRIN
#endif

using namespace std;

//------------------------------------------------------------
#if defined(HAVE_INT128)

static inline uint64_t Uint128Low64( const uint128_t x ) {
    return static_cast<uint64_t>(x);
}

static inline uint64_t Uint128High64( const uint128_t x ) {
    return static_cast<uint64_t>(x >> 64);
}

static inline uint128_t Uint128( uint64_t lo, uint64_t hi ) {
    return lo + (((uint128_t)hi) << 64);
}

#else
typedef std::pair<uint64_t, uint64_t> uint128_t;

static inline uint64_t Uint128Low64( const uint128_t x ) { return x.first; }

static inline uint64_t Uint128High64( const uint128_t x ) { return x.second; }

static inline uint128_t Uint128( uint64_t lo, uint64_t hi ) { return uint128_t(lo, hi); }

#endif

//------------------------------------------------------------
template <bool bswap>
static inline uint32_t Fetch32( const uint8_t * p ) {
    return GET_U32<bswap>(p, 0);
}

template <bool bswap>
static inline uint64_t Fetch64( const uint8_t * p ) {
    return GET_U64<bswap>(p, 0);
}

#if defined(FARMHASH_USE_INTRIN)

template <bool bswap>
static inline __m128i Fetch128( const uint8_t * s ) {
    __m128i d = _mm_loadu_si128(reinterpret_cast<const __m128i *>(s));

    if (bswap) {
        const __m128i mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        d = _mm_shuffle_epi8(d, mask);
    }
    return d;
}

#endif

#undef PERMUTE3
#define PERMUTE3(a, b, c) do { std::swap(a, b); std::swap(a, c); } while (0)

//------------------------------------------------------------
#if defined(FARMHASH_USE_INTRIN)

// Helpers for data-parallel operations (1x 128 bits or 2x 64 or 4x 32).
static inline __m128i Add64( __m128i x, __m128i y ) { return _mm_add_epi64(x, y); }

static inline __m128i Add32( __m128i x, __m128i y ) { return _mm_add_epi32(x, y); }

static inline __m128i Mul( __m128i x, __m128i y ) { return _mm_mullo_epi32(x, y); }

static inline __m128i Mul5( __m128i x ) { return Add32(x, _mm_slli_epi32(x, 2)); }

static inline __m128i Xor( __m128i x, __m128i y ) { return _mm_xor_si128(x, y); }

static inline __m128i Or( __m128i x, __m128i y ) { return _mm_or_si128(x, y); }

static inline __m128i RotateLeft( __m128i x, int c ) {
    return Or(_mm_slli_epi32(x, c), _mm_srli_epi32(x, 32 - c));
}

static inline __m128i Rol17( __m128i x ) { return RotateLeft(x, 17); }

static inline __m128i Rol19( __m128i x ) { return RotateLeft(x, 19); }

static inline __m128i Shuf( __m128i x, __m128i y ) { return _mm_shuffle_epi8(y, x); }

static inline __m128i Shuffle0321( __m128i x ) {
    return _mm_shuffle_epi32(x, (0 << 6) + (3 << 4) + (2 << 2) + (1 << 0));
}

#endif

//------------------------------------------------------------
// Some primes between 2^63 and 2^64 for various uses.
static const uint64_t k0 = UINT64_C(0xc3a5c85c97cb3127);
static const uint64_t k1 = UINT64_C(0xb492b66fbe98f273);
static const uint64_t k2 = UINT64_C(0x9ae16a3b2f90404f);

// Magic numbers for 32-bit hashing.  Copied from Murmur3.
static const uint32_t c1 = 0xcc9e2d51;
static const uint32_t c2 = 0x1b873593;

//------------------------------------------------------------
// Helper bit mixing functions

// A 32-bit to 32-bit integer hash copied from Murmur3.
// mul
static inline uint32_t fmix( uint32_t h ) {
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

// Helper from Murmur3 for combining two 32-bit values.
// mul
static inline uint32_t Mur( uint32_t a, uint32_t h ) {
    a *= c1;
    a  = ROTR32(a, 17);
    a *= c2;
    h ^= a;
    h  = ROTR32(h, 19);
    return h * 5 + 0xe6546b64;
}

static inline uint64_t ShiftMix( uint64_t val ) {
    return val ^ (val >> 47);
}

// Hash 128 input bits down to 64 bits of output.
// This is intended to be a reasonably good hash function.
// 64x64
static inline uint64_t Hash128to64( uint128_t x ) {
    // Murmur-inspired hashing.
    const uint64_t kMul = UINT64_C(0x9ddfea08eb382d69);
    uint64_t       a    = (Uint128Low64(x)  ^ Uint128High64(x)) * kMul;

    a ^= (a >> 47);
    uint64_t b =          (Uint128High64(x) ^ a) * kMul;
    b ^= (b >> 47);
    b *= kMul;
    return b;
}

// 64x64
static inline uint64_t HashLen16( uint64_t u, uint64_t v ) {
    return Hash128to64(Uint128(u, v));
}

// 64x64
static inline uint64_t HashLen16( uint64_t u, uint64_t v, uint64_t mul ) {
    // Murmur-inspired hashing.
    uint64_t a = (u ^ v) * mul;

    a ^= (a >> 47);
    uint64_t b = (v ^ a) * mul;
    b ^= (b >> 47);
    b *= mul;
    return b;
}

// Return a 16-byte hash for 48 bytes.  Quick and dirty.
// Callers do best to use "random-looking" values for a and b.
static inline pair<uint64_t, uint64_t> WeakHashLen32WithSeeds( uint64_t w,
        uint64_t x, uint64_t y, uint64_t z, uint64_t a, uint64_t b ) {
    a += w;
    b  = ROTR64(b + a + z, 21);
    uint64_t c = a;
    a += x;
    a += y;
    b += ROTR64(a        , 44);
    return make_pair(a + z, b + c);
}

// Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty.
template <bool bswap>
static inline pair<uint64_t, uint64_t> WeakHashLen32WithSeeds( const uint8_t * s, uint64_t a, uint64_t b ) {
    return WeakHashLen32WithSeeds(Fetch64<bswap>(s), Fetch64<bswap>(
            s + 8), Fetch64<bswap>(s + 16), Fetch64<bswap>(s + 24), a, b);
}

//------------------------------------------------------------
namespace farmhashna {
    template <bool bswap>
    static inline uint64_t HashLen0to16( const uint8_t * s, size_t len );

    template <bool bswap>
    static inline uint64_t HashLen17to32( const uint8_t * s, size_t len );

    template <bool bswap>
    static inline uint64_t HashLen33to64( const uint8_t * s, size_t len );

    template <bool bswap>
    static uint64_t Hash64( const uint8_t * s, size_t len );

    template <bool bswap>
    static uint64_t Hash64WithSeeds( const uint8_t * s, size_t len, uint64_t seed0, uint64_t seed1 );

    template <bool bswap>
    static uint64_t Hash64WithSeed( const uint8_t * s, size_t len, uint64_t seed );
} // namespace farmhashna

template <bool bswap>
static inline uint64_t farmhashna::HashLen0to16( const uint8_t * s, size_t len ) {
    if (len >= 8) {
        uint64_t mul = k2 + len * 2;
        uint64_t a   = Fetch64<bswap>(s)      + k2;
        uint64_t b   = Fetch64<bswap>(s + len - 8);
        uint64_t c   = ROTR64(b, 37)  * mul + a;
        uint64_t d   = (ROTR64(a, 25) + b)  * mul;
        return HashLen16(c, d, mul);
    }
    if (len >= 4) {
        uint64_t mul = k2 + len * 2;
        uint64_t a   = Fetch32<bswap>(s);
        return HashLen16(len + (a << 3), Fetch32<bswap>(s + len - 4), mul);
    }
    if (len > 0) {
        uint8_t  a = s[0];
        uint8_t  b = s[len >> 1];
        uint8_t  c = s[len  - 1];
        uint32_t y = static_cast<uint32_t>(a) + (static_cast<uint32_t>(b) << 8);
        uint32_t z = len + (static_cast<uint32_t>(c) << 2);
        return ShiftMix(y * k2 ^ z * k0) * k2;
    }
    return k2;
}

// This probably works well for 16-byte strings as well, but it may be overkill
// in that case.
template <bool bswap>
static inline uint64_t farmhashna::HashLen17to32( const uint8_t * s, size_t len ) {
    uint64_t mul = k2 + len * 2;
    uint64_t a   = Fetch64<bswap>(s           ) * k1;
    uint64_t b   = Fetch64<bswap>(s + 8       );
    uint64_t c   = Fetch64<bswap>(s + len -  8) * mul;
    uint64_t d   = Fetch64<bswap>(s + len - 16) * k2;

    return HashLen16(ROTR64(a + b, 43) + ROTR64(c, 30) + d, a + ROTR64(b + k2, 18) + c, mul);
}

// Return an 8-byte hash for 33 to 64 bytes.
template <bool bswap>
static inline uint64_t farmhashna::HashLen33to64( const uint8_t * s, size_t len ) {
    uint64_t mul = k2 + len * 2;
    uint64_t a   = Fetch64<bswap>(s           ) * k2;
    uint64_t b   = Fetch64<bswap>(s +  8      );
    uint64_t c   = Fetch64<bswap>(s + len -  8) * mul;
    uint64_t d   = Fetch64<bswap>(s + len - 16) * k2;
    uint64_t y   = ROTR64(a + b, 43) + ROTR64(c, 30) + d;
    uint64_t z   = HashLen16(y, a + ROTR64(b + k2, 18) + c, mul);
    uint64_t e   = Fetch64<bswap>(s + 16      ) * mul;
    uint64_t f   = Fetch64<bswap>(s + 24      );
    uint64_t g   = (y + Fetch64<bswap>(s + len - 32)) * mul;
    uint64_t h   = (z + Fetch64<bswap>(s + len - 24)) * mul;

    return HashLen16(ROTR64(e + f, 43) + ROTR64(g, 30) + h, e + ROTR64(f + a, 18) + g, mul);
}

template <bool bswap>
static uint64_t farmhashna::Hash64( const uint8_t * s, size_t len ) {
    const uint64_t seed = 81;

    if (len <= 32) {
        if (len <= 16) {
            return HashLen0to16<bswap>(s, len);
        } else {
            return HashLen17to32<bswap>(s, len);
        }
    } else if (len <= 64) {
        return HashLen33to64<bswap>(s, len);
    }

    // For strings over 64 bytes we loop. I nternal state consists of
    // 56 bytes: v, w, x, y, and z.
    uint64_t x = seed;
    uint64_t y = seed * k1 + 113;
    uint64_t z = ShiftMix(y * k2 + 113) * k2;
    pair<uint64_t, uint64_t> v = make_pair(0, 0);
    pair<uint64_t, uint64_t> w = make_pair(0, 0);
    x = x * k2 + Fetch64<bswap>(s);

    // Set end so that after the loop we have 1 to 64 bytes left to process.
    const uint8_t * end    = s   + ((len - 1) / 64) * 64;
    const uint8_t * last64 = end + ((len - 1) & 63) - 63;
    assert(s + len - 64 == last64);
    do {
        x  = ROTR64(x + y        + v.first + Fetch64<bswap>(s +  8), 37) * k1;
        y  = ROTR64(y + v.second +           Fetch64<bswap>(s + 48), 42) * k1;
        x ^= w.second;
        y += v.first + Fetch64<bswap>(s + 40);
        z  = ROTR64(z + w.first, 33) * k1;
        v  = WeakHashLen32WithSeeds<bswap>(s     , v.second * k1, x + w.first);
        w  = WeakHashLen32WithSeeds<bswap>(s + 32, z + w.second , y + Fetch64<bswap>(s + 16));
        std::swap(z, x);
        s += 64;
    } while (s != end);
    uint64_t mul = k1 + ((z & 0xff) << 1);
    // Make s point to the last 64 bytes of input.
    s        = last64;
    w.first += ((len - 1) & 63);
    v.first += w.first;
    w.first += v.first;
    x        = ROTR64(x + y        + v.first + Fetch64<bswap>(s +  8), 37) * mul;
    y        = ROTR64(y + v.second +           Fetch64<bswap>(s + 48), 42) * mul;
    x       ^= w.second * 9;
    y       += v.first * 9 + Fetch64<bswap>(s + 40);
    z        = ROTR64(z + w.first, 33) * mul;
    v        = WeakHashLen32WithSeeds<bswap>(s     , v.second * mul, x + w.first);
    w        = WeakHashLen32WithSeeds<bswap>(s + 32, z + w.second  , y + Fetch64<bswap>(s + 16));
    std::swap(z, x);
    return HashLen16(HashLen16(v.first, w.first, mul) + ShiftMix(y) * k0 + z,
            HashLen16(v.second, w.second, mul) + x, mul);
}

template <bool bswap>
static uint64_t farmhashna::Hash64WithSeeds( const uint8_t * s, size_t len, uint64_t seed0, uint64_t seed1 ) {
    return HashLen16(farmhashna::Hash64<bswap>(s, len) - seed0, seed1);
}

template <bool bswap>
static uint64_t farmhashna::Hash64WithSeed( const uint8_t * s, size_t len, uint64_t seed ) {
    return farmhashna::Hash64WithSeeds<bswap>(s, len, k2, seed);
}

//------------------------------------------------------------
namespace farmhashuo {
    static inline uint64_t H( uint64_t x, uint64_t y, uint64_t mul, int r );

    template <bool bswap>
    static uint64_t Hash64( const uint8_t * s, size_t len );

    template <bool bswap>
    static uint64_t Hash64WithSeeds( const uint8_t * s, size_t len, uint64_t seed0, uint64_t seed1 );

    template <bool bswap>
    static uint64_t Hash64WithSeed( const uint8_t * s, size_t len, uint64_t seed );
} // namespace farmhashuo

static inline uint64_t farmhashuo::H( uint64_t x, uint64_t y, uint64_t mul, int r ) {
    uint64_t a = (x ^ y) * mul;

    a ^= (a >> 47);
    uint64_t b = (y ^ a) * mul;
    return ROTR64(b, r) * mul;
}

template <bool bswap>
static uint64_t farmhashuo::Hash64WithSeeds( const uint8_t * s, size_t len, uint64_t seed0, uint64_t seed1 ) {
    if (len <= 64) {
        return farmhashna::Hash64WithSeeds<bswap>(s, len, seed0, seed1);
    }

    // For strings over 64 bytes we loop.  Internal state consists of
    // 64 bytes: u, v, w, x, y, and z.
    uint64_t x = seed0;
    uint64_t y = seed1 * k2 + 113;
    uint64_t z = ShiftMix(y * k2) * k2;
    pair<uint64_t, uint64_t> v = make_pair(seed0, seed1);
    pair<uint64_t, uint64_t> w = make_pair(    0,     0);
    uint64_t u   = x - z;
    x *= k2;
    uint64_t mul = k2 + (u & 0x82);

    // Set end so that after the loop we have 1 to 64 bytes left to process.
    const uint8_t * end    = s   + ((len - 1) / 64) * 64;
    const uint8_t * last64 = end + ((len - 1) & 63) - 63;
    assert(s + len - 64 == last64);
    do {
        uint64_t a0 = Fetch64<bswap>(s     );
        uint64_t a1 = Fetch64<bswap>(s +  8);
        uint64_t a2 = Fetch64<bswap>(s + 16);
        uint64_t a3 = Fetch64<bswap>(s + 24);
        uint64_t a4 = Fetch64<bswap>(s + 32);
        uint64_t a5 = Fetch64<bswap>(s + 40);
        uint64_t a6 = Fetch64<bswap>(s + 48);
        uint64_t a7 = Fetch64<bswap>(s + 56);
        x        += a0 + a1;
        y        += a2;
        z        += a3;
        v.first  += a4;
        v.second += a5 + a1;
        w.first  += a6;
        w.second += a7;

        x         = ROTR64(x       , 26);
        x        *= 9;
        y         = ROTR64(y       , 29);
        z        *= mul;
        v.first   = ROTR64(v.first , 33);
        v.second  = ROTR64(v.second, 30);
        w.first  ^= x;
        w.first  *= 9;
        z         = ROTR64(z       , 32);
        z        += w.second;
        w.second += z;
        z        *= 9;
        std::swap(u, y);

        z        += a0 + a6;
        v.first  += a2;
        v.second += a3;
        w.first  += a4;
        w.second += a5 + a6;
        x        += a1;
        y        += a7;

        y        += v.first;
        v.first  += x - y;
        v.second += w.first;
        w.first  += v.second;
        w.second += x - y;
        x        += w.second;
        w.second  = ROTR64(w.second, 34);
        std::swap(u, z);
        s        += 64;
    } while (s != end);
    // Make s point to the last 64 bytes of input.
    s        = last64;
    u       *= 9;
    v.second = ROTR64(v.second   , 28);
    v.first  = ROTR64(v.first    , 20);
    w.first += ((len - 1) & 63);
    u       += y;
    y       += u;
    x        = ROTR64(y - x + v.first + Fetch64<bswap>(s + 8), 37) * mul;
    y        = ROTR64(y ^ v.second ^ Fetch64<bswap>(s + 48), 42) * mul;
    x       ^= w.second * 9;
    y       += v.first + Fetch64<bswap>(s + 40);
    z        = ROTR64(z + w.first, 33) * mul;
    v        = WeakHashLen32WithSeeds<bswap>(s     , v.second * mul, x + w.first);
    w        = WeakHashLen32WithSeeds<bswap>(s + 32, z + w.second  , y + Fetch64<bswap>(s + 16));
    return farmhashuo::H(HashLen16(v.first + x, w.first ^ y, mul) + z - u, farmhashuo::H(
            v.second + y, w.second + z, k2, 30) ^ x, k2, 31);
}

template <bool bswap>
static uint64_t farmhashuo::Hash64WithSeed( const uint8_t * s, size_t len, uint64_t seed ) {
    return len <= 64 ? farmhashna::Hash64WithSeed<bswap>(s, len, seed) :
                       farmhashuo::Hash64WithSeeds<bswap>(s, len, 0, seed);
}

template <bool bswap>
static uint64_t farmhashuo::Hash64( const uint8_t * s, size_t len ) {
    return len <= 64 ? farmhashna::Hash64<bswap>(s, len) :
                       farmhashuo::Hash64WithSeeds<bswap>(s, len, 81, 0);
}

//------------------------------------------------------------
namespace farmhashxo {
    template <bool bswap>
    static inline uint64_t H32( const uint8_t * s, size_t len, uint64_t mul, uint64_t seed0 = 0, uint64_t seed1 = 0 );

    template <bool bswap>
    static inline uint64_t HashLen33to64( const uint8_t * s, size_t len );

    template <bool bswap>
    static inline uint64_t HashLen65to96( const uint8_t * s, size_t len );

    template <bool bswap>
    static uint64_t Hash64( const uint8_t * s, size_t len );

    template <bool bswap>
    static uint64_t Hash64WithSeeds( const uint8_t * s, size_t len, uint64_t seed0, uint64_t seed1 );

    template <bool bswap>
    static uint64_t Hash64WithSeed( const uint8_t * s, size_t len, uint64_t seed );
} // namespace farmhashxo

template <bool bswap>
static inline uint64_t farmhashxo::H32( const uint8_t * s, size_t len, uint64_t mul, uint64_t seed0, uint64_t seed1 ) {
    uint64_t a = Fetch64<bswap>(s           ) * k1;
    uint64_t b = Fetch64<bswap>(s + 8       );
    uint64_t c = Fetch64<bswap>(s + len -  8) * mul;
    uint64_t d = Fetch64<bswap>(s + len - 16) * k2;
    uint64_t u = ROTR64(a + b, 43) + ROTR64(c, 30) + d + seed0;
    uint64_t v = a + ROTR64(b + k2, 18) + c + seed1;

    a = ShiftMix((u ^ v) * mul);
    b = ShiftMix((v ^ a) * mul);
    return b;
}

// Return an 8-byte hash for 33 to 64 bytes.
template <bool bswap>
static inline uint64_t farmhashxo::HashLen33to64( const uint8_t * s, size_t len ) {
    uint64_t mul0 = k2 - 30;
    uint64_t mul1 = k2 - 30 + 2 * len;
    uint64_t h0   = H32<bswap>(s, 32, mul0);
    uint64_t h1   = H32<bswap>(s + len - 32, 32, mul1);

    return ((h1 * mul1) + h0) * mul1;
}

// Return an 8-byte hash for 65 to 96 bytes.
template <bool bswap>
static inline uint64_t farmhashxo::HashLen65to96( const uint8_t * s, size_t len ) {
    uint64_t mul0 = k2 - 114;
    uint64_t mul1 = k2 - 114 + 2 * len;
    uint64_t h0   = H32<bswap>(s           , 32, mul0);
    uint64_t h1   = H32<bswap>(s + 32      , 32, mul1);
    uint64_t h2   = H32<bswap>(s + len - 32, 32, mul1, h0, h1);

    return (h2 * 9 + (h0 >> 17) + (h1 >> 21)) * mul1;
}

template <bool bswap>
static uint64_t farmhashxo::Hash64( const uint8_t * s, size_t len ) {
    if (len <= 32) {
        if (len <= 16) {
            return farmhashna::HashLen0to16<bswap>(s, len);
        } else {
            return farmhashna::HashLen17to32<bswap>(s, len);
        }
    } else if (len <= 64) {
        return farmhashxo::HashLen33to64<bswap>(s, len);
    } else if (len <= 96) {
        return farmhashxo::HashLen65to96<bswap>(s, len);
    } else if (len <= 256) {
        return farmhashna::Hash64<bswap>(s, len);
    } else {
        return farmhashuo::Hash64<bswap>(s, len);
    }
}

template <bool bswap>
static uint64_t farmhashxo::Hash64WithSeeds( const uint8_t * s, size_t len, uint64_t seed0, uint64_t seed1 ) {
    return farmhashuo::Hash64WithSeeds<bswap>(s, len, seed0, seed1);
}

template <bool bswap>
static uint64_t farmhashxo::Hash64WithSeed( const uint8_t * s, size_t len, uint64_t seed ) {
    return farmhashuo::Hash64WithSeed<bswap>(s, len, seed);
}

//------------------------------------------------------------
#if defined(HAVE_SSE_4_1)
namespace farmhashte {
    template <bool bswap>
    static inline uint64_t Hash64Long( const uint8_t * s, size_t n, uint64_t seed0, uint64_t seed1 );

    template <bool bswap>
    static uint64_t Hash64( const uint8_t * s, size_t len );

    template <bool bswap>
    static uint64_t Hash64WithSeeds( const uint8_t * s, size_t len, uint64_t seed0, uint64_t seed1 );

    template <bool bswap>
    static uint64_t Hash64WithSeed( const uint8_t * s, size_t len, uint64_t seed );
} // namespace farmhashte

// Requires n >= 256.  Requires SSE4.1. Should be slightly faster if the
// compiler uses AVX instructions (e.g., use the -mavx flag with GCC).
template <bool bswap>
static inline uint64_t farmhashte::Hash64Long( const uint8_t * s, size_t n, uint64_t seed0, uint64_t seed1 ) {
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Woverflow"
    const __m128i kMult =
            _mm_set_epi8(0xbd, 0xd6, 0x33, 0x39, 0x45, 0x54, 0xfa,
            0x03, 0x34, 0x3e, 0x33, 0xed, 0xcc, 0x9e, 0x2d, 0x51);
  #pragma GCC diagnostic pop

    const __m128i kShuf =
            _mm_set_epi8( 4, 11, 10, 5, 8, 15, 6, 9, 12, 2, 14, 13, 0, 7, 3, 1);
    uint64_t        seed2 = (seed0 + 113) * (seed1 + 9);
    uint64_t        seed3 = (ROTR64(seed0, 23) + 27) * (ROTR64(seed1, 30) + 111);
    __m128i         d0    = _mm_cvtsi64_si128(seed0);
    __m128i         d1    = _mm_cvtsi64_si128(seed1);
    __m128i         d2    = Shuf(kShuf, d0);
    __m128i         d3    = Shuf(kShuf, d1);
    __m128i         d4    = Xor(d0, d1);
    __m128i         d5    = Xor(d1, d2);
    __m128i         d6    = Xor(d2, d4);
    __m128i         d7    = _mm_set1_epi32(seed2 >> 32);
    __m128i         d8    = Mul(kMult, d2);
    __m128i         d9    = _mm_set1_epi32(seed3 >> 32);
    __m128i         d10   = _mm_set1_epi32(seed3      );
    __m128i         d11   = Add64(d2, _mm_set1_epi32(seed2));
    const uint8_t * end   = s + (n & ~static_cast<size_t>(255));

    do {
        __m128i z;
        z   = Fetch128<bswap>(s);
        d0  = Add64(d0, z);
        d1  = Shuf(kShuf, d1);
        d2  = Xor(d2, d0);
        d4  = Xor(d4, z );
        d4  = Xor(d4, d1);
        std::swap(d0, d6);
        z   = Fetch128<bswap>(s + 16);
        d5  = Add64(d5, z);
        d6  = Shuf(kShuf, d6);
        d8  = Shuf(kShuf, d8);
        d7  = Xor(d7, d5);
        d0  = Xor(d0, z );
        d0  = Xor(d0, d6);
        std::swap(d5, d11);
        z   = Fetch128<bswap>(s + 32);
        d1  = Add64(d1, z);
        d2  = Shuf(kShuf, d2);
        d4  = Shuf(kShuf, d4);
        d5  = Xor(d5, z );
        d5  = Xor(d5, d2);
        std::swap(d10, d4);
        z   = Fetch128<bswap>(s + 48);
        d6  = Add64(d6, z);
        d7  = Shuf(kShuf, d7);
        d0  = Shuf(kShuf, d0);
        d8  = Xor(d8, d6);
        d1  = Xor(d1, z );
        d1  = Add64(d1, d7);
        z   = Fetch128<bswap>(s + 64);
        d2  = Add64(d2, z);
        d5  = Shuf(kShuf, d5);
        d4  = Add64(d4, d2);
        d6  = Xor(d6, z  );
        d6  = Xor(d6, d11);
        std::swap(d8, d2);
        z   = Fetch128<bswap>(s + 80);
        d7  = Xor(d7, z);
        d8  = Shuf(kShuf, d8);
        d1  = Shuf(kShuf, d1);
        d0  = Add64(d0, d7);
        d2  = Add64(d2, z );
        d2  = Add64(d2, d8);
        std::swap(d1, d7);
        z   = Fetch128<bswap>(s + 96);
        d4  = Shuf(kShuf, d4);
        d6  = Shuf(kShuf, d6);
        d8  = Mul(kMult, d8);
        d5  = Xor(d5, d11);
        d7  = Xor(d7, z  );
        d7  = Add64(d7, d4);
        std::swap(d6, d0);
        z   = Fetch128<bswap>(s + 112);
        d8  = Add64(d8, z);
        d0  = Shuf(kShuf, d0);
        d2  = Shuf(kShuf, d2);
        d1  = Xor(d1 , d8);
        d10 = Xor(d10, z );
        d10 = Xor(d10, d0);
        std::swap(d11, d5);
        z   = Fetch128<bswap>(s + 128);
        d4  = Add64(d4, z);
        d5  = Shuf(kShuf, d5);
        d7  = Shuf(kShuf, d7);
        d6  = Add64(d6, d4);
        d8  = Xor(d8, z );
        d8  = Xor(d8, d5);
        std::swap(d4, d10);
        z   = Fetch128<bswap>(s + 144);
        d0  = Add64(d0, z);
        d1  = Shuf(kShuf, d1);
        d2  = Add64(d2, d0);
        d4  = Xor(d4, z );
        d4  = Xor(d4, d1);
        z   = Fetch128<bswap>(s + 160);
        d5  = Add64(d5, z);
        d6  = Shuf(kShuf, d6);
        d8  = Shuf(kShuf, d8);
        d7  = Xor(d7, d5);
        d0  = Xor(d0, z );
        d0  = Xor(d0, d6);
        std::swap(d2, d8);
        z   = Fetch128<bswap>(s + 176);
        d1  = Add64(d1, z);
        d2  = Shuf(kShuf, d2);
        d4  = Shuf(kShuf, d4);
        d5  = Mul(kMult, d5);
        d5  = Xor(d5, z );
        d5  = Xor(d5, d2);
        std::swap(d7, d1);
        z   = Fetch128<bswap>(s + 192);
        d6  = Add64(d6, z);
        d7  = Shuf(kShuf, d7);
        d0  = Shuf(kShuf, d0);
        d8  = Add64(d8, d6);
        d1  = Xor(d1, z );
        d1  = Xor(d1, d7);
        std::swap(d0, d6);
        z   = Fetch128<bswap>(s + 208);
        d2  = Add64(d2, z);
        d5  = Shuf(kShuf, d5);
        d4  = Xor(d4, d2);
        d6  = Xor(d6, z );
        d6  = Xor(d6, d9);
        std::swap(d5, d11);
        z   = Fetch128<bswap>(s + 224);
        d7  = Add64(d7, z);
        d8  = Shuf(kShuf, d8);
        d1  = Shuf(kShuf, d1);
        d0  = Xor(d0, d7);
        d2  = Xor(d2, z );
        d2  = Xor(d2, d8);
        std::swap(d10, d4);
        z   = Fetch128<bswap>(s + 240);
        d3  = Add64(d3, z);
        d4  = Shuf(kShuf, d4);
        d6  = Shuf(kShuf, d6);
        d7  = Mul(kMult, d7);
        d5  = Add64(d5, d3);
        d7  = Xor(d7, z );
        d7  = Xor(d7, d4);
        std::swap(d3, d9);
        s  += 256;
    } while (s != end);
    d6 = Add64(Mul(kMult, d6), _mm_cvtsi64_si128(n));
    if (n % 256 != 0) {
        d7 = Add64(_mm_shuffle_epi32(d8, (0 << 6) + (3 << 4) + (2 << 2) + (1 << 0)), d7    );
        d8 = Add64(Mul(kMult, d8), _mm_cvtsi64_si128(farmhashxo::Hash64<bswap>(s, n % 256)));
    }
    __m128i t[8];
    d0   = Mul(kMult, Shuf(kShuf, Mul(kMult, d0)));
    d3   = Mul(kMult, Shuf(kShuf, Mul(kMult, d3)));
    d9   = Mul(kMult, Shuf(kShuf, Mul(kMult, d9)));
    d1   = Mul(kMult, Shuf(kShuf, Mul(kMult, d1)));
    d0   = Add64(d11, d0);
    d3   = Xor(d7, d3);
    d9   = Add64(d8 , d9);
    d1   = Add64(d10, d1);
    d4   = Add64(d3 , d4);
    d5   = Add64(d9 , d5);
    d6   = Xor(d1, d6);
    d2   = Add64(d0, d2);
    t[0] = d0;
    t[1] = d3;
    t[2] = d9;
    t[3] = d1;
    t[4] = d4;
    t[5] = d5;
    t[6] = d6;
    t[7] = d2;
    return farmhashxo::Hash64<bswap>(reinterpret_cast<const uint8_t *>(t), sizeof(t));
}

template <bool bswap>
static uint64_t farmhashte::Hash64( const uint8_t * s, size_t len ) {
    // Empirically, farmhashxo seems faster until length 512.
    return len >= 512 ? farmhashte::Hash64Long<bswap>(s, len, k2, k1) :
                        farmhashxo::Hash64<bswap>(s, len);
}

template <bool bswap>
static uint64_t farmhashte::Hash64WithSeed( const uint8_t * s, size_t len, uint64_t seed ) {
    return len >= 512 ? farmhashte::Hash64Long<bswap>(s, len, k1, seed) :
                        farmhashxo::Hash64WithSeed<bswap>(s, len, seed);
}

template <bool bswap>
static uint64_t farmhashte::Hash64WithSeeds( const uint8_t * s, size_t len, uint64_t seed0, uint64_t seed1 ) {
    return len >= 512 ? farmhashte::Hash64Long<bswap>(s, len, seed0, seed1) :
                        farmhashxo::Hash64WithSeeds<bswap>(s, len, seed0, seed1);
}

#endif

//------------------------------------------------------------
#if defined(HAVE_SSE_4_1)
namespace farmhashnt {
    template <bool bswap>
    static uint32_t Hash32( const uint8_t * s, size_t len );

    template <bool bswap>
    static uint32_t Hash32WithSeed( const uint8_t * s, size_t len, uint32_t seed );
}

template <bool bswap>
static uint32_t farmhashnt::Hash32( const uint8_t * s, size_t len ) {
    return static_cast<uint32_t>(farmhashte::Hash64<bswap>(s, len));
}

template <bool bswap>
static uint32_t farmhashnt::Hash32WithSeed( const uint8_t * s, size_t len, uint32_t seed ) {
    return static_cast<uint32_t>(farmhashte::Hash64WithSeed<bswap>(s, len, seed));
}

#endif

//------------------------------------------------------------
namespace farmhashmk {
    static inline uint32_t Hash32Len0to4( const uint8_t * s, size_t len, uint32_t seed = 0 );

    template <bool bswap>
    static inline uint32_t Hash32Len5to12( const uint8_t * s, size_t len, uint32_t seed = 0 );

    template <bool bswap>
    static inline uint32_t Hash32Len13to24( const uint8_t * s, size_t len, uint32_t seed = 0 );

    template <bool bswap>
    static uint32_t Hash32( const uint8_t * s, size_t len );

    template <bool bswap>
    static uint32_t Hash32WithSeed( const uint8_t * s, size_t len, uint32_t seed );
} // namespace farmhashmk

template <bool bswap>
static inline uint32_t farmhashmk::Hash32Len13to24( const uint8_t * s, size_t len, uint32_t seed ) {
    uint32_t a = Fetch32<bswap>(s - 4   + (len >> 1));
    uint32_t b = Fetch32<bswap>(s + 4               );
    uint32_t c = Fetch32<bswap>(s + len - 8         );
    uint32_t d = Fetch32<bswap>(s +       (len >> 1));
    uint32_t e = Fetch32<bswap>(s                   );
    uint32_t f = Fetch32<bswap>(s + len - 4         );
    uint32_t h = d * c1 + len + seed;

    a = ROTR32(a, 12) + f;
    h = Mur(c, h) + a;
    a = ROTR32(a, 3) + c;
    h = Mur(e, h) + a;
    a = ROTR32(a + f, 12)   + d;
    h = Mur(b    ^ seed, h) + a;
    return fmix(h);
}

static inline uint32_t farmhashmk::Hash32Len0to4( const uint8_t * s, size_t len, uint32_t seed ) {
    uint32_t b = seed;
    uint32_t c = 9;

    for (size_t i = 0; i < len; i++) {
        int8_t v = s[i];
        b  = b * c1 + v;
        c ^= b;
    }
    return fmix(Mur(b, Mur(len, c)));
}

template <bool bswap>
static inline uint32_t farmhashmk::Hash32Len5to12( const uint8_t * s, size_t len, uint32_t seed ) {
    uint32_t a = len, b = len * 5, c = 9, d = b + seed;

    a += Fetch32<bswap>(s);
    b += Fetch32<bswap>(s + len - 4);
    c += Fetch32<bswap>(s + ((len >> 1) & 4));
    return fmix(seed ^ Mur(c, Mur(b, Mur(a, d))));
}

template <bool bswap>
static uint32_t farmhashmk::Hash32( const uint8_t * s, size_t len ) {
    if (len <= 24) {
        return len <= 12 ?
                   (len <= 4 ? farmhashmk::Hash32Len0to4(s, len) : farmhashmk::Hash32Len5to12<bswap>(s, len)) :
                   farmhashmk::Hash32Len13to24<bswap>(s, len);
    }

    // len > 24
    uint32_t h = len, g = c1 * len, f = g;
    uint32_t a0 = ROTR32(Fetch32<bswap>(s + len -  4) * c1, 17) * c2;
    uint32_t a1 = ROTR32(Fetch32<bswap>(s + len -  8) * c1, 17) * c2;
    uint32_t a2 = ROTR32(Fetch32<bswap>(s + len - 16) * c1, 17) * c2;
    uint32_t a3 = ROTR32(Fetch32<bswap>(s + len - 12) * c1, 17) * c2;
    uint32_t a4 = ROTR32(Fetch32<bswap>(s + len - 20) * c1, 17) * c2;
    h ^= a0;
    h  = ROTR32(h, 19);
    h  = h * 5 + 0xe6546b64;
    h ^= a2;
    h  = ROTR32(h, 19);
    h  = h * 5 + 0xe6546b64;
    g ^= a1;
    g  = ROTR32(g, 19);
    g  = g * 5 + 0xe6546b64;
    g ^= a3;
    g  = ROTR32(g, 19);
    g  = g * 5 + 0xe6546b64;
    f += a4;
    f  = ROTR32(f, 19) + 113;
    size_t iters = (len - 1) / 20;
    do {
        uint32_t a = Fetch32<bswap>(s     );
        uint32_t b = Fetch32<bswap>(s +  4);
        uint32_t c = Fetch32<bswap>(s +  8);
        uint32_t d = Fetch32<bswap>(s + 12);
        uint32_t e = Fetch32<bswap>(s + 16);
        h += a;
        g += b;
        f += c;
        h  = Mur(d, h) + e;
        g  = Mur(c, g) + a;
        f  = Mur(b + e * c1, f) + d;
        f += g;
        g += f;
        s += 20;
    } while (--iters != 0);
    g = ROTR32(g    , 11) * c1;
    g = ROTR32(g    , 17) * c1;
    f = ROTR32(f    , 11) * c1;
    f = ROTR32(f    , 17) * c1;
    h = ROTR32(h + g, 19);
    h = h * 5 + 0xe6546b64;
    h = ROTR32(h    , 17) * c1;
    h = ROTR32(h + f, 19);
    h = h * 5 + 0xe6546b64;
    h = ROTR32(h    , 17) * c1;
    return h;
}

template <bool bswap>
static uint32_t farmhashmk::Hash32WithSeed( const uint8_t * s, size_t len, uint32_t seed ) {
    if (len <= 24) {
        if (len >= 13) { return farmhashmk::Hash32Len13to24<bswap>(s, len, seed * c1); } else if (len >= 5) {
            return farmhashmk::Hash32Len5to12<bswap>(s, len, seed);
        } else {
            return farmhashmk::Hash32Len0to4(s, len, seed);
        }
    }
    uint32_t h = farmhashmk::Hash32Len13to24<bswap>(s, 24, seed ^ len);
    return Mur(farmhashmk::Hash32<bswap>(s + 24, len - 24) + seed, h);
}

//------------------------------------------------------------
#if defined(HAVE_X86_64_CRC32C) && defined(HAVE_X86_64_AES)
namespace farmhashsu {
    template <bool bswap>
    static uint32_t Hash32( const uint8_t * s, size_t len );

    template <bool bswap>
    static uint32_t Hash32WithSeed( const uint8_t * s, size_t len, uint32_t seed );
}

template <bool bswap>
static uint32_t farmhashsu::Hash32( const uint8_t * s, size_t len ) {
    const uint32_t seed = 81;

    if (len <= 24) {
        return len <= 12 ?
                   (len <= 4 ?
                       farmhashmk::Hash32Len0to4(s, len) :
                       farmhashmk::Hash32Len5to12<bswap>(s, len)) :
                   farmhashmk::Hash32Len13to24<bswap>(s, len);
    }

    if (len < 40) {
        uint32_t a = len, b = seed * c2, c = a + b;
        a += Fetch32<bswap>(s + len -  4);
        b += Fetch32<bswap>(s + len - 20);
        c += Fetch32<bswap>(s + len - 16);
        uint32_t d = a;
        a  = ROTR32(a, 21);
        a  = Mur(a, Mur(b, _mm_crc32_u32(c, d)));
        a += Fetch32<bswap>(s + len - 12);
        b += Fetch32<bswap>(s + len -  8);
        d += a;
        a += d;
        b  = Mur(b, d) * c2;
        a  = _mm_crc32_u32(a, b + c);
        return farmhashmk::Hash32Len13to24<bswap>(s, (len + 1) / 2, a) + b;
    }

  #undef Mulc1
  #define Mulc1(x) Mul((x), cc1)

  #undef Mulc2
  #define Mulc2(x) Mul((x), cc2)

  #undef Murk
#define Murk(a, h)                               \
  Add32(k,                                       \
          Mul5(                                  \
               Rol19(                            \
                     Xor(                        \
                         Mulc2(                  \
                               Rol17(            \
                                     Mulc1(a))), \
                         (h)))))

    const __m128i cc1 = _mm_set1_epi32(c1);
    const __m128i cc2 = _mm_set1_epi32(        c2       );
    __m128i       h   = _mm_set1_epi32(      seed       );
    __m128i       g   = _mm_set1_epi32(        c1 * seed);
    __m128i       f   = g;
    __m128i       k   = _mm_set1_epi32(0xe6546b64       );
    __m128i       q;
    if (len < 80) {
        __m128i a = Fetch128<bswap>(s     );
        __m128i b = Fetch128<bswap>(s + 16);
        __m128i c = Fetch128<bswap>(s + (len - 15) / 2);
        __m128i d = Fetch128<bswap>(s + len - 32);
        __m128i e = Fetch128<bswap>(s + len - 16);
        h = Add32(h, a);
        g = Add32(g, b);
        q = g;
        g = Shuffle0321(g);
        f = Add32(f, c);
        __m128i be = Add32(b, Mulc1(e));
        h = Add32(h, f);
        f = Add32(f, h);
        h = Add32(Murk(d, h), e);
        k = Xor(k, _mm_shuffle_epi8(g, f));
        g = Add32(Xor(c, g) , a);
        f = Add32(Xor(be, f), d);
        k = Add32(k, be        );
        k = Add32(k, _mm_shuffle_epi8(f, h));
        f = Add32(f, g);
        g = Add32(g, f);
        g = Add32(_mm_set1_epi32(len), Mulc1(g));
    } else {
        // len >= 80
        // The following is loosely modelled after farmhashmk::Hash32.
        size_t iters = (len - 1) / 80;
        len -= iters * 80;

  #undef Chunk
#define Chunk() do {                          \
        __m128i a = Fetch128<bswap>(s);       \
        __m128i b = Fetch128<bswap>(s + 16);  \
        __m128i c = Fetch128<bswap>(s + 32);  \
        __m128i d = Fetch128<bswap>(s + 48);  \
        __m128i e = Fetch128<bswap>(s + 64);  \
        h = Add32(h, a);                      \
        g = Add32(g, b);                      \
        g = Shuffle0321(g);                   \
        f = Add32(f, c);                      \
        __m128i be = Add32(b, Mulc1(e));      \
        h = Add32(h, f);                      \
        f = Add32(f, h);                      \
        h = Add32(h, d);                      \
        q = Add32(q, e);                      \
        h = Rol17(h);                         \
        h = Mulc1(h);                         \
        k = Xor(k, _mm_shuffle_epi8(g, f));   \
        g = Add32(Xor(c, g), a);              \
        f = Add32(Xor(be, f), d);             \
        std::swap(f, q);                      \
        q = _mm_aesimc_si128(q);              \
        k = Add32(k, be);                     \
        k = Add32(k, _mm_shuffle_epi8(f, h)); \
        f = Add32(f, g);                      \
        g = Add32(g, f);                      \
        f = Mulc1(f);                         \
    } while (0)

        q = g;
        while (iters-- != 0) {
            Chunk();
            s += 80;
        }

        if (len != 0) {
            h = Add32(h, _mm_set1_epi32(len));
            s = s + len - 80;
            Chunk();
        }
    }

    g      = Shuffle0321(g);
    k      = Xor(k, g);
    k      = Xor(k, q);
    h      = Xor(h, q);
    f      = Mulc1(f);
    k      = Mulc2(k);
    g      = Mulc1(g);
    h      = Mulc2(h);
    k      = Add32(k, _mm_shuffle_epi8(g, f));
    h      = Add32(h, f);
    f      = Add32(f, h);
    g      = Add32(g, k);
    k      = Add32(k, g);
    k      = Xor(k, _mm_shuffle_epi8(f, h));
    __m128i buf[4];
    buf[0] = f;
    buf[1] = g;
    buf[2] = k;
    buf[3] = h;
    s      = reinterpret_cast<uint8_t *>(buf);
    uint32_t x = Fetch32<bswap>(s    );
    uint32_t y = Fetch32<bswap>(s + 4);
    uint32_t z = Fetch32<bswap>(s + 8);
    x = _mm_crc32_u32(x     , Fetch32<bswap>(s + 12));
    y = _mm_crc32_u32(y     , Fetch32<bswap>(s + 16));
    z = _mm_crc32_u32(z * c1, Fetch32<bswap>(s + 20));
    x = _mm_crc32_u32(x     , Fetch32<bswap>(s + 24));
    y = _mm_crc32_u32(y * c1, Fetch32<bswap>(s + 28));
    uint32_t o = y;
    z = _mm_crc32_u32(z     , Fetch32<bswap>(s + 32));
    x = _mm_crc32_u32(x * c1, Fetch32<bswap>(s + 36));
    y = _mm_crc32_u32(y     , Fetch32<bswap>(s + 40));
    z = _mm_crc32_u32(z * c1, Fetch32<bswap>(s + 44));
    x = _mm_crc32_u32(x     , Fetch32<bswap>(s + 48));
    y = _mm_crc32_u32(y * c1, Fetch32<bswap>(s + 52));
    z = _mm_crc32_u32(z     , Fetch32<bswap>(s + 56));
    x = _mm_crc32_u32(x     , Fetch32<bswap>(s + 60));
    return (o - x + y - z) * c1;
}

  #undef Chunk
  #undef Murk
  #undef Mulc2
  #undef Mulc1

template <bool bswap>
static uint32_t farmhashsu::Hash32WithSeed( const uint8_t * s, size_t len, uint32_t seed ) {
    if (len <= 24) {
        if (len >= 13) { return farmhashmk::Hash32Len13to24<bswap>(s, len, seed * c1); } else if (len >= 5) {
            return farmhashmk::Hash32Len5to12<bswap>(s, len, seed);
        } else {
            return farmhashmk::Hash32Len0to4(s, len, seed);
        }
    }
    uint32_t h = farmhashmk::Hash32Len13to24<bswap>(s, 24, seed ^ len);
    return _mm_crc32_u32(farmhashsu::Hash32<bswap>(s + 24, len - 24) + seed, h);
}

#endif

//------------------------------------------------------------
#if defined(HAVE_X86_64_CRC32C)
namespace farmhashsa {
    template <bool bswap>
    static uint32_t Hash32( const uint8_t * s, size_t len );

    template <bool bswap>
    static uint32_t Hash32WithSeed( const uint8_t * s, size_t len, uint32_t seed );
}

template <bool bswap>
static uint32_t farmhashsa::Hash32( const uint8_t * s, size_t len ) {
    const uint32_t seed = 81;

    if (len <= 24) {
        return len <= 12 ?
                   (len <= 4 ?
                       farmhashmk::Hash32Len0to4(s, len) :
                       farmhashmk::Hash32Len5to12<bswap>(s, len)) :
                   farmhashmk::Hash32Len13to24<bswap>(s, len);
    }

    if (len < 40) {
        uint32_t a = len, b = seed * c2, c = a + b;
        a += Fetch32<bswap>(s + len -  4);
        b += Fetch32<bswap>(s + len - 20);
        c += Fetch32<bswap>(s + len - 16);
        uint32_t d = a;
        a  = ROTR32(a, 21);
        a  = Mur(a, Mur(b, Mur(c, d)));
        a += Fetch32<bswap>(s + len - 12);
        b += Fetch32<bswap>(s + len -  8);
        d += a;
        a += d;
        b  = Mur(b, d) * c2;
        a  = _mm_crc32_u32(a, b + c);
        return farmhashmk::Hash32Len13to24<bswap>(s, (len + 1) / 2, a) + b;
    }

  #undef Mulc1
  #define Mulc1(x) Mul((x), cc1)

  #undef Mulc2
  #define Mulc2(x) Mul((x), cc2)

  #undef Murk
#define Murk(a, h)                               \
  Add32(k,                                       \
          Mul5(                                  \
               Rol19(                            \
                     Xor(                        \
                         Mulc2(                  \
                               Rol17(            \
                                     Mulc1(a))), \
                         (h)))))

    const __m128i cc1 = _mm_set1_epi32(c1);
    const __m128i cc2 = _mm_set1_epi32(        c2       );
    __m128i       h   = _mm_set1_epi32(      seed       );
    __m128i       g   = _mm_set1_epi32(        c1 * seed);
    __m128i       f   = g;
    __m128i       k   = _mm_set1_epi32(0xe6546b64       );
    if (len < 80) {
        __m128i a = Fetch128<bswap>(s     );
        __m128i b = Fetch128<bswap>(s + 16);
        __m128i c = Fetch128<bswap>(s +     (len - 15) / 2);
        __m128i d = Fetch128<bswap>(s + len - 32);
        __m128i e = Fetch128<bswap>(s + len - 16);
        h = Add32(h, a);
        g = Add32(g, b);
        g = Shuffle0321(g);
        f = Add32(f, c);
        __m128i be = Add32(b, Mulc1(e));
        h = Add32(h, f);
        f = Add32(f, h);
        h = Add32(Murk(d, h), e);
        k = Xor(k, _mm_shuffle_epi8(g, f));
        g = Add32(Xor(c, g) , a);
        f = Add32(Xor(be, f), d);
        k = Add32(k, be        );
        k = Add32(k, _mm_shuffle_epi8(f, h));
        f = Add32(f, g);
        g = Add32(g, f);
        g = Add32(_mm_set1_epi32(len), Mulc1(g));
    } else {
        // len >= 80
        // The following is loosely modelled after farmhashmk::Hash32.
        size_t iters = (len - 1) / 80;
        len -= iters * 80;

  #undef Chunk
#define Chunk() do {                          \
        __m128i a = Fetch128<bswap>(s);       \
        __m128i b = Fetch128<bswap>(s + 16);  \
        __m128i c = Fetch128<bswap>(s + 32);  \
        __m128i d = Fetch128<bswap>(s + 48);  \
        __m128i e = Fetch128<bswap>(s + 64);  \
        h = Add32(h, a);                      \
        g = Add32(g, b);                      \
        g = Shuffle0321(g);                   \
        f = Add32(f, c);                      \
        __m128i be = Add32(b, Mulc1(e));      \
        h = Add32(h, f);                      \
        f = Add32(f, h);                      \
        h = Add32(Murk(d, h), e);             \
        k = Xor(k, _mm_shuffle_epi8(g, f));   \
        g = Add32(Xor(c, g), a);              \
        f = Add32(Xor(be, f), d);             \
        k = Add32(k, be);                     \
        k = Add32(k, _mm_shuffle_epi8(f, h)); \
        f = Add32(f, g);                      \
        g = Add32(g, f);                      \
        f = Mulc1(f);                         \
    } while (0)

        while (iters-- != 0) {
            Chunk();
            s += 80;
        }

        if (len != 0) {
            h = Add32(h, _mm_set1_epi32(len));
            s = s + len - 80;
            Chunk();
        }
    }

    g      = Shuffle0321(g);
    k      = Xor(k, g);
    f      = Mulc1(f);
    k      = Mulc2(k);
    g      = Mulc1(g);
    h      = Mulc2(h);
    k      = Add32(k, _mm_shuffle_epi8(g, f));
    h      = Add32(h, f);
    f      = Add32(f, h);
    g      = Add32(g, k);
    k      = Add32(k, g);
    k      = Xor(k, _mm_shuffle_epi8(f, h));
    __m128i buf[4];
    buf[0] = f;
    buf[1] = g;
    buf[2] = k;
    buf[3] = h;
    s      = reinterpret_cast<uint8_t *>(buf);
    uint32_t x = Fetch32<bswap>(s    );
    uint32_t y = Fetch32<bswap>(s + 4);
    uint32_t z = Fetch32<bswap>(s + 8);
    x = _mm_crc32_u32(x     , Fetch32<bswap>(s + 12));
    y = _mm_crc32_u32(y     , Fetch32<bswap>(s + 16));
    z = _mm_crc32_u32(z * c1, Fetch32<bswap>(s + 20));
    x = _mm_crc32_u32(x     , Fetch32<bswap>(s + 24));
    y = _mm_crc32_u32(y * c1, Fetch32<bswap>(s + 28));
    uint32_t o = y;
    z = _mm_crc32_u32(z     , Fetch32<bswap>(s + 32));
    x = _mm_crc32_u32(x * c1, Fetch32<bswap>(s + 36));
    y = _mm_crc32_u32(y     , Fetch32<bswap>(s + 40));
    z = _mm_crc32_u32(z * c1, Fetch32<bswap>(s + 44));
    x = _mm_crc32_u32(x     , Fetch32<bswap>(s + 48));
    y = _mm_crc32_u32(y * c1, Fetch32<bswap>(s + 52));
    z = _mm_crc32_u32(z     , Fetch32<bswap>(s + 56));
    x = _mm_crc32_u32(x     , Fetch32<bswap>(s + 60));
    return (o - x + y - z) * c1;
}

  #undef Chunk
  #undef Murk
  #undef Mulc2
  #undef Mulc1

template <bool bswap>
static uint32_t farmhashsa::Hash32WithSeed( const uint8_t * s, size_t len, uint32_t seed ) {
    if (len <= 24) {
        if (len >= 13) { return farmhashmk::Hash32Len13to24<bswap>(s, len, seed * c1); } else if (len >= 5) {
            return farmhashmk::Hash32Len5to12<bswap>(s, len, seed);
        } else {
            return farmhashmk::Hash32Len0to4(s, len, seed);
        }
    }
    uint32_t h = farmhashmk::Hash32Len13to24<bswap>(s, 24, seed ^ len);
    return _mm_crc32_u32(farmhashsa::Hash32<bswap>(s + 24, len - 24) + seed, h);
}

#endif

//------------------------------------------------------------
namespace farmhashcc {
    static inline uint32_t Hash32Len0to4( const uint8_t * s, size_t len );

    template <bool bswap>
    static inline uint32_t Hash32Len5to12( const uint8_t * s, size_t len );

    template <bool bswap>
    static inline uint32_t Hash32Len13to24( const uint8_t * s, size_t len );

    template <bool bswap>
    static uint32_t Hash32( const uint8_t * s, size_t len );

    template <bool bswap>
    static uint32_t Hash32WithSeed( const uint8_t * s, size_t len, uint32_t seed );

    template <bool bswap>
    static inline uint64_t HashLen0to16( const uint8_t * s, size_t len );

    template <bool bswap>
    static inline uint128_t CityMurmur( const uint8_t * s, size_t len, uint128_t seed );

    template <bool bswap>
    static uint128_t Hash128WithSeed( const uint8_t * s, size_t len, uint128_t seed );
} // namespace farmhashcc

template <bool bswap>
static inline uint32_t farmhashcc::Hash32Len13to24( const uint8_t * s, size_t len ) {
    uint32_t a = Fetch32<bswap>(s - 4   + (len >> 1));
    uint32_t b = Fetch32<bswap>(s + 4               );
    uint32_t c = Fetch32<bswap>(s + len - 8         );
    uint32_t d = Fetch32<bswap>(s +       (len >> 1));
    uint32_t e = Fetch32<bswap>(s                   );
    uint32_t f = Fetch32<bswap>(s + len - 4         );
    uint32_t h = len;

    return fmix(Mur(f, Mur(e, Mur(d, Mur(c, Mur(b, Mur(a, h)))))));
}

static inline uint32_t farmhashcc::Hash32Len0to4( const uint8_t * s, size_t len ) {
    uint32_t b = 0;
    uint32_t c = 9;

    for (size_t i = 0; i < len; i++) {
        int8_t v = s[i];
        b  = b * c1 + v;
        c ^= b;
    }
    return fmix(Mur(b, Mur(len, c)));
}

template <bool bswap>
static inline uint32_t farmhashcc::Hash32Len5to12( const uint8_t * s, size_t len ) {
    uint32_t a = len, b = len * 5, c = 9, d = b;

    a += Fetch32<bswap>(s);
    b += Fetch32<bswap>(s + len - 4);
    c += Fetch32<bswap>(s + ((len >> 1) & 4));
    return fmix(Mur(c, Mur(b, Mur(a, d))));
}

template <bool bswap>
static uint32_t farmhashcc::Hash32( const uint8_t * s, size_t len ) {
    if (len <= 24) {
        return len <= 12 ?
                   (len <= 4 ? farmhashcc::Hash32Len0to4(s, len) : farmhashcc::Hash32Len5to12<bswap>(s, len)) :
                   farmhashcc::Hash32Len13to24<bswap>(s, len);
    }

    // len > 24
    uint32_t h = len, g = c1 * len, f = g;
    uint32_t a0 = ROTR32(Fetch32<bswap>(s + len -  4) * c1, 17) * c2;
    uint32_t a1 = ROTR32(Fetch32<bswap>(s + len -  8) * c1, 17) * c2;
    uint32_t a2 = ROTR32(Fetch32<bswap>(s + len - 16) * c1, 17) * c2;
    uint32_t a3 = ROTR32(Fetch32<bswap>(s + len - 12) * c1, 17) * c2;
    uint32_t a4 = ROTR32(Fetch32<bswap>(s + len - 20) * c1, 17) * c2;
    h ^= a0;
    h  = ROTR32(h, 19);
    h  = h * 5 + 0xe6546b64;
    h ^= a2;
    h  = ROTR32(h, 19);
    h  = h * 5 + 0xe6546b64;
    g ^= a1;
    g  = ROTR32(g, 19);
    g  = g * 5 + 0xe6546b64;
    g ^= a3;
    g  = ROTR32(g, 19);
    g  = g * 5 + 0xe6546b64;
    f += a4;
    f  = ROTR32(f, 19);
    f  = f * 5 + 0xe6546b64;
    size_t iters = (len - 1) / 20;
    do {
        uint32_t a0 = ROTR32(Fetch32<bswap>(s)      * c1, 17) * c2;
        uint32_t a1 = Fetch32<bswap>(s +  4);
        uint32_t a2 = ROTR32(Fetch32<bswap>(s +  8) * c1, 17) * c2;
        uint32_t a3 = ROTR32(Fetch32<bswap>(s + 12) * c1, 17) * c2;
        uint32_t a4 = Fetch32<bswap>(s + 16);
        h ^= a0;
        h  = ROTR32(h, 18);
        h  = h * 5 + 0xe6546b64;
        f += a1;
        f  = ROTR32(f, 19);
        f  = f * c1;
        g += a2;
        g  = ROTR32(g, 18);
        g  = g * 5 + 0xe6546b64;
        h ^= a3 + a1;
        h  = ROTR32(h, 19);
        h  = h * 5 + 0xe6546b64;
        g ^= a4;
        g  = BSWAP(g) * 5;
        h += a4 * 5;
        h  = BSWAP(h);
        f += a0;
        PERMUTE3(f, h, g);
        s += 20;
    } while (--iters != 0);
    g = ROTR32(g    , 11) * c1;
    g = ROTR32(g    , 17) * c1;
    f = ROTR32(f    , 11) * c1;
    f = ROTR32(f    , 17) * c1;
    h = ROTR32(h + g, 19);
    h = h * 5 + 0xe6546b64;
    h = ROTR32(h    , 17) * c1;
    h = ROTR32(h + f, 19);
    h = h * 5 + 0xe6546b64;
    h = ROTR32(h    , 17) * c1;
    return h;
}

template <bool bswap>
static uint32_t farmhashcc::Hash32WithSeed( const uint8_t * s, size_t len, uint32_t seed ) {
    if (len <= 24) {
        if (len >= 13) { return farmhashmk::Hash32Len13to24<bswap>(s, len, seed * c1); } else if (len >= 5) {
            return farmhashmk::Hash32Len5to12<bswap>(s, len, seed);
        } else {
            return farmhashmk::Hash32Len0to4(s, len, seed);
        }
    }
    uint32_t h = farmhashmk::Hash32Len13to24<bswap>(s, 24, seed ^ len);
    return Mur(farmhashcc::Hash32<bswap>(s + 24, len - 24) + seed, h);
}

template <bool bswap>
static inline uint64_t farmhashcc::HashLen0to16( const uint8_t * s, size_t len ) {
    if (len >= 8) {
        uint64_t mul = k2 + len * 2;
        uint64_t a   = Fetch64<bswap>(s)      + k2;
        uint64_t b   = Fetch64<bswap>(s + len - 8);
        uint64_t c   = ROTR64(b, 37)  * mul + a;
        uint64_t d   = (ROTR64(a, 25) + b)  * mul;
        return HashLen16(c, d, mul);
    }
    if (len >= 4) {
        uint64_t mul = k2 + len * 2;
        uint64_t a   = Fetch32<bswap>(s);
        return HashLen16(len + (a << 3), Fetch32<bswap>(s + len - 4), mul);
    }
    if (len > 0) {
        uint8_t  a = s[0];
        uint8_t  b = s[len >> 1];
        uint8_t  c = s[len  - 1];
        uint32_t y = static_cast<uint32_t>(a) + (static_cast<uint32_t>(b) << 8);
        uint32_t z = len + (static_cast<uint32_t>(c) << 2);
        return ShiftMix(y * k2 ^ z * k0) * k2;
    }
    return k2;
}

template <bool bswap>
static inline uint128_t farmhashcc::CityMurmur( const uint8_t * s, size_t len, uint128_t seed ) {
    uint64_t    a = Uint128Low64(seed);
    uint64_t    b = Uint128High64(seed);
    uint64_t    c = 0;
    uint64_t    d = 0;
    signed long l = len - 16;

    if (l <= 0) { // len <= 16
        a = ShiftMix(a * k1) * k1;
        c = b * k1 + farmhashcc::HashLen0to16<bswap>(s, len);
        d = ShiftMix(a + (len >= 8 ? Fetch64<bswap>(s) : c));
    } else { // len > 16
        c  = HashLen16(Fetch64<bswap>(s + len - 8) + k1, a      );
        d  = HashLen16(b + len, c + Fetch64<bswap>(s + len - 16));
        a += d;
        do {
            a ^= ShiftMix(Fetch64<bswap>(s)     * k1) * k1;
            a *= k1;
            b ^= a;
            c ^= ShiftMix(Fetch64<bswap>(s + 8) * k1) * k1;
            c *= k1;
            d ^= c;
            s += 16;
            l -= 16;
        } while (l > 0);
    }
    a = HashLen16(a, c);
    b = HashLen16(d, b);
    return Uint128(a ^ b, HashLen16(b, a));
}

template <bool bswap>
static uint128_t farmhashcc::Hash128WithSeed( const uint8_t * s, size_t len, uint128_t seed ) {
    if (len < 128) {
        return farmhashcc::CityMurmur<bswap>(s, len, seed);
    }

    // We expect len >= 128 to be the common case.  Keep 56 bytes of state:
    // v, w, x, y, and z.
    pair<uint64_t, uint64_t> v, w;
    uint64_t x = Uint128Low64(seed);
    uint64_t y = Uint128High64(seed);
    uint64_t z = len * k1;
    v.first  = ROTR64(y ^ k1 , 49) * k1 + Fetch64<bswap>(s);
    v.second = ROTR64(v.first, 42) * k1 + Fetch64<bswap>(s + 8);
    w.first  = ROTR64(y + z  , 35) * k1 + x;
    w.second = ROTR64(x + Fetch64<bswap>(s + 88), 53) * k1;

    // This is the same inner loop as CityHash64(), manually unrolled.
    do {
        x    = ROTR64(x + y        + v.first + Fetch64<bswap>(s +  8), 37) * k1;
        y    = ROTR64(y + v.second +           Fetch64<bswap>(s + 48), 42) * k1;
        x   ^= w.second;
        y   += v.first + Fetch64<bswap>(s + 40);
        z    = ROTR64(z + w.first, 33) * k1;
        v    = WeakHashLen32WithSeeds<bswap>(s     , v.second * k1, x + w.first);
        w    = WeakHashLen32WithSeeds<bswap>(s + 32, z + w.second , y + Fetch64<bswap>(s + 16));
        std::swap(z, x);
        s   += 64;
        x    = ROTR64(x + y        + v.first + Fetch64<bswap>(s +  8), 37) * k1;
        y    = ROTR64(y + v.second +           Fetch64<bswap>(s + 48), 42) * k1;
        x   ^= w.second;
        y   += v.first + Fetch64<bswap>(s + 40);
        z    = ROTR64(z + w.first, 33) * k1;
        v    = WeakHashLen32WithSeeds<bswap>(s     , v.second * k1, x + w.first);
        w    = WeakHashLen32WithSeeds<bswap>(s + 32, z + w.second , y + Fetch64<bswap>(s + 16));
        std::swap(z, x);
        s   += 64;
        len -= 128;
    } while (likely(len >= 128));
    x       += ROTR64(v.first + z, 49) * k0;
    y        = y * k0 + ROTR64(w.second, 37);
    z        = z * k0 + ROTR64(w.first , 27);
    w.first *= 9;
    v.first *= k0;
    // If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s.
    for (size_t tail_done = 0; tail_done < len;) {
        tail_done += 32;
        y          = ROTR64(x + y, 42) * k0 + v.second;
        w.first   += Fetch64<bswap>(s + len - tail_done + 16);
        x          = x                 * k0 + w.first;
        z         += w.second +    Fetch64 <bswap>(s + len - tail_done);
        w.second  += v.first;
        v          = WeakHashLen32WithSeeds<bswap>(s + len - tail_done, v.first + z, v.second);
        v.first   *= k0;
    }
    // At this point our 56 bytes of state should contain more than
    // enough information for a strong 128-bit hash.  We use two
    // different 56-byte-to-8-byte hashes to get a 16-byte final result.
    x = HashLen16(x    , v.first);
    y = HashLen16(y + z, w.first);
    return Uint128(HashLen16(x + v.second, w.second) + y, HashLen16(x + w.second, y + v.second));
}

//------------------------------------------------------------
template <bool bswap>
static void FarmHashNA( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = farmhashna::Hash64WithSeed<bswap>((const uint8_t *)in, len, seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void FarmHashUO( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = farmhashuo::Hash64WithSeed<bswap>((const uint8_t *)in, len, seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

// Since the XO version of Hash64WithSeed is just a call to the UO
// version, the XO version won't be tested explicitly.

#if defined(HAVE_SSE_4_1)

template <bool bswap>
static void FarmHashTE( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = farmhashte::Hash64WithSeed<bswap>((const uint8_t *)in, len, seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void FarmHashNT( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = farmhashnt::Hash32WithSeed<bswap>((const uint8_t *)in, len, seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

#endif

template <bool bswap>
static void FarmHashMK( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = farmhashmk::Hash32WithSeed<bswap>((const uint8_t *)in, len, seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

#if defined(HAVE_X86_64_CRC32C) && defined(HAVE_X86_64_AES)

template <bool bswap>
static void FarmHashSU( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = farmhashsu::Hash32WithSeed<bswap>((const uint8_t *)in, len, seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

#endif

#if defined(HAVE_X86_64_CRC32C)

template <bool bswap>
static void FarmHashSA( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = farmhashsa::Hash32WithSeed<bswap>((const uint8_t *)in, len, seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

#endif

template <bool bswap>
static void FarmHashCC_32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = farmhashcc::Hash32WithSeed<bswap>((const uint8_t *)in, len, seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap, uint32_t seedmode>
static void FarmHashCC_128( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint128_t seed128;

    switch (seedmode) {
    case 1: seed128 = Uint128((uint64_t)seed, 0); break;
    case 2: seed128 = Uint128(0, (uint64_t)seed); break;
    case 3: seed128 = Uint128((uint64_t)seed, (uint64_t)seed); break;
    default: exit(1);
    }
    uint128_t h = farmhashcc::Hash128WithSeed<bswap>((const uint8_t *)in, len, seed128);
    PUT_U64<bswap>(Uint128Low64(h) , (uint8_t *)out, 0);
    PUT_U64<bswap>(Uint128High64(h), (uint8_t *)out, 8);
}

template <bool bswap, uint32_t seedmode>
static void FarmHashCityMurmur_128( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint128_t seed128;

    switch (seedmode) {
    case 1: seed128 = Uint128((uint64_t)seed, 0); break;
    case 2: seed128 = Uint128(0, (uint64_t)seed); break;
    case 3: seed128 = Uint128((uint64_t)seed, (uint64_t)seed); break;
    default: exit(1);
    }
    uint128_t h = farmhashcc::CityMurmur<bswap>((const uint8_t *)in, len, seed128);
    PUT_U64<bswap>(Uint128Low64(h) , (uint8_t *)out, 0);
    PUT_U64<bswap>(Uint128High64(h), (uint8_t *)out, 8);
}

REGISTER_FAMILY(farmhash,
   $.src_url    = "https://github.com/google/farmhash",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(FarmHash_64__NA,
   $.desc       = "FarmHash Hash64WithSeed (NA version)",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.sort_order      = 10,
   $.verification_LE = 0xEBC4A679,
   $.verification_BE = 0xB24C5C09,
   $.hashfn_native   = FarmHashNA<false>,
   $.hashfn_bswap    = FarmHashNA<true>
 );

REGISTER_HASH(FarmHash_64__UO,
   $.desc       = "FarmHash Hash64WithSeed (UO version)",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.sort_order      = 20,
   $.verification_LE = 0x5438EF2C,
   $.verification_BE = 0x72B8113E,
   $.hashfn_native   = FarmHashUO<false>,
   $.hashfn_bswap    = FarmHashUO<true>
 );

#if defined(HAVE_SSE_4_1)
REGISTER_HASH(FarmHash_64__TE,
   $.desc       = "FarmHash Hash64WithSeed (TE version)",
   $.impl       = "sse41",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.sort_order      = 30,
   $.verification_LE = 0xF1BF42C3,
   $.verification_BE = 0x7188736E,
   $.hashfn_native   = FarmHashTE<false>,
   $.hashfn_bswap    = FarmHashTE<true>
 );

REGISTER_HASH(FarmHash_32__NT,
   $.desc       = "FarmHash Hash32WithSeed (NT version)",
   $.impl       = "sse41",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 32,
   $.sort_order      = 40,
   $.verification_LE = 0x47AB39AF,
   $.verification_BE = 0x6AE8BA9B,
   $.hashfn_native   = FarmHashNT<false>,
   $.hashfn_bswap    = FarmHashNT<true>
 );
#endif

REGISTER_HASH(FarmHash_32__MK,
   $.desc       = "FarmHash Hash32WithSeed (MK version)",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY        |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 32,
   $.sort_order      = 50,
   $.verification_LE = 0x0DC9AF39,
   $.verification_BE = 0x6B67BB90,
   $.hashfn_native   = FarmHashMK<false>,
   $.hashfn_bswap    = FarmHashMK<true>
 );

#if defined(HAVE_X86_64_CRC32C) && defined(HAVE_X86_64_AES)
REGISTER_HASH(FarmHash_32__SU,
   $.desc       = "FarmHash Hash32WithSeed (SU version)",
   $.impl       = "x64crc+aes",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED  |
         FLAG_HASH_AES_BASED   |
         FLAG_HASH_CRC_BASED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY        |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 32,
   $.sort_order      = 60,
   $.verification_LE = 0xE7A53C98,
   $.verification_BE = 0x9CC06B52,
   $.hashfn_native   = FarmHashSU<false>,
   $.hashfn_bswap    = FarmHashSU<true>
 );
#endif

#if defined(HAVE_X86_64_CRC32C)
REGISTER_HASH(FarmHash_32__SA,
   $.desc       = "FarmHash Hash32WithSeed (SA version)",
   $.impl       = "x64crc",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED  |
         FLAG_HASH_CRC_BASED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY        |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 32,
   $.sort_order      = 70,
   $.verification_LE = 0x553B1655,
   $.verification_BE = 0x19A1CCEA,
   $.hashfn_native   = FarmHashSA<false>,
   $.hashfn_bswap    = FarmHashSA<true>
 );
#endif

REGISTER_HASH(FarmHash_32__CC,
   $.desc       = "FarmHash Hash32WithSeed (CC version)",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY        |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 32,
   $.sort_order      = 80,
   $.verification_LE = 0x61DEEE7E,
   $.verification_BE = 0xAE9514F0,
   $.hashfn_native   = FarmHashCC_32<false>,
   $.hashfn_bswap    = FarmHashCC_32<true>
 );

REGISTER_HASH(FarmHash_128__CC__seed1,
   $.desc       = "FarmHash Hash128WithSeed (CC version, seeded low 64 bit)",
   $.hash_flags =
         FLAG_HASH_XL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.sort_order      = 90,
   $.verification_LE = 0x305C0D9A,
   $.verification_BE = 0xDC1669A2,
   $.hashfn_native   = FarmHashCC_128<false, 1>,
   $.hashfn_bswap    = FarmHashCC_128<true, 1>
 );

REGISTER_HASH(FarmHash_128__CC__seed2,
   $.desc       = "FarmHash Hash128WithSeed (CC version, seeded high 64 bit)",
   $.hash_flags =
         FLAG_HASH_XL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.sort_order      = 100,
   $.verification_LE = 0x0DB4D383,
   $.verification_BE = 0xFA39DBEA,
   $.hashfn_native   = FarmHashCC_128<false, 2>,
   $.hashfn_bswap    = FarmHashCC_128<true, 2>
 );

REGISTER_HASH(FarmHash_128__CC__seed3,
   $.desc       = "FarmHash Hash128WithSeed (CC version, seeded low+high 64 bit)",
   $.hash_flags =
         FLAG_HASH_XL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.sort_order      = 110,
   $.verification_LE = 0xA93EBF71,
   $.verification_BE = 0x38CD0ED1,
   $.hashfn_native   = FarmHashCC_128<false, 3>,
   $.hashfn_bswap    = FarmHashCC_128<true, 3>
 );

REGISTER_HASH(FarmHash_128__CM__seed1,
   $.desc       = "FarmHash CityMurmur (CM version, seeded low 64 bit)",
   $.hash_flags =
         FLAG_HASH_XL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.sort_order      = 120,
   $.verification_LE = 0x6593FD6D,
   $.verification_BE = 0xF84ED47F,
   $.hashfn_native   = FarmHashCityMurmur_128<false, 1>,
   $.hashfn_bswap    = FarmHashCityMurmur_128<true, 1>
 );

REGISTER_HASH(FarmHash_128__CM__seed2,
   $.desc       = "FarmHash CityMurmur (CM version, seeded high 64 bit)",
   $.hash_flags =
         FLAG_HASH_XL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.sort_order      = 130,
   $.verification_LE = 0xF1483884,
   $.verification_BE = 0x5185F2C4,
   $.hashfn_native   = FarmHashCityMurmur_128<false, 2>,
   $.hashfn_bswap    = FarmHashCityMurmur_128<true, 2>
 );

REGISTER_HASH(FarmHash_128__CM__seed3,
   $.desc       = "FarmHash CityMurmur (CM version, seeded low+high 64 bit)",
   $.hash_flags =
         FLAG_HASH_XL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.sort_order      = 140,
   $.verification_LE = 0x6D028510,
   $.verification_BE = 0xFC258701,
   $.hashfn_native   = FarmHashCityMurmur_128<false, 3>,
   $.hashfn_bswap    = FarmHashCityMurmur_128<true, 3>
 );
