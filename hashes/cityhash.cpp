/*
 * CityHash family v1.1.1, by Geoff Pike and Jyrki Alakuijala
 *
 * Copyright (C) 2022 Frank J. T. Wojcik
 * Copyright (c) 2014-2015 Reini Urban
 * Copyright (c) 2011 Google, Inc.
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
#if !defined(IMPORT_CITY)
  #include "Platform.h"
  #include "Hashlib.h"
#endif

// CityHash128WithSeed is no longer enabled in this family. This is because
// this exact same hash function is part of the (later) FarmHash family,
// and there's no point in testing them twice.

#if defined(HAVE_X86_64_CRC32C)
  #include "Intrinsics.h"
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

static inline uint64_t Uint128Low64( const uint128_t x ) {
    return x.first;
}

static inline uint64_t Uint128High64( const uint128_t x ) {
    return x.second;
}

static inline uint128_t Uint128( uint64_t lo, uint64_t hi ) {
    return uint128_t(lo, hi);
}

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

//------------------------------------------------------------
// Some primes between 2^63 and 2^64 for various uses.
static const uint64_t k0 = UINT64_C(0xc3a5c85c97cb3127);
static const uint64_t k1 = UINT64_C(0xb492b66fbe98f273);
static const uint64_t k2 = UINT64_C(0x9ae16a3b2f90404f);

// Magic numbers for 32-bit hashing.  Copied from Murmur3.
static const uint32_t c1 = 0xcc9e2d51;
static const uint32_t c2 = 0x1b873593;

//------------------------------------------------------------
// A 32-bit to 32-bit integer hash copied from Murmur3.
static uint32_t fmix( uint32_t h ) {
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

// Helper from Murmur3 for combining two 32-bit values.
static uint32_t Mur( uint32_t a, uint32_t h ) {
    a *= c1;
    a  = ROTR32(a, 17);
    a *= c2;
    h ^= a;
    h  = ROTR32(h, 19);
    return h * 5 + 0xe6546b64;
}

#define PERMUTE3(a, b, c) do { std::swap(a, b); std::swap(a, c); } while (0)

//------------------------------------------------------------
// All seeding for these 32-bit functions is unofficial and home-grown for
// SMHasher3

static uint32_t Hash32Len0to4( const uint8_t * s, size_t len, uint32_t seed ) {
    uint32_t b = seed;
    uint32_t c = 9;

    for (size_t i = 0; i < len; i++) {
        b  = b * c1 + s[i];
        c ^= b;
    }
    return fmix(Mur(b, Mur(len, c)));
}

template <bool bswap>
static uint32_t Hash32Len5to12( const uint8_t * s, size_t len, uint32_t seed ) {
    uint32_t a = len + seed, b = a * 5, c = 9, d = b;

    a += Fetch32<bswap>(s);
    b += Fetch32<bswap>(s + len - 4);
    c += Fetch32<bswap>(s + ((len >> 1) & 4));
    return fmix(Mur(c, Mur(b, Mur(a, d))));
}

template <bool bswap>
static uint32_t Hash32Len13to24( const uint8_t * s, size_t len, uint32_t seed ) {
    uint32_t a = Fetch32<bswap>(s - 4   + (len >> 1));
    uint32_t b = Fetch32<bswap>(s + 4               );
    uint32_t c = Fetch32<bswap>(s + len - 8         );
    uint32_t d = Fetch32<bswap>(s +       (len >> 1));
    uint32_t e = Fetch32<bswap>(s                   );
    uint32_t f = Fetch32<bswap>(s + len - 4         );
    uint32_t h = seed + len;

    return fmix(Mur(f, Mur(e, Mur(d, Mur(c, Mur(b, Mur(a, h)))))));
}

template <bool bswap>
static uint32_t CityHash32WithSeed( const uint8_t * s, size_t len, uint32_t seed ) {
    if (len <= 24) {
        return len <= 12 ?
                   (len <= 4 ?
                       Hash32Len0to4(s, len, seed) :
                       Hash32Len5to12<bswap>(s, len, seed)) :
                   Hash32Len13to24<bswap>(s, len, seed);
    }

    // len > 24
    uint32_t h = len + seed, g = c1 * h, f = g;
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
    g = ROTR32(g, 11) * c1;
    g = ROTR32(g, 17) * c1;
    f = ROTR32(f, 11) * c1;
    f = ROTR32(f, 17) * c1;
    h = h + g;
    h = ROTR32(h, 19);
    h = h * 5 + 0xe6546b64;
    h = ROTR32(h, 17) * c1;
    h = h + f;
    h = ROTR32(h, 19);
    h = h * 5 + 0xe6546b64;
    h = ROTR32(h, 17) * c1;
    return h;
}

//------------------------------------------------------------
// Hash 128 input bits down to 64 bits of output.
// This is intended to be a reasonably good hash function.
static inline uint64_t Hash128to64( const uint128_t & x ) {
    // Murmur-inspired hashing.
    const uint64_t kMul = UINT64_C(0x9ddfea08eb382d69);
    uint64_t       a    = (Uint128Low64(x)  ^ Uint128High64(x)) * kMul;
    uint64_t       b;

    a ^= (a >> 47);
    b  = (Uint128High64(x) ^ a) * kMul;
    b ^= (b >> 47);
    b *= kMul;
    return b;
}

static uint64_t HashLen16( uint64_t u, uint64_t v ) {
    return Hash128to64(Uint128(u, v));
}

static uint64_t HashLen16( uint64_t u, uint64_t v, uint64_t mul ) {
    // Murmur-inspired hashing.
    uint64_t a = (u ^ v) * mul;

    a ^= (a >> 47);
    uint64_t b = (v ^ a) * mul;
    b ^= (b >> 47);
    b *= mul;
    return b;
}

static uint64_t ShiftMix( uint64_t val ) {
    return val ^ (val >> 47);
}

// Return a 16-byte hash for 48 bytes.  Quick and dirty.
// Callers do best to use "random-looking" values for a and b.
static pair<uint64_t, uint64_t> WeakHashLen32WithSeeds( uint64_t w, uint64_t x,
        uint64_t y, uint64_t z, uint64_t a, uint64_t b ) {
    a += w;
    uint64_t c = a;
    b  = b + a + z;
    b  = ROTR64(b, 21);
    a += x;
    a += y;
    b += ROTR64(a, 44);
    return make_pair(a + z, b + c);
}

// Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty.
template <bool bswap>
static pair<uint64_t, uint64_t> WeakHashLen32WithSeeds( const uint8_t * s, uint64_t a, uint64_t b ) {
    return WeakHashLen32WithSeeds(Fetch64<bswap>(s), Fetch64<bswap>(
            s + 8), Fetch64<bswap>(s + 16), Fetch64<bswap>(s + 24), a, b);
}

//------------------------------------------------------------
template <bool bswap>
static uint64_t HashLen0to16( const uint8_t * s, size_t len ) {
    if (len >= 8) {
        uint64_t mul = k2 + len * 2;
        uint64_t a   = Fetch64<bswap>(s) + k2;
        uint64_t b   = Fetch64<bswap>(s + len - 8);
        uint64_t c   = ROTR64(b, 37) * mul + a;
        uint64_t d   = (ROTR64(a, 25) + b) * mul;
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
        uint32_t y = static_cast<uint32_t>(a)   + (static_cast<uint32_t>(b) << 8);
        uint32_t z = static_cast<uint32_t>(len) + (static_cast<uint32_t>(c) << 2);
        return ShiftMix(y * k2 ^ z * k0) * k2;
    }
    return k2;
}

// This probably works well for 16-byte strings as well, but it may be overkill
// in that case.
template <bool bswap>
static uint64_t HashLen17to32( const uint8_t * s, size_t len ) {
    uint64_t mul = k2 + len * 2;
    uint64_t a   = Fetch64<bswap>(s           ) * k1;
    uint64_t b   = Fetch64<bswap>(s + 8       );
    uint64_t c   = Fetch64<bswap>(s + len -  8) * mul;
    uint64_t d   = Fetch64<bswap>(s + len - 16) * k2;

    return HashLen16(ROTR64(a + b, 43) + ROTR64(c, 30) + d, a + ROTR64(b + k2, 18) + c, mul);
}

// Return an 8-byte hash for 33 to 64 bytes.
template <bool bswap>
static uint64_t HashLen33to64( const uint8_t * s, size_t len ) {
    uint64_t mul = k2 + len * 2;
    uint64_t a   = Fetch64<bswap>(s    ) * k2;
    uint64_t b   = Fetch64<bswap>(s + 8);
    uint64_t c   = Fetch64<bswap>(s + len - 24);
    uint64_t d   = Fetch64<bswap>(s + len - 32);
    uint64_t e   = Fetch64<bswap>(s + 16) * k2;
    uint64_t f   = Fetch64<bswap>(s + 24) * 9;
    uint64_t g   = Fetch64<bswap>(s + len -  8);
    uint64_t h   = Fetch64<bswap>(s + len - 16) * mul;
    uint64_t u   = ROTR64(a + g, 43) + (ROTR64(b, 30) + c) * 9;
    uint64_t v   = ((a + g) ^ d) + f + 1;
    uint64_t w   = BSWAP((u + v) * mul) + h;
    uint64_t x   = ROTR64(e + f, 42) + c;
    uint64_t y   = (BSWAP((v + w) * mul) + g) * mul;
    uint64_t z   = e + f + c;
    a = BSWAP((x + z) * mul + y) + b;
    b = ShiftMix((z + a) * mul + d + h) * mul;
    return b + x;
}

template <bool bswap>
static uint64_t CityHash64( const uint8_t * s, size_t len ) {
    if (len <= 32) {
        if (len <= 16) {
            return HashLen0to16<bswap>(s, len);
        } else {
            return HashLen17to32<bswap>(s, len);
        }
    } else if (len <= 64) {
        return HashLen33to64<bswap>(s, len);
    }

    // For strings over 64 bytes we hash the end first, and then as we
    // loop we keep 56 bytes of state: v, w, x, y, and z.
    uint64_t x = Fetch64<bswap>(s + len - 40);
    uint64_t y = Fetch64<bswap>(s + len - 16) + Fetch64<bswap>(s + len - 56);
    uint64_t z = HashLen16(Fetch64<bswap>(s + len - 48) + len, Fetch64<bswap>(s + len - 24));
    pair<uint64_t, uint64_t> v = WeakHashLen32WithSeeds<bswap>(s + len - 64, len   , z);
    pair<uint64_t, uint64_t> w = WeakHashLen32WithSeeds<bswap>(s + len - 32, y + k1, x);
    x = x * k1 + Fetch64<bswap>(s);

    // Decrease len to the nearest multiple of 64, and operate on 64-byte chunks.
    len = (len - 1) & ~static_cast<size_t>(63);
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
        len -= 64;
    } while (len != 0);
    return HashLen16(HashLen16(v.first, w.first) + ShiftMix(y) * k1 + z, HashLen16(v.second, w.second) + x);
}

template <bool bswap>
static uint64_t CityHash64WithSeeds( const uint8_t * s, size_t len, uint64_t seed0, uint64_t seed1 ) {
    return HashLen16(CityHash64<bswap>(s, len) - seed0, seed1);
}

template <bool bswap>
static uint64_t CityHash64WithSeed( const uint8_t * s, size_t len, uint64_t seed ) {
    return CityHash64WithSeeds<bswap>(s, len, k2, seed);
}

//------------------------------------------------------------
template <bool bswap>
static uint128_t CityMurmur( const uint8_t * s, size_t len, uint128_t seed ) {
    uint64_t a = Uint128Low64(seed);
    uint64_t b = Uint128High64(seed);
    uint64_t c = 0;
    uint64_t d = 0;

    if (len <= 16) {
        a = ShiftMix(a * k1) * k1;
        c = b * k1 + HashLen0to16<bswap>(s, len);
        d = ShiftMix(a + (len >= 8 ? Fetch64<bswap>(s) : c));
    } else {
        c  = HashLen16(Fetch64<bswap>(s + len - 8) + k1, a      );
        d  = HashLen16(b + len, c + Fetch64<bswap>(s + len - 16));
        a += d;
        // len > 16 here, so do...while is safe
        do {
            a   ^= ShiftMix(Fetch64<bswap>(s)     * k1) * k1;
            a   *= k1;
            b   ^= a;
            c   ^= ShiftMix(Fetch64<bswap>(s + 8) * k1) * k1;
            c   *= k1;
            d   ^= c;
            s   += 16;
            len -= 16;
        } while (len > 16);
    }
    a = HashLen16(a, c);
    b = HashLen16(d, b);
    return Uint128(a ^ b, HashLen16(b, a));
}

template <bool bswap>
static uint128_t CityHash128WithSeed( const uint8_t * s, size_t len, uint128_t seed ) {
    if (len < 128) {
        return CityMurmur<bswap>(s, len, seed);
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
    x += ROTR64(v.first + z, 49) * k0;
    y  = y * k0 + ROTR64(w.second, 37);
    z  = z * k0 + ROTR64(w.first,  27);
    w.first *= 9;
    v.first *= k0;
    // If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s.
    for (size_t tail_done = 0; tail_done < len;) {
        tail_done += 32;
        y          = ROTR64(x + y, 42) * k0 + v.second;
        w.first   += Fetch64<bswap>(s + len - tail_done + 16);
        x          = x                 * k0 + w.first;
        z         += w.second +     Fetch64<bswap>(s + len - tail_done);
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

template <bool bswap>
static uint128_t CityHash128( const char * s, size_t len ) {
    return len >= 16 ?
               CityHash128WithSeed<bswap>(s + 16, len - 16, Uint128(Fetch64<bswap>(s), Fetch64<bswap>(s + 8) + k0)) :
               CityHash128WithSeed<bswap>(s     , len     , Uint128(k0, k1));
}

//------------------------------------------------------------
#if defined(HAVE_X86_64_CRC32C)

// Requires len >= 240.
template <bool bswap>
static void CityHashCrc256Long( const uint8_t * s, size_t len, uint32_t seed, uint64_t * result ) {
    uint64_t a = Fetch64<bswap>(s +  56) + k0;
    uint64_t b = Fetch64<bswap>(s +  96) + k0;
    uint64_t c = HashLen16(b, len);
    uint64_t d = Fetch64<bswap>(s + 120) * k0 + len;
    uint64_t e = Fetch64<bswap>(s + 184) + seed;
    uint64_t f = 0;
    uint64_t g = 0;
    uint64_t h = c + d;
    uint64_t x = seed;
    uint64_t y = 0;
    uint64_t z = 0;

    result[0] = c;
    result[1] = d;

    // 240 bytes of input per iter.
    size_t iters = len / 240;
    len -= iters * 240;
    do {
#undef CHUNK
#define CHUNK(r)                      \
        PERMUTE3(x, z, y);            \
        b += Fetch64<bswap>(s);       \
        c += Fetch64<bswap>(s + 8);   \
        d += Fetch64<bswap>(s + 16);  \
        e += Fetch64<bswap>(s + 24);  \
        f += Fetch64<bswap>(s + 32);  \
        a += b;                       \
        h += f;                       \
        b += c;                       \
        f += d;                       \
        g += e;                       \
        e += z;                       \
        g += x;                       \
        z  = _mm_crc32_u64(z, b + g); \
        y  = _mm_crc32_u64(y, e + h); \
        x  = _mm_crc32_u64(x, f + a); \
        e  = ROTR64(e, r);            \
        c += e;                       \
        s += 40

        CHUNK( 0); PERMUTE3(a, h, c);
        CHUNK(33); PERMUTE3(a, h, f);
        CHUNK( 0); PERMUTE3(b, h, f);
        CHUNK(42); PERMUTE3(b, h, d);
        CHUNK( 0); PERMUTE3(b, h, e);
        CHUNK(33); PERMUTE3(a, h, e);
    } while (--iters > 0);

    while (len >= 40) {
        CHUNK(29);
        e ^= ROTR64(a, 20);
        h += ROTR64(b, 30);
        g ^= ROTR64(c, 40);
        f += ROTR64(d, 34);
        PERMUTE3(c, h, g);
        len -= 40;
    }
    if (len > 0) {
        s = s + len - 40;
        CHUNK(33);
        e ^= ROTR64(a, 43);
        h += ROTR64(b, 42);
        g ^= ROTR64(c, 41);
        f += ROTR64(d, 40);
    }
    result[0] ^= h;
    result[1] ^= g;

    g += h;
    a  = HashLen16(a, g + z);
    x += y << 32;
    b += x;
    c  = HashLen16(c, z) + h;
    d  = HashLen16(d, e + result[0]);
    g += e;
    h += HashLen16(x, f);
    e  = HashLen16(a, d) + g;
    z  = HashLen16(b, c) + a;
    y  = HashLen16(g, h) + c;

    result[0]  = e + z + y + x;
    a          = ShiftMix((a + y) * k0) * k0 + b;
    result[1] += a + result[0];
    a          = ShiftMix(a * k0) * k0 + c;
    result[2]  = a + result[1];
    a          = ShiftMix((a + e) * k0) * k0;
    result[3]  = a + result[2];
}

// Requires len < 240.
template <bool bswap>
static void CityHashCrc256Short( const uint8_t * s, size_t len, uint64_t * result ) {
    uint8_t buf[240];

    memcpy(buf, s, len);
    memset(buf + len, 0, 240 - len);
    CityHashCrc256Long<bswap>(buf, 240, ~static_cast<uint32_t>(len), result);
}

template <bool bswap>
static void CityHashCrc256( const uint8_t * s, size_t len, uint64_t * result ) {
    if (likely(len >= 240)) {
        CityHashCrc256Long<bswap>(s, len, 0, result);
    } else {
        CityHashCrc256Short<bswap>(s, len, result);
    }
}

// Requires len < 240.
// Unofficial homegrown seeding for SMHasher3
template <bool bswap>
static void CityHashCrc256ShortWithSeed( const uint8_t * s, size_t len, uint32_t seed, uint64_t * result ) {
    uint8_t buf[240];

    memcpy(buf, s, len);
    memset(buf + len, 0, 240 - len);
    CityHashCrc256Long<bswap>(buf, 240, HashLen16(seed, ~static_cast<uint32_t>(len)), result);
}

// Unofficial
template <bool bswap>
static void CityHashCrc256WithSeed( const uint8_t * s, size_t len, uint32_t seed, uint64_t * result ) {
    if (likely(len >= 240)) {
        CityHashCrc256Long<bswap>(s, len, seed, result);
    } else {
        CityHashCrc256ShortWithSeed<bswap>(s, len, seed, result);
    }
}

template <bool bswap>
static uint128_t CityHashCrc128WithSeed( const uint8_t * s, size_t len, uint128_t seed ) {
    if (len <= 900) {
        return CityHash128WithSeed<bswap>(s, len, seed);
    } else {
        uint64_t result[4];
        CityHashCrc256<bswap>(s, len, result);
        uint64_t u = Uint128High64(seed) + result[0];
        uint64_t v = Uint128Low64(seed)  + result[1];
        return Uint128(HashLen16(u, v + result[2]), HashLen16(ROTR64(v, 32), u * k0 + result[3]));
    }
}

template <bool bswap>
static uint128_t CityHashCrc128( const uint8_t * s, size_t len ) {
    if (len <= 900) {
        return CityHash128<bswap>(s, len);
    } else {
        uint64_t result[4];
        CityHashCrc256<bswap>(s, len, result);
        return Uint128(result[2], result[3]);
    }
}

#endif

//------------------------------------------------------------
template <bool bswap>
static void City32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h;

    h = CityHash32WithSeed<bswap>((const uint8_t *)in, len, (uint32_t)seed);
    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void City64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h;

    h = CityHash64WithSeed<bswap>((const uint8_t *)in, len, (uint64_t)seed);
    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

#if 0

template <bool bswap, uint32_t seedmode>
static void City128( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint128_t seed128;

    switch (seedmode) {
    case 1: seed128 = Uint128((uint64_t)seed, 0); break;
    case 2: seed128 = Uint128(0, (uint64_t)seed); break;
    case 3: seed128 = Uint128((uint64_t)seed, (uint64_t)seed); break;
    default: exit(1);
    }

    uint128_t h;
    h = CityHash128WithSeed<bswap>((const uint8_t *)in, len, seed128);
    PUT_U64<bswap>(Uint128Low64(h) , (uint8_t *)out, 0);
    PUT_U64<bswap>(Uint128High64(h), (uint8_t *)out, 8);
}

template <bool bswap, uint32_t seedmode>
static void CityMurmur_128( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint128_t seed128;

    switch (seedmode) {
    case 1: seed128 = Uint128((uint64_t)seed, 0); break;
    case 2: seed128 = Uint128(0, (uint64_t)seed); break;
    case 3: seed128 = Uint128((uint64_t)seed, (uint64_t)seed); break;
    default: exit(1);
    }

    uint128_t h;
    h = CityMurmur<bswap>((const uint8_t *)in, len, seed128);
    PUT_U64<bswap>(Uint128Low64(h) , (uint8_t *)out, 0);
    PUT_U64<bswap>(Uint128High64(h), (uint8_t *)out, 8);
}

#endif

#if defined(HAVE_X86_64_CRC32C)

template <bool bswap, uint32_t seedmode>
static void CityCrc128( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint128_t seed128;

    switch (seedmode) {
    case 1: seed128 = Uint128((uint64_t)seed, 0); break;
    case 2: seed128 = Uint128(0, (uint64_t)seed); break;
    case 3: seed128 = Uint128((uint64_t)seed, (uint64_t)seed); break;
    default: exit(1);
    }

    uint128_t h;
    h = CityHashCrc128WithSeed<bswap>((const uint8_t *)in, len, seed128);
    PUT_U64<bswap>(Uint128Low64(h) , (uint8_t *)out, 0);
    PUT_U64<bswap>(Uint128High64(h), (uint8_t *)out, 8);
}

template <bool bswap>
static void CityCrc256( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t result[4];

    CityHashCrc256WithSeed<bswap>((const uint8_t *)in, len, (uint64_t)seed, result);
    PUT_U64<bswap>(result[0], (uint8_t *)out,  0);
    PUT_U64<bswap>(result[1], (uint8_t *)out,  8);
    PUT_U64<bswap>(result[2], (uint8_t *)out, 16);
    PUT_U64<bswap>(result[3], (uint8_t *)out, 24);
}

#endif

//------------------------------------------------------------
#if !defined(IMPORT_CITY)
REGISTER_FAMILY(cityhash,
   $.src_url    = "https://github.com/google/cityhash",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(CityHash_32,
   $.desc       = "Google CityHash32 (modified seeding)",
   $.hash_flags =
         FLAG_HASH_NO_SEED         |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0xEDED9084,
   $.verification_BE = 0x2E033380,
   $.hashfn_native   = City32<false>,
   $.hashfn_bswap    = City32<true>
 );

REGISTER_HASH(CityHash_64,
   $.desc       = "Google CityHash64WithSeed",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x5FABC5C5,
   $.verification_BE = 0x355FC63A,
   $.hashfn_native   = City64<false>,
   $.hashfn_bswap    = City64<true>
 );

  #if 0
REGISTER_HASH(CityHash_128__seed1,
   $.desc       = "Google CityHash128WithSeed (seeded low 64 bits)",
   $.hash_flags =
         FLAG_HASH_XL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x305C0D9A,
   $.verification_BE = 0,
   $.hashfn_native   = City128<false, 1>,
   $.hashfn_bswap    = City128<true, 1>
 );

REGISTER_HASH(CityHash_128__seed2,
   $.desc       = "Google CityHash128WithSeed (seeded high 64 bits)",
   $.hash_flags =
         FLAG_HASH_XL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x0DB4D383,
   $.verification_BE = 0,
   $.hashfn_native   = City128<false, 2>,
   $.hashfn_bswap    = City128<true, 2>
 );

REGISTER_HASH(CityHash_128__seed3,
   $.desc       = "Google CityHash128WithSeed (seeded low+high 64 bits)",
   $.hash_flags =
         FLAG_HASH_XL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0xA93EBF71,
   $.verification_BE = 0,
   $.hashfn_native   = City128<false, 3>,
   $.hashfn_bswap    = City128<true, 3>
 );
  #endif

  #if 0
REGISTER_HASH(CityMurmur__seed1,
   $.desc       = "CityMurmur (seeded low 64 bits)",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x6593FD6D,
   $.verification_BE = 0,
   $.hashfn_native   = CityMurmur_128<false, 1>,
   $.hashfn_bswap    = CityMurmur_128<true, 1>
 );

REGISTER_HASH(CityMurmur__seed2,
   $.desc       = "CityMurmur (seeded high 64 bits)",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0xF1483884,
   $.verification_BE = 0,
   $.hashfn_native   = CityMurmur_128<false, 2>,
   $.hashfn_bswap    = CityMurmur_128<true, 2>
 );

REGISTER_HASH(CityMurmur__seed3,
   $.desc       = "CityMurmur (seeded low+high 64 bits)",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x6D028510,
   $.verification_BE = 0,
   $.hashfn_native   = CityMurmur_128<false, 3>,
   $.hashfn_bswap    = CityMurmur_128<true, 3>
 );
  #endif

  #if defined(HAVE_X86_64_CRC32C)

REGISTER_HASH(CityHashCrc_128__seed1,
   $.desc       = "Google CityHashCrc128WithSeed (seeded low 64 bits)",
   $.impl       = "hwcrc_x64",
   $.hash_flags =
         FLAG_HASH_XL_SEED         |
         FLAG_HASH_CRC_BASED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x98C09AB4,
   $.verification_BE = 0xF3DF4378,
   $.hashfn_native   = CityCrc128<false, 1>,
   $.hashfn_bswap    = CityCrc128<true, 1>
 );

REGISTER_HASH(CityHashCrc_128__seed2,
   $.desc       = "Google CityHashCrc128WithSeed (seeded high 64 bits)",
   $.impl       = "hwcrc_x64",
   $.hash_flags =
         FLAG_HASH_XL_SEED         |
         FLAG_HASH_CRC_BASED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0xDA655B2C,
   $.verification_BE = 0x8CF5BD76,
   $.hashfn_native   = CityCrc128<false, 2>,
   $.hashfn_bswap    = CityCrc128<true, 2>
 );

REGISTER_HASH(CityHashCrc_128__seed3,
   $.desc       = "Google CityHashCrc128WithSeed (seeded low+high 64 bits)",
   $.impl       = "hwcrc_x64",
   $.hash_flags =
         FLAG_HASH_XL_SEED         |
         FLAG_HASH_CRC_BASED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x85279D96,
   $.verification_BE = 0xFBB049D5,
   $.hashfn_native   = CityCrc128<false, 3>,
   $.hashfn_bswap    = CityCrc128<true, 3>
 );

REGISTER_HASH(CityHashCrc_256,
   $.desc       = "Google CityHashCrc256 (with modified seeding)",
   $.impl       = "hwcrc_x64",
   $.hash_flags =
         FLAG_HASH_NO_SEED         |
         FLAG_HASH_SMALL_SEED      |
         FLAG_HASH_CRC_BASED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_SLOW            |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 256,
   $.verification_LE = 0xB5F99A90,
   $.verification_BE = 0xD5FEE0A0,
   $.hashfn_native   = CityCrc256<false>,
   $.hashfn_bswap    = CityCrc256<true>
 );

  #endif
#endif
