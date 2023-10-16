/*
 * wyhash
 * This is free and unencumbered software released into the public
 * domain under The Unlicense (http://unlicense.org/).
 *
 * author: 王一 Wang Yi <godspeed_china@yeah.net>
 * contributors: Frank J. T. Wojcik, Reini Urban, Dietrich Epp, Joshua
 * Haberman, Tommy Ettinger, Daniel Lemire, Otmar Ertl, cocowalla,
 * leo-yuriev, Diego Barrios Romero, paulie-g, dumblob, Yann Collet,
 * ivte-ms, hyb, James Z.M. Gao, easyaspi314 (Devin), TheOneric
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a
 * compiled binary, for any purpose, commercial or non-commercial, and
 * by any means.
 *
 * In jurisdictions that recognize copyright laws, the author or
 * authors of this software dedicate any and all copyright interest in
 * the software to the public domain. We make this dedication for the
 * benefit of the public at large and to the detriment of our heirs
 * and successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to
 * this software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */
#include "Platform.h"
#include "Hashlib.h"

#include "Mathmult.h"

//-----------------------------------------------------------------------------
// Data reading functions, common to 32- and 64-bit hashes
template <bool bswap>
static inline uint64_t _wyr8( const uint8_t * p ) {
    return GET_U64<bswap>(p, 0);
}

template <bool bswap>
static inline uint64_t _wyr4( const uint8_t * p ) {
    return GET_U32<bswap>(p, 0);
}

static inline uint64_t _wyr3( const uint8_t * p, size_t k ) {
    return (((uint64_t)p[0]) << 16) | (((uint64_t)p[k >> 1]) << 8) | p[k - 1];
}

//-----------------------------------------------------------------------------
// 128-bit multiply function
//
// All platform-specific code returns the same results for a given
// choice of strict. I.e. for a given set of template parameter
// choices, this function should always give the same answer
// regardless of platform.
static inline uint64_t _wyrot( uint64_t x ) { return ROTL64(x, 32); }

// TODO: pass mum32bit template param through _wyhash64
template <bool mum32bit, bool strict>
static inline void _wymum( uint64_t * A, uint64_t * B ) {
    if (mum32bit) {
        uint64_t hh = (*A >> 32) * (*B >> 32), hl = (*A >> 32) * (uint32_t)*B,
                lh = (uint32_t)*A * (*B >> 32), ll = (uint64_t)(uint32_t)*A * (uint32_t)*B;
        if (strict) {
            *A ^= _wyrot(hl) ^ hh; *B ^= _wyrot(lh) ^ ll;
        } else {
            *A  = _wyrot(hl) ^ hh; *B  = _wyrot(lh) ^ ll;
        }
    } else {
        uint64_t rlo, rhi;
        MathMult::mult64_128(rlo, rhi, *A, *B);
        if (strict) {
            *A ^= rlo; *B ^= rhi;
        } else {
            *A  = rlo; *B  = rhi;
        }
    }
}

//-----------------------------------------------------------------------------
// multiply and xor mix function, aka MUM
template <bool strict>
static inline uint64_t _wymix( uint64_t A, uint64_t B ) {
    _wymum<false, strict>(&A, &B);
    return A ^ B;
}

// wyhash64 main function
template <bool bswap, bool strict>
static inline uint64_t _wyhash64( const void * key, size_t len, uint64_t seed, const uint64_t * secrets ) {
    const uint8_t * p = (const uint8_t *)key;
    uint64_t        a, b;

    seed ^= _wymix<strict>(seed ^ secrets[0], secrets[1]);

    if (likely(len <= 16)) {
        if (likely(len >= 4)) {
            a = (_wyr4<bswap>(p) << 32) | _wyr4<bswap>(p + ((len >> 3) << 2));
            b = (_wyr4<bswap>(p + len - 4) << 32) | _wyr4<bswap>(p + len - 4 - ((len >> 3) << 2));
        } else if (likely(len > 0)) {
            a = _wyr3(p, len);
            b = 0;
        } else {
            a = b = 0;
        }
    } else {
        size_t i = len;
        if (unlikely(i >= 48)) {
            uint64_t see1 = seed, see2 = seed;
            do {
                seed = _wymix<strict>(_wyr8<bswap>(p)      ^ secrets[1], _wyr8<bswap>(p +  8) ^ seed);
                see1 = _wymix<strict>(_wyr8<bswap>(p + 16) ^ secrets[2], _wyr8<bswap>(p + 24) ^ see1);
                see2 = _wymix<strict>(_wyr8<bswap>(p + 32) ^ secrets[3], _wyr8<bswap>(p + 40) ^ see2);
                p   += 48; i -= 48;
            } while (likely(i >= 48));
            seed ^= see1 ^ see2;
        }
        while (unlikely(i > 16)) {
            seed = _wymix<strict>(_wyr8<bswap>(p) ^ secrets[1], _wyr8<bswap>(p + 8) ^ seed);
            i   -= 16; p += 16;
        }
        a = _wyr8<bswap>(p + i - 16);
        b = _wyr8<bswap>(p + i -  8);
    }
    a ^= secrets[1];
    b ^= seed;
    _wymum<false, strict>(&a, &b);
    return _wymix<strict>(a ^ secrets[0] ^ len, b ^ secrets[1]);
}

//-----------------------------------------------------------------------------
// 32-bit hash function
static inline void _wymix32( uint32_t * A,  uint32_t * B ) {
    uint64_t c;

    c  = *A ^ 0x53c5ca59;
    c *= *B ^ 0x74743c1b;
    *A = (uint32_t)c;
    *B = (uint32_t)(c >> 32);
}

template <bool bswap>
static inline uint32_t _wyhash32( const void * key, uint64_t len, uint32_t seed ) {
    const uint8_t * p    = (const uint8_t *)key;
    uint64_t        i    = len;
    uint32_t        see1 = (uint32_t       )len;

    seed ^= (uint32_t)(len >> 32);
    _wymix32(&seed, &see1);

    for (; i > 8; i -= 8, p += 8) {
        seed ^= _wyr4<bswap>(p    );
        see1 ^= _wyr4<bswap>(p + 4);
        _wymix32(&seed, &see1);
    }
    if (i >= 4) {
        seed ^= _wyr4<bswap>(p        );
        see1 ^= _wyr4<bswap>(p + i - 4);
    } else if (i) {
        seed ^= _wyr3(p, (size_t)i);
    }
    _wymix32(&seed, &see1);
    _wymix32(&seed, &see1);
    return seed ^ see1;
}

//-----------------------------------------------------------------------------
// the default secret parameters
static const uint64_t _wyp[4] = {
    UINT64_C(0x2d358dccaa6c78a5), UINT64_C(0x8bb84b93962eacc9),
    UINT64_C(0x4b33a62ed433d4a3), UINT64_C(0x4d5a2da51de1aa47)
};

//-----------------------------------------------------------------------------
// The published wyhash.h file tries to auto-detect system endianness,
// while the published wyhash32.h file relies on a WYHASH32_BIG_ENDIAN
// being #defined appropriately. SMHasher3 operates as it that is set
// correctly. Both published files convert bytes into integers in a
// little-endian fashion, but return results simply as a 64-bit integer, so
// the calls to (e.g.) _wyhash32 are made to always read in little-endian
// mode, but the calls to (e.g.) PUT_U32 are always done in "native" mode.

template <bool bswap>
static void Wyhash32( const void * in, const size_t len, const seed_t seed, void * out ) {
    if (isLE()) {
        PUT_U32<bswap>(_wyhash32<false>(in, (uint64_t)len, (uint32_t)seed), (uint8_t *)out, 0);
    } else {
        PUT_U32<bswap>(_wyhash32<true>(in, (uint64_t)len, (uint32_t)seed), (uint8_t *)out, 0);
    }
}

template <bool bswap, bool strict>
static void Wyhash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    if (isLE()) {
        PUT_U64<bswap>(_wyhash64<false, strict>(in, len, (uint64_t)seed, _wyp), (uint8_t *)out, 0);
    } else {
        PUT_U64<bswap>(_wyhash64<true, strict>(in, len, (uint64_t)seed, _wyp), (uint8_t *)out, 0);
    }
}

//-----------------------------------------------------------------------------
static bool wyhash64_selftest( void ) {
    struct {
        const uint64_t  hash;
        const char *    key;
    } selftests[] = {
        { UINT64_C (0x93228a4de0eec5a2), "" }                          ,
        { UINT64_C (0xc5bac3db178713c4), "a" }                         ,
        { UINT64_C (0xa97f2f7b1d9b3314), "abc" }                       ,
        { UINT64_C (0x786d1f1df3801df4), "message digest" }            ,
        { UINT64_C (0xdca5a8138ad37c87), "abcdefghijklmnopqrstuvwxyz" },
        { UINT64_C (0xb9e734f117cfaf70), "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" },
        { UINT64_C (0x6cc5eab49a92d617), "123456789012345678901234567890123456789012345678901234567890"\
                                         "12345678901234567890" },
    };

    for (size_t i = 0; i < sizeof(selftests) / sizeof(selftests[0]); i++) {
        uint64_t h;
        if (isLE()) {
            Wyhash64<false, false>(selftests[i].key, strlen(selftests[i].key), i, &h);
        } else {
            Wyhash64<true, false>(selftests[i].key, strlen(selftests[i].key), i, &h);
            // h is in little-endian format
            h = COND_BSWAP(h, true);
        }
        if (h != selftests[i].hash) {
            printf("Hash %016" PRIx64 " != expected %016" PRIx64 " for string \"%s\"\n",
                    h, selftests[i].hash, selftests[i].key);
            return false;
        }
    }

    return true;
}

//-----------------------------------------------------------------------------
REGISTER_FAMILY(wyhash,
   $.src_url    = "https://github.com/wangyi-fudan/wyhash",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(wyhash_32,
   $.desc       = "wyhash v4, 32-bit native version",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY         |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 32,
   $.verification_LE = 0x09DE8066,
   $.verification_BE = 0x46D1F8A2,
   $.hashfn_native   = Wyhash32<false>,
   $.hashfn_bswap    = Wyhash32<true>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeds        = { 0x429dacdd, 0xd637dbf3 }
 );

REGISTER_HASH(wyhash,
   $.desc       = "wyhash v4.2, 64-bit non-strict version",
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 64,
   $.verification_LE = 0x9DAE7DD3,
   $.verification_BE = 0x2E958F8A,
   $.hashfn_native   = Wyhash64<false, false>,
   $.hashfn_bswap    = Wyhash64<true, false>,
   $.initfn          = wyhash64_selftest
 );

REGISTER_HASH(wyhash__strict,
   $.desc       = "wyhash v4.2, 64-bit strict version",
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 64,
   $.verification_LE = 0x82FE7E2E,
   $.verification_BE = 0xBA2BDA4F,
   $.hashfn_native   = Wyhash64<false, true>,
   $.hashfn_bswap    = Wyhash64<true, true>
 );
