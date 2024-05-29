/*
 * rapidhash - Very fast, high quality, platform independant hashing algorithm.
 * Copyright (C) 2024 Nicolas De Carli
 *
 * Based on 'wyhash', by Wang Yi <godspeed_china@yeah.net>
 *
 * BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * You can contact the author at:
 *   - rapidhash source repository: https://github.com/Nicoshev/rapidhash
 */

/*
 *  Includes.
 */
#include "Platform.h"
#include "Hashlib.h"

#include "Mathmult.h"

/*
 *  Read functions.
 */
template <bool bswap>
static inline uint64_t rapid_read64( const uint8_t * p ) {
    return GET_U64<bswap>(p, 0);
}

template <bool bswap>
static inline uint64_t rapid_read32( const uint8_t * p ) {
    return GET_U32<bswap>(p, 0);
}

static inline uint64_t rapid_readSmall( const uint8_t * p, size_t k ) {
    return (((uint64_t)p[0]) << 56) | (((uint64_t)p[k >> 1]) << 32) | p[k - 1];
}

/*
 *  64*64 -> 128bit multiply function.
 *
 *  @param A  Address of 64-bit number.
 *  @param B  Address of 64-bit number.
 *
 *  Calculates 128-bit C = A * B.
 *
 *  When isProtected is false:
 *  Overwritres A contents with C's low 64 bits.
 *  Overwritres B contents with C's high 64 bits.
 *
 *  When isProtected is true:
 *  Xors and overwrites A contents with C's low 64 bits.
 *  Xors and overwrites B contents with C's high 64 bits.
 */
template <bool isProtected>
static inline void rapid_mum( uint64_t * A, uint64_t * B ) {
    uint64_t rlo, rhi;

    MathMult::mult64_128(rlo, rhi, *A, *B);
    if (isProtected) {
        *A ^= rlo; *B ^= rhi;
    } else {
        *A  = rlo; *B  = rhi;
    }
}

/*
 *  Multiply and xor mix function.
 *
 *  @param A  64-bit number.
 *  @param B  64-bit number.
 *
 *  Calculates 128-bit C = A * B.
 *  Returns 64-bit xor between high and low 64 bits of C.
 */
template <bool isProtected>
static inline uint64_t rapid_mix( uint64_t A, uint64_t B ) {
    rapid_mum<isProtected>(&A, &B);
    return A ^ B;
}

/*
 *  rapidhash main function.
 *
 *  @param key     Buffer to be hashed.
 *  @param len     @key length, in bytes.
 *  @param seed    64-bit seed used to alter the hash result predictably.
 *  @param secret  Triplet of 64-bit secrets used to alter hash result predictably.
 *
 *  Returns a 64-bit hash.
 */
template <bool bswap, bool isProtected, bool unrolled>
static inline uint64_t rapidhash( const void * key, size_t len, uint64_t seed, const uint64_t * secrets ) {
    const uint8_t * p = (const uint8_t *)key;
    uint64_t        a, b;

    seed ^= rapid_mix<isProtected>(seed ^ secrets[0], secrets[1]) ^ len;

    if (likely(len <= 16)) {
        if (likely(len >= 4)) {
            const uint8_t * plast = p + len - 4;
            a = (rapid_read32<bswap>(p)         << 32) | rapid_read32<bswap>(plast);
            const uint64_t delta  = ((len & 24) >> (len >> 3));
            b = (rapid_read32<bswap>(p + delta) << 32) | rapid_read32<bswap>(plast - delta);
        } else if (likely(len > 0)) {
            a = rapid_readSmall(p, len);
            b = 0;
        } else {
            a = b = 0;
        }
    } else {
        size_t i = len;
        if (unlikely(i > 48)) {
            uint64_t see1 = seed, see2 = seed;
            if (unrolled) {
                while (likely(i >= 96)) {
                    seed = rapid_mix<isProtected>(rapid_read64<bswap>(p)      ^ secrets[0],
                            rapid_read64<bswap>(p +  8) ^ seed);
                    see1 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 16) ^ secrets[1],
                            rapid_read64<bswap>(p + 24) ^ see1);
                    see2 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 32) ^ secrets[2],
                            rapid_read64<bswap>(p + 40) ^ see2);
                    seed = rapid_mix<isProtected>(rapid_read64<bswap>(p + 48) ^ secrets[0],
                            rapid_read64<bswap>(p + 56) ^ seed);
                    see1 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 64) ^ secrets[1],
                            rapid_read64<bswap>(p + 72) ^ see1);
                    see2 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 80) ^ secrets[2],
                            rapid_read64<bswap>(p + 88) ^ see2);
                    p   += 96; i -= 96;
                }
                if (unlikely(i >= 48)) {
                    seed = rapid_mix<isProtected>(rapid_read64<bswap>(p)      ^ secrets[0],
                            rapid_read64<bswap>(p +  8) ^ seed);
                    see1 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 16) ^ secrets[1],
                            rapid_read64<bswap>(p + 24) ^ see1);
                    see2 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 32) ^ secrets[2],
                            rapid_read64<bswap>(p + 40) ^ see2);
                    p   += 48; i -= 48;
                }
            } else {
                do {
                    seed = rapid_mix<isProtected>(rapid_read64<bswap>(p)      ^ secrets[0],
                            rapid_read64<bswap>(p +  8) ^ seed);
                    see1 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 16) ^ secrets[1],
                            rapid_read64<bswap>(p + 24) ^ see1);
                    see2 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 32) ^ secrets[2],
                            rapid_read64<bswap>(p + 40) ^ see2);
                    p   += 48; i -= 48;
                } while (likely(i >= 48));
            }
            seed ^= see1 ^ see2;
        }
        if (i > 16) {
            seed = rapid_mix<isProtected>(rapid_read64<bswap>(p) ^ secrets[2],
                    rapid_read64<bswap>(p + 8) ^ seed ^ secrets[1]);
            if (i > 32) {
                seed = rapid_mix<isProtected>(rapid_read64<bswap>(p + 16) ^ secrets[2],
                        rapid_read64<bswap>(p + 24) ^ seed);
            }
        }
        a = rapid_read64<bswap>(p + i - 16);
        b = rapid_read64<bswap>(p + i -  8);
    }
    a ^= secrets[1];
    b ^= seed;
    rapid_mum<isProtected>(&a, &b);
    return rapid_mix<isProtected>(a ^ secrets[0] ^ len, b ^ secrets[1]);
}

/*
 *  Default secret parameters.
 */
static const uint64_t rapid_secret[3] = {
    UINT64_C(0x2d358dccaa6c78a5), UINT64_C(0x8bb84b93962eacc9), UINT64_C(0x4b33a62ed433d4a3)
};

//-----------------------------------------------------------------------------
template <bool bswap, bool isProtected, bool unrolled>
static void RapidHash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    if (isLE()) {
        PUT_U64<bswap>(rapidhash<false, isProtected, unrolled>(in, len,
                (uint64_t)seed, rapid_secret), (uint8_t *)out, 0);
    } else {
        PUT_U64<bswap>(rapidhash<true, isProtected, unrolled>(in, len,
                (uint64_t)seed, rapid_secret), (uint8_t *)out, 0);
    }
}

//-----------------------------------------------------------------------------
static bool rapidhash64_selftest( void ) {
    struct {
        const uint64_t  hash;
        const char *    key;
    } selftests[] = {
        { UINT64_C(0x93228a4de0eec5a2), "" }                          ,
        { UINT64_C(0x0dc3b86c0704cea4), "a" }                         ,
        { UINT64_C(0x93dc6a6329f8ddba), "abc" }                       ,
        { UINT64_C(0x0031cdc21324150f), "message digest" }            ,
        { UINT64_C(0xd7523bef5b2a3fbd), "abcdefghijklmnopqrstuvwxyz" },
        { UINT64_C(0x416757764b7bd75b), "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" },
        { UINT64_C(0xa2db61f63e5a8f20), "123456789012345678901234567890123456789012345678901234567890" \
                                        "12345678901234567890" },
    };

    for (size_t i = 0; i < sizeof(selftests) / sizeof(selftests[0]); i++) {
        uint64_t h;
        if (isLE()) {
            RapidHash64<false, false, false>(selftests[i].key, strlen(selftests[i].key), i, &h);
        } else {
            RapidHash64<true, false, false>(selftests[i].key, strlen(selftests[i].key), i, &h);
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
REGISTER_FAMILY(rapidhash,
   $.src_url    = "https://github.com/Nicoshev/rapidhash",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(rapidhash,
   $.desc       = "rapidhash, 64-bit",
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 64,
   $.verification_LE = 0xAF404C4B,
   $.verification_BE = 0x42E57D06,
   $.hashfn_native   = RapidHash64<false, false, true>,
   $.hashfn_bswap    = RapidHash64<true, false, true>,
   $.initfn          = rapidhash64_selftest
 );

REGISTER_HASH(rapidhash__protected,
   $.desc       = "rapidhash, 64-bit protected version",
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 64,
   $.verification_LE = 0xEC83AD3A,
   $.verification_BE = 0x06304A0F,
   $.hashfn_native   = RapidHash64<false, true, false>,
   $.hashfn_bswap    = RapidHash64<true, true, false>
 );
