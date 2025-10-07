/*
 * rapidhash - Very fast, high quality, platform independant hashing algorithm.
 * Copyright (C) 2025 Nicolas De Carli
 * Copyright (C) 2025 Frank J. T. Wojcik
 *
 * Based on 'wyhash', by Wang Yi <godspeed_china@yeah.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
 *  Default secret parameters.
 */
static const uint64_t rapid_secret[8] = {
    UINT64_C(0x2d358dccaa6c78a5), UINT64_C(0x8bb84b93962eacc9),
    UINT64_C(0x4b33a62ed433d4a3), UINT64_C(0x4d5a2da51de1aa47),
    UINT64_C(0xa0761d6478bd642f), UINT64_C(0xe7037ed1a0b428db),
    UINT64_C(0x90ed1765281c388c), UINT64_C(0xaaaaaaaaaaaaaaaa),
};

/*
 *  rapidhash main function.
 *
 *  @param key     Buffer to be hashed.
 *  @param len     @key length, in bytes.
 *  @param seed    64-bit seed used to alter the hash result predictably.
 *  @param secrets Array of 8 64-bit secrets used to alter hash result predictably.
 *
 *  Returns a 64-bit hash.
 */
template <bool bswap, bool isProtected, bool unrolled>
static inline uint64_t rapidhash( const void * key, size_t len, uint64_t seed, const uint64_t * secrets ) {
    const uint8_t * p = (const uint8_t *)key;
    size_t          i = len;
    uint64_t        a, b;

    seed ^= rapid_mix<isProtected>(seed ^ secrets[2], secrets[1]);

    if (likely(len <= 16)) {
        if (len >= 4) {
            seed ^= len;
            if (len >= 8) {
                const uint8_t * plast = p + len - 8;
                a = rapid_read64<bswap>(p    );
                b = rapid_read64<bswap>(plast);
            } else {
                const uint8_t * plast = p + len - 4;
                a = rapid_read32<bswap>(p    );
                b = rapid_read32<bswap>(plast);
            }
        } else if (likely(len > 0)) {
            a = (((uint64_t)p[0]) << 45) | p[len - 1];
            b = p[len >> 1];
        } else {
            a = b = 0;
        }
    } else {
        if (len > 112) {
            uint64_t see1 = seed, see2 = seed;
            uint64_t see3 = seed, see4 = seed;
            uint64_t see5 = seed, see6 = seed;
            if (unrolled) {
                while (i > 224) {
                    seed = rapid_mix<isProtected>(rapid_read64<bswap>(p      ) ^ secrets[0],
                            rapid_read64<bswap>(p +   8) ^ seed);
                    see1 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  16) ^ secrets[1],
                            rapid_read64<bswap>(p +  24) ^ see1);
                    see2 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  32) ^ secrets[2],
                            rapid_read64<bswap>(p +  40) ^ see2);
                    see3 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  48) ^ secrets[3],
                            rapid_read64<bswap>(p +  56) ^ see3);
                    see4 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  64) ^ secrets[4],
                            rapid_read64<bswap>(p +  72) ^ see4);
                    see5 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  80) ^ secrets[5],
                            rapid_read64<bswap>(p +  88) ^ see5);
                    see6 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  96) ^ secrets[6],
                            rapid_read64<bswap>(p + 104) ^ see6);
                    seed = rapid_mix<isProtected>(rapid_read64<bswap>(p + 112) ^ secrets[0],
                            rapid_read64<bswap>(p + 120) ^ seed);
                    see1 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 128) ^ secrets[1],
                            rapid_read64<bswap>(p + 136) ^ see1);
                    see2 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 144) ^ secrets[2],
                            rapid_read64<bswap>(p + 152) ^ see2);
                    see3 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 160) ^ secrets[3],
                            rapid_read64<bswap>(p + 168) ^ see3);
                    see4 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 176) ^ secrets[4],
                            rapid_read64<bswap>(p + 184) ^ see4);
                    see5 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 192) ^ secrets[5],
                            rapid_read64<bswap>(p + 200) ^ see5);
                    see6 = rapid_mix<isProtected>(rapid_read64<bswap>(p + 208) ^ secrets[6],
                            rapid_read64<bswap>(p + 216) ^ see6);
                    p   += 224; i -= 224;
                }
                if (i > 112) {
                    seed = rapid_mix<isProtected>(rapid_read64<bswap>(p      ) ^ secrets[0],
                            rapid_read64<bswap>(p +   8) ^ seed);
                    see1 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  16) ^ secrets[1],
                            rapid_read64<bswap>(p +  24) ^ see1);
                    see2 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  32) ^ secrets[2],
                            rapid_read64<bswap>(p +  40) ^ see2);
                    see3 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  48) ^ secrets[3],
                            rapid_read64<bswap>(p +  56) ^ see3);
                    see4 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  64) ^ secrets[4],
                            rapid_read64<bswap>(p +  72) ^ see4);
                    see5 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  80) ^ secrets[5],
                            rapid_read64<bswap>(p +  88) ^ see5);
                    see6 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  96) ^ secrets[6],
                            rapid_read64<bswap>(p + 104) ^ see6);
                    p   += 112; i -= 112;
                }
            } else {
                do {
                    seed = rapid_mix<isProtected>(rapid_read64<bswap>(p      ) ^ secrets[0],
                            rapid_read64<bswap>(p +   8) ^ seed);
                    see1 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  16) ^ secrets[1],
                            rapid_read64<bswap>(p +  24) ^ see1);
                    see2 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  32) ^ secrets[2],
                            rapid_read64<bswap>(p +  40) ^ see2);
                    see3 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  48) ^ secrets[3],
                            rapid_read64<bswap>(p +  56) ^ see3);
                    see4 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  64) ^ secrets[4],
                            rapid_read64<bswap>(p +  72) ^ see4);
                    see5 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  80) ^ secrets[5],
                            rapid_read64<bswap>(p +  88) ^ see5);
                    see6 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  96) ^ secrets[6],
                            rapid_read64<bswap>(p + 104) ^ see6);
                    p   += 112; i -= 112;
                } while (i > 112);
            }
            seed ^= see1;
            see2 ^= see3;
            see4 ^= see5;
            seed ^= see6;
            see2 ^= see4;
            seed ^= see2;
        }
        if (i > 16) {
            seed = rapid_mix<isProtected>(rapid_read64<bswap>(p) ^ secrets[2],
                    rapid_read64<bswap>(p + 8) ^ seed);
            if (i > 32) {
                seed = rapid_mix<isProtected>(rapid_read64<bswap>(p + 16) ^ secrets[2],
                        rapid_read64<bswap>(p + 24) ^ seed);
                if (i > 48) {
                    seed = rapid_mix<isProtected>(rapid_read64<bswap>(p + 32) ^ secrets[1],
                            rapid_read64<bswap>(p + 40) ^ seed);
                    if (i > 64) {
                        seed = rapid_mix<isProtected>(rapid_read64<bswap>(p + 48) ^ secrets[1],
                                rapid_read64<bswap>(p + 56) ^ seed);
                        if (i > 80) {
                            seed = rapid_mix<isProtected>(rapid_read64<bswap>(p + 64) ^ secrets[2],
                                    rapid_read64<bswap>(p + 72) ^ seed);
                            if (i > 96) {
                                seed = rapid_mix<isProtected>(rapid_read64<bswap>(p + 80) ^ secrets[1],
                                        rapid_read64<bswap>(p + 88) ^ seed);
                            }
                        }
                    }
                }
            }
        }
        a = rapid_read64<bswap>(p + i - 16) ^ i;
        b = rapid_read64<bswap>(p + i -  8);
    }
    a ^= secrets[1];
    b ^= seed;
    rapid_mum<isProtected>(&a, &b);
    return rapid_mix<isProtected>(a ^ secrets[7], b ^ secrets[1] ^ i);
}

/*
 *  rapidhashMicro main function.
 *
 *  @param key     Buffer to be hashed.
 *  @param len     @key length, in bytes.
 *  @param seed    64-bit seed used to alter the hash result predictably.
 *  @param secrets Array of 8 64-bit secrets used to alter hash result predictably.
 *                 Note that secrets[5] and secrets[6] are unused here.
 *
 *  Returns a 64-bit hash.
 */
template <bool bswap, bool isProtected>
static inline uint64_t rapidhashMicro( const void * key, size_t len, uint64_t seed, const uint64_t * secrets ) {
    const uint8_t * p = (const uint8_t *)key;
    size_t          i = len;
    uint64_t        a, b;

    seed ^= rapid_mix<isProtected>(seed ^ secrets[2], secrets[1]);

    if (likely(len <= 16)) {
        if (len >= 4) {
            seed ^= len;
            if (len >= 8) {
                const uint8_t * plast = p + len - 8;
                a = rapid_read64<bswap>(p    );
                b = rapid_read64<bswap>(plast);
            } else {
                const uint8_t * plast = p + len - 4;
                a = rapid_read32<bswap>(p    );
                b = rapid_read32<bswap>(plast);
            }
        } else if (likely(len > 0)) {
            a = (((uint64_t)p[0]) << 45) | p[len - 1];
            b = p[len >> 1];
        } else {
            a = b = 0;
        }
    } else {
        if (len > 80) {
            uint64_t see1 = seed, see2 = seed;
            uint64_t see3 = seed, see4 = seed;
            do {
                seed = rapid_mix<isProtected>(rapid_read64<bswap>(p      ) ^ secrets[0],
                        rapid_read64<bswap>(p +   8) ^ seed);
                see1 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  16) ^ secrets[1],
                        rapid_read64<bswap>(p +  24) ^ see1);
                see2 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  32) ^ secrets[2],
                        rapid_read64<bswap>(p +  40) ^ see2);
                see3 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  48) ^ secrets[3],
                        rapid_read64<bswap>(p +  56) ^ see3);
                see4 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  64) ^ secrets[4],
                        rapid_read64<bswap>(p +  72) ^ see4);
                p   += 80; i -= 80;
            } while (i > 80);
            seed ^= see1;
            see2 ^= see3;
            seed ^= see4;
            seed ^= see2;
        }
        if (i > 16) {
            seed = rapid_mix<isProtected>(rapid_read64<bswap>(p) ^ secrets[2],
                    rapid_read64<bswap>(p + 8) ^ seed);
            if (i > 32) {
                seed = rapid_mix<isProtected>(rapid_read64<bswap>(p + 16) ^ secrets[2],
                        rapid_read64<bswap>(p + 24) ^ seed);
                if (i > 48) {
                    seed = rapid_mix<isProtected>(rapid_read64<bswap>(p + 32) ^ secrets[1],
                            rapid_read64<bswap>(p + 40) ^ seed);
                    if (i > 64) {
                        seed = rapid_mix<isProtected>(rapid_read64<bswap>(p + 48) ^ secrets[1],
                                rapid_read64<bswap>(p + 56) ^ seed);
                    }
                }
            }
        }
        a = rapid_read64<bswap>(p + i - 16) ^ i;
        b = rapid_read64<bswap>(p + i -  8);
    }
    a ^= secrets[1];
    b ^= seed;
    rapid_mum<isProtected>(&a, &b);
    return rapid_mix<isProtected>(a ^ secrets[7], b ^ secrets[1] ^ i);
}

/*
 *  rapidhashNano main function.
 *
 *  @param key     Buffer to be hashed.
 *  @param len     @key length, in bytes.
 *  @param seed    64-bit seed used to alter the hash result predictably.
 *  @param secrets Array of 8 64-bit secrets used to alter hash result predictably.
 *                 Note that secrets[3] through secrets[6] are unused here.
 *
 *  Returns a 64-bit hash.
 */
template <bool bswap, bool isProtected>
static inline uint64_t rapidhashNano( const void * key, size_t len, uint64_t seed, const uint64_t * secrets ) {
    const uint8_t * p = (const uint8_t *)key;
    size_t          i = len;
    uint64_t        a, b;

    seed ^= rapid_mix<isProtected>(seed ^ secrets[2], secrets[1]);

    if (likely(len <= 16)) {
        if (len >= 4) {
            seed ^= len;
            if (len >= 8) {
                const uint8_t * plast = p + len - 8;
                a = rapid_read64<bswap>(p    );
                b = rapid_read64<bswap>(plast);
            } else {
                const uint8_t * plast = p + len - 4;
                a = rapid_read32<bswap>(p    );
                b = rapid_read32<bswap>(plast);
            }
        } else if (likely(len > 0)) {
            a = (((uint64_t)p[0]) << 45) | p[len - 1];
            b = p[len >> 1];
        } else {
            a = b = 0;
        }
    } else {
        if (len > 48) {
            uint64_t see1 = seed, see2 = seed;
            do {
                seed = rapid_mix<isProtected>(rapid_read64<bswap>(p      ) ^ secrets[0],
                        rapid_read64<bswap>(p +   8) ^ seed);
                see1 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  16) ^ secrets[1],
                        rapid_read64<bswap>(p +  24) ^ see1);
                see2 = rapid_mix<isProtected>(rapid_read64<bswap>(p +  32) ^ secrets[2],
                        rapid_read64<bswap>(p +  40) ^ see2);
                p   += 48; i -= 48;
            } while (i > 48);
            seed ^= see1;
            seed ^= see2;
        }
        if (i > 16) {
            seed = rapid_mix<isProtected>(rapid_read64<bswap>(p) ^ secrets[2],
                    rapid_read64<bswap>(p + 8) ^ seed);
            if (i > 32) {
                seed = rapid_mix<isProtected>(rapid_read64<bswap>(p + 16) ^ secrets[2],
                        rapid_read64<bswap>(p + 24) ^ seed);
            }
        }
        a = rapid_read64<bswap>(p + i - 16) ^ i;
        b = rapid_read64<bswap>(p + i -  8);
    }
    a ^= secrets[1];
    b ^= seed;
    rapid_mum<isProtected>(&a, &b);
    return rapid_mix<isProtected>(a ^ secrets[7], b ^ secrets[1] ^ i);
}

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

template <bool bswap, bool isProtected>
static void RapidHashMicro64( const void * in, const size_t len, const seed_t seed, void * out ) {
    if (isLE()) {
        PUT_U64<bswap>(rapidhashMicro<false, isProtected>(in, len, (uint64_t)seed, rapid_secret), (uint8_t *)out, 0);
    } else {
        PUT_U64<bswap>(rapidhashMicro<true, isProtected>(in, len, (uint64_t)seed, rapid_secret), (uint8_t *)out, 0);
    }
}

template <bool bswap, bool isProtected>
static void RapidHashNano64( const void * in, const size_t len, const seed_t seed, void * out ) {
    if (isLE()) {
        PUT_U64<bswap>(rapidhashNano<false, isProtected>(in, len, (uint64_t)seed, rapid_secret), (uint8_t *)out, 0);
    } else {
        PUT_U64<bswap>(rapidhashNano<true, isProtected>(in, len, (uint64_t)seed, rapid_secret), (uint8_t *)out, 0);
    }
}

//-----------------------------------------------------------------------------
REGISTER_FAMILY(rapidhash,
   $.src_url    = "https://github.com/Nicoshev/rapidhash",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(rapidhash,
   $.desc       = "rapidhash v3, 64-bit",
   $.sort_order = 0,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x1FDC65EE,
   $.verification_BE = 0xB2DB16B5,
   $.hashfn_native   = RapidHash64<false, false, true>,
   $.hashfn_bswap    = RapidHash64<true, false, true>
);

REGISTER_HASH(rapidhash__protected,
   $.desc       = "rapidhash v3, 64-bit protected version",
   $.sort_order = 10,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x72C9270A,
   $.verification_BE = 0x9A145308,
   $.hashfn_native   = RapidHash64<false, true, false>,
   $.hashfn_bswap    = RapidHash64<true, true, false>
);

REGISTER_HASH(rapidhash_micro,
   $.desc       = "rapidhashMicro v3, 64-bit",
   $.sort_order = 20,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x6F183D61,
   $.verification_BE = 0xFAAE4D8F,
   $.hashfn_native   = RapidHashMicro64<false, false>,
   $.hashfn_bswap    = RapidHashMicro64<true, false>
);

REGISTER_HASH(rapidhash_micro__protected,
   $.desc       = "rapidhashMicro v3, 64-bit protected version",
   $.sort_order = 30,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xC7F9987C,
   $.verification_BE = 0xDC04682C,
   $.hashfn_native   = RapidHashMicro64<false, true>,
   $.hashfn_bswap    = RapidHashMicro64<true, true>
);

REGISTER_HASH(rapidhash_nano,
   $.desc       = "rapidhashNano v3, 64-bit",
   $.sort_order = 40,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x2C200DC7,
   $.verification_BE = 0xC082DAAD,
   $.hashfn_native   = RapidHashNano64<false, false>,
   $.hashfn_bswap    = RapidHashNano64<true, false>
);

REGISTER_HASH(rapidhash_nano__protected,
   $.desc       = "rapidhashNano v3, 64-bit protected version",
   $.sort_order = 50,
   $.hash_flags =
     0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x7A2FA761,
   $.verification_BE = 0xCC879229,
   $.hashfn_native   = RapidHashNano64<false, true>,
   $.hashfn_bswap    = RapidHashNano64<true, true>
);
