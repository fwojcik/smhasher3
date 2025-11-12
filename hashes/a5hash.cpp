/*
 * A5HASH
 * Copyright (C) 2021-2025  Frank J. T. Wojcik
 * Copyright (c) 2025 Aleksey Vaneev
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
#include "Mathmult.h"

//------------------------------------------------------------
#define A5HASH_VAL10 UINT64_C(0xAAAAAAAAAAAAAAAA) ///< `10` bit-pairs.
#define A5HASH_VAL01 UINT64_C(0x5555555555555555) ///< `01` bit-pairs.

template <bool bswap>
static FORCE_INLINE uint32_t a5hash_lu32( const uint8_t * const p ) {
    return GET_U32<bswap>(p, 0);
}

template <bool bswap>
static FORCE_INLINE uint64_t a5hash_lu64( const uint8_t * const p ) {
    return GET_U64<bswap>(p, 0);
}

static FORCE_INLINE void a5hash_umul64( const uint32_t u, const uint32_t v, uint32_t * const rl, uint32_t * const rh ) {
    const uint64_t r = (uint64_t)u * v;

    *rl = (uint32_t)r;
    *rh = (uint32_t)(r >> 32);
}

static FORCE_INLINE void a5hash_umul128( const uint64_t u, const uint64_t v,
        uint64_t * const rl, uint64_t * const rh ) {
    uint64_t rlo, rhi;

    MathMult::mult64_128(rlo, rhi, u, v);
    *rl = rlo;
    *rh = rhi;
}

//------------------------------------------------------------
// 64-bit hash function
template <bool bswap>
static FORCE_INLINE uint64_t a5hash( const void * const Msg0, size_t MsgLen, const uint64_t UseSeed ) {
    const uint8_t * Msg = (const uint8_t *)Msg0;

    uint64_t val01      = A5HASH_VAL01;
    uint64_t val10      = A5HASH_VAL10;

    // The seeds are initialized to mantissa bits of PI.

    uint64_t Seed1 = UINT64_C(0x243F6A8885A308D3) ^ MsgLen;
    uint64_t Seed2 = UINT64_C(0x452821E638D01377) ^ MsgLen;

    a5hash_umul128(Seed2 ^ (UseSeed & val10), Seed1 ^ (UseSeed & val01), &Seed1, &Seed2);

    if (MsgLen > 16) {
        val01 ^= Seed1;
        val10 ^= Seed2;

        do {
            a5hash_umul128(((uint64_t)a5hash_lu32<bswap>(Msg     ) << 32) ^
                                      a5hash_lu32<bswap>(Msg +  4)        ^ Seed1,
                           ((uint64_t)a5hash_lu32<bswap>(Msg +  8) << 32) ^
                                      a5hash_lu32<bswap>(Msg + 12)        ^ Seed2,
                           &Seed1, &Seed2);

            MsgLen -= 16;
            Msg    += 16;

            Seed1  += val01;
            Seed2  += val10;
        } while (MsgLen > 16);
    }

    if (MsgLen == 0) {
        goto _fin;
    }

    if (MsgLen > 3) {
        const uint8_t * Msg4;
        size_t          mo;

        Msg4   = Msg + MsgLen - 4;
        mo     = MsgLen >> 3;

        Seed1 ^= (uint64_t)a5hash_lu32<bswap>(Msg)          << 32 |
                           a5hash_lu32<bswap>(Msg4);
        Seed2 ^= (uint64_t)a5hash_lu32<bswap>(Msg + mo * 4) << 32 |
                           a5hash_lu32<bswap>(Msg4 - mo * 4);
  _fin:

        a5hash_umul128(Seed1        , Seed2, &Seed1, &Seed2);

        a5hash_umul128(Seed1 ^ val01, Seed2, &Seed1, &Seed2);

        return Seed1 ^ Seed2;
    } else {
        Seed1 ^= Msg[0];

        if (--MsgLen != 0) {
            Seed1 ^= (uint64_t)Msg[1] << 8;

            if (--MsgLen != 0) {
                Seed1 ^= (uint64_t)Msg[2] << 16;
            }
        }

        goto _fin;
    }
}

//------------------------------------------------------------
// 32-bit hash function
template <bool bswap, bool small_platform>
static FORCE_INLINE uint32_t a5hash32( const void * const Msg0, size_t MsgLen, const uint32_t UseSeed ) {
    const uint8_t * Msg = (const uint8_t *)Msg0;

    uint32_t val01      = (uint32_t)A5HASH_VAL01;
    uint32_t val10      = (uint32_t)A5HASH_VAL10;

    // The seeds are initialized to mantissa bits of PI.

    uint32_t Seed1 = 0x243F6A88 ^ (uint32_t)MsgLen;
    uint32_t Seed2 = 0x85A308D3 ^ (uint32_t)MsgLen;
    uint32_t Seed3, Seed4;
    uint32_t a, b, c, d;

    if (small_platform) {
        Seed3 = 0xFB0BD3EA;
        Seed4 = 0x0F58FD47;
    } else {
        a5hash_umul64((uint32_t)(MsgLen >> 32) ^ 0x452821E6,
                      (uint32_t)(MsgLen >> 32) ^ 0x38D01377,
                      &Seed3, &Seed4);
    }

    a5hash_umul64(Seed2 ^ (UseSeed & val10), Seed1 ^ (UseSeed & val01), &Seed1, &Seed2);

    if (MsgLen < 17) {
        if (MsgLen > 3) {
            const uint8_t * const Msg4 = Msg + MsgLen - 4;
            size_t mo;

            a =  a5hash_lu32<bswap>(Msg );
            b =  a5hash_lu32<bswap>(Msg4);

            if (MsgLen < 9) {
                goto _fin;
            }

            mo = MsgLen >> 3;

            c  = a5hash_lu32<bswap>(Msg  + mo * 4);
            d  = a5hash_lu32<bswap>(Msg4 - mo * 4);
        } else {
            a = 0;
            b = 0;

            if (MsgLen != 0) {
                a = Msg[0];

                if (MsgLen != 1) {
                    a |= (uint32_t)Msg[1] << 8;

                    if (MsgLen != 2) {
                        a |= (uint32_t)Msg[2] << 16;
                    }
                }
            }

            goto _fin;
        }
    } else {
        val01 ^= Seed1;
        val10 ^= Seed2;

        do {
            const uint32_t s1 = Seed1;
            const uint32_t s4 = Seed4;

            a5hash_umul64(a5hash_lu32<bswap>(Msg)     + Seed1, a5hash_lu32<bswap>(Msg +  4) + Seed2, &Seed1, &Seed2);

            a5hash_umul64(a5hash_lu32<bswap>(Msg + 8) + Seed3, a5hash_lu32<bswap>(Msg + 12) + Seed4, &Seed3, &Seed4);

            MsgLen -= 16;
            Msg    += 16;

            Seed1  += val01;
            Seed2  += s4;
            Seed3  += s1;
            Seed4  += val10;
        } while (MsgLen > 16);

        a = a5hash_lu32<bswap>(Msg + MsgLen -  8);
        b = a5hash_lu32<bswap>(Msg + MsgLen -  4);

        if (MsgLen < 9) {
            goto _fin;
        }

        c = a5hash_lu32<bswap>(Msg + MsgLen - 16);
        d = a5hash_lu32<bswap>(Msg + MsgLen - 12);
    }

    a5hash_umul64(c + Seed3, d + Seed4, &Seed3, &Seed4);

  _fin:
    Seed1 ^= Seed3;
    Seed2 ^= Seed4;

    a5hash_umul64(a + Seed1, b + Seed2, &Seed1, &Seed2);

    a5hash_umul64(val01 ^ Seed1, Seed2, &a, &b);

    return a ^ b;
}

//------------------------------------------------------------
// 128-bit hash function
template <bool bswap, bool truncate>
static FORCE_INLINE uint64_t a5hash128( const void * const Msg0, size_t MsgLen,
        const uint64_t UseSeed, void * const rh ) {
    const uint8_t * Msg = (const uint8_t *)Msg0;

    uint64_t val01      = A5HASH_VAL01;
    uint64_t val10      = A5HASH_VAL10;

    // The seeds are initialized to mantissa bits of PI.

    uint64_t Seed1 = UINT64_C(0x243F6A8885A308D3) ^ MsgLen;
    uint64_t Seed2 = UINT64_C(0x452821E638D01377) ^ MsgLen;
    uint64_t Seed3 = UINT64_C(0xA4093822299F31D0);
    uint64_t Seed4 = UINT64_C(0xC0AC29B7C97C50DD);
    uint64_t a, b, c, d;

    a5hash_umul128(Seed2 ^ (UseSeed & val10), Seed1 ^ (UseSeed & val01), &Seed1, &Seed2);

    if (MsgLen < 17) {
        if (MsgLen > 3) {
            const uint8_t * Msg4;
            size_t          mo;

            Msg4 = Msg + MsgLen - 4;
            mo   = MsgLen >> 3;

            a    = (uint64_t)a5hash_lu32<bswap>(Msg)           << 32 |
                             a5hash_lu32<bswap>(Msg4);
            b    = (uint64_t)a5hash_lu32<bswap>(Msg  + mo * 4) << 32 |
                             a5hash_lu32<bswap>(Msg4 - mo * 4);

  _fin16:
            a5hash_umul128(a + Seed1, b + Seed2, &Seed1, &Seed2);

            a5hash_umul128(val01 ^ Seed1, Seed2, &a, &b);

            a ^= b;

            if (!truncate) {
                a5hash_umul128(Seed1 ^ Seed3, Seed2 ^ Seed4, &Seed3, &Seed4);

                Seed3 ^= Seed4;
                memcpy(rh, &Seed3, 8);
            }

            return a;
        } else {
            a = 0;
            b = 0;

            if (MsgLen != 0) {
                a = Msg[0];

                if (--MsgLen != 0) {
                    a |= (uint64_t)Msg[1] << 8;

                    if (--MsgLen != 0) {
                        a |= (uint64_t)Msg[2] << 16;
                    }
                }
            }

            goto _fin16;
        }
    }

    if (MsgLen < 33) {
        a = (uint64_t)a5hash_lu32<bswap>(Msg)               << 32 |
                      a5hash_lu32<bswap>(Msg +  4);
        b = (uint64_t)a5hash_lu32<bswap>(Msg +  8)          << 32 |
                      a5hash_lu32<bswap>(Msg + 12);
        c = (uint64_t)a5hash_lu32<bswap>(Msg + MsgLen - 16) << 32 |
                      a5hash_lu32<bswap>(Msg + MsgLen - 12);
        d = (uint64_t)a5hash_lu32<bswap>(Msg + MsgLen -  8) << 32 |
                      a5hash_lu32<bswap>(Msg + MsgLen -  4);

  _fin_m:
        a5hash_umul128(c + Seed3, d + Seed4, &Seed3, &Seed4);

  _fin:
        Seed1 ^= Seed3;
        Seed2 ^= Seed4;

        a5hash_umul128(a + Seed1, b + Seed2, &Seed1, &Seed2);

        a5hash_umul128(val01 ^ Seed1, Seed2, &a, &b);

        a ^= b;

        if (!truncate) {
            a5hash_umul128(Seed1 ^ Seed3, Seed2 ^ Seed4, &Seed3, &Seed4);

            Seed3 ^= Seed4;
            memcpy(rh, &Seed3, 8);
        }

        return a;
    } else {
        val01 ^= Seed1;
        val10 ^= Seed2;

        if (MsgLen > 64) {
            uint64_t Seed5 = UINT64_C(0x082EFA98EC4E6C89);
            uint64_t Seed6 = UINT64_C(0x3F84D5B5B5470917);
            uint64_t Seed7 = UINT64_C(0x13198A2E03707344);
            uint64_t Seed8 = UINT64_C(0xBE5466CF34E90C6C);

            do {
                const uint64_t s1 = Seed1;
                const uint64_t s3 = Seed3;
                const uint64_t s5 = Seed5;

                a5hash_umul128(a5hash_lu64<bswap>(Msg)      + Seed1, a5hash_lu64<bswap>(
                        Msg + 32) + Seed2, &Seed1, &Seed2);

                Seed1 += val01;
                Seed2 += Seed8;

                a5hash_umul128(a5hash_lu64<bswap>(Msg +  8) + Seed3, a5hash_lu64<bswap>(
                        Msg + 40) + Seed4, &Seed3, &Seed4);

                Seed3 += s1;
                Seed4 += val10;

                a5hash_umul128(a5hash_lu64<bswap>(Msg + 16) + Seed5, a5hash_lu64<bswap>(
                        Msg + 48) + Seed6, &Seed5, &Seed6);

                a5hash_umul128(a5hash_lu64<bswap>(Msg + 24) + Seed7, a5hash_lu64<bswap>(
                        Msg + 56) + Seed8, &Seed7, &Seed8);

                MsgLen -= 64;
                Msg    += 64;

                Seed5  += s3;
                Seed6  += val10;
                Seed7  += s5;
                Seed8  += val10;
            } while (MsgLen > 64);

            Seed1 ^= Seed5;
            Seed2 ^= Seed6;
            Seed3 ^= Seed7;
            Seed4 ^= Seed8;

            if (MsgLen > 32) {
                goto _tail32;
            }
        } else {
            uint64_t s1;

  _tail32:
            s1 = Seed1;

            a5hash_umul128(a5hash_lu64<bswap>(Msg)      + Seed1, a5hash_lu64<bswap>(Msg +  8) + Seed2, &Seed1, &Seed2);

            Seed1 += val01;
            Seed2 += Seed4;

            a5hash_umul128(a5hash_lu64<bswap>(Msg + 16) + Seed3, a5hash_lu64<bswap>(Msg + 24) + Seed4, &Seed3, &Seed4);

            MsgLen -= 32;
            Msg    += 32;

            Seed3  += s1;
            Seed4  += val10;
        }

        a = a5hash_lu64<bswap>(Msg + MsgLen - 16);
        b = a5hash_lu64<bswap>(Msg + MsgLen -  8);

        if (MsgLen < 17) {
            goto _fin;
        }

        c = a5hash_lu64<bswap>(Msg + MsgLen - 32);
        d = a5hash_lu64<bswap>(Msg + MsgLen - 24);

        goto _fin_m;
    }
}

//------------------------------------------------------------
template <bool bswap>
static void a5hash_64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t hash = a5hash<bswap>(in, len, (uint64_t)seed);

    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}

template <bool bswap>
static void a5hash_32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t hash = a5hash32<bswap, true>(in, len, (uint32_t)seed);

    PUT_U32<bswap>(hash, (uint8_t *)out, 0);
}

template <bool bswap>
static void a5hash_128( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t hashH;
    uint64_t hashL = a5hash128<bswap, false>(in, len, (uint64_t)seed, &hashH);

    PUT_U64<bswap>(hashL, (uint8_t *)out, 0);
    PUT_U64<bswap>(hashH, (uint8_t *)out, 8);
}

template <bool bswap>
static void a5hash_128_64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t hashL = a5hash128<bswap, true>(in, len, (uint64_t)seed, NULL);

    PUT_U64<bswap>(hashL, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(a5hash,
   $.src_url    = "https://github.com/avaneev/a5hash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
);

REGISTER_HASH(a5hash,
   $.desc       = "a5hash v5.21, 64-bit version",
   $.hash_flags =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE      |
         FLAG_IMPL_MULTIPLY          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xADDE79B3,
   $.verification_BE = 0x11A303D0,
   $.hashfn_native   = a5hash_64<false>,
   $.hashfn_bswap    = a5hash_64<true>
);

REGISTER_HASH(a5hash_32,
   $.desc       = "a5hash v5.21, 32-bit version",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED        |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE      |
         FLAG_IMPL_MULTIPLY          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0xA948D11B,
   $.verification_BE = 0x9C6196A0,
   $.hashfn_native   = a5hash_32<false>,
   $.hashfn_bswap    = a5hash_32<true>
);

REGISTER_HASH(a5hash_128,
   $.desc       = "a5hash v5.21, 128-bit version",
   $.hash_flags =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE      |
         FLAG_IMPL_MULTIPLY          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x89406B11,
   $.verification_BE = 0x890F41CB,
   $.hashfn_native   = a5hash_128<false>,
   $.hashfn_bswap    = a5hash_128<true>
);

REGISTER_HASH(a5hash_128__64,
   $.desc       = "a5hash v5.21, 128-bit version, 64-bit truncated (rh==NULL)",
   $.hash_flags =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE      |
         FLAG_IMPL_MULTIPLY          |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x14AD402C,
   $.verification_BE = 0xA500372C,
   $.hashfn_native   = a5hash_128_64<false>,
   $.hashfn_bswap    = a5hash_128_64<true>
);
