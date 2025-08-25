/*
 * komihash version 5.27
 * Copyright (C) 2021-2025  Frank J. T. Wojcik
 * Copyright (c) 2021-2025 Aleksey Vaneev
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

#include "Mathmult.h"

//------------------------------------------------------------
// Unsigned 64-bit constants that define the initial state of the
// hash function (first mantissa bits of PI)
#define KOMIHASH_IVAL1 UINT64_C(0x243F6A8885A308D3)
#define KOMIHASH_IVAL2 UINT64_C(0x13198A2E03707344)
#define KOMIHASH_IVAL3 UINT64_C(0xA4093822299F31D0)
#define KOMIHASH_IVAL4 UINT64_C(0x082EFA98EC4E6C89)
#define KOMIHASH_IVAL5 UINT64_C(0x452821E638D01377)
#define KOMIHASH_IVAL6 UINT64_C(0xBE5466CF34E90C6C)
#define KOMIHASH_IVAL7 UINT64_C(0xC0AC29B7C97C50DD)
#define KOMIHASH_IVAL8 UINT64_C(0x3F84D5B5B5470917)

// Unsigned 64-bit constant with `01` bit-pair replication
#define KOMIHASH_VAL01 UINT64_C(0x5555555555555555)

// Unsigned 64-bit constant with `10` bit-pair replication
#define KOMIHASH_VAL10 UINT64_C(0xAAAAAAAAAAAAAAAA)

//------------------------------------------------------------
// Wrapper around Mathmult.h routine
static FORCE_INLINE void kh_m128( const uint64_t m1, const uint64_t m2, uint64_t * const rl, uint64_t * const rha ) {
    uint64_t rlo, rhi;

    MathMult::mult64_128(rlo, rhi, m1, m2);
    *rl   = rlo;
    *rha += rhi;
}

// Common hashing round with 16-byte input
#define KOMIHASH_HASH16(m)                                 \
    kh_m128(Seed1 ^ GET_U64<bswap>(m, 0),                  \
            Seed5 ^ GET_U64<bswap>(m, 8), &Seed1, &Seed5); \
    Seed1 ^= Seed5;

// Common hashing round without input
#define KOMIHASH_HASHROUND()               \
    kh_m128(Seed1, Seed5, &Seed1, &Seed5); \
    Seed1 ^= Seed5;

// Macro for common hashing finalization round, with the final hashing
// input expected in the "r1h" and "r2h" temporary variables. The hash is
// left in the Seed1 variable.
#define KOMIHASH_HASHFIN()             \
    kh_m128(r1h, r2h, &Seed1, &Seed5); \
    Seed1 ^= Seed5;                    \
    KOMIHASH_HASHROUND();

//------------------------------------------------------------
// KOMIHASH hash function

template <bool bswap>
static FORCE_INLINE uint64_t komihash_epi( const uint8_t * Msg, size_t MsgLen, uint64_t Seed1, uint64_t Seed5 ) {
    uint64_t r1h, r2h;

    if (MsgLen > 31) {
        KOMIHASH_HASH16(Msg     );
        KOMIHASH_HASH16(Msg + 16);

        MsgLen -= 32;
        Msg    += 32;
    }

    if (MsgLen > 15) {
        KOMIHASH_HASH16(Msg);

        MsgLen -= 16;
        Msg    += 16;
    }

    int ml8 = MsgLen * 8;
    if (MsgLen < 8) {
        ml8 ^= 56;
        r1h  = GET_U64<bswap>(Msg + MsgLen - 8, 0) >> 8 | UINT64_C(1) << 56;
        r2h  = Seed5;
        r1h  = (r1h >> ml8) ^ Seed1;
    } else {
        ml8 ^= 120;
        r2h  = GET_U64<bswap>(Msg + MsgLen - 8, 0) >> 8 | UINT64_C(1) << 56;
        r1h  = GET_U64<bswap>(Msg, 0) ^ Seed1;
        r2h  = (r2h >> ml8) ^ Seed5;
    }

    KOMIHASH_HASHFIN();

    return Seed1;
}

/*
 * @param Msg0 The message to produce a hash from. The alignment of this
 * pointer is unimportant.
 * @param MsgLen Message's length, in bytes.
 * @param UseSeed Optional value, to use instead of the default seed. To use
 * the default seed, set to 0. The UseSeed value can have any bit length and
 * statistical quality, and is used only as an additional entropy source. May
 * need endianness-correction if this value is shared between big- and
 * little-endian systems.
 */
template <bool bswap>
static FORCE_INLINE uint64_t komihash_impl( const void * const Msg0, size_t MsgLen, const uint64_t UseSeed ) {
    const uint8_t * Msg = (const uint8_t *)Msg0;

    // The seeds are initialized to the first mantissa bits of PI.
    uint64_t Seed1 = KOMIHASH_IVAL1 ^ (UseSeed & KOMIHASH_VAL01);
    uint64_t Seed5 = KOMIHASH_IVAL5 ^ (UseSeed & KOMIHASH_VAL10);
    uint64_t r1h, r2h;

    // The three instructions in the "KOMIHASH_HASHROUND" macro represent the
    // simplest constantless PRNG, scalable to any even-sized state
    // variables, with the `Seed1` being the PRNG output (2^64 PRNG period).
    // It passes `PractRand` tests with rare non-systematic "unusual"
    // evaluations.
    //
    // To make this PRNG reliable, self-starting, and eliminate a risk of
    // stopping, the following variant can be used, which adds a "register
    // checker-board", a source of raw entropy. The PRNG is available as the
    // komirand() function. Not required for hashing (but works for it) since
    // the input entropy is usually available in abundance during hashing.
    //
    // Seed5 += r2h + 0xAAAAAAAAAAAAAAAA;
    //
    // (the `0xAAAA...` constant should match register's size; essentially,
    // it is a replication of the `10` bit-pair; it is not an arbitrary
    // constant).

    prefetch(Msg);

    KOMIHASH_HASHROUND(); // Required for PerlinNoise.

    if (likely(MsgLen < 16)) {
        r1h = Seed1;
        r2h = Seed5;

        if (MsgLen > 7) {
            // The following XOR instructions are equivalent to mixing a
            // message with a cryptographic one-time-pad (bitwise modulo 2
            // addition). Message's statistics and distribution are thus
            // unimportant.

            r1h ^= GET_U64<bswap>(Msg, 0);

            if (MsgLen < 12) {
                int ml8 = MsgLen * 8;
                const uint64_t m =
                        Msg[MsgLen - 3]       |
                        Msg[MsgLen - 1] << 16 |
                        UINT64_C(1)     << 24 |
                        Msg[MsgLen - 2] <<  8;

                ml8 ^= 88;
                r2h ^= m >> ml8;
            } else {
                const int      mhs = 128 - MsgLen * 8;
                const uint64_t mh  = (GET_U32<bswap>(Msg + MsgLen - 4, 0) |
                        UINT64_C(1) << 32) >> mhs;
                const uint64_t ml  = GET_U32 <bswap>(Msg          + 8, 0);

                r2h ^= mh << 32 | ml;
            }
        } else if (likely(MsgLen != 0)) {
            const int ml8 = MsgLen * 8;

            if (MsgLen < 4) {
                r1h ^= UINT64_C(1) << ml8;
                r1h ^= Msg[0];

                if (MsgLen != 1) {
                    r1h ^= Msg[1] << 8;

                    if (MsgLen != 2) {
                        r1h ^= Msg[2] << 16;
                    }
                }
            } else {
                const int      mhs = 64 - ml8;
                const uint64_t mh  = (GET_U32<bswap>(Msg + MsgLen - 4, 0) |
                        UINT64_C(1) << 32) >> mhs;
                const uint64_t ml  = GET_U32<bswap>(Msg, 0);

                r1h ^= mh << 32 | ml;
            }
        }
    } else {
        if (unlikely(MsgLen > 31)) {
            goto _long;
        }

        KOMIHASH_HASH16(Msg);

        int ml8 = MsgLen * 8;

        if (MsgLen < 24) {
            ml8 ^= 184;
            r1h  = GET_U64<bswap>(Msg + MsgLen - 8, 0) >> 8 | UINT64_C(1) << 56;
            r2h  = Seed5;
            r1h  = (r1h >> ml8) ^ Seed1;

            KOMIHASH_HASHFIN();

            return Seed1;
        } else {
            r2h  = GET_U64<bswap>(Msg + MsgLen - 8, 0) >> 8 | UINT64_C(1) << 56;
            ml8 ^= 248;
            r1h  = GET_U64<bswap>(Msg + 16        , 0) ^ Seed1;
            r2h  = (r2h >> ml8) ^ Seed5;
        }
    }

    KOMIHASH_HASHFIN();

    return Seed1;

  _long:
    if (likely(MsgLen > 63)) {
        uint64_t Seed2 = KOMIHASH_IVAL2 ^ Seed1;
        uint64_t Seed3 = KOMIHASH_IVAL3 ^ Seed1;
        uint64_t Seed4 = KOMIHASH_IVAL4 ^ Seed1;
        uint64_t Seed6 = KOMIHASH_IVAL6 ^ Seed5;
        uint64_t Seed7 = KOMIHASH_IVAL7 ^ Seed5;
        uint64_t Seed8 = KOMIHASH_IVAL8 ^ Seed5;

        do {
            kh_m128(Seed1 ^ GET_U64<bswap>(Msg,  0), Seed5 ^ GET_U64<bswap>(Msg, 32), &Seed1, &Seed5);

            kh_m128(Seed2 ^ GET_U64<bswap>(Msg,  8), Seed6 ^ GET_U64<bswap>(Msg, 40), &Seed2, &Seed6);

            kh_m128(Seed3 ^ GET_U64<bswap>(Msg, 16), Seed7 ^ GET_U64<bswap>(Msg, 48), &Seed3, &Seed7);

            kh_m128(Seed4 ^ GET_U64<bswap>(Msg, 24), Seed8 ^ GET_U64<bswap>(Msg, 56), &Seed4, &Seed8);

            Msg    += 64;
            MsgLen -= 64;

            prefetch(Msg);

            // Such "shifting" arrangement (below) does not increase
            // individual SeedN's PRNG period beyond 2^64, but reduces a
            // chance of any occassional synchronization between PRNG lanes
            // happening. Practically, Seed1-4 together become a single
            // "fused" 256-bit PRNG value, having 2^66 summary PRNG period.

            Seed4 ^= Seed7;
            Seed1 ^= Seed8;
            Seed3 ^= Seed6;
            Seed2 ^= Seed5;
        } while (likely(MsgLen > 63));

        Seed5 ^= Seed6 ^ Seed7 ^ Seed8;
        Seed1 ^= Seed2 ^ Seed3 ^ Seed4;
    }

    return komihash_epi<bswap>(Msg, MsgLen, Seed1, Seed5);
}

//------------------------------------------------------------
template <bool bswap>
static void komihash( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = komihash_impl<bswap>(in, len, (uint64_t)seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(komihash,
   $.src_url    = "https://github.com/avaneev/komihash/",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(komihash,
   $.desc       = "komihash v5.27",
   $.hash_flags =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE        |
         FLAG_IMPL_MULTIPLY_64_128     |
         FLAG_IMPL_SHIFT_VARIABLE      |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x8157FF6D,
   $.verification_BE = 0x68E116C0,
   $.hashfn_native   = komihash<false>,
   $.hashfn_bswap    = komihash<true>
 );
