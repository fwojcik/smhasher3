/*
 * komihash version 4.3
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2021 Aleksey Vaneev
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

#include "lib/Mathmult.h"

//------------------------------------------------------------
/*
 * Function builds an unsigned 64-bit value out of remaining bytes in a
 * message, and pads it with the "final byte". This function can only be
 * called if less than 8 bytes are left to read. The message should be "long",
 * permitting Msg[ -3 ] reads.
 *
 * @param Msg Message pointer, alignment is unimportant.
 * @param MsgLen Message's remaining length, in bytes; can be 0.
 * @param fb Final byte used for padding.
 */
template < bool bswap >
static inline uint64_t kh_lpu64ec_l3(const uint8_t* const Msg,
        const size_t MsgLen, uint64_t fb) {
    if (MsgLen < 4) {
        const uint8_t* const Msg3 = Msg + MsgLen - 3;
        const int ml8 = (int) (MsgLen << 3);
        const uint64_t m = (uint64_t) Msg3[ 0 ] | (uint64_t) Msg3[ 1 ] << 8 |
            (uint64_t) Msg3[ 2 ] << 16;

        return(fb << ml8 | m >> (24 - ml8));
    }

    const int ml8 = (int) (MsgLen << 3);
    const uint64_t mh = GET_U32<bswap>(Msg + MsgLen - 4, 0);
    const uint64_t ml = GET_U32<bswap>(Msg, 0);

    if (isLE() ^ bswap) {
        return(fb << ml8 | ml | (mh >> (64 - ml8)) << 32);
    } else {
        return(fb << ml8 | mh | (ml >> (64 - ml8)) << 32);
    }
}

/*
 * Function builds an unsigned 64-bit value out of remaining bytes in a
 * message, and pads it with the "final byte". This function can only be
 * called if less than 8 bytes are left to read. Can be used on "short"
 * messages, but MsgLen should be greater than 0.
 *
 * @param Msg Message pointer, alignment is unimportant.
 * @param MsgLen Message's remaining length, in bytes; cannot be 0.
 * @param fb Final byte used for padding.
 */
template < bool bswap >
static inline uint64_t kh_lpu64ec_nz(const uint8_t* const Msg,
        const size_t MsgLen, uint64_t fb) {
    if (MsgLen < 4) {
        fb <<= (MsgLen << 3);
        uint64_t m = Msg[ 0 ];

        if (MsgLen > 1) {
            m |= (uint64_t) Msg[ 1 ] << 8;

            if (MsgLen > 2) {
                m |= (uint64_t) Msg[ 2 ] << 16;
            }
        }

        return(fb | m);
    }

    const int ml8 = (int) (MsgLen << 3);
    const uint64_t mh = GET_U32<bswap>(Msg + MsgLen - 4, 0);
    const uint64_t ml = GET_U32<bswap>(Msg, 0);

    if (isLE() ^ bswap) {
        // mh has remaining bytes from MSB, so shift off low bits
        return (fb << ml8 | ml | (mh >> (64 - ml8)) << 32);
    } else {
        // mh has remaining bytes from LSB, so shift off high bits
        return (fb << ml8 | mh | (ml >> (64 - ml8)) << 32);
    }
}

/*
 * Function builds an unsigned 64-bit value out of remaining bytes in a
 * message, and pads it with the "final byte". This function can only be
 * called if less than 8 bytes are left to read. The message should be "long",
 * permitting Msg[ -4 ] reads.
 *
 * @param Msg Message pointer, alignment is unimportant.
 * @param MsgLen Message's remaining length, in bytes; can be 0.
 * @param fb Final byte used for padding.
 */
template < bool bswap >
static inline uint64_t kh_lpu64ec_l4(const uint8_t* const Msg,
        const size_t MsgLen, uint64_t fb) {
    const int ml8 = (int) (MsgLen << 3);

    if (MsgLen < 5) {
        if (isLE() ^ bswap) {
            return(fb << ml8 |
                    ((uint64_t)GET_U32<bswap>(Msg + MsgLen - 4, 0)) >> (32 - ml8));
        } else {
            // If MsgLen is 0 then "32 - ml8" is 32, and a uint32_t
            // shifted right by 32 bits is Undefined Behavior. This
            // odd construction avoids that.
            return(fb << ml8 |
                    (((uint64_t)GET_U32<bswap>(Msg + MsgLen - 4, 0)) &
                            (((uint64_t)UINT32_C(-1)) >> (32 - ml8))));
        }
    } else {
        if (isLE() ^ bswap) {
            return(fb << ml8 | GET_U64<bswap>(Msg + MsgLen - 8, 0) >> (64 - ml8));
        } else {
            return(fb << ml8 | (GET_U64<bswap>(Msg + MsgLen - 8, 0) & (UINT64_C(-1) >> (64 - ml8))));
        }
    }
}

//------------------------------------------------------------
// Wrapper around Mathmult.h routine
static inline void kh_m128(const uint64_t m1, const uint64_t m2,
        uint64_t* const rl, uint64_t* const rh) {
    uint64_t rlo, rhi;
    mult64_128(rlo, rhi, m1, m2);
    *rl = rlo;
    *rh = rhi;
}

// Common hashing round with 16-byte input, using the "r1l" and "r1h"
// temporary variables.
#define KOMIHASH_HASH16(m)                              \
    kh_m128(Seed1 ^ GET_U64<bswap>(m, 0),               \
            Seed5 ^ GET_U64<bswap>(m, 8), &r1l, &r1h);  \
    Seed5 += r1h;                                       \
    Seed1 = Seed5 ^ r1l;

// Common hashing round without input, using the "r2l" and "r2h" temporary
// variables.
#define KOMIHASH_HASHROUND()                    \
    kh_m128(Seed1, Seed5, &r2l, &r2h);          \
    Seed5 += r2h;                               \
    Seed1 = Seed5 ^ r2l;

// Common hashing finalization round, with the final hashing input expected in
// the "r2l" and "r2h" temporary variables.
#define KOMIHASH_HASHFIN()                      \
    kh_m128(r2l, r2h, &r1l, &r1h);              \
    Seed5 += r1h;                               \
    Seed1 = Seed5 ^ r1l;                        \
    KOMIHASH_HASHROUND();

//------------------------------------------------------------
// KOMIHASH hash function
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
template < bool bswap >
static inline uint64_t komihash_impl(const void* const Msg0, size_t MsgLen,
        const uint64_t UseSeed) {
    const uint8_t* Msg = (const uint8_t*) Msg0;

    // The seeds are initialized to the first mantissa bits of PI.
    uint64_t Seed1 = UINT64_C(0x243F6A8885A308D3) ^ (UseSeed & UINT64_C(0x5555555555555555));
    uint64_t Seed5 = UINT64_C(0x452821E638D01377) ^ (UseSeed & UINT64_C(0xAAAAAAAAAAAAAAAA));
    uint64_t r1l, r1h, r2l, r2h;

    // The three instructions in the "KOMIHASH_HASHROUND" macro represent the
    // simplest constant-less PRNG, scalable to any even-sized state
    // variables, with the `Seed1` being the PRNG output (2^64 PRNG period).
    // It passes `PractRand` tests with rare non-systematic "unusual"
    // evaluations.
    //
    // To make this PRNG reliable, self-starting, and eliminate a risk of
    // stopping, the following variant can be used, which is a "register
    // checker-board", a source of raw entropy. The PRNG is available as the
    // komirand() function. Not required for hashing (but works for it) since
    // the input entropy is usually available in abundance during hashing.
    //
    // Seed5 += r2h + 0xAAAAAAAAAAAAAAAA;
    //
    // (the `0xAAAA...` constant should match register's size; essentially,
    // it is a replication of the `10` bit-pair; it is not an arbitrary
    // constant).

    KOMIHASH_HASHROUND(); // Required for PerlinNoise.

    if (likely(MsgLen < 16)) {
        prefetch(Msg);

        r2l = Seed1;
        r2h = Seed5;

        if (MsgLen > 7) {
            // The following two XOR instructions are equivalent to mixing a
            // message with a cryptographic one-time-pad (bitwise modulo 2
            // addition). Message's statistics and distribution are thus
            // unimportant.

            r2h ^= kh_lpu64ec_l3<bswap>(Msg + 8, MsgLen - 8,
                    1 << (Msg[ MsgLen - 1 ] >> 7));

            r2l ^= GET_U64<bswap>(Msg, 0);
        } else if (likely(MsgLen != 0)) {
            r2l ^= kh_lpu64ec_nz<bswap>(Msg, MsgLen,
                    1 << (Msg[ MsgLen - 1 ] >> 7));
        }

        KOMIHASH_HASHFIN();

        return (Seed1);
    }

    if (likely(MsgLen < 32)) {
        prefetch(Msg);

        KOMIHASH_HASH16(Msg);

        const uint64_t fb = 1 << (Msg[MsgLen - 1] >> 7);

        if (MsgLen > 23) {
            r2h = Seed5 ^ kh_lpu64ec_l4<bswap>(Msg + 24, MsgLen - 24, fb);
            r2l = Seed1 ^ GET_U64<bswap>(Msg, 16);
        } else {
            r2l = Seed1 ^ kh_lpu64ec_l4<bswap>(Msg + 16, MsgLen - 16, fb);
            r2h = Seed5;
        }

        KOMIHASH_HASHFIN();

        return (Seed1);
    }

    if (MsgLen > 63) {
        uint64_t Seed2 = UINT64_C(0x13198A2E03707344) ^ Seed1;
        uint64_t Seed3 = UINT64_C(0xA4093822299F31D0) ^ Seed1;
        uint64_t Seed4 = UINT64_C(0x082EFA98EC4E6C89) ^ Seed1;
        uint64_t Seed6 = UINT64_C(0xBE5466CF34E90C6C) ^ Seed5;
        uint64_t Seed7 = UINT64_C(0xC0AC29B7C97C50DD) ^ Seed5;
        uint64_t Seed8 = UINT64_C(0x3F84D5B5B5470917) ^ Seed5;
        uint64_t r3l, r3h, r4l, r4h;

        do {
            prefetch(Msg);

            kh_m128(Seed1 ^ GET_U64<bswap>(Msg, 0),
                    Seed5 ^ GET_U64<bswap>(Msg, 8), &r1l, &r1h);

            kh_m128(Seed2 ^ GET_U64<bswap>(Msg, 16),
                    Seed6 ^ GET_U64<bswap>(Msg, 24), &r2l, &r2h);

            kh_m128(Seed3 ^ GET_U64<bswap>(Msg, 32),
                    Seed7 ^ GET_U64<bswap>(Msg, 40), &r3l, &r3h);

            kh_m128(Seed4 ^ GET_U64<bswap>(Msg, 48),
                    Seed8 ^ GET_U64<bswap>(Msg, 56), &r4l, &r4h);

            Msg += 64;
            MsgLen -= 64;

            // Such "shifting" arrangement (below) does not increase
            // individual SeedN's PRNG period beyond 2^64, but reduces a
            // chance of any occassional synchronization between PRNG lanes
            // happening. Practically, Seed1-4 together become a single
            // "fused" 256-bit PRNG value, having a summary PRNG period of
            // 2^66.

            Seed5 += r1h;
            Seed6 += r2h;
            Seed7 += r3h;
            Seed8 += r4h;
            Seed2 = Seed5 ^ r2l;
            Seed3 = Seed6 ^ r3l;
            Seed4 = Seed7 ^ r4l;
            Seed1 = Seed8 ^ r1l;

        } while (likely(MsgLen > 63));

        Seed5 ^= Seed6 ^ Seed7 ^ Seed8;
        Seed1 ^= Seed2 ^ Seed3 ^ Seed4;
    }

    prefetch(Msg);

    if (likely(MsgLen > 31)) {
        KOMIHASH_HASH16(Msg);
        KOMIHASH_HASH16(Msg + 16);

        Msg += 32;
        MsgLen -= 32;
    }

    if (MsgLen > 15) {
        KOMIHASH_HASH16(Msg);

        Msg += 16;
        MsgLen -= 16;
    }

    const uint64_t fb = 1 << (Msg[ MsgLen - 1 ] >> 7);

    if (MsgLen > 7) {
        r2h = Seed5 ^ kh_lpu64ec_l4<bswap>(Msg + 8, MsgLen - 8, fb);
        r2l = Seed1 ^ GET_U64<bswap>(Msg, 0);
    } else {
        r2l = Seed1 ^ kh_lpu64ec_l4<bswap>(Msg, MsgLen, fb);
        r2h = Seed5;
    }

    KOMIHASH_HASHFIN();

    return (Seed1);
}

//------------------------------------------------------------
template < bool bswap >
static void komihash(const void * in, const size_t len, const seed_t seed, void * out) {
    uint64_t h = komihash_impl<bswap>(in, len, (uint64_t)seed);
    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(komihash,
  $.src_url = "https://github.com/avaneev/komihash/",
  $.src_status = HashFamilyInfo::SRC_ACTIVE
);

REGISTER_HASH(komihash,
  $.desc = "komihash v4.3",
  $.hash_flags =
        FLAG_HASH_ENDIAN_INDEPENDENT,
  $.impl_flags =
        FLAG_IMPL_CANONICAL_LE        |
        FLAG_IMPL_128BIT              |
        FLAG_IMPL_MULTIPLY_64_128     |
        FLAG_IMPL_LICENSE_MIT,
  $.bits = 64,
  $.verification_LE = 0x703624A4,
  $.verification_BE = 0xB954DBAB,
  $.hashfn_native = komihash<false>,
  $.hashfn_bswap = komihash<true>
);
