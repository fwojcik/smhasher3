/*
 * PRVHASH - Pseudo-Random-Value Hash v4.3.7
 * Copyright (C) 2022-2023   Frank J. T. Wojcik
 * Copyright (c) 2020-2023 Aleksey Vaneev
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

/*
 * Function loads 64-bit message word and pads it with the "final byte". This
 * function should only be called if there is less than 8 bytes left to read.
 *
 * @param Msg Message pointer, alignment is unimportant. Should be below or
 * equal to MsgEnd.
 * @param MsgEnd Message's end pointer.
 * @param fb Final byte used for padding.
 */
template <bool bswap>
static FORCE_INLINE uint64_t prvhash_lpu64ec( const uint8_t * const Msg, const uint8_t * const MsgEnd, uint64_t fb ) {
    const size_t MsgLen = MsgEnd - Msg;
    const int    ml8    = (int)(MsgLen * 8);

    if (MsgLen < 4) {
        if (MsgLen != 0) {
            fb = fb << ml8 | (uint64_t)Msg[0];
            if (MsgLen > 1) {
                fb |= (uint64_t)Msg[1] << 8;
                if (MsgLen > 2) {
                    fb |= (uint64_t)Msg[2] << 16;
                }
            }
        }
        return fb;
    }

    const uint64_t mh = (uint64_t)GET_U32<bswap>(MsgEnd - 4, 0);
    const uint64_t ml = (uint64_t)GET_U32<bswap>(Msg       , 0);

    return fb << ml8 | ml | (mh >> (64 - ml8)) << 32;
}

static FORCE_INLINE uint64_t prvhash_core64( uint64_t & Seed, uint64_t & lcg, uint64_t & Hash ) {
    Seed *= lcg * 2 + 1;
    const uint64_t rs = Seed >> 32 | Seed << 32;
    Hash += rs   + UINT64_C(0xAAAAAAAAAAAAAAAA);
    lcg  += Seed + UINT64_C(0x5555555555555555);
    Seed ^= Hash;
    const uint64_t out = lcg ^ rs;

    return out;
}

/*
 * PRVHASH hash function. Produces and returns either a 64-bit or
 * 128-bit hash of the specified message, string, or binary data
 * block. This is a "minimal" implementation, designed for those 2 bit
 * widths only. Equivalent to the "prvhash64" function with HashLen ==
 * 8 or 16, but returns an immediate result.
 *
 * @param Msg0 The message to produce a hash from. The alignment of this
 * pointer is unimportant.
 * @param MsgLen Message's length, in bytes.
 * @param UseSeed Optional value, to use instead of the default seed. To use
 * the default seed, set to 0. The UseSeed value can have any bit length and
 * statistical quality, and is used only as an additional entropy source. If
 * this value is shared between big- and little-endian systems, it should be
 * endianness-corrected.
 * @param Hash2p Location to write the second 8-byte hash result to,
 * if width128 == true.
 */
template <bool bswap, bool width128>
static inline uint64_t prvhash64_64m( const void * const Msg0, const size_t MsgLen,
        const uint64_t UseSeed, uint64_t * Hash2p = NULL ) {
    const uint8_t *       Msg    = (const uint8_t *)Msg0;
    const uint8_t * const MsgEnd = Msg + MsgLen;

    uint64_t Seed  = UINT64_C(0x217992B44669F46A); // The state after 5 PRVHASH rounds
    uint64_t lcg   = UINT64_C(0xB5E2CC2FE9F0B35B); // from the "zero-state".
    uint64_t Hash  = UINT64_C(0x949B5E0A608D76D5);
    uint64_t Hash2 = 0;
    bool     hc    = true;

    Hash ^= UseSeed;

    uint64_t fb = 1;

    if (MsgLen != 0) {
        fb <<= (MsgEnd[-1] >> 7);
    }

    while (1) {
        uint64_t msgw;
        if (Msg < (MsgEnd - (sizeof(uint64_t) - 1))) {
            msgw = GET_U64<bswap>(Msg, 0);
        } else {
            if (Msg > MsgEnd) {
                break;
            }
            msgw = prvhash_lpu64ec<bswap>(Msg, MsgEnd, fb);
        }

        Seed ^= msgw;
        lcg  ^= msgw;

        prvhash_core64(Seed, lcg, hc ? Hash : Hash2);

        if (width128) {
            hc = !hc;
        }

        Msg += sizeof(uint64_t);
    }

    if (!width128) {
        prvhash_core64(Seed, lcg, Hash);
        return prvhash_core64(Seed, lcg, Hash);
    }

    const size_t fc = 16 + ((MsgLen < 8) ? 8 : 0);

    for (size_t k = 0; k <= fc; k += sizeof(uint64_t)) {
        prvhash_core64(Seed, lcg, hc ? Hash : Hash2);
        hc = !hc;
    }

    uint64_t h;
    if (hc) {
        h       = prvhash_core64(Seed, lcg, Hash );
        *Hash2p = prvhash_core64(Seed, lcg, Hash2);
    } else {
        *Hash2p = prvhash_core64(Seed, lcg, Hash2);
        h       = prvhash_core64(Seed, lcg, Hash );
    }
    return h;
}

/*
 * PRVHASH hash function. Produces and returns either a 64-bit or
 * 128-bit hash of the specified message, string, or binary data
 * block. This is a "minimal" implementation, designed for those 2 bit
 * widths only, and only with all the data in one-shot. Equivalent
 * (with a Seed0 of 0) to the official "prvhash64s_oneshot" function
 * with HashLen == 8 or 16, but returns an immediate result.
 */
#define PRVHASH_INIT_COUNT 5                        // Common number of initialization rounds.
#define PRH64S_FUSE 4                               // PRVHASH fusing.
#define PRH64S_LEN (sizeof(uint64_t) * PRH64S_FUSE) // Intermediate block's length.

template <bool bswap, bool width128>
static inline void prvhash64s_oneshot( const void * const Msg0, size_t MsgLen0,
        uint64_t Seed0, uint8_t * const HashOut ) {
    uint64_t Seed[PRH64S_FUSE];
    uint64_t lcg[PRH64S_FUSE];
    uint64_t Hash[2];
    bool     hc = true;

    memset(Hash, 0, sizeof(Hash));
    for (int i = 0; i < PRH64S_FUSE; i++) {
        Seed[i] = Seed0;
        lcg[i]  = 0;
    }
    for (int i = 0; i < PRVHASH_INIT_COUNT; i++) {
        for (int j = 0; j < PRH64S_FUSE; j++) {
            prvhash_core64(Seed[j], lcg[j], Hash[0]);
        }
    }

    const uint8_t * Msg    = (const uint8_t *)Msg0;
    size_t          MsgLen = MsgLen0;

    while (MsgLen >= PRH64S_LEN) {
        for (int j = 0; j < PRH64S_FUSE; j++) {
            const uint64_t m = GET_U64<bswap>(Msg, j * sizeof(uint64_t));
            Seed[j] ^= m;
            lcg[j]  ^= m;
            prvhash_core64(Seed[j], lcg[j], hc ? Hash[0] : Hash[1]);
        }
        Msg    += PRH64S_LEN;
        MsgLen -= PRH64S_LEN;
        if (width128) {
            hc = !hc;
        }
    }

    uint8_t fb = (MsgLen0 == 0) ? 1 : (uint8_t)(1 << (*(Msg + MsgLen - 1) >> 7));

    uint8_t   fbytes[PRH64S_LEN * 2 + 24];
    uint8_t * ptr      = fbytes;
    size_t    MsgExtra = 0;

    memcpy(ptr, Msg, MsgLen);
    ptr += MsgLen;

    memset(ptr, 0, sizeof(fbytes) - MsgLen);

    ptr[sizeof(uint64_t) - 1] = fb;
    ptr      += sizeof(uint64_t);
    MsgExtra += sizeof(uint64_t);

    PUT_U64<bswap>(MsgLen0 + sizeof(uint64_t), ptr, 0);
    ptr      += sizeof(uint64_t);
    MsgExtra += sizeof(uint64_t);

    fb        = (MsgLen0 == 0) ? 1 : (uint8_t)(1 << (*(ptr - 1) >> 7));

    ptr[sizeof(uint64_t) - 1] = fb;
    ptr      += sizeof(uint64_t);
    MsgExtra += sizeof(uint64_t);

    if (((ptr - fbytes) % PRH64S_LEN) != 0) {
        MsgExtra += PRH64S_LEN - ((ptr - fbytes) % PRH64S_LEN);
    }

    MsgLen += MsgExtra;
    ptr     = fbytes;

    while (MsgLen >= PRH64S_LEN) {
        for (int j = 0; j < PRH64S_FUSE; j++) {
            const uint64_t m = GET_U64<bswap>(ptr, 0);
            ptr     += sizeof(uint64_t);
            Seed[j] ^= m;
            lcg[j]  ^= m;
            prvhash_core64(Seed[j], lcg[j], hc ? Hash[0] : Hash[1]);
        }
        if (width128) {
            hc = !hc;
        }
        MsgLen -= PRH64S_LEN;
    }

    const size_t fc = 8 + (!width128 ?
                0 : (16 + (((((MsgLen0 + MsgExtra) < (16 * PRH64S_FUSE)) && !hc)) ? 8 : 0)));
    for (size_t k = 0; k <= fc; k += sizeof(uint64_t)) {
        for (int j = 0; j < PRH64S_FUSE; j++) {
            prvhash_core64(Seed[j], lcg[j], hc ? Hash[0] : Hash[1]);
        }
        if (width128) {
            hc = !hc;
        }
    }

    for (int k = 0; k < (width128 ? 2 : 1); k++) {
        uint64_t res = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t last;
            for (int j = 0; j < PRH64S_FUSE; j++) {
                last = prvhash_core64(Seed[j], lcg[j], hc ? Hash[0] : Hash[1]);
            }
            res ^= last;
            if (width128) {
                hc = !hc;
            }
        }
        PUT_U64<bswap>(res, HashOut, k * 8);
    }
}

template <bool bswap>
static void prvhash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = prvhash64_64m<bswap, false>(in, len, (uint64_t)seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void prvhash128( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h1, h2;

    h1 = prvhash64_64m<bswap, true>(in, len, (uint64_t)seed, &h2);
    PUT_U64<bswap>(h1, (uint8_t *)out, 0);
    PUT_U64<bswap>(h2, (uint8_t *)out, 8);
}

template <bool bswap>
static void prvhash64s( const void * in, const size_t len, const seed_t seed, void * out ) {
    prvhash64s_oneshot<bswap, false>(in, len, (uint64_t)seed, (uint8_t *)out);
}

template <bool bswap>
static void prvhash128s( const void * in, const size_t len, const seed_t seed, void * out ) {
    prvhash64s_oneshot<bswap, true>(in, len, (uint64_t)seed, (uint8_t *)out);
}

REGISTER_FAMILY(prvhash,
   $.src_url    = "https://github.com/avaneev/prvhash",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(prvhash_64,
   $.desc       = "prvhash64 v4.3.7 64-bit output",
   $.hash_flags =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_SLOW            |
         FLAG_IMPL_CANONICAL_LE    |
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_SHIFT_VARIABLE  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xD37C7E74,
   $.verification_BE = 0xFEFB13E6,
   $.hashfn_native   = prvhash64<false>,
   $.hashfn_bswap    = prvhash64<true>
 );

REGISTER_HASH(prvhash_128,
   $.desc       = "prvhash64 v4.3.7 128-bit output",
   $.hash_flags =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_SLOW            |
         FLAG_IMPL_CANONICAL_LE    |
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_SHIFT_VARIABLE  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0xB447480F,
   $.verification_BE = 0xF10CCBC1,
   $.hashfn_native   = prvhash128<false>,
   $.hashfn_bswap    = prvhash128<true>
 );

REGISTER_HASH(prvhash_64__incr,
   $.desc       = "prvhash64 v4.3.7 streaming mode 64-bit output",
   $.hash_flags =
         FLAG_HASH_XL_SEED,
   $.impl_flags =
         FLAG_IMPL_SLOW            |
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_SHIFT_VARIABLE  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x891521D6,
   $.verification_BE = 0xD41B8DB5,
   $.hashfn_native   = prvhash64s<false>,
   $.hashfn_bswap    = prvhash64s<true>
 );

REGISTER_HASH(prvhash_128__incr,
   $.desc       = "prvhash64 v4.3.7 streaming mode 128-bit output",
   $.hash_flags =
         FLAG_HASH_XL_SEED,
   $.impl_flags =
         FLAG_IMPL_SLOW            |
         FLAG_IMPL_MULTIPLY_64_64  |
         FLAG_IMPL_ROTATE          |
         FLAG_IMPL_SHIFT_VARIABLE  |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x0199728A,
   $.verification_BE = 0xD2B2DE25,
   $.hashfn_native   = prvhash128s<false>,
   $.hashfn_bswap    = prvhash128s<true>
 );
