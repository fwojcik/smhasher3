/*
 * MuseAir v0.3
 * By K--Aethiax
 *
 * Released into the public domain under the CC0 1.0 license. To view a
 * copy of this license, visit:
 * https://creativecommons.org/publicdomain/zero/1.0/
 */
#include "Platform.h"
#include "Hashlib.h"
#include "Mathmult.h"

//------------------------------------------------------------
// ``AiryAi(0)`` mantissas calculated by Y-Cruncher.
static const uint64_t MUSEAIR_CONSTANT[7] = {
    UINT64_C(0x5ae31e589c56e17a), UINT64_C(0x96d7bb04e64f6da9),
    UINT64_C(0x7ab1006b26f9eb64), UINT64_C(0x21233394220b8457),
    UINT64_C(0x047cb9557c9f3b43), UINT64_C(0xd24f2590c0bcee28),
    UINT64_C(0x33ea8f71bb6016d8),
};

//------------------------------------------------------------
template <bool bswap>
static FORCE_INLINE void museair_read_short( const uint8_t * bytes, const size_t len, uint64_t * i, uint64_t * j ) {
    if (len >= 4) {
        int off = (len & 24) >> (len >> 3); // len >= 8 ? 4 : 0
        *i = ((uint64_t)(GET_U32<bswap>(bytes, 0)  ) << 32) | GET_U32<bswap>(bytes, len - 4);
        *j = ((uint64_t)(GET_U32<bswap>(bytes, off)) << 32) | GET_U32<bswap>(bytes, len - 4 - off);
    } else if (len > 0) {
        // MSB <-> LSB
        // [0] [0] [0] for len == 1 (0b01)
        // [0] [1] [1] for len == 2 (0b10)
        // [0] [1] [2] for len == 3 (0b11)
        *i = ((uint64_t)bytes[0] << 48) | ((uint64_t)bytes[len >> 1] << 24) | (uint64_t)bytes[len - 1];
        *j = 0;
    } else {
        *i = 0;
        *j = 0;
    }
}

//------------------------------------------------------------
template <bool bfast>
static FORCE_INLINE void museair_mumix(uint64_t* state_p, uint64_t* state_q, uint64_t input_p, uint64_t input_q) {
    if (!bfast) {
        uint64_t lo, hi;
        *state_p ^= input_p;
        *state_q ^= input_q;
        MathMult::mult64_128(lo, hi, *state_p, *state_q);
        *state_p ^= lo;
        *state_q ^= hi;
    } else {
        MathMult::mult64_128(*state_p, *state_q, *state_p ^ input_p, *state_q ^ input_q);
    }
}

//------------------------------------------------------------
#define U64x(N) N * 8

template <bool bswap, bool bfast, bool b128>
static FORCE_INLINE void museair_hash_short(const uint8_t* bytes,
                                            const size_t len,
                                            const seed_t seed,
                                            uint64_t* out_lo,
                                            uint64_t* out_hi) {
    uint64_t lo0, lo1, lo2;
    uint64_t hi0, hi1, hi2;

    MathMult::mult64_128(lo2, hi2, seed ^ MUSEAIR_CONSTANT[0], len ^ MUSEAIR_CONSTANT[1]);

    uint64_t i, j;
    museair_read_short<bswap>(bytes, len <= 16 ? len : 16, &i, &j);
    i ^= len ^ lo2;
    j ^= seed ^ hi2;

    if (unlikely(len > U64x(2))) {
        uint64_t u, v;
        museair_read_short<bswap>(bytes + U64x(2), len - U64x(2), &u, &v);
        MathMult::mult64_128(lo0, hi0, MUSEAIR_CONSTANT[2], MUSEAIR_CONSTANT[3] ^ u);
        MathMult::mult64_128(lo1, hi1, MUSEAIR_CONSTANT[4], MUSEAIR_CONSTANT[5] ^ v);
        i ^= lo0 ^ hi1;
        j ^= lo1 ^ hi0;
    }

    if (b128) {
        MathMult::mult64_128(lo0, hi0, i, j);
        MathMult::mult64_128(lo1, hi1, i ^ MUSEAIR_CONSTANT[2], j ^ MUSEAIR_CONSTANT[3]);
        i = lo0 ^ hi1;
        j = lo1 ^ hi0;
        MathMult::mult64_128(lo0, hi0, i, j);
        MathMult::mult64_128(lo1, hi1, i ^ MUSEAIR_CONSTANT[4], j ^ MUSEAIR_CONSTANT[5]);
        *out_lo = lo0 ^ hi1;
        *out_hi = lo1 ^ hi0;
    } else {
        MathMult::mult64_128(lo2, hi2, i ^ MUSEAIR_CONSTANT[2], j ^ MUSEAIR_CONSTANT[3]);
        if (!bfast) {
            i ^= lo2;
            j ^= hi2;
        } else {
            i = lo2;
            j = hi2;
        }
        MathMult::mult64_128(lo2, hi2, i ^ MUSEAIR_CONSTANT[4], j ^ MUSEAIR_CONSTANT[5]);
        if (!bfast) {
            *out_lo = i ^ j ^ lo2 ^ hi2;
        } else {
            *out_lo = lo2 ^ hi2;
        }
    }
}

template <bool bswap, bool bfast, bool b128>
static NEVER_INLINE void museair_hash_loong(const uint8_t* bytes,
                                            const size_t len,
                                            const seed_t seed,
                                            uint64_t* out_lo,
                                            uint64_t* out_hi) {
    const uint8_t* p = bytes;
    size_t q = len;

    uint64_t i, j, k;

    uint64_t lo0, lo1, lo2, lo3, lo4, lo5 = MUSEAIR_CONSTANT[6];
    uint64_t hi0, hi1, hi2, hi3, hi4, hi5;

    uint64_t state[6] = {MUSEAIR_CONSTANT[0] + seed, MUSEAIR_CONSTANT[1] - seed, MUSEAIR_CONSTANT[2] ^ seed,
                         MUSEAIR_CONSTANT[3] + seed, MUSEAIR_CONSTANT[4] - seed, MUSEAIR_CONSTANT[5] ^ seed};

    if (unlikely(q >= U64x(12))) {
        do {
            if (!bfast) {
                state[0] ^= GET_U64<bswap>(p, U64x(0));
                state[1] ^= GET_U64<bswap>(p, U64x(1));
                MathMult::mult64_128(lo0, hi0, state[0], state[1]);
                state[0] += lo5 ^ hi0;

                state[1] ^= GET_U64<bswap>(p, U64x(2));
                state[2] ^= GET_U64<bswap>(p, U64x(3));
                MathMult::mult64_128(lo1, hi1, state[1], state[2]);
                state[1] += lo0 ^ hi1;

                state[2] ^= GET_U64<bswap>(p, U64x(4));
                state[3] ^= GET_U64<bswap>(p, U64x(5));
                MathMult::mult64_128(lo2, hi2, state[2], state[3]);
                state[2] += lo1 ^ hi2;

                state[3] ^= GET_U64<bswap>(p, U64x(6));
                state[4] ^= GET_U64<bswap>(p, U64x(7));
                MathMult::mult64_128(lo3, hi3, state[3], state[4]);
                state[3] += lo2 ^ hi3;

                state[4] ^= GET_U64<bswap>(p, U64x(8));
                state[5] ^= GET_U64<bswap>(p, U64x(9));
                MathMult::mult64_128(lo4, hi4, state[4], state[5]);
                state[4] += lo3 ^ hi4;

                state[5] ^= GET_U64<bswap>(p, U64x(10));
                state[0] ^= GET_U64<bswap>(p, U64x(11));
                MathMult::mult64_128(lo5, hi5, state[5], state[0]);
                state[5] += lo4 ^ hi5;
            } else {
                state[0] ^= GET_U64<bswap>(p, U64x(0));
                state[1] ^= GET_U64<bswap>(p, U64x(1));
                MathMult::mult64_128(lo0, hi0, state[0], state[1]);
                state[0] = lo5 ^ hi0;

                state[1] ^= GET_U64<bswap>(p, U64x(2));
                state[2] ^= GET_U64<bswap>(p, U64x(3));
                MathMult::mult64_128(lo1, hi1, state[1], state[2]);
                state[1] = lo0 ^ hi1;

                state[2] ^= GET_U64<bswap>(p, U64x(4));
                state[3] ^= GET_U64<bswap>(p, U64x(5));
                MathMult::mult64_128(lo2, hi2, state[2], state[3]);
                state[2] = lo1 ^ hi2;

                state[3] ^= GET_U64<bswap>(p, U64x(6));
                state[4] ^= GET_U64<bswap>(p, U64x(7));
                MathMult::mult64_128(lo3, hi3, state[3], state[4]);
                state[3] = lo2 ^ hi3;

                state[4] ^= GET_U64<bswap>(p, U64x(8));
                state[5] ^= GET_U64<bswap>(p, U64x(9));
                MathMult::mult64_128(lo4, hi4, state[4], state[5]);
                state[4] = lo3 ^ hi4;

                state[5] ^= GET_U64<bswap>(p, U64x(10));
                state[0] ^= GET_U64<bswap>(p, U64x(11));
                MathMult::mult64_128(lo5, hi5, state[5], state[0]);
                state[5] = lo4 ^ hi5;
            }

            p += U64x(12);
            q -= U64x(12);

        } while (likely(q >= U64x(12)));

        state[0] ^= lo5;
    }

    if (unlikely(q >= U64x(6))) {
        museair_mumix<bfast>(&state[0], &state[1], GET_U64<bswap>(p, U64x(0)),
                             GET_U64<bswap>(p, U64x(1)));
        museair_mumix<bfast>(&state[2], &state[3], GET_U64<bswap>(p, U64x(2)),
                             GET_U64<bswap>(p, U64x(3)));
        museair_mumix<bfast>(&state[4], &state[5], GET_U64<bswap>(p, U64x(4)),
                             GET_U64<bswap>(p, U64x(5)));

        p += U64x(6);
        q -= U64x(6);
    }

    if (likely(q >= U64x(2))) {
        museair_mumix<bfast>(&state[0], &state[3], GET_U64<bswap>(p, U64x(0)),
                             GET_U64<bswap>(p, U64x(1)));
        if (likely(q >= U64x(4))) {
            museair_mumix<bfast>(&state[1], &state[4], GET_U64<bswap>(p, U64x(2)),
                                 GET_U64<bswap>(p, U64x(3)));
        }
    }

    museair_mumix<bfast>(&state[2], &state[5], GET_U64<bswap>(p + q - U64x(2), 0),
            GET_U64<bswap>(p + q - U64x(1), 0));

    /*-------- epilogue --------*/

    i = state[0] - state[1];
    j = state[2] - state[3];
    k = state[4] - state[5];

    int rot = len & 63;
    i = ROTL64(i, rot);
    j = ROTR64(j, rot);
    k ^= len;

    MathMult::mult64_128(lo0, hi0, i, j);
    MathMult::mult64_128(lo1, hi1, j, k);
    MathMult::mult64_128(lo2, hi2, k, i);

    i = lo0 ^ hi2;
    j = lo1 ^ hi0;
    k = lo2 ^ hi1;

    MathMult::mult64_128(lo0, hi0, i, j);
    MathMult::mult64_128(lo1, hi1, j, k);
    MathMult::mult64_128(lo2, hi2, k, i);

    if (b128) {
        *out_lo = lo0 ^ lo1 ^ hi2;
        *out_hi = hi0 ^ hi1 ^ lo2;
    } else {
        *out_lo = (lo0 ^ hi2) + (lo1 ^ hi0) + (lo2 ^ hi1);
    }
}

//------------------------------------------------------------
template <bool bswap, bool bfast, bool b128>
static void MuseAirHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * bytes = (const uint8_t*)in;
    uint64_t out_lo, out_hi;

    if (likely(len <= 32)) {
        museair_hash_short<bswap, bfast, b128>(bytes, len, seed, &out_lo, &out_hi);
    } else {
        museair_hash_loong<bswap, bfast, b128>(bytes, len, seed, &out_lo, &out_hi);
    }

    out_lo = COND_BSWAP(out_lo, isBE());
    PUT_U64<false>(out_lo, (uint8_t*)out, 0);

    if (b128) {
        out_hi = COND_BSWAP(out_hi, isBE());
        PUT_U64<false>(out_hi, (uint8_t*)out, 8);
    }
}

//------------------------------------------------------------
REGISTER_FAMILY(museair,
   $.src_url    = "https://github.com/eternal-io/museair/",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(MuseAir,
   $.desc            = "MuseAir v0.3",
   $.hash_flags      =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_ROTATE_VARIABLE  |
         FLAG_IMPL_CANONICAL_LE     |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits            = 64,
   $.verification_LE = 0xF89F1683,
   $.verification_BE = 0xDFEF2570,
   $.hashfn_native   = MuseAirHash<false, false, false>,
   $.hashfn_bswap    = MuseAirHash<true, false, false>
 );

REGISTER_HASH(MuseAir__bfast,
   $.desc            = "MuseAir v0.3, bfast version",
   $.hash_flags      =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_ROTATE_VARIABLE  |
         FLAG_IMPL_CANONICAL_LE     |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits            = 64,
   $.verification_LE = 0xC61BEE56,
   $.verification_BE = 0x16186D00,
   $.hashfn_native   = MuseAirHash<false, true, false>,
   $.hashfn_bswap    = MuseAirHash<true, true, false>
 );

REGISTER_HASH(MuseAir_128,
   $.desc            = "MuseAir v0.3, 128 bits",
   $.hash_flags      =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_ROTATE_VARIABLE  |
         FLAG_IMPL_CANONICAL_LE     |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits            = 128,
   $.verification_LE = 0xD3DFE238,
   $.verification_BE = 0x05EC3BE4,
   $.hashfn_native   = MuseAirHash<false, false, true>,
   $.hashfn_bswap    = MuseAirHash<true, false, true>
 );

REGISTER_HASH(MuseAir_128__bfast,
   $.desc            = "MuseAir v0.3, 128 bits, bfast version",
   $.hash_flags      =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_ROTATE_VARIABLE  |
         FLAG_IMPL_CANONICAL_LE     |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits            = 128,
   $.verification_LE = 0x27939BF1,
   $.verification_BE = 0xCB4AB283,
   $.hashfn_native   = MuseAirHash<false, true, true>,
   $.hashfn_bswap    = MuseAirHash<true, true, true>
 );
