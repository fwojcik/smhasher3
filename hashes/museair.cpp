/*
 * MuseAir v0.2
 * Copyright (c) 2024 K--Aethiax
 *
 * Modified from "wyhash.h" (mainly these `#define`s), by Wang Yi <godspeed_china@yeah.net>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Alternatively, the contents of this file may be used under the terms of
 * the MIT license as described below.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "Platform.h"
#include "Hashlib.h"
#include "Mathmult.h"

//------------------------------------------------------------
static const uint64_t MUSEAIR_SECRET[6] = {
    UINT64_C(0x5ae31e589c56e17a), UINT64_C(0x96d7bb04e64f6da9),
    UINT64_C(0x7ab1006b26f9eb64), UINT64_C(0x21233394220b8457),
    UINT64_C(0x047cb9557c9f3b43), UINT64_C(0xd24f2590c0bcee28),
}; // ``AiryAi(0)`` mantissas calculated by Y-Cruncher.
static const uint64_t MUSEAIR_RING_PREV = UINT64_C(0x33ea8f71bb6016d8);

//------------------------------------------------------------
template <bool bswap>
static FORCE_INLINE void museair_read_short( const uint8_t * bytes, const size_t len, uint64_t * i, uint64_t * j ) {
    // For short inputs, refer to rapidhash, MuseAir has no much different from that.
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
static FORCE_INLINE void museair_wmul( uint64_t * lo, uint64_t * hi, uint64_t a, uint64_t b ) {
    uint64_t l, h;

    MathMult::mult64_128(l, h, a, b);
    *lo = l;
    *hi = h;
}

static FORCE_INLINE uint64_t museair_rotl( uint64_t v, uint8_t n ) {
    return ROTL64(v, n);
}

static FORCE_INLINE uint64_t museair_rotr( uint64_t v, uint8_t n ) {
    return ROTR64(v, n);
}

//------------------------------------------------------------
static FORCE_INLINE void museair_chixx( uint64_t * t, uint64_t * u, uint64_t * v ) {
    uint64_t x = ~*u & *v;
    uint64_t y = ~*v & *t;
    uint64_t z = ~*t & *u;

    *t ^= x;
    *u ^= y;
    *v ^= z;
}

template <bool BFast>
static FORCE_INLINE void museair_frac_6( uint64_t * state_p, uint64_t * state_q,
        const uint64_t input_p, const uint64_t input_q ) {
    uint64_t lo, hi;

    if (!BFast) {
        *state_p ^= input_p;
        *state_q ^= input_q;
        museair_wmul(&lo, &hi, *state_p, *state_q);
        *state_p ^= lo;
        *state_q ^= hi;
    } else {
        museair_wmul(&lo, &hi, *state_p ^ input_p, *state_q ^ input_q);
        *state_p = lo;
        *state_q = hi;
    }
}

template <bool BFast>
static FORCE_INLINE void museair_frac_3( uint64_t * state_p, uint64_t * state_q, const uint64_t input ) {
    uint64_t lo, hi;

    if (!BFast) {
        *state_q ^= input;
        museair_wmul(&lo, &hi, *state_p, *state_q);
        *state_p ^= lo;
        *state_q ^= hi;
    } else {
        museair_wmul(&lo, &hi, *state_p, *state_q ^ input);
        *state_p = lo;
        *state_q = hi;
    }
}

//------------------------------------------------------------
template <bool bswap, bool BFast>
static FORCE_INLINE void museair_layer_12( uint64_t * state, const uint8_t * p, uint64_t * ring_prev ) {
    uint64_t lo0, lo1, lo2, lo3, lo4, lo5;
    uint64_t hi0, hi1, hi2, hi3, hi4, hi5;

    if (!BFast) {
        state[0] ^= GET_U64<bswap>(p, 8 *  0);
        state[1] ^= GET_U64<bswap>(p, 8 *  1);
        museair_wmul(&lo0, &hi0, state[0], state[1]);
        state[0] += *ring_prev ^ hi0;

        state[1] ^= GET_U64<bswap>(p, 8 *  2);
        state[2] ^= GET_U64<bswap>(p, 8 *  3);
        museair_wmul(&lo1, &hi1, state[1], state[2]);
        state[1] += lo0        ^ hi1;

        state[2] ^= GET_U64<bswap>(p, 8 *  4);
        state[3] ^= GET_U64<bswap>(p, 8 *  5);
        museair_wmul(&lo2, &hi2, state[2], state[3]);
        state[2] += lo1        ^ hi2;

        state[3] ^= GET_U64<bswap>(p, 8 *  6);
        state[4] ^= GET_U64<bswap>(p, 8 *  7);
        museair_wmul(&lo3, &hi3, state[3], state[4]);
        state[3] += lo2        ^ hi3;

        state[4] ^= GET_U64<bswap>(p, 8 *  8);
        state[5] ^= GET_U64<bswap>(p, 8 *  9);
        museair_wmul(&lo4, &hi4, state[4], state[5]);
        state[4] += lo3        ^ hi4;

        state[5] ^= GET_U64<bswap>(p, 8 * 10);
        state[0] ^= GET_U64<bswap>(p, 8 * 11);
        museair_wmul(&lo5, &hi5, state[5], state[0]);
        state[5] += lo4        ^ hi5;
    } else {
        state[0] ^= GET_U64<bswap>(p, 8 *  0);
        state[1] ^= GET_U64<bswap>(p, 8 *  1);
        museair_wmul(&lo0, &hi0, state[0], state[1]);
        state[0]  = *ring_prev ^ hi0;

        state[1] ^= GET_U64<bswap>(p, 8 *  2);
        state[2] ^= GET_U64<bswap>(p, 8 *  3);
        museair_wmul(&lo1, &hi1, state[1], state[2]);
        state[1]  = lo0        ^ hi1;

        state[2] ^= GET_U64<bswap>(p, 8 *  4);
        state[3] ^= GET_U64<bswap>(p, 8 *  5);
        museair_wmul(&lo2, &hi2, state[2], state[3]);
        state[2]  = lo1        ^ hi2;

        state[3] ^= GET_U64<bswap>(p, 8 *  6);
        state[4] ^= GET_U64<bswap>(p, 8 *  7);
        museair_wmul(&lo3, &hi3, state[3], state[4]);
        state[3]  = lo2        ^ hi3;

        state[4] ^= GET_U64<bswap>(p, 8 *  8);
        state[5] ^= GET_U64<bswap>(p, 8 *  9);
        museair_wmul(&lo4, &hi4, state[4], state[5]);
        state[4]  = lo3        ^ hi4;

        state[5] ^= GET_U64<bswap>(p, 8 * 10);
        state[0] ^= GET_U64<bswap>(p, 8 * 11);
        museair_wmul(&lo5, &hi5, state[5], state[0]);
        state[5]  = lo4        ^ hi5;
    }
    *ring_prev = lo5;
}

template <bool bswap, bool BFast>
static FORCE_INLINE void museair_layer_6( uint64_t * state, const uint8_t * p ) {
    museair_frac_6<BFast>(&state[0], &state[1], GET_U64<bswap>(p, 8 * 0), GET_U64<bswap>(p, 8 * 1));
    museair_frac_6<BFast>(&state[2], &state[3], GET_U64<bswap>(p, 8 * 2), GET_U64<bswap>(p, 8 * 3));
    museair_frac_6<BFast>(&state[4], &state[5], GET_U64<bswap>(p, 8 * 4), GET_U64<bswap>(p, 8 * 5));
}

template <bool bswap, bool BFast>
static FORCE_INLINE void museair_layer_3( uint64_t * state, const uint8_t * p ) {
    museair_frac_3<BFast>(&state[0], &state[3], GET_U64<bswap>(p, 8 * 0));
    museair_frac_3<BFast>(&state[1], &state[4], GET_U64<bswap>(p, 8 * 1));
    museair_frac_3<BFast>(&state[2], &state[5], GET_U64<bswap>(p, 8 * 2));
}

template <bool bswap>
static FORCE_INLINE void museair_layer_0( uint64_t * state, const uint8_t * p,
        size_t q, size_t len, uint64_t * i, uint64_t * j, uint64_t * k ) {
    if (q <= 8 * 2) {
        uint64_t i_, j_;
        museair_read_short<bswap>(p, q, &i_, &j_);
        *i = i_;
        *j = j_;
        *k = 0;
    } else {
        *i = GET_U64<bswap>(p, 0    );
        *j = GET_U64<bswap>(p, 8    );
        *k = GET_U64<bswap>(p, q - 8);
    }

    if (len >= 8 * 3) {
        museair_chixx(&state[0], &state[2], &state[4]);
        museair_chixx(&state[1], &state[3], &state[5]);
        *i ^= state[0] + state[1];
        *j ^= state[2] + state[3];
        *k ^= state[4] + state[5];
    } else {
        *i ^= state[0];
        *j ^= state[1];
        *k ^= state[2];
    }
}

template <bool BFast>
static FORCE_INLINE void museair_layer_f( size_t len, uint64_t * i, uint64_t * j, uint64_t * k ) {
    uint8_t rot = (uint8_t)len & 63;

    museair_chixx(i, j, k);

    *i  = museair_rotl(*i, rot);
    *j  = museair_rotr(*j, rot);
    *k ^= (uint64_t)len;

    uint64_t lo0, lo1, lo2;
    uint64_t hi0, hi1, hi2;
    if (!BFast) {
        museair_wmul(&lo0, &hi0, *i ^ MUSEAIR_SECRET[3], *j);
        museair_wmul(&lo1, &hi1, *j ^ MUSEAIR_SECRET[4], *k);
        museair_wmul(&lo2, &hi2, *k ^ MUSEAIR_SECRET[5], *i);
        *i ^= lo0 ^ hi2;
        *j ^= lo1 ^ hi0;
        *k ^= lo2 ^ hi1;
    } else {
        museair_wmul(&lo0, &hi0, *i, *j);
        museair_wmul(&lo1, &hi1, *j, *k);
        museair_wmul(&lo2, &hi2, *k, *i);
        *i = lo0 ^ hi2;
        *j = lo1 ^ hi0;
        *k = lo2 ^ hi1;
    }
}

//------------------------------------------------------------
template <bool bswap, bool BFast>
static FORCE_INLINE void museair_tower_loong( const uint8_t * bytes, const size_t len,
        const uint64_t seed, uint64_t * i, uint64_t * j, uint64_t * k ) {
    const uint8_t * p = bytes;
    size_t          q = len;

    uint64_t state[6] = {
        MUSEAIR_SECRET[0] + seed, MUSEAIR_SECRET[1] - seed, MUSEAIR_SECRET[2] ^ seed,
        MUSEAIR_SECRET[3],        MUSEAIR_SECRET[4],        MUSEAIR_SECRET[5]
    };

    if (q >= 8 * 12) {
        state[3] += seed;
        state[4] -= seed;
        state[5] ^= seed;
        uint64_t ring_prev = MUSEAIR_RING_PREV;
        do {
            museair_layer_12<bswap, BFast>(&state[0], p, &ring_prev);
            p += 8 * 12;
            q -= 8 * 12;
        } while (likely(q >= 8 * 12));
        state[0] ^= ring_prev;
    }

    if (q >= 8 * 6) {
        museair_layer_6<bswap, BFast>(&state[0], p);
        p += 8 * 6;
        q -= 8 * 6;
    }

    if (q >= 8 * 3) {
        museair_layer_3<bswap, BFast>(&state[0], p);
        p += 8 * 3;
        q -= 8 * 3;
    }

    museair_layer_0<bswap>(&state[0], p, q, len, i, j, k);
    museair_layer_f<BFast>(len, i, j, k);
}

template <bool bswap>
static FORCE_INLINE void museair_tower_short( const uint8_t * bytes, const size_t len,
        const uint64_t seed, uint64_t * i, uint64_t * j ) {
    uint64_t lo, hi;

    museair_read_short<bswap>(bytes, len, i, j);
    museair_wmul(&lo, &hi, seed ^ MUSEAIR_SECRET[0], len ^ MUSEAIR_SECRET[1]);
    *i ^= lo ^ len;
    *j ^= hi ^ seed;
}

//------------------------------------------------------------
static FORCE_INLINE void museair_epi_short( uint64_t * i, uint64_t * j ) {
    uint64_t lo, hi;

    *i ^= MUSEAIR_SECRET[2];
    *j ^= MUSEAIR_SECRET[3];
    museair_wmul(&lo, &hi, *i, *j);
    *i ^= lo ^ MUSEAIR_SECRET[4];
    *j ^= hi ^ MUSEAIR_SECRET[5];
    museair_wmul(&lo, &hi, *i, *j);
    *i ^= *j ^ lo ^ hi;
}

template <bool BFast>
static FORCE_INLINE void museair_epi_short_128( uint64_t * i, uint64_t * j ) {
    uint64_t lo0, lo1;
    uint64_t hi0, hi1;

    if (!BFast) {
        museair_wmul(&lo0, &hi0, *i ^ MUSEAIR_SECRET[2], *j);
        museair_wmul(&lo1, &hi1, *i, *j ^ MUSEAIR_SECRET[3]);
        *i ^= lo0 ^ hi1;
        *j ^= lo1 ^ hi0;
        museair_wmul(&lo0, &hi0, *i ^ MUSEAIR_SECRET[4], *j);
        museair_wmul(&lo1, &hi1, *i, *j ^ MUSEAIR_SECRET[5]);
        *i ^= lo0 ^ hi1;
        *j ^= lo1 ^ hi0;
    } else {
        museair_wmul(&lo0, &hi0, *i, *j);
        museair_wmul(&lo1, &hi1, *i ^ MUSEAIR_SECRET[2], *j ^ MUSEAIR_SECRET[3]);
        *i = lo0 ^ hi1;
        *j = lo1 ^ hi0;
        museair_wmul(&lo0, &hi0, *i, *j);
        museair_wmul(&lo1, &hi1, *i ^ MUSEAIR_SECRET[4], *j ^ MUSEAIR_SECRET[5]);
        *i = lo0 ^ hi1;
        *j = lo1 ^ hi0;
    }
}

template <bool BFast>
static FORCE_INLINE void museair_epi_loong( uint64_t * i, uint64_t * j, uint64_t * k ) {
    uint64_t lo0, lo1, lo2;
    uint64_t hi0, hi1, hi2;

    if (!BFast) {
        museair_wmul(&lo0, &hi0, *i ^ MUSEAIR_SECRET[0], *j);
        museair_wmul(&lo1, &hi1, *j ^ MUSEAIR_SECRET[1], *k);
        museair_wmul(&lo2, &hi2, *k ^ MUSEAIR_SECRET[2], *i);
        *i ^= lo0 ^ hi2;
        *j ^= lo1 ^ hi0;
        *k ^= lo2 ^ hi1;
    } else {
        museair_wmul(&lo0, &hi0, *i, *j);
        museair_wmul(&lo1, &hi1, *j, *k);
        museair_wmul(&lo2, &hi2, *k, *i);
        *i = lo0 ^ hi2;
        *j = lo1 ^ hi0;
        *k = lo2 ^ hi1;
    }
    *i += *j + *k;
}

template <bool BFast>
static FORCE_INLINE void museair_epi_loong_128( uint64_t * i, uint64_t * j, uint64_t * k ) {
    uint64_t lo0, lo1, lo2;
    uint64_t hi0, hi1, hi2;

    if (!BFast) {
        museair_wmul(&lo0, &hi0, *i ^ MUSEAIR_SECRET[0], *j);
        museair_wmul(&lo1, &hi1, *j ^ MUSEAIR_SECRET[1], *k);
        museair_wmul(&lo2, &hi2, *k ^ MUSEAIR_SECRET[2], *i);
        *i ^= lo0 ^ lo1 ^ hi2;
        *j ^= hi0 ^ hi1 ^ lo2;
    } else {
        museair_wmul(&lo0, &hi0, *i, *j);
        museair_wmul(&lo1, &hi1, *j, *k);
        museair_wmul(&lo2, &hi2, *k, *i);
        *i = lo0 ^ lo1 ^ hi2;
        *j = hi0 ^ hi1 ^ lo2;
    }
}

//------------------------------------------------------------
template <bool bswap>
static FORCE_INLINE void museair_hash_short( const uint8_t * bytes, const size_t len,
        const uint64_t seed, uint64_t * i, uint64_t * j ) {
    museair_tower_short<bswap>(bytes, len, seed, i, j);
    museair_epi_short(i, j);
}

template <bool bswap, bool BFast>
static FORCE_INLINE void museair_hash_short_128( const uint8_t * bytes, const size_t len,
        const uint64_t seed, uint64_t * i, uint64_t * j ) {
    museair_tower_short<bswap>(bytes, len, seed, i, j);
    museair_epi_short_128<BFast>(i, j);
}

template <bool bswap, bool BFast>
static NEVER_INLINE void museair_hash_loong( const uint8_t * bytes, const size_t len,
        const uint64_t seed, uint64_t * i, uint64_t * j, uint64_t * k ) {
    museair_tower_loong<bswap, BFast>(bytes, len, seed, i, j, k);
    museair_epi_loong<BFast>(i, j, k);
}

template <bool bswap, bool BFast>
static NEVER_INLINE void museair_hash_loong_128( const uint8_t * bytes, const size_t len,
        const uint64_t seed, uint64_t * i, uint64_t * j, uint64_t * k ) {
    museair_tower_loong<bswap, BFast>(bytes, len, seed, i, j, k);
    museair_epi_loong_128<BFast>(i, j, k);
}

//------------------------------------------------------------
template <bool bswap, bool BFast>
static void museair64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t i, j, k;

    if (likely(len <= 16)) {
        museair_hash_short<bswap>((const uint8_t *)in, len, seed, &i, &j);
    } else {
        museair_hash_loong<bswap, BFast>((const uint8_t *)in, len, seed, &i, &j, &k);
    }
    PUT_U64<bswap>(i, (uint8_t *)out, 0);
}

template <bool bswap, bool BFast>
static void museair128( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t i, j, k;

    if (likely(len <= 16)) {
        museair_hash_short_128<bswap, BFast>((const uint8_t *)in, len, seed, &i, &j);
    } else {
        museair_hash_loong_128<bswap, BFast>((const uint8_t *)in, len, seed, &i, &j, &k);
    }

    PUT_U64<bswap>(i, (uint8_t *)out, 0);
    PUT_U64<bswap>(j, (uint8_t *)out, 8);
}

//------------------------------------------------------------
REGISTER_FAMILY(museair,
   $.src_url    = "https://github.com/eternal-io/museair-c",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(MuseAir,
   $.desc            = "MuseAir v0.2",
   $.hash_flags      =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_ROTATE_VARIABLE  |
         FLAG_IMPL_CANONICAL_LE     |
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 64,
   $.verification_LE = 0x46B2D34D,
   $.verification_BE = 0XCA508104,
   $.hashfn_native   = museair64<false, false>,
   $.hashfn_bswap    = museair64<true, false>
 );

REGISTER_HASH(MuseAir__bfast,
   $.desc            = "MuseAir v0.2, bfast version",
   $.hash_flags      =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_ROTATE_VARIABLE  |
         FLAG_IMPL_CANONICAL_LE     |
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 64,
   $.verification_LE = 0x98CDFE3E,
   $.verification_BE = 0XFD8F40F2,
   $.hashfn_native   = museair64<false, true>,
   $.hashfn_bswap    = museair64<true, true>
 );

REGISTER_HASH(MuseAir_128,
   $.desc            = "MuseAir v0.2, 128 bits",
   $.hash_flags      =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_ROTATE_VARIABLE  |
         FLAG_IMPL_CANONICAL_LE     |
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 128,
   $.verification_LE = 0xCABAA4CD,
   $.verification_BE = 0X2CCFCC50,
   $.hashfn_native   = museair128<false, false>,
   $.hashfn_bswap    = museair128<true, false>
 );

REGISTER_HASH(MuseAir_128__bfast,
   $.desc            = "MuseAir v0.2, 128 bits, bfast version",
   $.hash_flags      =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_MULTIPLY_64_128  |
         FLAG_IMPL_ROTATE_VARIABLE  |
         FLAG_IMPL_CANONICAL_LE     |
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 128,
   $.verification_LE = 0x81D30B6E,
   $.verification_BE = 0XC8E96C8D,
   $.hashfn_native   = museair128<false, true>,
   $.hashfn_bswap    = museair128<true, true>
 );
