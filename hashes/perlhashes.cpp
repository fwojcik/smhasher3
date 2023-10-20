/*
 * Various old hashes from perl5
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (C) 1993-2016, by Larry Wall and others.
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 */
#include "Platform.h"
#include "Hashlib.h"

//------------------------------------------------------------
// Old SMHasher version of these didn't include len in the initial
// hash value, as the perl code does. The old verification codes can
// be obtained by removing "+ (uint32_t)len" from the "hash =" lines.

static uint32_t djb2( const uint8_t * str, const size_t len, const uint32_t seed ) {
    const uint8_t * end  = str + len;
    uint32_t        hash = seed + (uint32_t)len;

    while (str < end) {
        hash = ((hash << 5) + hash) + *str++;
    }
    return hash;
}

static uint32_t sdbm( const uint8_t * str, const size_t len, const uint32_t seed ) {
    const uint8_t * end  = str + len;
    uint32_t        hash = seed + (uint32_t)len;

    while (str < end) {
        hash = (hash << 6) + (hash << 16) - hash + *str++;
    }
    return hash;
}

static uint32_t jenkinsOAAT( const uint8_t * str, const size_t len, const uint32_t seed ) {
    const uint8_t * end  = str + len;
    uint32_t        hash = seed + (uint32_t)len;

    while (str < end) {
        hash += *str++;
        hash += (hash << 10);
        hash ^= (hash >>  6);
    }
    hash += (hash <<  3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

static uint32_t jenkinsOAAT_old( const uint8_t * str, const size_t len, const uint32_t seed ) {
    const uint8_t * end  = str + len;
    uint32_t        hash = seed;

    while (str < end) {
        hash += *str++;
        hash += (hash << 10);
        hash ^= (hash >>  6);
    }
    hash += (hash <<  3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

static uint32_t jenkinsOAAT_hard( const uint8_t * str, const size_t len, const uint64_t seed64 ) {
    const uint8_t * end  = str + len;
    uint32_t        hash = (uint32_t)seed64 + (uint32_t)len;

    while (str < end) {
        hash += (hash << 10);
        hash ^= (hash >>  6);
        hash += *str++;
    }

    hash += (hash   << 10);
    hash ^= (hash   >>  6);
    hash += (seed64 >> 32) & 0xFF;

    hash += (hash   << 10);
    hash ^= (hash   >>  6);
    hash += (seed64 >> 40) & 0xFF;

    hash += (hash   << 10);
    hash ^= (hash   >>  6);
    hash += (seed64 >> 48) & 0xFF;

    hash += (hash   << 10);
    hash ^= (hash   >>  6);
    hash += (seed64 >> 56) & 0xFF;

    hash += (hash   << 10);
    hash ^= (hash   >>  6);
    hash += (hash   <<  3);
    hash ^= (hash   >> 11);
    hash += (hash   << 15);
    return hash;
}

//------------------------------------------------------------

/*
 * do a marsaglia xor-shift permutation followed by a
 * multiply by a prime (presumably large) and another
 * marsaglia xor-shift permutation.
 * One of these thoroughly changes the bits of the input.
 * Two of these with different primes passes the Strict Avalanche Criteria
 * in all the tests I did.
 *
 * Note that v cannot end up zero after a scramble64 unless it
 * was zero in the first place.
 */
#define STADTX_SCRAMBLE64(v,prime) { \
        v ^= (v >> 13);              \
        v ^= (v << 35);              \
        v ^= (v >> 30);              \
        v *= prime;                  \
        v ^= (v >> 19);              \
        v ^= (v << 15);              \
        v ^= (v >> 46);              \
    }

static thread_local uint64_t stadtx_state[4];

static uintptr_t stadtx_reseed( const seed_t seed ) {
    uint64_t * state = stadtx_state;
    uint64_t   seed0 = (uint64_t)seed;
    uint64_t   seed1 = (uint64_t)seed;

    /*
     * first we apply two masks to each word of the seed, this means that
     * a) at least one of state[0] and state[2] is nonzero,
     * b) at least one of state[1] and state[3] is nonzero
     * c) that state[0] and state[2] are different
     * d) that state[1] and state[3] are different
     * e) that the replacement value for any zero's is a totally different from the seed value.
     *    (iow, if seed[0] is 0x43f6a8885a308d31UL then state[0] becomes 0, which is the replaced
     *    with 1, which is totally different.).
     */
    /* hex expansion of pi, skipping first two digits. pi= 3.2[43f6...]*/
    /*
     * pi value in hex from here:
     * http://turner.faculty.swau.edu/mathematics/materialslibrary/pi/pibases.html
     */
    state[0] = seed0 ^ UINT64_C(0x43f6a8885a308d31);
    state[1] = seed1 ^ UINT64_C(0x3198a2e03707344a);
    state[2] = seed0 ^ UINT64_C(0x4093822299f31d00);
    state[3] = seed1 ^ UINT64_C(0x82efa98ec4e6c894);
    if (!state[0]) { state[0] = 1; }
    if (!state[1]) { state[1] = 2; }
    if (!state[2]) { state[2] = 4; }
    if (!state[3]) { state[3] = 8; }
    /*
     * and now for good measure we double scramble all four -
     * a double scramble guarantees a complete avalanche of all the
     * bits in the seed - IOW, by the time we are hashing the
     * four state vectors should be completely different and utterly
     * uncognizable from the input seed bits
     */
    STADTX_SCRAMBLE64(state[0], UINT64_C(0x801178846e899d17));
    STADTX_SCRAMBLE64(state[0], UINT64_C(0xdd51e5d1c9a5a151));
    STADTX_SCRAMBLE64(state[1], UINT64_C(0x93a7d6c8c62e4835));
    STADTX_SCRAMBLE64(state[1], UINT64_C(0x803340f36895c2b5));
    STADTX_SCRAMBLE64(state[2], UINT64_C(0xbea9344eb7565eeb));
    STADTX_SCRAMBLE64(state[2], UINT64_C(0xcd95d1e509b995cd));
    STADTX_SCRAMBLE64(state[3], UINT64_C(0x9999791977e30c13));
    STADTX_SCRAMBLE64(state[3], UINT64_C(0xaab8b6b05abfc6cd));

    return (uintptr_t)(void *)(stadtx_state);
}

#define STADTX_K0_U64 UINT64_C(0xb89b0f8e1655514f)
#define STADTX_K1_U64 UINT64_C(0x8c6f736011bd5127)
#define STADTX_K2_U64 UINT64_C(0x8f29bd94edce7b39)
#define STADTX_K3_U64 UINT64_C(0x9c1b8e1e9628323f)

#define STADTX_K2_U32 0x802910e3
#define STADTX_K3_U32 0x819b13af
#define STADTX_K4_U32 0x91cb27e5
#define STADTX_K5_U32 0xc1a269c1

template <bool bswap>
static inline uint64_t stadtx( const uint64_t * state, const uint8_t * key, const size_t key_len ) {
    size_t   len = key_len;
    uint64_t v0  = state[0] ^ ((key_len + 1) * STADTX_K0_U64);
    uint64_t v1  = state[1] ^ ((key_len + 2) * STADTX_K1_U64);

    if (len < 32) {
        switch (len >> 3) {
        case 3:
                v0  += GET_U64<bswap>(key, 0) * STADTX_K3_U64;
                v0   = ROTR64(v0, 17) ^ v1;
                v1   = ROTR64(v1, 53) + v0;
                key += 8;
        /* FALLTHROUGH */
        case 2:
                v0  += GET_U64<bswap>(key, 0) * STADTX_K3_U64;
                v0   = ROTR64(v0, 17) ^ v1;
                v1   = ROTR64(v1, 53) + v0;
                key += 8;
        /* FALLTHROUGH */
        case 1:
                v0  += GET_U64<bswap>(key, 0) * STADTX_K3_U64;
                v0   = ROTR64(v0, 17) ^ v1;
                v1   = ROTR64(v1, 53) + v0;
                key += 8;
        /* FALLTHROUGH */
        case 0:
        default:
                 break;
        }
        switch (len & 0x7) {
        case 7: v0 += (uint64_t)key[6] << 32;     /* FALLTHROUGH */
        case 6: v1 += (uint64_t)key[5] << 48;     /* FALLTHROUGH */
        case 5: v0 += (uint64_t)key[4] << 16;     /* FALLTHROUGH */
        case 4: v1 += (uint64_t)GET_U32<bswap>(key, 0);  break;
        case 3: v0 += (uint64_t)key[2] << 48;     /* FALLTHROUGH */
        case 2: v1 += (uint64_t)GET_U16<bswap>(key, 0);  break;
        case 1: v0 += (uint64_t)key[0];           /* FALLTHROUGH */
        case 0: v1  = ROTL64(v1, 32) ^ 0xFF;             break;
        }
        v1 ^= v0;
        v0  = ROTR64(v0, 33) + v1;
        v1  = ROTL64(v1, 17) ^ v0;
        v0  = ROTL64(v0, 43) + v1;
        v1  = ROTL64(v1, 31) - v0;
        v0  = ROTL64(v0, 13) ^ v1;
        v1 -= v0;
        v0  = ROTL64(v0, 41) + v1;
        v1  = ROTL64(v1, 37) ^ v0;
        v0  = ROTR64(v0, 39) + v1;
        v1  = ROTR64(v1, 15) + v0;
        v0  = ROTL64(v0, 15) ^ v1;
        v1  = ROTR64(v1, 5);
        return v0 ^ v1;
    }

    uint64_t v2 = state[2] ^ ((key_len + 3) * STADTX_K2_U64);
    uint64_t v3 = state[3] ^ ((key_len + 4) * STADTX_K3_U64);

    do {
        v0  += GET_U64<bswap>(key,  0) * STADTX_K2_U32; v0 = ROTL64(v0, 57) ^ v3;
        v1  += GET_U64<bswap>(key,  8) * STADTX_K3_U32; v1 = ROTL64(v1, 63) ^ v2;
        v2  += GET_U64<bswap>(key, 16) * STADTX_K4_U32; v2 = ROTR64(v2, 47) + v0;
        v3  += GET_U64<bswap>(key, 24) * STADTX_K5_U32; v3 = ROTR64(v3, 11) - v1;
        key += 32;
        len -= 32;
    } while (len >= 32);

    switch (len >> 3) {
    case 3: v0 += (GET_U64<bswap>(key, 0) * STADTX_K2_U32); key += 8; v0 = ROTL64(v0, 57) ^ v3; /* FALLTHROUGH */
    case 2: v1 += (GET_U64<bswap>(key, 0) * STADTX_K3_U32); key += 8; v1 = ROTL64(v1, 63) ^ v2; /* FALLTHROUGH */
    case 1: v2 += (GET_U64<bswap>(key, 0) * STADTX_K4_U32); key += 8; v2 = ROTR64(v2, 47) + v0; /* FALLTHROUGH */
    case 0: v3  = ROTR64(v3, 11) - v1;                                                          /* FALLTHROUGH */
    }
    v0 ^= (len + 1) * STADTX_K3_U64;
    switch (len & 0x7) {
    case 7: v1 += (uint64_t)key[6];
    /* FALLTHROUGH */
    case 6: v2 += (uint64_t)GET_U16<bswap>(key, 4);
            v3 += (uint64_t)GET_U32<bswap>(key, 0);
            break;
    case 5: v1 += (uint64_t)key[4];
    /* FALLTHROUGH */
    case 4: v2 += (uint64_t)GET_U32<bswap>(key, 0);
            break;
    case 3: v3 += (uint64_t)key[2];
    /* FALLTHROUGH */
    case 2: v1 += (uint64_t)GET_U16<bswap>(key, 0);
            break;
    case 1: v2 += (uint64_t)key[0];
    /* FALLTHROUGH */
    case 0: v3  = ROTL64(v3, 32) ^ 0xFF;
            break;
    }

    v1 -= v2;
    v0  = ROTR64(v0, 19);
    v1 -= v0;
    v1  = ROTR64(v1, 53);
    v3 ^= v1;
    v0 -= v3;
    v3  = ROTL64(v3, 43);
    v0 += v3;
    v0  = ROTR64(v0,  3);
    v3 -= v0;
    v2  = ROTR64(v2, 43) - v3;
    v2  = ROTL64(v2, 55) ^ v0;
    v1 -= v2;
    v3  = ROTR64(v3,  7) - v2;
    v2  = ROTR64(v2, 31);
    v3 += v2;
    v2 -= v1;
    v3  = ROTR64(v3, 39);
    v2 ^= v3;
    v3  = ROTR64(v3, 17) ^ v2;
    v1 += v3;
    v1  = ROTR64(v1,  9);
    v2 ^= v1;
    v2  = ROTL64(v2, 24);
    v3 ^= v2;
    v3  = ROTR64(v3, 59);
    v0  = ROTR64(v0,  1) - v1;

    return v0 ^ v1 ^ v2 ^ v3;
}

//------------------------------------------------------------

/*
 * This is two marsaglia xor-shift permutes, with a prime-multiple
 * sandwiched inside. The end result of doing this twice with different
 * primes is a completely avalanched v.
 */
#define ZAPHOD32_SCRAMBLE32(v,prime) {   \
        v ^= (v >>  9);                  \
        v ^= (v << 21);                  \
        v ^= (v >> 16);                  \
        v *= prime;                      \
        v ^= (v >> 17);                  \
        v ^= (v << 15);                  \
        v ^= (v >> 23);                  \
    }

#define ZAPHOD32_MIX(v0,v1,v2,text) {  \
        v0 = ROTL32(v0, 16) - v2;      \
        v1 = ROTR32(v1, 13) ^ v2;      \
        v2 = ROTL32(v2, 17) + v1;      \
        v0 = ROTR32(v0,  2) + v1;      \
        v1 = ROTR32(v1, 17) - v0;      \
        v2 = ROTR32(v2,  7) ^ v0;      \
    }

static thread_local uint32_t zaphod32_state[3];

static uintptr_t zaphod32_reseed( const seed_t seed ) {
    uint32_t * state = zaphod32_state;
    uint32_t   seed0 = (uint64_t)seed & 0xffffffff;
    uint32_t   seed1 = (uint64_t)seed >>        32;
    uint32_t   seed2 = 0;

    /* hex expansion of pi, skipping first two digits. pi= 3.2[43f6...]*/
    /*
     * pi value in hex from here:
     * http://turner.faculty.swau.edu/mathematics/materialslibrary/pi/pibases.html
     */
    /* Ensure that the three state vectors are nonzero regardless of the seed. */
    /*
     * The idea of these two steps is to ensure that the 0 state comes from a seed
     * utterly unlike that of the value we replace it with.
     */
    state[0] = seed0 ^ 0x43f6a888;
    state[1] = seed1 ^ 0x5a308d31;
    state[2] = seed2 ^ 0x3198a2e0;
    if (!state[0]) { state[0] = 1; }
    if (!state[1]) { state[1] = 2; }
    if (!state[2]) { state[2] = 4; }
    /*
     * these are pseudo-randomly selected primes between 2**31 and 2**32
     * (I generated a big list and then randomly chose some from the list)
     */
    ZAPHOD32_SCRAMBLE32(state[0], 0x9fade23b);
    ZAPHOD32_SCRAMBLE32(state[1], 0xaa6f908d);
    ZAPHOD32_SCRAMBLE32(state[2], 0xcdf6b72d);

    /*
     * now that we have scrambled we do some mixing to avalanche the
     * state bits to gether
     */
    ZAPHOD32_MIX(state[0], state[1], state[2], "ZAPHOD32 SEED-STATE A 1/4");
    ZAPHOD32_MIX(state[0], state[1], state[2], "ZAPHOD32 SEED-STATE A 2/4");
    ZAPHOD32_MIX(state[0], state[1], state[2], "ZAPHOD32 SEED-STATE A 3/4");
    ZAPHOD32_MIX(state[0], state[1], state[2], "ZAPHOD32 SEED-STATE A 4/4");

    /* and then scramble them again with different primes */
    ZAPHOD32_SCRAMBLE32(state[0], 0xc95d22a9);
    ZAPHOD32_SCRAMBLE32(state[1], 0x8497242b);
    ZAPHOD32_SCRAMBLE32(state[2], 0x9c5cc4e9);

    /* and a thorough final mix */
    ZAPHOD32_MIX(state[0], state[1], state[2], "ZAPHOD32 SEED-STATE B 1/5");
    ZAPHOD32_MIX(state[0], state[1], state[2], "ZAPHOD32 SEED-STATE B 2/5");
    ZAPHOD32_MIX(state[0], state[1], state[2], "ZAPHOD32 SEED-STATE B 3/5");
    ZAPHOD32_MIX(state[0], state[1], state[2], "ZAPHOD32 SEED-STATE B 4/5");
    ZAPHOD32_MIX(state[0], state[1], state[2], "ZAPHOD32 SEED-STATE B 5/5");

    return (uintptr_t)(void *)(zaphod32_state);
}

template <bool bswap>
static inline uint32_t zaphod32( const uint32_t * state, const uint8_t * key, const size_t key_len ) {
    const uint8_t * end;
    size_t          len = key_len;
    uint32_t        v0  = state[0];
    uint32_t        v1  = state[1];
    uint32_t        v2  = state[2] ^ (0xC41A7AB1 * ((uint32_t)key_len + 1));

    switch (len) {
    default: goto zaphod32_read8;
    case 12: v2 += (uint32_t)key[11] << 24; /* FALLTHROUGH */
    case 11: v2 += (uint32_t)key[10] << 16; /* FALLTHROUGH */
    case 10: v2 += (uint32_t)GET_U16<bswap>(key, 8);
             v1 -= GET_U32<bswap>(key, 4);
             v0 += GET_U32<bswap>(key, 0);
             goto zaphod32_finalize;
    case 9 : v2 += (uint32_t)key[8];          /* FALLTHROUGH */
    case  8: v1 -= GET_U32<bswap>(key, 4);
             v0 += GET_U32<bswap>(key, 0);
             goto zaphod32_finalize;
    case 7 : v2 += (uint32_t)key[6];          /* FALLTHROUGH */
    case  6: v0 += (uint32_t)GET_U16<bswap>(key, 4);
             v1 -= GET_U32<bswap>(key, 0);
             goto zaphod32_finalize;
    case 5 : v0 += (uint32_t)key[4];          /* FALLTHROUGH */
    case  4: v1 -= GET_U32<bswap>(key, 0);
             goto zaphod32_finalize;
    case 3 : v2 += (uint32_t)key[2];          /* FALLTHROUGH */
    case  2: v0 += (uint32_t)GET_U16<bswap>(key, 0); break;
    case  1: v0 += (uint32_t)key[0];                 break;
    case  0: v2 ^= 0xFF;                             break;
    }

    v0 -= v2;
    v2  = ROTL32(v2,  8) ^ v0;
    v0  = ROTR32(v0, 16) + v2;
    v2 += v0;
    v0 += v0 >> 9;
    v0 += v2;
    v2 ^= v0;
    v2 += v2 << 4;
    v0 -= v2;
    v2  = ROTR32(v2,  8) ^ v0;
    v0  = ROTL32(v0, 16) ^ v2;
    v2  = ROTL32(v2, 10) + v0;
    v0  = ROTR32(v0, 30) + v2;
    v2  = ROTR32(v2, 12);
    return v0 ^ v2;

  zaphod32_read8:
    len = key_len & 0x7;
    end = key + key_len - len;
    do {
        v1  -= GET_U32<bswap>(key, 0);
        v0  += GET_U32<bswap>(key, 4);
        ZAPHOD32_MIX(v0, v1, v2, "MIX 2-WORDS A");
        key += 8;
    } while (key < end);

    if (len >= 4) {
        v1  -= GET_U32<bswap>(key, 0);
        key += 4;
    }

    v0 += (uint32_t)(key_len) << 24;
    switch (len & 0x3) {
    case 3: v2 += (uint32_t)key[2]; /* FALLTHROUGH */
    case 2: v0 += (uint32_t)GET_U16<bswap>(key, 0);  break;
    case 1: v0 += (uint32_t)key[0];                  break;
    case 0: v2 ^= 0xFF;                              break;
    }

  zaphod32_finalize:
    v2 += v0;
    v1 -= v2;
    v1  = ROTL32(v1,  6);
    v2 ^= v1;
    v2  = ROTL32(v2, 28);
    v1 ^= v2;
    v0 += v1;
    v1  = ROTL32(v1, 24);
    v2 += v1;
    v2  = ROTL32(v2, 18) + v1;
    v0 ^= v2;
    v0  = ROTL32(v0, 20);
    v2 += v0;
    v1 ^= v2;
    v0 += v1;
    v0  = ROTL32(v0,  5);
    v2 += v0;
    v2  = ROTL32(v2, 22);
    v0 -= v1;
    v1 -= v2;
    v1  = ROTL32(v1, 17);

    return v0 ^ v1 ^ v2;
}

//------------------------------------------------------------

template <bool bswap>
static void perl_djb2( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = djb2((const uint8_t *)in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void perl_sdbm( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = sdbm((const uint8_t *)in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void perl_jenkins( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = jenkinsOAAT((const uint8_t *)in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void perl_jenkins_old( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = jenkinsOAAT_old((const uint8_t *)in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void perl_jenkins_hard( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = jenkinsOAAT_hard((const uint8_t *)in, len, (uint64_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void perl_stadtx( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t * s = (uint64_t *)(void *)(uintptr_t)seed;
    uint64_t   h;

    if (isLE()) {
        h = stadtx<false>(s, (const uint8_t *)in, len);
    } else {
        h = stadtx<true>(s, (const uint8_t *)in, len);
    }

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void perl_zaphod32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t * s = (uint32_t *)(void *)(uintptr_t)seed;
    uint32_t   h;

    if (isLE()) {
        h = zaphod32<false>(s, (const uint8_t *)in, len);
    } else {
        h = zaphod32<true>(s, (const uint8_t *)in, len);
    }

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(perlhashes,
   $.src_url    = "https://github.com/Perl/perl5/hv_func.h",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(perl_djb2,
   $.desc            = "djb2 OAAT hash (from old perl5 code)",
   $.hash_flags      =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_GPL3   |
         FLAG_IMPL_VERY_SLOW,
   $.bits            = 32,
   $.verification_LE = 0x4962CBAB,
   $.verification_BE = 0xCBC1BFB3,
   $.hashfn_native   = perl_djb2<false>,
   $.hashfn_bswap    = perl_djb2<true>
 );

REGISTER_HASH(perl_sdbm,
   $.desc            = "sdbm OAAT hash (from old perl5 code)",
   $.hash_flags      =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_GPL3   |
         FLAG_IMPL_VERY_SLOW,
   $.bits            = 32,
   $.verification_LE = 0xD973311D,
   $.verification_BE = 0xA3228EF6,
   $.hashfn_native   = perl_sdbm<false>,
   $.hashfn_bswap    = perl_sdbm<true>
 );

REGISTER_HASH(perl_jenkins,
   $.desc            = "Bob Jenkins' OAAT hash (from old perl5 code)",
   $.hash_flags      =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_GPL3   |
         FLAG_IMPL_VERY_SLOW,
   $.bits            = 32,
   $.verification_LE = 0xE3ED0E54,
   $.verification_BE = 0xA83E99BF,
   $.hashfn_native   = perl_jenkins<false>,
   $.hashfn_bswap    = perl_jenkins<true>
 );

REGISTER_HASH(perl_jenkins_old,
   $.desc       = "Bob Jenkins' OAAT hash (\"old\" version from old perl5 code)",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS   |
         FLAG_IMPL_LICENSE_GPL3   |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 32,
   $.verification_LE = 0xEE05869B,
   $.verification_BE = 0x691105C0,
   $.hashfn_native   = perl_jenkins_old<false>,
   $.hashfn_bswap    = perl_jenkins_old<true>
 );

REGISTER_HASH(perl_jenkins_hard,
   $.desc       = "Bob Jenkins' OAAT hash (\"hard\" version from old perl5 code)",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_LICENSE_GPL3   |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 32,
   $.verification_LE = 0x1C216B25,
   $.verification_BE = 0x3B326068,
   $.hashfn_native   = perl_jenkins_hard<false>,
   $.hashfn_bswap    = perl_jenkins_hard<true>
 );

REGISTER_HASH(perl_stadtx,
   $.desc       = "Stadtx hash from perl5",
   $.hash_flags =
        FLAG_HASH_XL_SEED        ,
   $.impl_flags =
        FLAG_IMPL_MULTIPLY_64_64 |
        FLAG_IMPL_ROTATE         |
        FLAG_IMPL_LICENSE_GPL3   ,
   $.bits = 64,
   $.verification_LE = 0xD983938D,
   $.verification_BE = 0x876FCA1E,
   $.hashfn_native   = perl_stadtx<false>,
   $.hashfn_bswap    = perl_stadtx<true>,
   $.seedfn          = stadtx_reseed
 );

REGISTER_HASH(perl_zaphod32,
   $.desc       = "Zaphod32 hash from perl5",
   $.hash_flags =
        FLAG_HASH_XL_SEED        ,
   $.impl_flags =
        FLAG_IMPL_MULTIPLY       |
        FLAG_IMPL_ROTATE         |
        FLAG_IMPL_LICENSE_GPL3   ,
   $.bits = 32,
   $.verification_LE = 0x2DC19200,
   $.verification_BE = 0xF329D3E4,
   $.hashfn_native   = perl_zaphod32<false>,
   $.hashfn_bswap    = perl_zaphod32<true>,
   $.seedfn          = zaphod32_reseed
 );
