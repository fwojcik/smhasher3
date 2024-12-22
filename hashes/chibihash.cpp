/*
 * ChibiHash64-v2
 * Copyright (C) 2024 NRK
 *
 * This is free and unencumbered software released into the public
 * domain under The Unlicense (http://unlicense.org/).
 */
#include "Platform.h"
#include "Hashlib.h"

#define chibihash64__load64le(p)   GET_U64<bswap>(p, 0)
#define chibihash64__load32le(p)   ((uint64_t)GET_U32<bswap>(p, 0))
#define chibihash64__rotl(x, n)    ROTL64(x, n)

template <bool bswap>
static void ChibiHash64_V2( const void * in, const size_t len, const seed_t seedIn, void * out ) {
    uint64_t        seed = (uint64_t)seedIn;
    const uint8_t * p    = (const uint8_t *)in;
    std::ptrdiff_t  l    = len;

    const uint64_t K     = UINT64_C(0x2B7E151628AED2A7); // digits of e
    uint64_t       seed2 = chibihash64__rotl(seed - K, 15) + chibihash64__rotl(seed - K, 47);
    uint64_t       h[4]  = { seed, seed + K, seed2, seed2 + (K * K ^ K) };

    // depending on your system unrolling might (or might not) make things
    // a tad bit faster on large strings. on my system, it actually makes
    // things slower.
    // generally speaking, the cost of bigger code size is usually not
    // worth the trade-off since larger code-size will hinder inlinability
    // but depending on your needs, you may want to uncomment the pragma
    // below to unroll the loop.
    //
    //#pragma GCC unroll 2
    for (; l >= 32; l -= 32) {
        for (int i = 0; i < 4; ++i, p += 8) {
            uint64_t stripe = chibihash64__load64le(p);
            h[i] = (stripe + h[i]) * K;
            h[(i + 1) & 3] += chibihash64__rotl(stripe, 27);
        }
    }

    for (; l >= 8; l -= 8, p += 8) {
        h[0] ^= chibihash64__load32le(p + 0); h[0] *= K;
        h[1] ^= chibihash64__load32le(p + 4); h[1] *= K;
    }

    if (l >= 4) {
        h[2] ^= chibihash64__load32le(p        );
        h[3] ^= chibihash64__load32le(p + l - 4);
    } else if (l > 0) {
        h[2] ^= p[0];
        h[3] ^= p[l / 2] | ((uint64_t)p[l - 1] << 8);
    }

    h[0] += chibihash64__rotl(h[2] * K, 31) ^ (h[2] >> 31);
    h[1] += chibihash64__rotl(h[3] * K, 31) ^ (h[3] >> 31);
    h[0] *= K; h[0] ^= h[0] >> 31;
    h[1] += h[0];

    uint64_t x = (uint64_t)len * K;
    x ^= chibihash64__rotl(x, 29);
    x += seed;
    x ^= h[1];

    x ^= chibihash64__rotl(x, 15) ^ chibihash64__rotl(x, 42);
    x *= K;
    x ^= chibihash64__rotl(x, 13) ^ chibihash64__rotl(x, 31);

    PUT_U64<bswap>(x, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(ChibiHash,
   $.src_url    = "https://github.com/N-R-K/ChibiHash",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(ChibiHash2,
   $.desc            = "ChibiHash64, v2",
   $.hash_flags      =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_CANONICAL_LE          |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN |
         FLAG_IMPL_MULTIPLY_64_64        |
         FLAG_IMPL_ROTATE,
   $.bits            = 64,
   $.verification_LE = 0x65ED889A,
   $.verification_BE = 0x37C9D593,
   $.hashfn_native   = ChibiHash64_V2<false>,
   $.hashfn_bswap    = ChibiHash64_V2<true>
 );
