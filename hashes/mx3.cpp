/*
 * mx3, v1, v2, and v3
 *
 * original author: Jon Maiga, 2020-08-03, jonkagstrom.com, @jonkagstrom
 * license: CC0 license
 */
#include "Platform.h"
#include "Hashlib.h"

//------------------------------------------------------------
static const uint64_t C = UINT64_C(0xbea225f9eb34556d);

// Unchanged from v2 -> v3
template <unsigned ver>
static inline uint64_t mix( uint64_t x ) {
    constexpr uint32_t R0 = (ver == 1) ?  0 : 32;
    constexpr uint32_t R1 = (ver == 1) ? 33 : 29;
    constexpr uint32_t R2 = (ver == 1) ? 29 : 32;
    constexpr uint32_t R3 = (ver == 1) ? 39 : 29;

    if (ver > 1) {
        x ^= x >> R0;
    }
    x *= C;
    x ^= x >> R1;
    x *= C;
    x ^= x >> R2;
    x *= C;
    x ^= x >> R3;
    return x;
}

template <unsigned ver>
static inline uint64_t mix_stream( uint64_t h, uint64_t x ) {
    constexpr uint32_t R1 = (ver == 1) ? 33 : (ver == 2) ? 43 : 39;

    x *= C;
    if (ver == 3) {
        x ^= (x >> R1);
    } else {
        x ^= (x >> R1) ^ (x >> 57);
    }
    x *= C;
    h += x;
    h *= C;
    return h;
}

// v3 only
static inline uint64_t mix_stream_v3( uint64_t h, uint64_t a, uint64_t b, uint64_t c, uint64_t d ) {
    a *= C;
    b *= C;
    c *= C;
    d *= C;
    a ^= a >> 39;
    b ^= b >> 39;
    c ^= c >> 39;
    d ^= d >> 39;
    h += a * C;
    h *= C;
    h += b * C;
    h *= C;
    h += c * C;
    h *= C;
    h += d * C;
    h *= C;
    return h;
}

template <unsigned ver, bool bswap>
static inline uint64_t mx3( const uint8_t * buf, size_t len, uint64_t seed ) {
    const uint8_t * const tail = buf + (len & ~7);

    uint64_t h = (ver < 3) ? (seed ^ len) : mix_stream<ver>(seed, len + 1);

    if (ver < 3) {
        while (len >= 32) {
            len -= 32;
            h    = mix_stream<ver>(h, GET_U64<bswap>(buf,  0));
            h    = mix_stream<ver>(h, GET_U64<bswap>(buf,  8));
            h    = mix_stream<ver>(h, GET_U64<bswap>(buf, 16));
            h    = mix_stream<ver>(h, GET_U64<bswap>(buf, 24));
            buf += 32;
        }
    } else {
        while (len >= 64) {
            len -= 64;
            h = mix_stream_v3(h, GET_U64<bswap>(buf,  0), GET_U64<bswap>(buf,  8),
                                 GET_U64<bswap>(buf, 16), GET_U64<bswap>(buf, 24));
            h = mix_stream_v3(h, GET_U64<bswap>(buf, 32), GET_U64<bswap>(buf, 40),
                                 GET_U64<bswap>(buf, 48), GET_U64<bswap>(buf, 56));
            buf += 64;
        }
    }

    while (len >= 8) {
        len -= 8;
        h    = mix_stream<ver>(h, GET_U64<bswap>(buf, 0));
        buf += 8;
    }

    if (ver < 3) {
        uint64_t v = 0;
        switch (len & 7) {
        case 7: v |= static_cast<uint64_t>(tail[6]) << 48; // FALLTHROUGH
        case 6: v |= static_cast<uint64_t>(tail[5]) << 40; // FALLTHROUGH
        case 5: v |= static_cast<uint64_t>(tail[4]) << 32; // FALLTHROUGH
        case 4: v |= static_cast<uint64_t>(tail[3]) << 24; // FALLTHROUGH
        case 3: v |= static_cast<uint64_t>(tail[2]) << 16; // FALLTHROUGH
        case 2: v |= static_cast<uint64_t>(tail[1]) <<  8; // FALLTHROUGH
        case 1: h  = mix_stream<ver>(h, v | tail[0]);      // FALLTHROUGH
        default:;
        }
    } else {
        const uint8_t * const tail8 = buf;
        switch (len) {
        case 0: return mix<ver>(h);
        case 1: return mix<ver>(mix_stream<ver>(h, tail8[0]));
        case 2: return mix<ver>(mix_stream<ver>(h, GET_U16<bswap>(tail8, 0)));
        case 3: return mix<ver>(mix_stream<ver>(h, GET_U16<bswap>(tail8, 0) | static_cast<uint64_t>(tail8[2]) << 16));
        case 4: return mix<ver>(mix_stream<ver>(h, GET_U32<bswap>(tail8, 0)));
        case 5: return mix<ver>(mix_stream<ver>(h, GET_U32<bswap>(tail8, 0) | static_cast<uint64_t>(tail8[4]) << 32));
        case 6: return mix<ver>(mix_stream<ver>(h, GET_U32<bswap>(tail8, 0) |
                    static_cast<uint64_t>(GET_U16<bswap>(tail8, 4)) << 32));
        case 7: return mix<ver>(mix_stream<ver>(h, GET_U32<bswap>(tail8, 0) |
                    static_cast<uint64_t>(GET_U16<bswap>(tail8, 4)) << 32   | static_cast<uint64_t>(tail8[6]) << 48));
        default:;
        }
    }

    return mix<ver>(h);
}

//------------------------------------------------------------
template <bool bswap>
static void mx3_v1( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = mx3<1, bswap>((const uint8_t *)in, len, (uint64_t)seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void mx3_v2( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = mx3<2, bswap>((const uint8_t *)in, len, (uint64_t)seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void mx3_v3( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = mx3<3, bswap>((const uint8_t *)in, len, (uint64_t)seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(mx3,
   $.src_url    = "https://github.com/jonmaiga/mx3/",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(mx3__v3,
   $.desc       = "mx3 (revision 3)",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64         |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 64,
   $.verification_LE = 0x7B287B65,
   $.verification_BE = 0x1EA42BEF,
   $.hashfn_native   = mx3_v3<false>,
   $.hashfn_bswap    = mx3_v3<true>
 );

REGISTER_HASH(mx3__v2,
   $.desc       = "mx3 (revision 2)",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64         |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 64,
   $.verification_LE = 0x527399AD,
   $.verification_BE = 0x5B6AAE8F,
   $.hashfn_native   = mx3_v2<false>,
   $.hashfn_bswap    = mx3_v2<true>,
   $.badseeddesc     = "All seeds give zero hashes on keys of all zero bytes if length==seed"
 );

REGISTER_HASH(mx3__v1,
   $.desc       = "mx3 (revision 1)",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64         |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 64,
   $.verification_LE = 0x4DB51E5B,
   $.verification_BE = 0x93E930B0,
   $.hashfn_native   = mx3_v1<false>,
   $.hashfn_bswap    = mx3_v1<true>,
   $.badseeddesc     = "All seeds give zero hashes on keys of all zero bytes if length==seed"
 );
