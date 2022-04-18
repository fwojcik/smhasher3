/*
 * mx3, v1 and v2
 *
 * original author: Jon Maiga, 2020-08-03, jonkagstrom.com, @jonkagstrom
 * license: CC0 license
 */
#include "Platform.h"
#include "Types.h"
#include "Hashlib.h"

//------------------------------------------------------------
static const uint64_t C = UINT64_C(0xbea225f9eb34556d);

template < bool v1 >
static inline uint64_t mix(uint64_t x) {
    constexpr uint32_t R0 = v1 ?  0 : 32;
    constexpr uint32_t R1 = v1 ? 33 : 29;
    constexpr uint32_t R2 = v1 ? 29 : 32;
    constexpr uint32_t R3 = v1 ? 39 : 29;

    if (!v1) {
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

template < bool v1 >
static inline uint64_t mix_stream(uint64_t h, uint64_t x) {
    constexpr uint32_t R1 = v1 ? 33 : 43;
    x *= C;
    x ^= (x >> 57) ^ (x >> R1);
    x *= C;
    h += x;
    h *= C;
    return h;
}

template < bool v1, bool bswap >
static inline uint64_t mx3(const uint8_t * buf, size_t len, uint64_t seed) {
    const uint8_t * const tail = buf + (len & ~7);

    uint64_t h = seed ^ len;
    while (len >= 32) {
        len -= 32;
        h = mix_stream<v1>(h, GET_U64<bswap>(buf,  0));
        h = mix_stream<v1>(h, GET_U64<bswap>(buf,  8));
        h = mix_stream<v1>(h, GET_U64<bswap>(buf, 16));
        h = mix_stream<v1>(h, GET_U64<bswap>(buf, 24));
        buf += 32;
    }

    while (len >= 8) {
        len -= 8;
        h = mix_stream<v1>(h, GET_U64<bswap>(buf,  0));
        buf += 8;
    }

    uint64_t v = 0;
    switch (len & 7) {
        case 7: v |= static_cast<uint64_t>(tail[6]) << 48;
        case 6: v |= static_cast<uint64_t>(tail[5]) << 40;
        case 5: v |= static_cast<uint64_t>(tail[4]) << 32;
        case 4: v |= static_cast<uint64_t>(tail[3]) << 24;
        case 3: v |= static_cast<uint64_t>(tail[2]) << 16;
        case 2: v |= static_cast<uint64_t>(tail[1]) << 8;
        case 1: h = mix_stream<v1>(h, v | tail[0]);
        default: ;
    }
    return mix<v1>(h);
}

//------------------------------------------------------------
template < bool bswap >
void mx3_v1(const void * in, const size_t len, const seed_t seed, void * out) {
    uint64_t h = mx3<true, bswap>((const uint8_t *)in, len, (uint64_t) seed);
    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

template < bool bswap >
void mx3_v2(const void * in, const size_t len, const seed_t seed, void * out) {
    uint64_t h = mx3<false, bswap>((const uint8_t *)in, len, (uint64_t) seed);
    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(mx3,
  $.src_url = "https://github.com/jonmaiga/mx3/",
  $.src_status = HashFamilyInfo::SRC_ACTIVE
);

REGISTER_HASH(mx3,
  $.desc = "mx3 (revision 2)",
  $.hash_flags =
        0,
  $.impl_flags =
        FLAG_IMPL_64BIT                  |
        FLAG_IMPL_MULTIPLY_64_64         |
        FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
  $.bits = 64,
  $.verification_LE = 0x527399AD,
  $.verification_BE = 0x5B6AAE8F,
  $.hashfn_native = mx3_v2<false>,
  $.hashfn_bswap = mx3_v2<true>
);

REGISTER_HASH(mx3_old,
  $.desc = "mx3 (revision 1)",
  $.hash_flags =
        0,
  $.impl_flags =
        FLAG_IMPL_64BIT                  |
        FLAG_IMPL_MULTIPLY_64_64         |
        FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
  $.bits = 64,
  $.verification_LE = 0x4DB51E5B,
  $.verification_BE = 0x93E930B0,
  $.hashfn_native = mx3_v1<false>,
  $.hashfn_bswap = mx3_v1<true>
);
