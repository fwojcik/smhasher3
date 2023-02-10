/*
 * Pearson-inspired block-based hashing
 * This is free and unencumbered software released into the public
 * domain under The Unlicense (http://unlicense.org/).
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a
 * compiled binary, for any purpose, commercial or non-commercial, and
 * by any means.
 *
 * In jurisdictions that recognize copyright laws, the author or
 * authors of this software dedicate any and all copyright interest in
 * the software to the public domain. We make this dedication for the
 * benefit of the public at large and to the detriment of our heirs
 * and successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to
 * this software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */
#include "Platform.h"
#include "Hashlib.h"

// David Stafford's Mix13 from http://zimbry.blogspot.com/2011/09/better-bit-mixing-improving-on.html
// the author clarified via eMail that this of his work is released to the public domain
#define permute64(in)                   \
    in ^= (in >> 30);                   \
    in *= UINT64_C(0xbf58476d1ce4e5b9); \
    in ^= (in >> 27);                   \
    in *= UINT64_C(0x94d049bb133111eb); \
    in ^= (in >> 31)

#define dec1(in) \
    in--

#define dec2(in) \
    dec1(in);    \
    dec1(in)

#define dec3(in) \
    dec2(in);    \
    dec1(in)

#define dec4(in) \
    dec3(in);    \
    dec1(in)

#define hash_round(hash, in, part) \
    hash##part ^= in;              \
    dec##part(hash##part);         \
    permute64(hash##part)

template <bool bswap>
static void blockpearson_hash_256( const void * in, const size_t org_len, const seed_t seed, void * out ) {
    const uint8_t * current = (const uint8_t *)in;

    uint64_t len   = (uint64_t)org_len;
    uint64_t hash1 = (uint64_t)seed;

    permute64(hash1);

    uint64_t hash2 = hash1;
    uint64_t hash3 = hash1;
    uint64_t hash4 = hash1;

    while (len > 7) {
        hash_round(hash, GET_U64<bswap>(current, 0), 1);
        hash_round(hash, GET_U64<bswap>(current, 0), 2);
        hash_round(hash, GET_U64<bswap>(current, 0), 3);
        hash_round(hash, GET_U64<bswap>(current, 0), 4);

        current += 8;
        len     -= 8;
    }

    // handle the rest
    hash1 = ~hash1;
    hash2 = ~hash2;
    hash3 = ~hash3;
    hash4 = ~hash4;

    while (len) {
        // byte-wise, no endianess
        hash_round(hash, *current, 1);
        hash_round(hash, *current, 2);
        hash_round(hash, *current, 3);
        hash_round(hash, *current, 4);

        current++;
        len--;
    }

    // digest length
    hash1 = ~hash1;
    hash2 = ~hash2;
    hash3 = ~hash3;
    hash4 = ~hash4;

    hash_round(hash, (uint64_t)org_len, 1);
    hash_round(hash, (uint64_t)org_len, 2);
    hash_round(hash, (uint64_t)org_len, 3);
    hash_round(hash, (uint64_t)org_len, 4);

    PUT_U64<!bswap>(hash4, (uint8_t *)out,  0);
    PUT_U64<!bswap>(hash3, (uint8_t *)out,  8);
    PUT_U64<!bswap>(hash2, (uint8_t *)out, 16);
    PUT_U64<!bswap>(hash1, (uint8_t *)out, 24);
}

template <bool bswap>
static void blockpearson_hash_128( const void * in, const size_t org_len, const seed_t seed, void * out ) {
    const uint8_t * current = (const uint8_t *)in;

    uint64_t len   = (uint64_t)org_len;
    uint64_t hash1 = (uint64_t)seed;

    permute64(hash1);

    uint64_t hash2 = hash1;

    while (len > 7) {
        hash_round(hash, GET_U64<bswap>(current, 0), 1);
        hash_round(hash, GET_U64<bswap>(current, 0), 2);

        current += 8;
        len     -= 8;
    }

    // handle the rest
    hash1 = ~hash1;
    hash2 = ~hash2;

    while (len) {
        // byte-wise, no endianess
        hash_round(hash, *current, 1);
        hash_round(hash, *current, 2);

        current++;
        len--;
    }

    // digest length
    hash1 = ~hash1;
    hash2 = ~hash2;

    hash_round(hash, (uint64_t)org_len, 1);
    hash_round(hash, (uint64_t)org_len, 2);

    PUT_U64<!bswap>(hash2, (uint8_t *)out, 0);
    PUT_U64<!bswap>(hash1, (uint8_t *)out, 8);
}

template <bool bswap>
static void blockpearson_hash_64( const void * in, const size_t org_len, const seed_t seed, void * out ) {
    const uint8_t * current = (const uint8_t *)in;

    uint64_t len   = (uint64_t)org_len;
    uint64_t hash1 = (uint64_t)seed;

    permute64(hash1);

    while (len > 7) {
        hash_round(hash, GET_U64<bswap>(current, 0), 1);

        current += 8;
        len     -= 8;
    }

    // handle the rest
    hash1 = ~hash1;

    while (len) {
        // byte-wise, no endianess
        hash_round(hash, *current, 1);

        current++;
        len--;
    }

    // digest length
    hash1 = ~hash1;

    hash_round(hash, (uint64_t)org_len, 1);

    // Previous SMHasher implementation didn't byteswap this properly
    PUT_U64<!bswap>(hash1, (uint8_t *)out, 0);
}

REGISTER_FAMILY(pearsonblock,
   $.src_url    = "https://github.com/Logan007/pearsonB",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(PearsonBlock_64,
   $.desc       = "Pearson-inspired block hash, 64-bit state",
   $.hash_flags =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_MULTIPLY_64_64         |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN  |
         FLAG_IMPL_SLOW,
   $.bits = 64,
   $.verification_LE = 0x14C3D184,
   $.verification_BE = 0x162C2D8A,
   $.hashfn_native   = blockpearson_hash_64<false>,
   $.hashfn_bswap    = blockpearson_hash_64<true>
 );

REGISTER_HASH(PearsonBlock_128,
   $.desc       = "Pearson-inspired block hash, 128-bit state",
   $.hash_flags =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_MULTIPLY_64_64         |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN  |
         FLAG_IMPL_SLOW,
   $.bits = 128,
   $.verification_LE = 0x6BEFE6EA,
   $.verification_BE = 0x00D61079,
   $.hashfn_native   = blockpearson_hash_128<false>,
   $.hashfn_bswap    = blockpearson_hash_128<true>
 );

REGISTER_HASH(PearsonBlock_256,
   $.desc       = "Pearson-inspired block hash, 256-bit state",
   $.hash_flags =
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_MULTIPLY_64_64         |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN  |
         FLAG_IMPL_SLOW,
   $.bits = 256,
   $.verification_LE = 0x999B3C19,
   $.verification_BE = 0x92D43B4F,
   $.hashfn_native   = blockpearson_hash_256<false>,
   $.hashfn_bswap    = blockpearson_hash_256<true>
 );
