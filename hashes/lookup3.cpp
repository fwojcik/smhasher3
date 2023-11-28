/*
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain
 *
 * You can use this free for any purpose.  It's in the public domain.
 * It has no warranty.
 */
#include "Platform.h"
#include "Hashlib.h"

//------------------------------------------------------------
#define mix(a,b,c)                     \
{                                      \
  a -= c;  a ^= ROTL32(c, 4);  c += b; \
  b -= a;  b ^= ROTL32(a, 6);  a += c; \
  c -= b;  c ^= ROTL32(b, 8);  b += a; \
  a -= c;  a ^= ROTL32(c,16);  c += b; \
  b -= a;  b ^= ROTL32(a,19);  a += c; \
  c -= b;  c ^= ROTL32(b, 4);  b += a; \
}

#define finalmix(a,b,c)      \
{                            \
  c ^= b; c -= ROTL32(b,14); \
  a ^= c; a -= ROTL32(c,11); \
  b ^= a; b -= ROTL32(a,25); \
  c ^= b; c -= ROTL32(b,16); \
  a ^= c; a -= ROTL32(c,4);  \
  b ^= a; b -= ROTL32(a,14); \
  c ^= b; c -= ROTL32(b,24); \
}

// If seed+len==0x21524111, then hash of all zeros is zero. Fix this by
// setting a high bit in the seed.
seed_t lookup3_seedfix( const HashInfo * hinfo, const seed_t seed ) {
    uint64_t seed64 = (uint64_t)seed;
    unused(hinfo);

    if (seed64 >= 0xffffffff) {
        seed64 |= (seed64 | 1) << 32;
    }
    return (seed_t)seed64;
}

template <bool hash64, bool bswap>
static void hashlittle( const uint8_t * key, size_t length, uint64_t seed64, uint8_t * out ) {
    uint32_t a, b, c; /* internal state */

    /* Set up the internal state */
    a  = b = c = 0xdeadbeef + ((uint32_t)length) + ((uint32_t)seed64);
    c += (uint32_t)(seed64 >> 32);

    /*------ all but last block: aligned reads and affect 32 bits of (a,b,c) */
    while (length > 12) {
        a      += GET_U32<bswap>(key, 0);
        b      += GET_U32<bswap>(key, 4);
        c      += GET_U32<bswap>(key, 8);
        mix(a, b, c);
        length -= 12;
        key    += 12;
    }

    /*----------------------------- handle the last (probably partial) block */
    switch (length) {
    case 12: c += GET_U32<bswap>(key, 8);
             b += GET_U32<bswap>(key, 4);
             a += GET_U32<bswap>(key, 0); break;
    case 11: c += ((uint32_t)key[10]) << 16; /* fall through */
    case 10: c += ((uint32_t)key[ 9]) <<  8; /* fall through */
    case  9: c += key[8];                    /* fall through */
    case  8: b += GET_U32<bswap>(key, 4);
             a += GET_U32<bswap>(key, 0); break;
    case  7: b += ((uint32_t)key[ 6]) << 16; /* fall through */
    case  6: b += ((uint32_t)key[ 5]) <<  8; /* fall through */
    case  5: b += key[4];                    /* fall through */
    case  4: a += GET_U32<bswap>(key, 0); break;
    case  3: a += ((uint32_t)key[ 2]) << 16; /* fall through */
    case  2: a += ((uint32_t)key[ 1]) <<  8; /* fall through */
    case  1: a += key[0];                  break;
    case  0: goto out;                       /* zero length strings require no more mixing */
    }

    finalmix(a, b, c);

  out:
    PUT_U32<bswap>(c, out, 0);
    if (hash64) { PUT_U32<bswap>(b, out, 4); }
}

//------------------------------------------------------------
template <bool hash64, bool bswap>
static void lookup3( const void * in, const size_t len, const seed_t seed, void * out ) {
    hashlittle<hash64, bswap>((const uint8_t *)in, len, (uint64_t)seed, (uint8_t *)out);
}

//------------------------------------------------------------
REGISTER_FAMILY(lookup3,
   $.src_url    = "http://www.burtleburtle.net/bob/c/lookup3.c",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(lookup3__32,
   $.desc       = "Bob Jenkins' lookup3 (32-bit output)",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN  |
         FLAG_IMPL_SLOW,
   $.bits = 32,
   $.verification_LE = 0x3D83917A,
   $.verification_BE = 0x18E6AA76,
   $.hashfn_native   = lookup3<false, false>,
   $.hashfn_bswap    = lookup3<false, true>
 );

REGISTER_HASH(lookup3,
   $.desc       = "Bob Jenkins' lookup3 (64-bit output)",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN  |
         FLAG_IMPL_SLOW,
   $.bits = 64,
   $.verification_LE = 0x6AE8AB7C,
   $.verification_BE = 0x074EBE4E,
   $.hashfn_native   = lookup3<true, false>,
   $.hashfn_bswap    = lookup3<true, true>,
   $.seedfixfn       = lookup3_seedfix,
   $.badseeddesc     = "If seed+len==0x21524111, then hash of all zeros is zero."
 );
