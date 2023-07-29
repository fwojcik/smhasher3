/*
 * Chaskey-12
 *
 * Written in 2015 by Nicky Mouha, based on Chaskey and SipHash
 *
 * To the extent possible under law, the author has dedicated all
 * copyright and related and neighboring rights to this software to
 * the public domain worldwide. This software is distributed without
 * any warranty.
 *
 * This is released under CC0 Public Domain Dedication. See
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
#include "Platform.h"
#include "Hashlib.h"

//------------------------------------------------------------
#define ROUND(v)                                             \
    do {                                                     \
        v[0] += v[1]; v[1] = ROTL32(v[1],  5);               \
        v[1] ^= v[0]; v[0] = ROTL32(v[0], 16);               \
        v[2] += v[3]; v[3] = ROTL32(v[3],  8); v[3] ^= v[2]; \
        v[0] += v[3]; v[3] = ROTL32(v[3], 13); v[3] ^= v[0]; \
        v[2] += v[1]; v[1] = ROTL32(v[1],  7);               \
        v[1] ^= v[2]; v[2] = ROTL32(v[2], 16);               \
    } while(0)

typedef struct {
    uint32_t  k[4];
    uint32_t  k1[4];
    uint32_t  k2[4];
} keys_t;

template <uint32_t rounds, uint32_t tagwords, bool bswap>
static void chaskey_impl( uint8_t * tag, const uint8_t * m, const size_t mlen, const keys_t *k ) {
    const uint8_t * end = m + (((mlen - 1) >> 4) << 4); /* pointer to last message block */

    uint32_t v[4] = { k->k[0], k->k[1], k->k[2], k->k[3] };

    if (mlen != 0) {
        for (; m != end; m += 16) {
            v[0] ^= GET_U32<bswap>(m,  0);
            v[1] ^= GET_U32<bswap>(m,  4);
            v[2] ^= GET_U32<bswap>(m,  8);
            v[3] ^= GET_U32<bswap>(m, 12);
            for (uint32_t i = 0; i < rounds; i++) {
                ROUND(v);
            }
        }
    }

    const size_t     remain = mlen & 0xF;
    const uint8_t *  lastblock;
    const uint32_t * lastkey;
    uint8_t          lb[16];

    if ((mlen != 0) && (remain == 0)) {
        lastkey   = k->k1;
        lastblock = m;
    } else {
        lastkey = k->k2;
        memset(lb, 0, sizeof(lb));
        memcpy(lb, m, remain);
        lb[remain] = 0x01; /* padding bit */
        lastblock  = lb;
    }

    v[0] ^= GET_U32<bswap>(lastblock,  0);
    v[1] ^= GET_U32<bswap>(lastblock,  4);
    v[2] ^= GET_U32<bswap>(lastblock,  8);
    v[3] ^= GET_U32<bswap>(lastblock, 12);

    v[0] ^= lastkey[0];
    v[1] ^= lastkey[1];
    v[2] ^= lastkey[2];
    v[3] ^= lastkey[3];

    for (uint32_t i = 0; i < rounds; i++) {
        ROUND(v);
    }

    v[0] ^= lastkey[0];
    v[1] ^= lastkey[1];
    v[2] ^= lastkey[2];
    v[3] ^= lastkey[3];

    for (uint32_t i = 0; i < tagwords; i++) {
        PUT_U32<bswap>(v[i], tag, 4 * i);
    }
}

//------------------------------------------------------------
static const volatile uint32_t C[2] = { 0x00, 0x87 };

#define TIMESTWO(out,in)                        \
    do {                                        \
        out[0] = (in[0] << 1) ^ C[in[3] >> 31]; \
        out[1] = (in[1] << 1) | (in[0] >> 31);  \
        out[2] = (in[2] << 1) | (in[1] >> 31);  \
        out[3] = (in[3] << 1) | (in[2] >> 31);  \
    } while(0)

static void make_subkeys( keys_t * keys ) {
    TIMESTWO(keys->k1, keys->k );
    TIMESTWO(keys->k2, keys->k1);
}

//------------------------------------------------------------

// Chaskey uses a 16-byte key, plus two more 16-byte subkeys that are
// most easily precomputed.  To make this fit SMhasher's 64-bit seed
// model, we do two things:
// - Have a homegrown function to expand a 64-bit seed to a 128-bit
//   chaskey key.
// - Have a "seed function" which expands the seed into a thread-local
//   structure and returns a pointer to that structure cast to a 64-bit
//   integer.  The actual hash function then dereferences the "seed"
//   it receives to find the key.
static thread_local keys_t chaskeys;

// Homegrown seeding for SMHasher3
//
// These magic numbers were obtained by taking the test vector key
// from the reference KAT vectors below, which is:
//    { 0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc }
// and putting through the inverse of ROUND() 6 times. This means a
// seed of 0 will end up with chaskeys.k[] set to that test vector key.
//
// The choice of 6 rounds was semi-arbitrarily made as half of the
// ISO-standard 12-round PERMUTE(), since the seed space is half of
// the state space. ROUND() also has full diffusion after 3 rounds, so
// this is two full diffusions. Finally, a 6-round permutation is the
// smallest number where chaskey passes this SMHasher3 test suite.
static uintptr_t seed_subkeys( uint64_t seed ) {
    uint32_t seedlo = (uint32_t)(seed      );
    uint32_t seedhi = (uint32_t)(seed >> 32);

    chaskeys.k[0] = seedlo ^ 0xe5d2aff1;
    chaskeys.k[1] = seedhi ^ 0x5c0e8048;
    chaskeys.k[2] = seedlo ^ 0xc35ad9d8;
    chaskeys.k[3] = seedhi ^ 0xfbdf7e14;

    ROUND(chaskeys.k);
    ROUND(chaskeys.k);
    ROUND(chaskeys.k);
    ROUND(chaskeys.k);
    ROUND(chaskeys.k);
    ROUND(chaskeys.k);

    make_subkeys(&chaskeys);
    return (uintptr_t)&chaskeys;
}

template <uint32_t rounds, uint32_t tagwords, bool bswap>
static void chaskey( const void * in, const size_t len, const seed_t seed, void * out ) {
    const keys_t * keys = (const keys_t *)(uintptr_t)seed;

    chaskey_impl<rounds, tagwords, bswap>((uint8_t *)out, (const uint8_t *)in, len, keys);
}

//------------------------------------------------------------
// Test vectors from chaskey-12 reference implementation
static const uint8_t vectors[64][8] = {
    { 0xdd, 0x3e, 0x18, 0x49, 0xd6, 0x82, 0x45, 0x55 },
    { 0xed, 0x1d, 0xa8, 0x9e, 0xc9, 0x31, 0x79, 0xca },
    { 0x98, 0xfe, 0x20, 0xa3, 0x43, 0xcd, 0x66, 0x6f },
    { 0xf6, 0xf4, 0x18, 0xac, 0xdd, 0x7d, 0x9f, 0xa1 },
    { 0x4c, 0xf0, 0x49, 0x60, 0x09, 0x99, 0x49, 0xf3 },
    { 0x75, 0xc8, 0x32, 0x52, 0x65, 0x3d, 0x3b, 0x57 },
    { 0x96, 0x4b, 0x04, 0x61, 0xfb, 0xe9, 0x22, 0x73 },
    { 0x14, 0x1f, 0xa0, 0x8b, 0xbf, 0x39, 0x96, 0x36 },
    { 0x41, 0x2d, 0x98, 0xed, 0x93, 0x6d, 0x4a, 0xb2 },
    { 0xfb, 0x0d, 0x98, 0xbc, 0x70, 0xe3, 0x05, 0xf9 },
    { 0x36, 0xf8, 0x8e, 0x1f, 0xda, 0x86, 0xc8, 0xab },
    { 0x4d, 0x1a, 0x18, 0x15, 0x86, 0x8a, 0x5a, 0xa8 },
    { 0x7a, 0x79, 0x12, 0xc1, 0x99, 0x9e, 0xae, 0x81 },
    { 0x9c, 0xa1, 0x11, 0x37, 0xb4, 0xa3, 0x46, 0x01 },
    { 0x79, 0x05, 0x14, 0x2f, 0x3b, 0xe7, 0x7e, 0x67 },
    { 0x6a, 0x3e, 0xe3, 0xd3, 0x5c, 0x04, 0x33, 0x97 },
    { 0xd1, 0x39, 0x70, 0xd7, 0xbe, 0x9b, 0x23, 0x50 },
    { 0x32, 0xac, 0xd9, 0x14, 0xbf, 0xda, 0x3b, 0xc8 },
    { 0x8a, 0x58, 0xd8, 0x16, 0xcb, 0x7a, 0x14, 0x83 },
    { 0x03, 0xf4, 0xd6, 0x66, 0x38, 0xef, 0xad, 0x8d },
    { 0xf9, 0x93, 0x22, 0x37, 0xff, 0x05, 0xe8, 0x31 },
    { 0xf5, 0xfe, 0xdb, 0x13, 0x48, 0x62, 0xb4, 0x71 },
    { 0x8b, 0xb5, 0x54, 0x86, 0xf3, 0x8d, 0x57, 0xea },
    { 0x8a, 0x3a, 0xcb, 0x94, 0xb5, 0xad, 0x59, 0x1c },
    { 0x7c, 0xe3, 0x70, 0x87, 0x23, 0xf7, 0x49, 0x5f },
    { 0xf4, 0x2f, 0x3d, 0x2f, 0x40, 0x57, 0x10, 0xc2 },
    { 0xb3, 0x93, 0x3a, 0x16, 0x7e, 0x56, 0x36, 0xac },
    { 0x89, 0x9a, 0x79, 0x45, 0x42, 0x3a, 0x5e, 0x1b },
    { 0x65, 0xe1, 0x2d, 0xf5, 0xa6, 0x95, 0xfa, 0xc8 },
    { 0xb8, 0x24, 0x49, 0xd8, 0xc8, 0xa0, 0x6a, 0xe9 },
    { 0xa8, 0x50, 0xdf, 0xba, 0xde, 0xfa, 0x42, 0x29 },
    { 0xfd, 0x42, 0xc3, 0x9d, 0x08, 0xab, 0x71, 0xa0 },
    { 0xb4, 0x65, 0xc2, 0x41, 0x26, 0x10, 0xbf, 0x84 },
    { 0x89, 0xc4, 0xa9, 0xdd, 0xb5, 0x3e, 0x69, 0x91 },
    { 0x5a, 0x9a, 0xf9, 0x1e, 0xb0, 0x95, 0xd3, 0x31 },
    { 0x8e, 0x54, 0x91, 0x4c, 0x15, 0x1e, 0x46, 0xb0 },
    { 0xfa, 0xb8, 0xab, 0x0b, 0x5b, 0xea, 0xae, 0xc6 },
    { 0x60, 0xad, 0x90, 0x6a, 0xcd, 0x06, 0xc8, 0x23 },
    { 0x6b, 0x1e, 0x6b, 0xc2, 0x42, 0x6d, 0xad, 0x17 },
    { 0x90, 0x32, 0x8f, 0xd2, 0x59, 0x88, 0x9a, 0x8f },
    { 0xf0, 0xf7, 0x81, 0x5e, 0xe6, 0xf3, 0xd5, 0x16 },
    { 0x97, 0xe7, 0xe2, 0xce, 0xbe, 0xa8, 0x26, 0xb8 },
    { 0xb0, 0xfa, 0x18, 0x45, 0xf7, 0x2a, 0x76, 0xd6 },
    { 0xa4, 0x68, 0xbd, 0xfc, 0xdf, 0x0a, 0xa9, 0xc7 },
    { 0xda, 0x84, 0xe1, 0x13, 0x38, 0x38, 0x7d, 0xa7 },
    { 0xb3, 0x0d, 0x5e, 0xad, 0x8e, 0x39, 0xf2, 0xbc },
    { 0x17, 0x8a, 0x43, 0xd2, 0xa0, 0x08, 0x50, 0x3e },
    { 0x6d, 0xfa, 0xa7, 0x05, 0xa8, 0xa0, 0x6c, 0x70 },
    { 0xaa, 0x04, 0x7f, 0x07, 0xc5, 0xae, 0x8d, 0xb4 },
    { 0x30, 0x5b, 0xbb, 0x42, 0x0c, 0x5d, 0x5e, 0xcc },
    { 0x08, 0x32, 0x80, 0x31, 0x59, 0x75, 0x0f, 0x49 },
    { 0x90, 0x80, 0x25, 0x4f, 0xb7, 0x9b, 0xab, 0x1a },
    { 0x61, 0xc2, 0x85, 0xca, 0x24, 0x57, 0x74, 0xa4 },
    { 0x2a, 0xae, 0x03, 0x5c, 0xfb, 0x61, 0xf9, 0x7a },
    { 0xf5, 0x28, 0x90, 0x75, 0xc9, 0xab, 0x39, 0xe5 },
    { 0xe6, 0x5c, 0x42, 0x37, 0x32, 0xda, 0xe7, 0x95 },
    { 0x4b, 0x22, 0xcf, 0x0d, 0x9d, 0xa8, 0xde, 0x3d },
    { 0x26, 0x26, 0xea, 0x2f, 0xa1, 0xf9, 0xab, 0xcf },
    { 0xd1, 0xe1, 0x7e, 0x6e, 0xc4, 0xa8, 0x8d, 0xa6 },
    { 0x16, 0x57, 0x44, 0x28, 0x27, 0xff, 0x64, 0x0a },
    { 0xfd, 0x15, 0x5a, 0x40, 0xdf, 0x15, 0xf6, 0x30 },
    { 0xff, 0xeb, 0x59, 0x6f, 0x29, 0x9f, 0x58, 0xb2 },
    { 0xbe, 0x4e, 0xe4, 0xed, 0x39, 0x75, 0xdf, 0x87 },
    { 0xfc, 0x7f, 0x9d, 0xf7, 0x99, 0x1b, 0x87, 0xbc }
};

static bool chaskey_selftest( void ) {
    uint8_t tag[8];
    uint8_t m[64];

    for (int i = 0; i < 64; i++) { m[i] = i; }

    // As mentioned above, this sets the key to the vector
    // { 0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc }.
    seed_t s    = seed_subkeys(0);

    bool passed = true;
    for (int i = 0; i < 64; i++) {
        if (isLE()) {
            chaskey<12, 2, false>(m, i, s, tag);
        } else {
            chaskey<12, 2, true>(m, i, s, tag);
        }
        if (0 != memcmp(tag, vectors[i], 8)) {
            printf("Mismatch with len %d\n  Expected:", i);
            for (int j = 0; j < 8; j++) { printf(" %02x", vectors[i][j]); }
            printf("\n  Found   :");
            for (int j = 0; j < 8; j++) { printf(" %02x", tag[j]); }
            printf("\n\n");
            passed = false;
        }
    }

    return passed;
}

//------------------------------------------------------------
REGISTER_FAMILY(chaskey,
   $.src_url    = "http://mouha.be/chaskey/",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(chaskey_12__32,
   $.desc       = "Chaskey PRF (12 rounds, 32 bits)",
   $.sort_order = 20,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN  |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 32,
   $.verification_LE = 0x672570CB,
   $.verification_BE = 0x22B350D2,
   $.initfn          = chaskey_selftest,
   $.seedfn          = seed_subkeys,
   $.hashfn_native   = chaskey<12, 1, false>,
   $.hashfn_bswap    = chaskey<12, 1, true>
 );

REGISTER_HASH(chaskey_12__64,
   $.desc       = "Chaskey PRF (12 rounds, 64 bits)",
   $.sort_order = 20,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN  |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 64,
   $.verification_LE = 0x919290D6,
   $.verification_BE = 0x5D0E8285,
   $.initfn          = chaskey_selftest,
   $.seedfn          = seed_subkeys,
   $.hashfn_native   = chaskey<12, 2, false>,
   $.hashfn_bswap    = chaskey<12, 2, true>
 );

REGISTER_HASH(chaskey_12,
   $.desc       = "Chaskey PRF (12 rounds, 128 bits)",
   $.sort_order = 20,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN  |
         FLAG_IMPL_VERY_SLOW,
   $.bits = 128,
   $.verification_LE = 0x1E983B23,
   $.verification_BE = 0xB042962B,
   $.initfn          = chaskey_selftest,
   $.seedfn          = seed_subkeys,
   $.hashfn_native   = chaskey<12, 4, false>,
   $.hashfn_bswap    = chaskey<12, 4, true>
 );

REGISTER_HASH(chaskey_8__32,
   $.desc       = "Chaskey PRF (8 rounds, 32 bits)",
   $.sort_order = 10,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN  |
         FLAG_IMPL_SLOW,
   $.bits = 32,
   $.verification_LE = 0xA984B318,
   $.verification_BE = 0x23FE2699,
   $.initfn          = chaskey_selftest,
   $.seedfn          = seed_subkeys,
   $.hashfn_native   = chaskey<8, 1, false>,
   $.hashfn_bswap    = chaskey<8, 1, true>
 );

REGISTER_HASH(chaskey_8__64,
   $.desc       = "Chaskey PRF (8 rounds, 64 bits)",
   $.sort_order = 10,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN  |
         FLAG_IMPL_SLOW,
   $.bits = 64,
   $.verification_LE = 0x4DA0DD3A,
   $.verification_BE = 0x87A85CD2,
   $.initfn          = chaskey_selftest,
   $.seedfn          = seed_subkeys,
   $.hashfn_native   = chaskey<8, 2, false>,
   $.hashfn_bswap    = chaskey<8, 2, true>
 );

REGISTER_HASH(chaskey_8,
   $.desc       = "Chaskey PRF (8 rounds, 128 bits)",
   $.sort_order = 10,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN  |
         FLAG_IMPL_SLOW,
   $.bits = 128,
   $.verification_LE = 0x48B645E4,
   $.verification_BE = 0xB84D00F9,
   $.initfn          = chaskey_selftest,
   $.seedfn          = seed_subkeys,
   $.hashfn_native   = chaskey<8, 4, false>,
   $.hashfn_bswap    = chaskey<8, 4, true>
 );
