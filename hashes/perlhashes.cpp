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

//------------------------------------------------------------
REGISTER_FAMILY(perloldhashes,
   $.src_url    = "https://github.com/Perl/perl5/blob/6b0260474df579e9412f57249519747ab8bb5c2b/hv_func.h",
   $.src_status = HashFamilyInfo::SRC_FROZEN
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
