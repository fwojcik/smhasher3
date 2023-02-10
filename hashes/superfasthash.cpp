/*
 * SuperFastHash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (C) 2004, 2005 Paul Hsieh
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
/*
 * The base code for this was obtained from
 * http://www.azillionmonkeys.com/qed/hash.html under the LGPL 2.1
 * license, which allows for relicensing of the code under any version
 * of the GPL since GPLv2 (see
 * https://www.gnu.org/licenses/gpl-faq.html#AllCompatibility).
 */
#include "Platform.h"
#include "Hashlib.h"

//------------------------------------------------------------
template <bool bswap>
static uint32_t SuperFastHash( const uint8_t * data, size_t len, const uint32_t seed ) {
    uint32_t hash = seed;
    uint32_t tmp;
    size_t   rem;

    if ((len <= 0) || (data == NULL)) { return 0; }

    hash += len;
    rem   = len & 3;
    len >>= 2;

    /* Main loop */
    for (; len > 0; len--) {
        hash += GET_U16<bswap>(data, 0);
        tmp   = (GET_U16<bswap>(data, 2) << 11) ^ hash;
        hash  = (hash                    << 16) ^ tmp;
        hash += hash >> 11;
        data += 2 * sizeof(uint16_t);
    }

    /* Handle end cases */
    switch (rem) {
    case 3:
            hash += GET_U16<bswap>(data, 0);
            hash ^= hash << 16;
            hash ^= ((uint32_t)(int8_t)data[sizeof(uint16_t)]) << 18;
            hash += hash >> 11;
            break;
    case 2:
            hash += GET_U16<bswap>(data, 0);
            hash ^= hash << 11;
            hash += hash >> 17;
            break;
    case 1:
            hash += (int8_t)(*data);
            hash ^= hash << 10;
            hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}

//------------------------------------------------------------
template <bool bswap>
static void SFH( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = SuperFastHash<bswap>((const uint8_t *)in, len, (uint32_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(superfasthash,
   $.src_url    = "http://www.azillionmonkeys.com/qed/hash.html",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(SuperFastHash,
   $.desc       = "Paul Hsieh's SuperFastHash",
   $.hash_flags =
         FLAG_HASH_ENDIAN_INDEPENDENT  |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE        |
         FLAG_IMPL_LICENSE_GPL3        |
         FLAG_IMPL_SLOW,
   $.bits = 32,
   $.verification_LE = 0xCFA52B38,
   $.verification_BE = 0xDF0823CA,
   $.hashfn_native   = SFH<false>,
   $.hashfn_bswap    = SFH<true>
 );
