/*
 * Pengyhash, v0.3
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (c) 2023       Alberto Fajardo
 * Copyright (C) 2023       jason
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
 *
 */
#include "Platform.h"
#include "Hashlib.h"

//------------------------------------------------------------
#define V64(p) (                                                                                               \
                (uint64_t)(p)[0]     | (uint64_t)(p)[1]<<8  | (uint64_t)(p)[2]<<16 | (uint64_t)(p)[3]<<24 |    \
                (uint64_t)(p)[4]<<32 | (uint64_t)(p)[5]<<40 | (uint64_t)(p)[6]<<48 | (uint64_t)(p)[7]<<56      \
)

static uint64_t pengyhash( const uint8_t * p, size_t size, uint64_t seed ) {
    uint64_t s[4] = { 0 };
    uint64_t f[4] = { 0 };
    uint8_t  i;

    for (*s = size; size >= 32; size -= 32, p += 32) {
        s[1] += V64(p +  8); s[1] = (s[0] += s[1] + V64(p)     ) ^ ROTL64(s[1], 14);
        s[3] += V64(p + 24); s[3] = (s[2] += s[3] + V64(p + 16)) ^ ROTL64(s[3], 23);
        s[3] += V64(p + 24); s[3] = (s[0] += s[3] + V64(p)     ) ^ ROTL64(s[3], 11);
        s[1] += V64(p +  8); s[1] = (s[2] += s[1] + V64(p + 16)) ^ ROTL64(s[1], 40);
    }

    for (i = 0; (size_t)(i + 8) < size; i += 8, p += 8) {
        f[i / 8] = V64(p);
    }
    for (; i < size; i++) {
        f[i / 8] |= (uint64_t)p[i % 8] << i % 8 * 8;
    }

    for (i = 0; i < 6; i++) {
        s[1] += seed;
        s[1] += f[1]; s[1] = (s[0] += s[1] + f[0]) ^ ROTL64(s[1], 14);
        s[3] += f[3]; s[3] = (s[2] += s[3] + f[2]) ^ ROTL64(s[3], 23);
        s[3] += f[3]; s[3] = (s[0] += s[3] + f[0]) ^ ROTL64(s[3],  9);
        s[1] += f[1]; s[1] = (s[2] += s[1] + f[2]) ^ ROTL64(s[1], 40);
    }

    return s[0] + s[1] + s[2] + s[3];
}

//------------------------------------------------------------
static void pengy( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = pengyhash((const uint8_t *)in, len, (uint64_t)seed);

    h = COND_BSWAP(h, isBE());
    PUT_U64<false>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(pengyhash,
   $.src_url    = "https://github.com/tinypeng/pengyhash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(pengyhash,
   $.desc       = "pengyhash v0.3",
   $.hash_flags =
        FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
        FLAG_IMPL_ROTATE            |
        FLAG_IMPL_CANONICAL_BOTH    |
        FLAG_IMPL_LICENSE_GPL3,
   $.bits = 64,
   $.verification_LE = 0x861A1254,
   $.verification_BE = 0x861A1254,
   $.hashfn_native   = pengy,
   $.hashfn_bswap    = pengy
 );
