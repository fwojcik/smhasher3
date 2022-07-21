/*
 * Pengyhash, v0.2
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2020 Alberto Fajardo
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "Platform.h"
#include "Hashlib.h"

//------------------------------------------------------------
template <bool bswap>
static uint64_t pengyhash( const uint8_t * p, size_t size, uint64_t seed ) {
    uint64_t b[4] = { 0 };
    uint64_t s[4] = { 0, 0, 0, size };
    int      i;

    for (; size >= 32; size -= 32, p += 32) {
        memcpy(b, p, 32);

        s[1] = (s[0] += s[1] + GET_U64<bswap>((uint8_t *)&b[3], 0)) + (s[1] << 14 | s[1] >> 50);
        s[3] = (s[2] += s[3] + GET_U64<bswap>((uint8_t *)&b[2], 0)) + (s[3] << 23 | s[3] >> 41);
        s[3] = (s[0] += s[3] + GET_U64<bswap>((uint8_t *)&b[1], 0)) ^ (s[3] << 16 | s[3] >> 48);
        s[1] = (s[2] += s[1] + GET_U64<bswap>((uint8_t *)&b[0], 0)) ^ (s[1] << 40 | s[1] >> 24);
    }

    memcpy(b, p, size);

    for (i = 0; i < 6; i++) {
        s[1] = (s[0] += s[1] + GET_U64<bswap>((uint8_t *)&b[3], 0)) + (s[1] << 14 | s[1] >> 50) + seed;
        s[3] = (s[2] += s[3] + GET_U64<bswap>((uint8_t *)&b[2], 0)) + (s[3] << 23 | s[3] >> 41);
        s[3] = (s[0] += s[3] + GET_U64<bswap>((uint8_t *)&b[1], 0)) ^ (s[3] << 16 | s[3] >> 48);
        s[1] = (s[2] += s[1] + GET_U64<bswap>((uint8_t *)&b[0], 0)) ^ (s[1] << 40 | s[1] >> 24);
    }

    return s[0] + s[1] + s[2] + s[3];
}

//------------------------------------------------------------
template <bool bswap>
static void pengy( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = pengyhash<bswap>((const uint8_t *)in, len, (uint64_t)seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(pengyhash,
   $.src_url    = "https://github.com/tinypeng/pengyhash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(pengyhash,
   $.desc       = "pengyhash v0.2",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_ROTATE       |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 64,
   $.verification_LE = 0x1FC2217B,
   $.verification_BE = 0x774D23AB,
   $.hashfn_native   = pengy<false>,
   $.hashfn_bswap    = pengy<true>
 );
