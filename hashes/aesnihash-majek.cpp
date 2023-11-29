/*
 * aes-based hash from mmuniq
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2015-2021 Reini Urban
 * Copyright (c) 2015-2017 Cloudflare, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   * Neither the name of the Cloudflare, Inc. nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
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

#if defined(HAVE_X86_64_AES)
  #include "Intrinsics.h"

template <bool bswap>
static void aesnihash( const void * inv, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * in     = (uint8_t *)inv;
    uint64_t        src_sz = len;

    uint8_t tmp_buf[16]    = { 0 };
    __m128i rk0     = _mm_set_epi64x(UINT64_C(0x646f72616e646f6d), UINT64_C(0x736f6d6570736575));
    __m128i rk1     = _mm_set_epi64x(UINT64_C(0x126f12321321456d), UINT64_C(0x1231236570743245));
    // Homegrown seeding for SMHasher3
    __m128i seed128 = _mm_set_epi64x(0, (int64_t)seed);
    __m128i hash    = _mm_xor_si128(rk0, seed128);

    while (src_sz >= 16) {
  onemoretry:
        __m128i piece = _mm_loadu_si128((__m128i *)in);
        // Arbitrarily chose 64-bit wordlen
        if (bswap) { piece = mm_bswap64(piece); }
        in     += 16;
        src_sz -= 16;
        hash    = _mm_aesenc_si128(_mm_xor_si128(hash, piece), rk0);
        hash    = _mm_aesenc_si128(hash, rk1);
    }

    if (src_sz > 0) {
        uint64_t i;
        for (i = 0; i < src_sz && i < 16; i++) {
            tmp_buf[i] = in[i];
        }
        src_sz = 16;
        in     = &tmp_buf[0];
        goto onemoretry;
    }

    // src_sz is always 0 here; wonder if that was intended.
    // Of course the xor below will cancel out _any_ value...
    hash = _mm_aesenc_si128(hash, _mm_set_epi64x(src_sz, src_sz));

    // _mm_extract_epi64 assumes SSE4.1 is available
    uint64_t result = _mm_cvtsi128_si64(hash) ^ _mm_extract_epi64(hash, 1);
    memcpy(out, &result, 8);
}

#endif

REGISTER_FAMILY(aesnihash_majek,
   $.src_url    = "https://gist.github.com/majek/96dd615ed6c8aa64f60aac14e3f6ab5a",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

#if defined(HAVE_X86_64_AES)

REGISTER_HASH(aesnihash_majek,
   $.desc       = "majek's aesnihash",
   $.impl       = "aesni",
   $.hash_flags =
         FLAG_HASH_NO_SEED        |
         FLAG_HASH_AES_BASED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS   |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 64,
   $.verification_LE = 0xA68E0D42,
   $.verification_BE = 0xEBC48EDA,
   $.hashfn_native   = aesnihash<false>,
   $.hashfn_bswap    = aesnihash<true>,
   $.badseeddesc     = "All seeds collide on keys of all zero bytes when (len/16) is constant."
 );

#endif
