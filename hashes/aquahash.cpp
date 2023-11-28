/*
 * AquaHash
 * Copyright (C) 2022       Frank J. T. Wojcik
 * Copyright (C) 2018       J. Andrew Rogers
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
/*
 * This code is based on https://github.com/jandrewrogers/AquaHash, and has been
 * modified for use in SMHasher3.
 */
#include "Platform.h"
#include "Hashlib.h"

#if defined(HAVE_X86_64_AES)

  #include "Intrinsics.h"

  #include <cassert>

//------------------------------------------------------------
template <bool bswap>
static __m128i SmallKeyAlgorithm( const uint8_t * key, const size_t bytes, __m128i hash ) {
    // bulk hashing loop -- 128-bit block size
    const __m128i * ptr128 = reinterpret_cast<const __m128i *>(key);

    if (bytes / sizeof(hash)) {
        __m128i temp = _mm_set_epi64x(0xa11202c9b468bea1, 0xd75157a01452495b);
        for (uint32_t i = 0; i < bytes / sizeof(hash); ++i) {
            __m128i b = _mm_loadu_si128(ptr128++);
            if (bswap) { b = mm_bswap64(b); }
            hash = _mm_aesenc_si128(hash, b);
            temp = _mm_aesenc_si128(temp, b);
        }
        hash = _mm_aesenc_si128(hash, temp);
    }

    // AES sub-block processor
    const uint8_t * ptr8 = reinterpret_cast<const uint8_t *>(ptr128);
    if (bytes & 8) {
        __m128i b = _mm_set_epi64x(GET_U64<bswap>(ptr8, 0), 0xa11202c9b468bea1);
        hash  = _mm_xor_si128(hash, b);
        ptr8 += 8;
    }

    if (bytes & 4) {
        __m128i b = _mm_set_epi32(0xb1293b33, 0x05418592, GET_U32<bswap>(ptr8, 0), 0xd210d232);
        hash  = _mm_xor_si128(hash, b);
        ptr8 += 4;
    }

    if (bytes & 2) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverflow"
        __m128i b = _mm_set_epi16(0xbd3d, 0xc2b7, 0xb87c, 0x4715, 0x6a6c, 0x9527, GET_U16<bswap>(ptr8, 0), 0xac2e);
#pragma GCC diagnostic pop
        hash  = _mm_xor_si128(hash, b);
        ptr8 += 2;
    }

    if (bytes & 1) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverflow"
        __m128i b = _mm_set_epi8(0xcc, 0x96, 0xed, 0x16, 0x74, 0xea, 0xaa, 0x03,
                0x1e, 0x86, 0x3f, 0x24, 0xb2, 0xa8, *ptr8, 0x31);
#pragma GCC diagnostic pop
        hash = _mm_xor_si128(hash, b);
    }

    // this algorithm construction requires no less than three AES rounds to finalize
    hash = _mm_aesenc_si128(hash, _mm_set_epi64x(0x8e51ef21fabb4522, 0xe43d7a0656954b6c));
    hash = _mm_aesenc_si128(hash, _mm_set_epi64x(0x56082007c71ab18f, 0x76435569a03af7fa));
    return _mm_aesenc_si128(hash, _mm_set_epi64x(0xd2600de7157abc68, 0x6339e901c3031efb));
}

template <bool bswap>
static __m128i LargeKeyAlgorithm( const uint8_t * key, const size_t bytes, __m128i seed ) {
    // initialize 4 x 128-bit hashing lanes, for a 512-bit block size
    __m128i block[4] = {
        _mm_xor_si128(seed, _mm_set_epi64x(0xa11202c9b468bea1, 0xd75157a01452495b)),
        _mm_xor_si128(seed, _mm_set_epi64x(0xb1293b3305418592, 0xd210d232c6429b69)),
        _mm_xor_si128(seed, _mm_set_epi64x(0xbd3dc2b7b87c4715, 0x6a6c9527ac2e0e4e)),
        _mm_xor_si128(seed, _mm_set_epi64x(0xcc96ed1674eaaa03, 0x1e863f24b2a8316a))
    };

    // bulk hashing loop -- 512-bit block size
    const __m128i * ptr128 = reinterpret_cast<const __m128i *>(key);

    for (size_t block_counter = 0; block_counter < bytes / sizeof(block); block_counter++) {
        if (bswap) {
            block[0] = _mm_aesenc_si128(block[0], mm_bswap64(_mm_loadu_si128(ptr128++)));
            block[1] = _mm_aesenc_si128(block[1], mm_bswap64(_mm_loadu_si128(ptr128++)));
            block[2] = _mm_aesenc_si128(block[2], mm_bswap64(_mm_loadu_si128(ptr128++)));
            block[3] = _mm_aesenc_si128(block[3], mm_bswap64(_mm_loadu_si128(ptr128++)));
        } else {
            block[0] = _mm_aesenc_si128(block[0], _mm_loadu_si128(ptr128++));
            block[1] = _mm_aesenc_si128(block[1], _mm_loadu_si128(ptr128++));
            block[2] = _mm_aesenc_si128(block[2], _mm_loadu_si128(ptr128++));
            block[3] = _mm_aesenc_si128(block[3], _mm_loadu_si128(ptr128++));
        }
    }

    // process remaining AES blocks
    if (bytes & 32) {
        if (bswap) {
            block[0] = _mm_aesenc_si128(block[0], mm_bswap64(_mm_loadu_si128(ptr128++)));
            block[1] = _mm_aesenc_si128(block[1], mm_bswap64(_mm_loadu_si128(ptr128++)));
        } else {
            block[0] = _mm_aesenc_si128(block[0], _mm_loadu_si128(ptr128++));
            block[1] = _mm_aesenc_si128(block[1], _mm_loadu_si128(ptr128++));
        }
    }

    if (bytes & 16) {
        if (bswap) {
            block[2] = _mm_aesenc_si128(block[2], mm_bswap64(_mm_loadu_si128(ptr128++)));
        } else {
            block[2] = _mm_aesenc_si128(block[2], _mm_loadu_si128(ptr128++));
        }
    }

    // AES sub-block processor
    const uint8_t * ptr8 = reinterpret_cast<const uint8_t *>(ptr128);
    if (bytes & 8) {
        __m128i b = _mm_set_epi64x(GET_U64<bswap>(ptr8, 0), 0xa11202c9b468bea1);
        block[3] = _mm_aesenc_si128(block[3], b);
        ptr8    += 8;
    }

    if (bytes & 4) {
        __m128i b = _mm_set_epi32(0xb1293b33, 0x05418592, GET_U32<bswap>(ptr8, 0), 0xd210d232);
        block[0] = _mm_aesenc_si128(block[0], b);
        ptr8    += 4;
    }

    if (bytes & 2) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverflow"
        __m128i b = _mm_set_epi16(0xbd3d, 0xc2b7, 0xb87c, 0x4715, 0x6a6c, 0x9527, GET_U16<bswap>(ptr8, 0), 0xac2e);
#pragma GCC diagnostic pop
        block[1] = _mm_aesenc_si128(block[1], b);
        ptr8    += 2;
    }

    if (bytes & 1) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverflow"
        __m128i b = _mm_set_epi8(0xcc, 0x96, 0xed, 0x16, 0x74, 0xea, 0xaa, 0x03,
                0x1e, 0x86, 0x3f, 0x24, 0xb2, 0xa8, *ptr8, 0x31);
#pragma GCC diagnostic pop
        block[2] = _mm_aesenc_si128(block[2], b);
    }

    // indirectly mix hashing lanes
    const __m128i mix = _mm_xor_si128(_mm_xor_si128(block[0], block[1]), _mm_xor_si128(block[2], block[3]));
    block[0] = _mm_aesenc_si128(block[0], mix);
    block[1] = _mm_aesenc_si128(block[1], mix);
    block[2] = _mm_aesenc_si128(block[2], mix);
    block[3] = _mm_aesenc_si128(block[3], mix);

    // reduction from 512-bit block size to 128-bit hash
    __m128i hash = _mm_aesenc_si128(_mm_aesenc_si128(block[0], block[1]), _mm_aesenc_si128(block[2], block[3]));

    // this algorithm construction requires no less than one round to finalize
    return _mm_aesenc_si128(hash, _mm_set_epi64x(0x8e51ef21fabb4522, 0xe43d7a0656954b6c));
}

//------------------------------------------------------------
template <bool bswap>
static void AquaHash( const void * in, const size_t len, const seed_t seed, void * out ) {
    __m128i seed128 = _mm_set1_epi64x((uint64_t)seed);
    __m128i hash128;

    if (len < 64) {
        hash128 = SmallKeyAlgorithm<bswap>((const uint8_t *)in, len, seed128);
    } else {
        hash128 = LargeKeyAlgorithm<bswap>((const uint8_t *)in, len, seed128);
    }

    memcpy(out, &hash128, 16);
}

#endif

//------------------------------------------------------------
REGISTER_FAMILY(AquaHash,
   $.src_url    = "https://github.com/jandrewrogers/AquaHash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

#if defined(HAVE_X86_64_AES)

REGISTER_HASH(AquaHash,
   $.desc            = "AquaHash",
   $.impl            = "aesni",
   $.hash_flags      =
         FLAG_HASH_AES_BASED      |
         FLAG_HASH_XL_SEED        ,
   $.impl_flags      =
         FLAG_IMPL_LICENSE_APACHE2,
   $.bits            = 128,
   $.verification_LE = 0x9E92BCC4,
   $.verification_BE = 0xE8DC341E,
   $.hashfn_native   = AquaHash<false>,
   $.hashfn_bswap    = AquaHash<true>
 );

#endif
