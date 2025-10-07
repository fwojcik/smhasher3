/*
 * GxHash
 * Copyright (C) 2025  Frank J. T. Wojcik
 * Copyright (c) 2023 Olivier Giniaux
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include "Platform.h"
#include "Hashlib.h"

#if defined(HAVE_X86_64_AES) && defined(HAVE_SSE_2)
  #include "Intrinsics.h"
  #define GX_IMPL_STR "sse2+aesni"
  #define GX_IMPL_X86
#else
  #include "AES.h"
  #define GX_IMPL_STR "g+" AES_IMPL_STR
#endif

//------------------------------------------------------------
// The row of all zeroes is only used for the generic implementation.
// This is converted to 8-bit data for platform-(endian-)independence.
const uint8_t KEYDATA[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x42, 0x45, 0x78, 0xf2, 0x21, 0x3e, 0x9d, 0xb0, 0xe5, 0x22, 0xc2, 0x89, 0x8e, 0xc2, 0x3b, 0xfc,
    0x79, 0xe2, 0xfc, 0x03, 0x9b, 0x2e, 0x6b, 0xcb, 0x58, 0xdc, 0x61, 0xb3, 0xd9, 0x2b, 0x13, 0x39,
    0x32, 0x2e, 0x01, 0xd0, 0x7d, 0x2b, 0x9d, 0x68, 0xb7, 0xb1, 0x44, 0x55, 0x2b, 0x12, 0x8b, 0xc7,
};

//------------------------------------------------------------
constexpr uint64_t VECTOR_SIZE   = 16;
constexpr uint64_t PAGE_SIZE     = 0x1000;
constexpr uint64_t UNROLL_FACTOR = 8;

#if defined(GX_IMPL_X86)
const __m128i * KEYS = (const __m128i *)&KEYDATA[1 * VECTOR_SIZE];
static_assert(sizeof(__m128i) == VECTOR_SIZE, "Code assumes VECTOR_SIZE == sizeof(__m128i)");

static FORCE_INLINE bool check_same_page( const __m128i * ptr ) {
    uint64_t offset = ((uintptr_t)ptr) & (PAGE_SIZE - 1);

    return offset < (PAGE_SIZE - VECTOR_SIZE);
}

static FORCE_INLINE __m128i get_partial_unsafe( const __m128i * ptr, const size_t len ) {
    __m128i indices = _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    __m128i len_vec = _mm_set1_epi8((uint8_t)len);
    __m128i mask    = _mm_cmpgt_epi8(len_vec, indices);
    __m128i partial = _mm_and_si128(_mm_loadu_si128(ptr), mask);

    return _mm_add_epi8(partial, len_vec);
}

static FORCE_INLINE __m128i get_partial_safe( const __m128i * ptr, const size_t len ) {
    uint8_t buf[VECTOR_SIZE] = { 0 };

    memcpy(buf, ptr, len);
    __m128i partial = _mm_loadu_si128((const __m128i *)buf);
    return _mm_add_epi8(partial, _mm_set1_epi8((uint8_t)len));
}

static FORCE_INLINE __m128i get_partial( const __m128i * ptr, const size_t len ) {
    if (check_same_page(ptr)) {
        return get_partial_unsafe(ptr, len);
    } else {
        return get_partial_safe(ptr, len);
    }
}

static FORCE_INLINE __m128i compress_8( const __m128i * ptr, const __m128i * end,
        __m128i hash_vector, const size_t len ) {
    // Disambiguation vectors
    __m128i t1 = _mm_setzero_si128();
    __m128i t2 = _mm_setzero_si128();
    // Hash is processed in two separate 128-bit parallel lanes.
    // This allows the same processing to be applied using 256-bit V-AES intrinsics
    // so that hashes are stable in both cases.
    __m128i lane1 = hash_vector;
    __m128i lane2 = hash_vector;

    while (ptr < end) {
        static_assert(UNROLL_FACTOR == 8, "Loop is coded to unroll 8 times");
        __m128i v0 = _mm_loadu_si128(ptr++);
        __m128i v1 = _mm_loadu_si128(ptr++);
        __m128i v2 = _mm_loadu_si128(ptr++);
        __m128i v3 = _mm_loadu_si128(ptr++);
        __m128i v4 = _mm_loadu_si128(ptr++);
        __m128i v5 = _mm_loadu_si128(ptr++);
        __m128i v6 = _mm_loadu_si128(ptr++);
        __m128i v7 = _mm_loadu_si128(ptr++);

        __m128i tmp1, tmp2;
        tmp1  = _mm_aesenc_si128(v0  , v2);
        tmp2  = _mm_aesenc_si128(v1  , v3);
        tmp1  = _mm_aesenc_si128(tmp1, v4);
        tmp2  = _mm_aesenc_si128(tmp2, v5);
        tmp1  = _mm_aesenc_si128(tmp1, v6);
        tmp2  = _mm_aesenc_si128(tmp2, v7);

        t1    = _mm_add_epi8(t1, _mm_loadu_si128(&KEYS[0]));
        t2    = _mm_add_epi8(t2, _mm_loadu_si128(&KEYS[1]));

        lane1 = _mm_aesenclast_si128(_mm_aesenc_si128(tmp1, t1), lane1);
        lane2 = _mm_aesenclast_si128(_mm_aesenc_si128(tmp2, t2), lane2);
    }

    // For 'Zeroes' test
    const __m128i len_vec = _mm_set1_epi32((uint32_t)len);
    lane1 = _mm_add_epi8(lane1, len_vec);
    lane2 = _mm_add_epi8(lane2, len_vec);

    return _mm_aesenc_si128(lane1, lane2);
}

static FORCE_INLINE __m128i compress_many( const __m128i * ptr, const __m128i * end,
        __m128i hash_vector, const size_t len ) {
    const uint64_t  unrollable_blocks_count =  (end - ptr) / UNROLL_FACTOR;
    const __m128i * endptr = end - unrollable_blocks_count * UNROLL_FACTOR;

    // Process first individual blocks until we have a whole number of 8 blocks
    while (ptr < endptr) {
        __m128i v0 = _mm_loadu_si128(ptr++);
        hash_vector = _mm_aesenc_si128(hash_vector, v0);
    }

    // Process the remaining n * 8 blocks
    return compress_8(ptr, end, hash_vector, len);
}

static FORCE_INLINE __m128i compress_all( const void * in, const size_t len ) {
    const __m128i * ptr = (const __m128i *)in;
    const __m128i * end = (const __m128i *)((const uint8_t *)in + len);
    const uint64_t  extra_bytes_count = len % VECTOR_SIZE;
    __m128i         hash_vector;

    if (len == 0) {
        return _mm_setzero_si128();
    }

    if (len <= VECTOR_SIZE) {
        return get_partial(ptr, len);
    }

    if (extra_bytes_count == 0) {
        hash_vector = _mm_loadu_si128(ptr++);
    } else {
        hash_vector = get_partial(ptr, extra_bytes_count);
        ptr         = (const __m128i *)((const uint8_t *)ptr + extra_bytes_count);
    }

    __m128i v0 = _mm_loadu_si128(ptr++);
    if (len > VECTOR_SIZE * 2) {
        // Fast path when input length > 32 and <= 48
        __m128i v = _mm_loadu_si128(ptr++);
        v0 = _mm_aesenc_si128(v0, v);

        if (len > VECTOR_SIZE * 3) {
            // Fast path when input length > 48 and <= 64
            __m128i v = _mm_loadu_si128(ptr++);
            v0 = _mm_aesenc_si128(v0, v);

            if (len > VECTOR_SIZE * 4) {
                // Input message is large and we can use the high ILP loop
                hash_vector = compress_many(ptr, end, hash_vector, len);
            }
        }
    }

    v0 = _mm_aesenc_si128(v0, _mm_loadu_si128(&KEYS[0]));
    v0 = _mm_aesenc_si128(v0, _mm_loadu_si128(&KEYS[1]));
    v0 = _mm_aesenclast_si128(hash_vector, v0);

    return v0;
}

static FORCE_INLINE __m128i finalize( __m128i hash ) {
    hash = _mm_aesenc_si128(hash, _mm_loadu_si128(    &KEYS[0]));
    hash = _mm_aesenc_si128(hash, _mm_loadu_si128(    &KEYS[1]));
    hash = _mm_aesenclast_si128(hash, _mm_loadu_si128(&KEYS[2]));
    return hash;
}

template <bool output64>
static FORCE_INLINE void gxhash_x86( const void * in, const size_t len, const uint64_t seed, void * out ) {
    __m128i seedx = _mm_set1_epi64x(seed);

    __m128i state = compress_all(in, len);

    state = _mm_aesenc_si128(state, seedx);
    state = finalize(state);
    if (output64) {
        PUT_U64<false>(_mm_extract_epi64(state, 0), (uint8_t *)out, 0);
    } else {
        _mm_storeu_si128((__m128i *)out, state);
    }
}

#else
typedef uint8_t aesblock_t[VECTOR_SIZE];

static FORCE_INLINE void get_partial( aesblock_t block, const uint8_t * ptr, const size_t len ) {
    memcpy(&block[0], ptr, len);
    memset(&block[len], 0, VECTOR_SIZE - len);
    for (unsigned ii = 0; ii < VECTOR_SIZE; ii++) {
        block[ii] += (uint8_t)len;
    }
}

static FORCE_INLINE void compress_8( aesblock_t hash_vector, const uint8_t * ptr,
        const uint8_t * end, const size_t len ) {
    const uint8_t * KEYPTR1 = &KEYDATA[1 * VECTOR_SIZE];
    const uint8_t * KEYPTR2 = &KEYDATA[2 * VECTOR_SIZE];

    // Disambiguation vectors
    aesblock_t t1, t2;

    memset(t1, 0, VECTOR_SIZE);
    memset(t2, 0, VECTOR_SIZE);
    // Hash is processed in two separate 128-bit parallel lanes.
    // This allows the same processing to be applied using 256-bit V-AES intrinsics
    // so that hashes are stable in both cases.
    aesblock_t lane1, lane2;
    memcpy(lane1, hash_vector, VECTOR_SIZE);
    memcpy(lane2, hash_vector, VECTOR_SIZE);

    while (ptr < end) {
        static_assert(UNROLL_FACTOR == 8, "Loop is coded to unroll 8 times");
        aesblock_t v0, v1, v2, v3, v4, v5, v6, v7;
        memcpy(v0, ptr + 0 * VECTOR_SIZE, VECTOR_SIZE);
        memcpy(v1, ptr + 1 * VECTOR_SIZE, VECTOR_SIZE);
        memcpy(v2, ptr + 2 * VECTOR_SIZE, VECTOR_SIZE);
        memcpy(v3, ptr + 3 * VECTOR_SIZE, VECTOR_SIZE);
        memcpy(v4, ptr + 4 * VECTOR_SIZE, VECTOR_SIZE);
        memcpy(v5, ptr + 5 * VECTOR_SIZE, VECTOR_SIZE);
        memcpy(v6, ptr + 6 * VECTOR_SIZE, VECTOR_SIZE);
        memcpy(v7, ptr + 7 * VECTOR_SIZE, VECTOR_SIZE);
        ptr += 8 * VECTOR_SIZE;

        AES_EncryptRound(v2, v0);
        AES_EncryptRound(v3, v1);
        AES_EncryptRound(v4, v0);
        AES_EncryptRound(v5, v1);
        AES_EncryptRound(v6, v0);
        AES_EncryptRound(v7, v1);

        for (size_t ii = 0; ii < VECTOR_SIZE; ii++) {
            t1[ii] += KEYPTR1[ii];
            t2[ii] += KEYPTR2[ii];
        }

        AES_EncryptRound(t1, v0);
        AES_EncryptRound(t2, v1);
        AES_EncryptRoundNoMixCol(lane1, v0);
        AES_EncryptRoundNoMixCol(lane2, v1);
        memcpy(lane1, v0, VECTOR_SIZE);
        memcpy(lane2, v1, VECTOR_SIZE);
    }

    // For 'Zeroes' test
    aesblock_t len_vec;
    uint32_t   len_int = COND_BSWAP((uint32_t)len, isBE());
    PUT_U32<false>(len_int, len_vec,  0);
    PUT_U32<false>(len_int, len_vec,  4);
    PUT_U32<false>(len_int, len_vec,  8);
    PUT_U32<false>(len_int, len_vec, 12);
    for (size_t ii = 0; ii < VECTOR_SIZE; ii++) {
        lane1[ii] += len_vec[ii];
        lane2[ii] += len_vec[ii];
    }

    AES_EncryptRound(lane2, lane1);
    memcpy(hash_vector, lane1, VECTOR_SIZE);
}

static FORCE_INLINE void compress_many( aesblock_t hash_vector, const uint8_t * ptr,
        const uint8_t * end, const size_t len ) {
    const uint64_t  unrollable_blocks_count = (end - ptr) / (VECTOR_SIZE * UNROLL_FACTOR);
    const uint8_t * endptr = end - unrollable_blocks_count * VECTOR_SIZE * UNROLL_FACTOR;
    aesblock_t      v0;

    // Process first individual blocks until we have a whole number of 8 blocks
    while (ptr < endptr) {
        memcpy(v0, ptr, VECTOR_SIZE);
        ptr += VECTOR_SIZE;
        AES_EncryptRound(v0, hash_vector);
    }

    // Process the remaining n * 8 blocks
    compress_8(hash_vector, ptr, end, len);
}

static FORCE_INLINE void compress_all( aesblock_t hash_vector, const void * in, const size_t len ) {
    const uint8_t * ptr = (const uint8_t *)in;
    const uint8_t * end = ptr + len;
    const uint64_t  extra_bytes_count = len % VECTOR_SIZE;

    if (len == 0) {
        memset(hash_vector, 0, VECTOR_SIZE);
        return;
    }

    if (len <= VECTOR_SIZE) {
        get_partial(hash_vector, ptr, len);
        return;
    }

    if (extra_bytes_count == 0) {
        memcpy(hash_vector, ptr, VECTOR_SIZE);
        ptr += VECTOR_SIZE;
    } else {
        get_partial(hash_vector, ptr, extra_bytes_count);
        ptr += extra_bytes_count;
    }

    aesblock_t v0;
    memcpy(v0, ptr, VECTOR_SIZE);
    ptr += VECTOR_SIZE;
    if (len > VECTOR_SIZE * 2) {
        aesblock_t v;

        // Fast path when input length > 32 and <= 48
        memcpy(v, ptr, VECTOR_SIZE);
        ptr += VECTOR_SIZE;
        AES_EncryptRound(v, v0);

        if (len > VECTOR_SIZE * 3) {
            // Fast path when input length > 48 and <= 64
            memcpy(v, ptr, VECTOR_SIZE);
            ptr += VECTOR_SIZE;
            AES_EncryptRound(v, v0);

            if (len > VECTOR_SIZE * 4) {
                // Input message is large and we can use the high ILP loop
                compress_many(hash_vector, ptr, end, len);
            }
        }
    }

    AES_EncryptRound(&KEYDATA[1 * VECTOR_SIZE], v0);
    AES_EncryptRound(&KEYDATA[2 * VECTOR_SIZE], v0);
    AES_EncryptRoundNoMixCol(v0, hash_vector);
}

static FORCE_INLINE void finalize( aesblock_t hash ) {
    AES_Encrypt<3>(&KEYDATA[0 * VECTOR_SIZE], hash, hash);
}

template <bool output64>
static FORCE_INLINE void gxhash_generic( const void * in, const size_t len, const uint64_t seed, void * out ) {
    aesblock_t seedx, state;
    uint64_t   seedb = COND_BSWAP(seed, isBE());

    memcpy(&seedx[0]            , &seedb, sizeof(seedb));
    memcpy(&seedx[sizeof(seedb)], &seedb, sizeof(seedb));

    compress_all(state, in, len);
    AES_EncryptRound(seedx, state);
    finalize(state);
    memcpy(out, state, output64 ? 8 : 16);
}

#endif

//------------------------------------------------------------
static void GxHash128( const void * in, const size_t len, const seed_t seed, void * out ) {
#if defined(GX_IMPL_X86)
    gxhash_x86<false>(in, len, (uint64_t)seed, out);
#else
    gxhash_generic<false>(in, len, (uint64_t)seed, out);
#endif
}

static void GxHash64( const void * in, const size_t len, const seed_t seed, void * out ) {
#if defined(GX_IMPL_X86)
    gxhash_x86<true>(in, len, (uint64_t)seed, out);
#else
    gxhash_generic<true>(in, len, (uint64_t)seed, out);
#endif
}

//------------------------------------------------------------
REGISTER_FAMILY(gxhash,
   $.src_url    = "https://github.com/ogxd/gxhash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
);

REGISTER_HASH(gxhash,
   $.desc            = "GxHash (ported from Rust)",
   $.impl            = GX_IMPL_STR,
   $.hash_flags      =
         FLAG_HASH_AES_BASED           |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_READ_PAST_EOB       |
         FLAG_IMPL_CANONICAL_BOTH      |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 128,
   $.verification_LE = 0x64A77B47,
   $.verification_BE = 0x64A77B47,
   $.hashfn_native   = GxHash128,
   $.hashfn_bswap    = GxHash128
);

REGISTER_HASH(gxhash_64,
   $.desc            = "GxHash, lower 64 bits (ported from Rust)",
   $.impl            = GX_IMPL_STR,
   $.hash_flags      =
         FLAG_HASH_AES_BASED           |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags      =
         FLAG_IMPL_READ_PAST_EOB       |
         FLAG_IMPL_CANONICAL_BOTH      |
         FLAG_IMPL_LICENSE_MIT,
   $.bits            = 64,
   $.verification_LE = 0x48F84240,
   $.verification_BE = 0x48F84240,
   $.hashfn_native   = GxHash64,
   $.hashfn_bswap    = GxHash64
);
