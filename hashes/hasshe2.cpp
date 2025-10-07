/*
 * hash he2
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

#if defined(HAVE_SSE_2)
  #include "Intrinsics.h"
  #define HASSHE2_IMPL_STR "sse2"
#else
  #define HASSHE2_IMPL_STR "portable"
#endif

//------------------------------------------------------------
alignas(16) const static uint32_t coeffs[12] = {
    /* Four carefully selected coefficients and interleaving zeros. */
    0x98b365a1,          0, 0x52c69cab,          0,
    0xb76a9a41,          0, 0xcc4d2c7b,          0,
    /* 128 bits of random data. */
    0x564a4447, 0xc7265595, 0xe20c241d, 0x128fa608,
};

//------------------------------------------------------------
// Portable implementation of the hash
static void combine_and_mix( uint64_t state[4], const uint64_t input[2] ) {
    /*
     * Phase 1: Perform four 32x32->64 bit multiplication with the
     * input block and words 1 and 3 coeffs, respectively.  This
     * effectively propagates a bit change in input to 32 more
     * significant bit positions.  Combine into internal state by
     * subtracting the result of multiplications from the internal
     * state.
     */
    state[0] -= ((uint64_t)(coeffs[0])) * (input[1] & 0xffffffff);
    state[1] -= ((uint64_t)(coeffs[2])) * (input[1] >>        32);
    state[2] -= ((uint64_t)(coeffs[4])) * (input[0] & 0xffffffff);
    state[3] -= ((uint64_t)(coeffs[6])) * (input[0] >>        32);

    /*
     * Phase 2: Perform shifts and xors to propagate the 32-bit
     * changes produced above into 64-bit (and even a little larger)
     * changes in the internal state.
     */
    /* state ^= state >64> 29; */
    /* state +64= state <64< 16; */
    /* state ^= state >64> 21; */
    for (int i = 0; i < 4; i++) {
        state[i] ^= state[i] >> 29;
        state[i] += state[i] << 16;
        state[i] ^= state[i] >> 21;
    }
    state[1] += (state[1] << 32) + (state[0] >> 32);
    state[0] += (state[0] << 32);
    state[3] += (state[3] << 32) + (state[2] >> 32);
    state[2] += (state[2] << 32);

    /*
     * Phase 3: Propagate the changes among the four 64-bit words by
     * performing 64-bit subtractions and 32-bit word shuffling.
     */
    state[0] -= state[2];
    state[1] -= state[3];

    uint64_t tmp;

    tmp      = state[2];
    state[2] = ((state[2] >> 32) + (state[3] << 32)) - state[0];
    state[3] = ((state[3] >> 32) + (tmp      << 32)) - state[1];

    tmp      = state[1];
    state[1] = ((state[0] >> 32) + (state[0] << 32)) - state[3];
    state[0] = tmp - state[2];

    tmp      = state[2];
    state[2] = ((state[3] >> 32) + (state[2] << 32)) - state[0];
    state[3] = ((tmp      >> 32) + (state[3] << 32)) - state[1];

    tmp      = state[0];
    state[0] = ((state[1] >> 32) + (state[0] << 32)) - state[2];
    state[1] = ((tmp      >> 32) + (state[1] << 32)) - state[3];

    /*
     * With good coefficients any one-bit flip in the input has now
     * changed all bits in the internal state with a probability
     * between 45% to 55%.
     */
}

template <bool orig, bool bswap>
static void hasshe2_portable( const uint8_t * input_buf, size_t n_bytes, uint64_t seed, void * output_state ) {
    // Put 2 copies of the lower 32 bits of the input length into orig_bytes
    const uint64_t orig_bytes = (n_bytes & 0xffffffff) | ((uint64_t)n_bytes << 32);

    uint64_t state[4];
    uint64_t input[2];

    /*
     * Initialize internal state to something random.  (Alternatively,
     * if hashing a chain of data, read in the previous hash result from
     * somewhere.)
     *
     * Seeding is homegrown for SMHasher3
     */
    state[0]  = coeffs[ 8] + (((uint64_t)coeffs[ 9]) << 32);
    state[1]  = coeffs[10] + (((uint64_t)coeffs[11]) << 32);
    state[0] ^= seed;
    state[1] ^= seed;
    state[2]  = state[0];
    state[3]  = state[1];

    while (n_bytes >= 16) {
        /*
         * Read in 16 bytes, or 128 bits, from buf.  Advance buf and
         * decrement n_bytes accordingly.
         */
        for (int i = 0; i < 2; i++) {
            input[i] = GET_U64<bswap>(input_buf, i * 8);
        }
        input_buf += 16;
        n_bytes   -= 16;

        combine_and_mix(state, input);
    }
    if (n_bytes > 0) {
        uint8_t buf[16];
        memcpy(buf, input_buf, n_bytes);
        memset(buf + n_bytes, 0, 16 - n_bytes);
        for (int i = 0; i < 2; i++) {
            input[i] = GET_U64<bswap>(buf, i * 8);
        }

        combine_and_mix(state, input);
    }

    /*
     * Postprocessing.  Copy half of the internal state into fake input,
     * replace it with the constant rnd_data, and do one combine and mix
     * phase more.
     */
    input[0] = state[0] ^ (orig ? 0 : orig_bytes);
    input[1] = state[1] ^ (orig ? 0 : orig_bytes);
    state[0] = coeffs[ 8] + (((uint64_t)coeffs[ 9]) << 32);
    state[1] = coeffs[10] + (((uint64_t)coeffs[11]) << 32);
    combine_and_mix(state, input);

    for (int i = 0; i < 4; i++) {
        PUT_U64<bswap>(state[i], (uint8_t *)output_state, i * 8);
    }
}

//------------------------------------------------------------
#if defined(HAVE_SSE_2)

#define COMBINE_AND_MIX(c_1, c_2, s_1, s_2, in)                              \
  /* Phase 1: Perform four 32x32->64 bit multiplication with the             \
     input block and words 1 and 3 coeffs, respectively.  This               \
     effectively propagates a bit change in input to 32 more                 \
     significant bit positions.  Combine into internal state by              \
     subtracting the result of multiplications from the internal             \
     state. */                                                               \
  s_1 = _mm_sub_epi64(s_1, _mm_mul_epu32(c_1, _mm_unpackhi_epi32(in, in)));  \
  s_2 = _mm_sub_epi64(s_2, _mm_mul_epu32(c_2, _mm_unpacklo_epi32(in, in)));  \
  /* Phase 2: Perform shifts and xors to propagate the 32-bit                \
     changes produced above into 64-bit (and even a little larger)           \
     changes in the internal state. */                                       \
  /* state ^= state >64> 29; */                                              \
  s_1 = _mm_xor_si128(s_1, _mm_srli_epi64(s_1, 29));                         \
  s_2 = _mm_xor_si128(s_2, _mm_srli_epi64(s_2, 29));                         \
  /* state +64= state <64< 16; */                                            \
  s_1 = _mm_add_epi64(s_1, _mm_slli_epi64(s_1, 16));                         \
  s_2 = _mm_add_epi64(s_2, _mm_slli_epi64(s_2, 16));                         \
  /* state ^= state >64> 21; */                                              \
  s_1 = _mm_xor_si128(s_1, _mm_srli_epi64(s_1, 21));                         \
  s_2 = _mm_xor_si128(s_2, _mm_srli_epi64(s_2, 21));                         \
  /* state +64= state <128< 32; */                                           \
  s_1 = _mm_add_epi64(s_1, _mm_slli_si128(s_1, 4));                          \
  s_2 = _mm_add_epi64(s_2, _mm_slli_si128(s_2, 4));                          \
                                                                             \
  /* Phase 3: Propagate the changes among the four 64-bit words by           \
     performing 64-bit subtractions and 32-bit word shuffling. */            \
  s_1 = _mm_sub_epi64(s_1, s_2);                                             \
  s_2 = _mm_sub_epi64(_mm_shuffle_epi32(s_2, _MM_SHUFFLE(0, 3, 2, 1)), s_1); \
  s_1 = _mm_sub_epi64(_mm_shuffle_epi32(s_1, _MM_SHUFFLE(0, 1, 3, 2)), s_2); \
  s_2 = _mm_sub_epi64(_mm_shuffle_epi32(s_2, _MM_SHUFFLE(2, 1, 0, 3)), s_1); \
  s_1 = _mm_sub_epi64(_mm_shuffle_epi32(s_1, _MM_SHUFFLE(2, 1, 0, 3)), s_2); \
                                                                             \
  /* With good coefficients any one-bit flip in the input has now            \
     changed all bits in the internal state with a probability               \
     between 45% to 55%. */

template <bool orig, bool bswap>
static void hasshe2_sse2( const uint8_t * input_buf, size_t n_bytes, uint64_t seed, void * output_state ) {
    __m128i coeffs_1, coeffs_2, rnd_data, seed_xmm, len_xmm, input, state_1, state_2;

    coeffs_1 = _mm_load_si128((__m128i *)coeffs      );
    coeffs_2 = _mm_load_si128((__m128i *)(coeffs + 4));
    rnd_data = _mm_load_si128((__m128i *)(coeffs + 8));
    seed_xmm = _mm_set_epi64x(seed, seed);
    len_xmm  = _mm_set_epi32(n_bytes, n_bytes, n_bytes, n_bytes);

    /*
     * Initialize internal state to something random.  (Alternatively,
     * if hashing a chain of data, read in the previous hash result from
     * somewhere.)
     *
     * Seeding is homegrown for SMHasher3
     */
    state_1 = state_2 = _mm_xor_si128(rnd_data, seed_xmm);

    while (n_bytes >= 16) {
        /*
         * Read in 16 bytes, or 128 bits, from buf.  Advance buf and
         * decrement n_bytes accordingly.
         */
        input      = _mm_loadu_si128((__m128i *)input_buf);
        if (bswap) { input = mm_bswap64(input); }
        input_buf += 16;
        n_bytes   -= 16;

        COMBINE_AND_MIX(coeffs_1, coeffs_2, state_1, state_2, input);
    }
    if (n_bytes > 0) {
        alignas(16) uint8_t buf[16];
        memcpy(buf, input_buf, n_bytes);
        memset(buf + n_bytes, 0, 16 - n_bytes);
        input = _mm_load_si128((__m128i *)buf);
        if (bswap) { input = mm_bswap64(input); }
        COMBINE_AND_MIX(coeffs_1, coeffs_2, state_1, state_2, input);
    }

    /*
     * Postprocessing.  Copy half of the internal state into fake input,
     * replace it with the constant rnd_data, and do one combine and mix
     * phase more.
     */
    input   = orig ? state_1 : _mm_xor_si128(state_1, len_xmm);
    state_1 = rnd_data;

    COMBINE_AND_MIX(coeffs_1, coeffs_2, state_1, state_2, input);

    if (bswap) {
        state_1 = mm_bswap64(state_1);
        state_2 = mm_bswap64(state_2);
    }
    _mm_storeu_si128((__m128i *)output_state, state_1);
    _mm_storeu_si128((__m128i *)((char *)output_state + 16), state_2);
}

#endif

template <bool orig, bool bswap>
static void Hasshe2( const void * in, const size_t len, const seed_t seed, void * out ) {
#if defined(HAVE_SSE_2)
    hasshe2_sse2<orig, bswap>((const uint8_t *)in, len, (uint64_t)seed, out);
#else
    hasshe2_portable<orig, bswap>((const uint8_t *)in, len, (uint64_t)seed, out);
#endif
}

REGISTER_FAMILY(hasshe2,
   $.src_url    = "http://cessu.blogspot.com/2008/11/hashing-with-sse2-revisited-or-my-hash.html",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(hasshe2,
   $.desc       = "hasshe2 (SSE2-oriented hash)",
   $.impl       = HASSHE2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS           |
         FLAG_IMPL_MULTIPLY               |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN  |
         FLAG_IMPL_SLOW,
   $.bits = 256,
   $.verification_LE = 0x68CBC5F1,
   $.verification_BE = 0x562ECEB4,
   $.hashfn_native   = Hasshe2<true, false>,
   $.hashfn_bswap    = Hasshe2<true, true>,
   $.badseeddesc     = "All seeds collide on keys of all zero bytes when (len/16) is constant."
 );

REGISTER_HASH(hasshe2__tweaked,
   $.desc       = "hasshe2 (SSE2-oriented hash, tweaked to mix len into hash)",
   $.impl       = HASSHE2_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY               |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN  |
         FLAG_IMPL_SLOW,
   $.bits = 256,
   $.verification_LE = 0x7FE1B096,
   $.verification_BE = 0x917658B8,
   $.hashfn_native   = Hasshe2<false, false>,
   $.hashfn_bswap    = Hasshe2<false, true>
 );
