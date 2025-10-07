/*
 * HighwayHash
 * Copyright (C) 2023       Frank J. T. Wojcik
 * Copyright (C) 2016-2019  Google Inc.
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
 */

#if defined(_MSC_VER)
  #include <intrin.h>
  #pragma intrinsic(_ReadWriteBarrier)
  #define HH_COMPILER_FENCE _ReadWriteBarrier()
#elif defined(HAVE_X86_64_ASM)
  #define HH_COMPILER_FENCE asm volatile("" : : : "memory")
#else
  #define HH_COMPILER_FENCE
#endif

//------------------------------------------------------------

typedef __m128i block_t[2];

typedef struct state_struct {
    __m128i  v0L, v0H;
    __m128i  v1L, v1H;
    __m128i  mul0L, mul0H;
    __m128i  mul1L, mul1H;
} highwayhash_state_t;

void dump_state( const highwayhash_state_t * s ) {
    return;
    printf("\tv0   %016llx %016llx %016llx %016llx\n", s->v0L[0]  , s->v0L[1]  , s->v0H[0]  , s->v0H[1]  );
    printf("\tv1   %016llx %016llx %016llx %016llx\n", s->v1L[0]  , s->v1L[1]  , s->v1H[0]  , s->v1H[1]  );
    printf("\tmul0 %016llx %016llx %016llx %016llx\n", s->mul0L[0], s->mul0L[1], s->mul0H[0], s->mul0H[1]);
    printf("\tmul1 %016llx %016llx %016llx %016llx\n", s->mul1L[0], s->mul1L[1], s->mul1H[0], s->mul1H[1]);
    printf("\n");
}

alignas(32) static thread_local highwayhash_state_t seeded_state;

static uintptr_t HighwayHashReseed( const seed_t seed ) {
    alignas(16) static const uint64_t key[4] = { 1, 2, 3, 4 };
    const __m128i seedvec  = _mm_set1_epi64x((uint64_t)seed);
    const __m128i keyvec0L = _mm_xor_si128(_mm_load_si128((__m128i *)&key[0]), seedvec);
    const __m128i keyvec0H = _mm_xor_si128(_mm_load_si128((__m128i *)&key[2]), seedvec);
    const __m128i keyvec1L = _mm_shuffle_epi32(keyvec0L, _MM_SHUFFLE(2, 3, 0, 1));
    const __m128i keyvec1H = _mm_shuffle_epi32(keyvec0H, _MM_SHUFFLE(2, 3, 0, 1));

    seeded_state.mul0L = _mm_load_si128((__m128i *)&init0[0]);
    seeded_state.mul0H = _mm_load_si128((__m128i *)&init0[2]);
    seeded_state.mul1L = _mm_load_si128((__m128i *)&init1[0]);
    seeded_state.mul1H = _mm_load_si128((__m128i *)&init1[2]);
    seeded_state.v0L   = _mm_xor_si128(seeded_state.mul0L, keyvec0L);
    seeded_state.v0H   = _mm_xor_si128(seeded_state.mul0H, keyvec0H);
    seeded_state.v1L   = _mm_xor_si128(seeded_state.mul1L, keyvec1L);
    seeded_state.v1H   = _mm_xor_si128(seeded_state.mul1H, keyvec1H);

    return (uintptr_t)(void *)&seeded_state;
}

//------------------------------------------------------------

static HH_INLINE void GetBlock( block_t & HH_RESTRICT block, const uint8_t * HH_RESTRICT bytes ) {
    block[0] = _mm_loadu_si128((__m128i *)bytes);
    block[1] = _mm_loadu_si128((__m128i *)(bytes + 16));
    if (isBE()) {
        block[0] = mm_bswap64(block[0]);
        block[1] = mm_bswap64(block[1]);
    }
}

static HH_INLINE __m128i LoadMultipleOfFour( const uint8_t * bytes, const size_t size ) {
    __m128i mask4 = _mm_cvtsi64_si128(UINT64_C(0xFFFFFFFF));
    __m128i ret   = _mm_setzero_si128();

    if (size & 8) {
        ret    = _mm_loadl_epi64((const __m128i *)bytes);
        mask4  = _mm_slli_si128(mask4, 8);
        bytes += 8;
    }
    if (size & 4) {
        const __m128i word2     = _mm_cvtsi32_si128(GET_U32<false>(bytes, 0));
        const __m128i broadcast = _mm_shuffle_epi32(word2, 0x00);
        ret = _mm_or_si128(ret, _mm_and_si128(broadcast, mask4));
    }
    return ret;
}

static HH_INLINE void GetRemainder( block_t & HH_RESTRICT block, const uint8_t * HH_RESTRICT bytes,
        const size_t size_mod32 ) {
    const uint8_t * remainder = bytes + (size_mod32 & ~3);
    const size_t    size_mod4 = size_mod32 & 3;

    // const __m128i   size      = _mm_set1_epi32(size_mod32);

    if (unlikely(size_mod32 & 16)) { // 16..31 bytes left
        const __m128i  packetL = _mm_loadu_si128((__m128i *)bytes);
        __m128i        packetH = LoadMultipleOfFour(bytes + 16, size_mod32);
        const uint32_t last4   = COND_BSWAP(Load3LE_AllowReadBefore(remainder, size_mod4), isBE());
        packetH  = _mm_insert_epi32(packetH, last4, 3);
        block[0] = packetL;
        block[1] = packetH;
    } else {
        const __m128i  packetL = LoadMultipleOfFour(bytes, size_mod32);
        const uint64_t last4   = COND_BSWAP(Load3LE_AllowUnordered(remainder, size_mod4), isBE());
        // Rather than insert into packetL[3], it is faster to initialize
        // the otherwise empty packetH.
        const __m128i  packetH    = _mm_cvtsi64_si128(last4);
        block[0] = packetL;
        block[1] = packetH;
    }
}

//------------------------------------------------------------

static HH_INLINE __m128i ZipperMerge( const __m128i & v ) {
    const __m128i hilomask = {
        UINT64_C(0x000F010E05020C03), UINT64_C(0x070806090D0A040B)
    };

    return _mm_shuffle_epi8(v, hilomask);
}

static HH_INLINE void Update( highwayhash_state_t * s, const block_t & packet ) {
    __m128i tmpL, tmpH;

    // printf("\tUPD  %016llx %016llx %016llx %016llx\n", packet[0][0], packet[0][1], packet[1][0], packet[1][1]);

    s->v1L   = _mm_add_epi64(s->v1L, packet[0]);           // v1   += packet
    s->v1H   = _mm_add_epi64(s->v1H, packet[1]);
    s->v1L   = _mm_add_epi64(s->v1L, s->mul0L );           // v1   += mul0
    s->v1H   = _mm_add_epi64(s->v1H, s->mul0H );
    tmpL     = _mm_mul_epu32(s->v1L, _mm_shuffle_epi32(s->v0L, _MM_SHUFFLE(2, 3, 0, 1)));
    tmpH     = _mm_mul_epu32(s->v1H, _mm_srli_epi64(s->v0H, 32));
    s->mul0L = _mm_xor_si128(s->mul0L, tmpL);              // mul0 ^= MulLow32(v1, v0 >> 32);
    s->mul0H = _mm_xor_si128(s->mul0H, tmpH);
    s->v0L   = _mm_add_epi64(s->v0L, s->mul1L);            // v0   += mul1;
    s->v0H   = _mm_add_epi64(s->v0H, s->mul1H);
    tmpL     = _mm_mul_epu32(s->v0L, _mm_shuffle_epi32(s->v1L, _MM_SHUFFLE(2, 3, 0, 1)));
    tmpH     = _mm_mul_epu32(s->v0H, _mm_srli_epi64(s->v1H, 32));
    s->mul1L = _mm_xor_si128(s->mul1L, tmpL);              // mul1 ^= MulLow32(v0, v1 >> 32);
    s->mul1H = _mm_xor_si128(s->mul1H, tmpH);
    s->v0L   = _mm_add_epi64(s->v0L, ZipperMerge(s->v1L)); // v0 += ZipperMerge(v1);
    s->v0H   = _mm_add_epi64(s->v0H, ZipperMerge(s->v1H));
    s->v1L   = _mm_add_epi64(s->v1L, ZipperMerge(s->v0L)); // v1 += ZipperMerge(v0);
    s->v1H   = _mm_add_epi64(s->v1H, ZipperMerge(s->v0H));
}

static HH_INLINE void PermuteAndUpdate( highwayhash_state_t * state ) {
    block_t permuted_block;

    permuted_block[1] = _mm_shuffle_epi32(state->v0L, _MM_SHUFFLE(2, 3, 0, 1));
    permuted_block[0] = _mm_shuffle_epi32(state->v0H, _MM_SHUFFLE(2, 3, 0, 1));

    Update(state, permuted_block);
}

static HH_INLINE void PadState( highwayhash_state_t * state, const size_t size_mod32 ) {
    // v0 += size_mod32
    const __m128i vsize_mod32 = _mm_set1_epi32((uint32_t)size_mod32);

    state->v0L = _mm_add_epi64(state->v0L, vsize_mod32);
    state->v0H = _mm_add_epi64(state->v0H, vsize_mod32);

    // v1 = Rotate32By(v1, size_mod32)
    const __m128i count_left     = _mm_cvtsi64_si128(size_mod32);
    const __m128i count_right    = _mm_cvtsi64_si128(32 - size_mod32);
    const __m128i shifted_leftL  = _mm_sll_epi32(state->v1L, count_left);
    const __m128i shifted_leftH  = _mm_sll_epi32(state->v1H, count_left);
    const __m128i shifted_rightL = _mm_srl_epi32(state->v1L, count_right);
    const __m128i shifted_rightH = _mm_srl_epi32(state->v1H, count_right);
    state->v1L = _mm_or_si128(shifted_leftL, shifted_rightL);
    state->v1H = _mm_or_si128(shifted_leftH, shifted_rightH);
}

//------------------------------------------------------------

// XORs a << 1 and a << 2 into b after clearing the upper two bits of a.
// Also does the same for the upper 128 bit lane "b". Bit shifts are only
// possible on independent 64-bit lanes. We therefore insert the upper bits
// of a[0] that were lost into a[1]. Thanks to D. Lemire for helpful comments!
static HH_INLINE __m128i ModularReduction( const __m128i & HH_RESTRICT a32_unmasked, const __m128i & HH_RESTRICT a10 ) {
    __m128i out               = a10;

    const __m128i zero        = _mm_setzero_si128();
    const __m128i sign_bit128 = _mm_insert_epi32(zero, UINT32_C(0x80000000), 3);
    const __m128i top_bits2   = _mm_srli_epi64(a32_unmasked, 64 - 2);

    HH_COMPILER_FENCE;

    const __m128i shifted1_unmasked = _mm_add_epi64(a32_unmasked, a32_unmasked); // (avoids needing port0)
    // Only the lower halves of top_bits1's 128 bit lanes will be used, so we
    // can compute it before clearing the upper two bits of a32_unmasked.
    const __m128i top_bits1 = _mm_srli_epi64(a32_unmasked, 64 - 1);
    const __m128i shifted2  = _mm_add_epi64(shifted1_unmasked, shifted1_unmasked);
    HH_COMPILER_FENCE;

    const __m128i new_low_bits2 = _mm_slli_si128(top_bits2, 8);
    out = _mm_xor_si128(out, shifted2);
    // The result must be as if the upper two bits of the input had been clear,
    // otherwise we're no longer computing a reduction.
    const __m128i shifted1 = _mm_andnot_si128(sign_bit128, shifted1_unmasked);
    HH_COMPILER_FENCE;

    const __m128i new_low_bits1 = _mm_slli_si128(top_bits1, 8);
    out = _mm_xor_si128(out, new_low_bits2);
    out = _mm_xor_si128(out, shifted1);
    out = _mm_xor_si128(out, new_low_bits1);

    return out;
}

template <bool bswap, unsigned output_words>
static HH_INLINE void Finalize( const highwayhash_state_t * state, uint8_t * out ) {
    if (output_words == 1) {
        const __m128i sum0 = _mm_add_epi64(state->v0L, state->mul0L);
        const __m128i sum1 = _mm_add_epi64(state->v1L, state->mul1L);
              __m128i hash = _mm_add_epi64(sum0, sum1);
        if (bswap) {
            hash = mm_bswap64(hash);
        }
        _mm_storel_epi64((__m128i *)out, hash);
    } else if (output_words == 2) {
        const __m128i sum0 = _mm_add_epi64(state->v0L, state->mul0L);
        const __m128i sum1 = _mm_add_epi64(state->v1H, state->mul1H);
              __m128i hash = _mm_add_epi64(sum0, sum1);
        if (bswap) {
            hash = mm_bswap64(hash);
        }
        _mm_storeu_si128((__m128i *)out, hash);
    } else {
        const __m128i sum0L = _mm_add_epi64(state->v0L, state->mul0L);
        const __m128i sum1L = _mm_add_epi64(state->v1L, state->mul1L);
        const __m128i sum0H = _mm_add_epi64(state->v0H, state->mul0H);
        const __m128i sum1H = _mm_add_epi64(state->v1H, state->mul1H);
              __m128i hashL = ModularReduction(sum1L, sum0L);
              __m128i hashH = ModularReduction(sum1H, sum0H);
        if (bswap) {
            hashL = mm_bswap64(hashL);
            hashH = mm_bswap64(hashH);
        }
        _mm_storeu_si128((__m128i *)out       , hashL);
        _mm_storeu_si128((__m128i *)(out + 16), hashH);
    }
}
