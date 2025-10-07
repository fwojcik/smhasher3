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
  #define HH_COMPILER_FENCE __asm__ __volatile__ ("" : : : "memory")
#else
  #define HH_COMPILER_FENCE
#endif

//------------------------------------------------------------

typedef __m256i block_t;

typedef struct state_struct {
    __m256i  v0;
    __m256i  v1;
    __m256i  mul0;
    __m256i  mul1;
} highwayhash_state_t;

void dump_state( const highwayhash_state_t * s ) {
    return;
    printf("\tv0   %016llx %016llx %016llx %016llx\n", s->v0[0]  , s->v0[1]  , s->v0[2]  , s->v0[3]  );
    printf("\tv1   %016llx %016llx %016llx %016llx\n", s->v1[0]  , s->v1[1]  , s->v1[2]  , s->v1[3]  );
    printf("\tmul0 %016llx %016llx %016llx %016llx\n", s->mul0[0], s->mul0[1], s->mul0[2], s->mul0[3]);
    printf("\tmul1 %016llx %016llx %016llx %016llx\n", s->mul1[0], s->mul1[1], s->mul1[2], s->mul1[3]);
    printf("\n");
}

alignas(32) static thread_local highwayhash_state_t seeded_state;

static uintptr_t HighwayHashReseed( const seed_t seed ) {
    alignas(16) static const uint64_t key[4] = { 1, 2, 3, 4 };
    const __m256i seedvec = _mm256_set1_epi64x((uint64_t)seed);
    const __m256i keyvec0 = _mm256_xor_si256(_mm256_load_si256((__m256i *)key), seedvec);
    const __m256i keyvec1 = _mm256_shuffle_epi32(keyvec0, _MM_SHUFFLE(2, 3, 0, 1));

    seeded_state.mul0 = _mm256_load_si256((__m256i *)init0);
    seeded_state.mul1 = _mm256_load_si256((__m256i *)init1);
    seeded_state.v0   = _mm256_xor_si256(seeded_state.mul0, keyvec0);
    seeded_state.v1   = _mm256_xor_si256(seeded_state.mul1, keyvec1);

    return (uintptr_t)(void *)&seeded_state;
}

//------------------------------------------------------------

static HH_INLINE void GetBlock( block_t & HH_RESTRICT block, const uint8_t * HH_RESTRICT bytes ) {
    block = _mm256_loadu_si256((__m256i *)bytes);
    if (isBE()) {
        block = mm256_bswap64(block);
    }
}

static HH_INLINE void GetRemainder( block_t & HH_RESTRICT block, const uint8_t * HH_RESTRICT bytes,
        const size_t size_mod32 ) {
    const uint8_t * remainder = bytes + (size_mod32 & ~3);
    const size_t    size_mod4 = size_mod32 & 3;
    const __m128i   size      = _mm_set1_epi32(size_mod32);

    // (Branching is faster than a single _mm256_maskload_epi32.)
    if (unlikely(size_mod32 & 16)) { // 16..31 bytes left
        const __m128i  packetL    = _mm_loadu_si128((__m128i *)bytes);
        const __m128i  maskvals   = _mm_set_epi32(31, 27, 23, 19);
        const __m128i  int_mask   = _mm_cmpgt_epi32(size, maskvals);
        const __m128i  int_lanes  = _mm_maskload_epi32((const int *)(bytes + 16), int_mask);
        const uint32_t last4      = COND_BSWAP(Load3LE_AllowReadBefore(remainder, size_mod4), isBE());
        const __m128i  packetH    = _mm_insert_epi32(int_lanes, last4, 3);
        const __m256i  packetL256 = _mm256_castsi128_si256(packetL);
        block = _mm256_inserti128_si256(packetL256, packetH, 1);
    } else {
        const __m128i  maskvals = _mm_set_epi32(15, 11, 7, 3);
        const __m128i  int_mask = _mm_cmpgt_epi32(size, maskvals);
        const __m128i  packetL  = _mm_maskload_epi32((const int *)bytes, int_mask);
        const uint64_t last3    = COND_BSWAP(Load3LE_AllowUnordered(remainder, size_mod4), isBE());
        // Rather than insert into packetL[3], it is faster to initialize
        // the otherwise empty packetH.
        const __m128i packetH    = _mm_cvtsi64_si128(last3);
        const __m256i packetL256 = _mm256_castsi128_si256(packetL);
        block = _mm256_inserti128_si256(packetL256, packetH, 1);
    }
}

//------------------------------------------------------------

static HH_INLINE __m256i ZipperMerge( const __m256i & v ) {
    const __m256i hilomask = {
        UINT64_C(0x000F010E05020C03), UINT64_C(0x070806090D0A040B),
        UINT64_C(0x000F010E05020C03), UINT64_C(0x070806090D0A040B)
    };

    return _mm256_shuffle_epi8(v, hilomask);
}

static HH_INLINE void Update( highwayhash_state_t * s, const block_t & packet ) {
    __m256i tmp;

    // printf("\tUPD  %016llx %016llx %016llx %016llx\n", packet[0], packet[1], packet[2], packet[3]);

    s->v1   = _mm256_add_epi64(s->v1, packet );            // v1   += packet
    s->v1   = _mm256_add_epi64(s->v1, s->mul0);            // v1   += mul0
    tmp     = _mm256_mul_epu32(s->v1, _mm256_srli_epi64(s->v0, 32));
    s->mul0 = _mm256_xor_si256(s->mul0, tmp);              // mul0 ^= MulLow32(v1, v0 >> 32);
    HH_COMPILER_FENCE;
    s->v0   = _mm256_add_epi64(s->v0, s->mul1);            // v0   += mul1;
    tmp     = _mm256_mul_epu32(s->v0, _mm256_srli_epi64(s->v1, 32));
    s->mul1 = _mm256_xor_si256(s->mul1, tmp);              // mul1 ^= MulLow32(v0, v1 >> 32);
    HH_COMPILER_FENCE;
    s->v0   = _mm256_add_epi64(s->v0, ZipperMerge(s->v1)); // v0 += ZipperMerge(v1);
    s->v1   = _mm256_add_epi64(s->v1, ZipperMerge(s->v0)); // v1 += ZipperMerge(v0);
}

static HH_INLINE void PermuteAndUpdate( highwayhash_state_t * state ) {
    // This is faster than extracti128 plus inserti128 followed by
    // Rotate64By32.
    const __m256i indices = {
        UINT64_C(0x0000000400000005), UINT64_C(0x0000000600000007),
        UINT64_C(0x0000000000000001), UINT64_C(0x0000000200000003),
    };
    const __m256i permuted = _mm256_permutevar8x32_epi32(state->v0, indices);

    Update(state, permuted);
}

static HH_INLINE void PadState( highwayhash_state_t * state, const size_t size_mod32 ) {
    const __m256i size256     = _mm256_broadcastd_epi32(_mm_cvtsi64_si128(size_mod32));
    const __m256i C32         = _mm256_broadcastd_epi32(_mm_cvtsi32_si128(32));
    const __m256i C32msize256 = _mm256_sub_epi32(C32, size256);

    state->v0 = _mm256_add_epi64(state->v0, size256);

    // Use variable shifts because sll_epi32 has 4 cycle latency (presumably
    // to broadcast the shift count).
    const __m256i shifted_left  = _mm256_sllv_epi32(state->v1, size256);
    const __m256i shifted_right = _mm256_srlv_epi32(state->v1, C32msize256);
    state->v1 = _mm256_or_si256(shifted_left, shifted_right);
}

//------------------------------------------------------------

// XORs a << 1 and a << 2 into b after clearing the upper two bits of a.
// Also does the same for the upper 128 bit lane "b". Bit shifts are only
// possible on independent 64-bit lanes. We therefore insert the upper bits
// of a[0] that were lost into a[1]. Thanks to D. Lemire for helpful comments!
static HH_INLINE __m256i ModularReduction( const __m256i & HH_RESTRICT b32a32, const __m256i & HH_RESTRICT b10a10 ) {
    __m256i out                     = b10a10;

    const __m256i zero              = _mm256_xor_si256(b32a32, b32a32);
    const __m256i top_bits2         = _mm256_srli_epi64(b32a32, 64 - 2);
    const __m256i ones              = _mm256_cmpeq_epi64(b32a32, b32a32); // FF .. FF
    const __m256i shifted1_unmasked = _mm256_add_epi64(b32a32, b32a32);   // (avoids needing port0)

    HH_COMPILER_FENCE;

    // Only the lower halves of top_bits1's 128 bit lanes will be used, so we
    // can compute it before clearing the upper two bits of b32a32.
    const __m256i top_bits1    = _mm256_srli_epi64(b32a32, 64 - 1);
    const __m256i upper_8bytes = _mm256_slli_si256(ones, 8); // F 0 F 0
    const __m256i shifted2     = _mm256_add_epi64(shifted1_unmasked, shifted1_unmasked);
    HH_COMPILER_FENCE;

    const __m256i upper_bit_of_128 = _mm256_slli_epi64(upper_8bytes, 63); // 80..00 80..00
    const __m256i new_low_bits2    = _mm256_unpacklo_epi64(zero, top_bits2);
    out = _mm256_xor_si256(out, shifted2);
    HH_COMPILER_FENCE;

    // The result must be as if the upper two bits of the input had been clear,
    // otherwise we're no longer computing a reduction.
    const __m256i shifted1 = _mm256_andnot_si256(upper_bit_of_128, shifted1_unmasked);
    out = _mm256_xor_si256(out, new_low_bits2);
    HH_COMPILER_FENCE;

    const __m256i new_low_bits1 = _mm256_unpacklo_epi64(zero, top_bits1);
    out = _mm256_xor_si256(out, shifted1);

    out = _mm256_xor_si256(out, new_low_bits1);

    return out;
}

template <bool bswap, unsigned output_words>
static HH_INLINE void Finalize( const highwayhash_state_t * state, uint8_t * out ) {
    const __m256i sum0 = _mm256_add_epi64(state->v0, state->mul0);
    const __m256i sum1 = _mm256_add_epi64(state->v1, state->mul1);

    if (output_words == 1) {
        const __m128i sum2 = _mm256_castsi256_si128(sum0);
        const __m128i sum3 = _mm256_castsi256_si128(sum1);
        __m128i       hash = _mm_add_epi64(sum2, sum3);
        if (bswap) {
            hash = mm_bswap64(hash);
        }
        _mm_storel_epi64((__m128i *)out, hash);
    } else if (output_words == 2) {
        const __m128i sum2 = _mm256_castsi256_si128(sum0);
        const __m128i sum3 = _mm256_extracti128_si256(sum1, 1);
        __m128i       hash = _mm_add_epi64(sum2, sum3);
        if (bswap) {
            hash = mm_bswap64(hash);
        }
        _mm_storeu_si128((__m128i *)out, hash);
    } else {
        __m256i hash = ModularReduction(sum1, sum0);
        if (bswap) {
            hash = mm256_bswap64(hash);
        }
        _mm256_storeu_si256((__m256i *)out, hash);
    }
}
