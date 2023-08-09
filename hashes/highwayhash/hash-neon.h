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

#if defined(HAVE_ARM_ASM) || defined(HAVE_ARM64_ASM)
  #define HH_COMPILER_FENCE __asm__ __volatile__ ("" : : : "memory")
#else
  #define HH_COMPILER_FENCE
#endif

// Prevent Clang from converting to vaddhn when nearby vmovn, which
// causes four spills in the main loop on ARMv7a.
#if defined(__GNUC__)
  #define HH_ADD_FENCE(v) __asm__("" : "+w" (v))
#else
  #define HH_ADD_FENCE(v)
#endif

static HH_INLINE uint64x2_t vld1q_low_u64( const uint64_t * p ) {
    return vcombine_u64(vld1_u64(p), vdup_n_u64(0));
}

#define vshlq_n_u128(a, imm) (vreinterpretq_u64_u8(vextq_u8(vdupq_n_u8(0), vreinterpretq_u8_u64(a), 16 - (imm))))

//------------------------------------------------------------

typedef uint64x2_t block_t[2];

typedef struct state_struct {
    uint64x2_t v0L, v0H;
    uint64x2_t v1L, v1H;
    uint64x2_t mul0L, mul0H;
    uint64x2_t mul1L, mul1H;
} highwayhash_state_t;

void dump_state(const highwayhash_state_t * s) {
    return;
    printf("\tv0   %016lx %016lx %016lx %016lx\n", s->v0L[0], s->v0L[1], s->v0H[0], s->v0H[1]);
    printf("\tv1   %016lx %016lx %016lx %016lx\n", s->v1L[0], s->v1L[1], s->v1H[0], s->v1H[1]);
    printf("\tmul0 %016lx %016lx %016lx %016lx\n", s->mul0L[0], s->mul0L[1], s->mul0H[0], s->mul0H[1]);
    printf("\tmul1 %016lx %016lx %016lx %016lx\n", s->mul1L[0], s->mul1L[1], s->mul1H[0], s->mul1H[1]);
    printf("\n");
}

alignas(16) static thread_local highwayhash_state_t seeded_state;

static uintptr_t HighwayHashReseed( const seed_t seed ) {
    alignas(16) static const uint64_t key[4] = { 1, 2, 3, 4 };
    const uint64x2_t seedvec  = vdupq_n_u64((uint64_t)seed);
    const uint64x2_t keyvec0L = veorq_u64(vreinterpretq_u64_u8(vld1q_u8((const uint8_t *)&key[0])), seedvec);
    const uint64x2_t keyvec0H = veorq_u64(vreinterpretq_u64_u8(vld1q_u8((const uint8_t *)&key[2])), seedvec);
    const uint64x2_t keyvec1L = vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64(keyvec0L)));
    const uint64x2_t keyvec1H = vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64(keyvec0H)));

    seeded_state.mul0L = vreinterpretq_u64_u8(vld1q_u8((const uint8_t *)&init0[0]));
    seeded_state.mul0H = vreinterpretq_u64_u8(vld1q_u8((const uint8_t *)&init0[2]));
    seeded_state.mul1L = vreinterpretq_u64_u8(vld1q_u8((const uint8_t *)&init1[0]));
    seeded_state.mul1H = vreinterpretq_u64_u8(vld1q_u8((const uint8_t *)&init1[2]));
    seeded_state.v0L   = veorq_u64(seeded_state.mul0L, keyvec0L);
    seeded_state.v0H   = veorq_u64(seeded_state.mul0H, keyvec0H);
    seeded_state.v1L   = veorq_u64(seeded_state.mul1L, keyvec1L);
    seeded_state.v1H   = veorq_u64(seeded_state.mul1H, keyvec1H);

    return (uintptr_t)(void *)&seeded_state;
}

//------------------------------------------------------------

static HH_INLINE void GetBlock( block_t & HH_RESTRICT block, const uint8_t * HH_RESTRICT bytes ) {
    block[0] = vreinterpretq_u64_u8(vld1q_u8((const uint8_t *)bytes));
    block[1] = vreinterpretq_u64_u8(vld1q_u8((const uint8_t *)(bytes + 16)));
    if (isBE()) {
        block[0] = Vbswap64_u64(block[0]);
        block[1] = Vbswap64_u64(block[1]);
    }
}

static HH_INLINE uint64x2_t LoadMultipleOfFour( const uint8_t * bytes, const size_t size ) {
    // Mask of 1-bits where the final 4 bytes should be inserted (replacement
    // for variable shift/insert using broadcast+blend).
    alignas(16) const uint64_t mask_pattern[2] = { UINT64_C(0xFFFFFFFF), 0 };
    uint64x2_t mask4 = vld1q_u64(mask_pattern);  // 'insert' into lane 0
    uint64x2_t ret   = vdupq_n_u64(0);

    if (size & 8) {
        ret    = vld1q_low_u64((const uint64_t *)bytes);
        mask4  = vshlq_n_u128(mask4, 8); // mask4 = 0 ~0 0 0 ('insert' into lane 2)
        bytes += 8;
    }
    if (size & 4) {
        // = 0 word2 0 word2; mask4 will select which lane to keep.
        const uint64x2_t broadcast = vreinterpretq_u64_u32(vdupq_n_u32(GET_U32<false>(bytes, 0)));
        // (slightly faster than blendv_epi8)
        ret = vorrq_u64(ret, vandq_u64(broadcast, mask4));
    }
    return ret;
}

static HH_INLINE void GetRemainder( block_t & HH_RESTRICT block, const uint8_t * HH_RESTRICT bytes, const size_t size_mod32 ) {
    const uint8_t * remainder = bytes + (size_mod32 & ~3);
    const size_t    size_mod4 = size_mod32 & 3;

    if (unlikely(size_mod32 & 16)) {  // 16..31 bytes left
        const uint64x2_t  packetL    = vreinterpretq_u64_u8(vld1q_u8(bytes));
              uint64x2_t  packetH    = LoadMultipleOfFour(bytes + 16, size_mod32);
        const uint32_t    last4      = COND_BSWAP(Load3LE_AllowReadBefore(remainder, size_mod4), isBE());
        packetH  = vreinterpretq_u64_u32(vsetq_lane_u32(last4, vreinterpretq_u32_u64(packetH), 3));
        block[0] = packetL;
        block[1] = packetH;
    } else {
        const uint64x2_t  packetL    = LoadMultipleOfFour(bytes, size_mod32);
        const uint64_t    last4      = COND_BSWAP(Load3LE_AllowUnordered(remainder, size_mod4), isBE());
        // Rather than insert into packetL[3], it is faster to initialize
        // the otherwise empty packetH.
        alignas(16) uint64_t tmp[2]  = { last4, 0 };
        const uint64x2_t  packetH    = vld1q_u64(tmp);
        block[0] = packetL;
        block[1] = packetH;
    }
}

//------------------------------------------------------------
static HH_INLINE uint64x2_t ZipperMerge(const uint64x2_t& v) {
    const uint8_t shuffle_positions[] = {
         3, 12,  2,  5, 14,  1, 15,  0,
        11,  4, 10, 13,  9,  6,  8,  7
    };
    const uint8x16_t tbl = vld1q_u8(shuffle_positions);
    // Note: vqtbl1q_u8 is polyfilled for ARMv7a in vector_neon.h.
    return vreinterpretq_u64_u8(vqtbl1q_u8(vreinterpretq_u8_u64(v), tbl));
}

static HH_INLINE void Update( highwayhash_state_t * s, const block_t& packet ) {
    uint64x2_t tmpL, tmpH;
    //printf("\tUPD  %016lx %016lx %016lx %016lx\n", packet[0][0], packet[0][1], packet[1][0], packet[1][1]);

    s->v1L   = vaddq_u64(s->v1L, packet[0]); HH_ADD_FENCE(s->v1L); // v1   += packet
    s->v1H   = vaddq_u64(s->v1H, packet[1]); HH_ADD_FENCE(s->v1H);
    s->v1L   = vaddq_u64(s->v1L, s->mul0L); HH_ADD_FENCE(s->v1L);  // v1   += mul0
    s->v1H   = vaddq_u64(s->v1H, s->mul0H); HH_ADD_FENCE(s->v1H);
    tmpL     = vmull_u32(vmovn_u64(s->v1L), vshrn_n_u64(s->v0L, 32));
    tmpH     = vmull_u32(vmovn_u64(s->v1H), vshrn_n_u64(s->v0H, 32));
    s->mul0L = veorq_u64(s->mul0L, tmpL);                          // mul0 ^= MulLow32(v1, v0 >> 32);
    s->mul0H = veorq_u64(s->mul0H, tmpH);
    s->v0L   = vaddq_u64(s->v0L, s->mul1L); HH_ADD_FENCE(s->v0L);  // v0   += mul1;
    s->v0H   = vaddq_u64(s->v0H, s->mul1H); HH_ADD_FENCE(s->v0H);
    tmpL     = vmull_u32(vmovn_u64(s->v0L), vshrn_n_u64(s->v1L, 32));
    tmpH     = vmull_u32(vmovn_u64(s->v0H), vshrn_n_u64(s->v1H, 32));
    s->mul1L = veorq_u64(s->mul1L, tmpL);                          // mul1 ^= MulLow32(v0, v1 >> 32);
    s->mul1H = veorq_u64(s->mul1H, tmpH);
    s->v0L   = vaddq_u64(s->v0L, ZipperMerge(s->v1L));             // v0 += ZipperMerge(v1);
    s->v0H   = vaddq_u64(s->v0H, ZipperMerge(s->v1H));
    s->v1L   = vaddq_u64(s->v1L, ZipperMerge(s->v0L));             // v1 += ZipperMerge(v0);
    s->v1H   = vaddq_u64(s->v1H, ZipperMerge(s->v0H));
}

static HH_INLINE void PermuteAndUpdate( highwayhash_state_t * state ) {
    block_t permuted_block;
    permuted_block[1] = vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64(state->v0L)));
    permuted_block[0] = vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64(state->v0H)));

    Update(state, permuted_block);
}

static HH_INLINE void PadState( highwayhash_state_t * state, const size_t size_mod32 ) {
    // v0 += size_mod32
    // We can't use vshl/vsra because it needs a constant expression.
    // In order to do this right now, we would need a switch statement.
    const int32x4_t vsize_mod32     = vdupq_n_s32((int32_t)size_mod32);
    // -32 - size_mod32
    const int32x4_t shift_right_amt = vdupq_n_s32((int32_t)size_mod32 + (~32 + 1));
    state->v0L = vaddq_u64(state->v0L, vreinterpretq_u64_s32(vsize_mod32));
    state->v0H = vaddq_u64(state->v0H, vreinterpretq_u64_s32(vsize_mod32));

    // v1 = Rotate32By(v1, size_mod32)
    state->v1L = vreinterpretq_u64_u32(vorrq_u32(
            vshlq_u32(vreinterpretq_u32_u64(state->v1L), vsize_mod32),
            vshlq_u32(vreinterpretq_u32_u64(state->v1L), shift_right_amt)));
    state->v1H = vreinterpretq_u64_u32(vorrq_u32(
            vshlq_u32(vreinterpretq_u32_u64(state->v1H), vsize_mod32),
            vshlq_u32(vreinterpretq_u32_u64(state->v1H), shift_right_amt)));
}

//------------------------------------------------------------
// XORs a << 1 and a << 2 into b after clearing the upper two bits of a.
// Also does the same for the upper 128 bit lane "b". Bit shifts are only
// possible on independent 64-bit lanes. We therefore insert the upper bits
// of a[0] that were lost into a[1]. Thanks to D. Lemire for helpful comments!
static HH_INLINE uint64x2_t ModularReduction( const uint64x2_t & HH_RESTRICT a32_unmasked, const uint64x2_t & HH_RESTRICT a10 ) {
    uint64x2_t out = a10;

    const uint32x4_t zero        = vdupq_n_u32(0);
    const uint64x2_t sign_bit128 = vreinterpretq_u64_u32(vsetq_lane_u32(UINT32_C(0x80000000), zero, 3));
    const uint64x2_t top_bits2   = vshrq_n_u64(a32_unmasked, 64 - 2);
    HH_COMPILER_FENCE;

    uint64x2_t shifted1_unmasked = vaddq_u64(a32_unmasked, a32_unmasked);
    HH_ADD_FENCE(shifted1_unmasked);
    // Only the lower halves of top_bits1's 128 bit lanes will be used, so we
    // can compute it before clearing the upper two bits of a32_unmasked.
    const uint64x2_t top_bits1 = vshrq_n_u64(a32_unmasked, 64 - 1);
          uint64x2_t shifted2  = vaddq_u64(shifted1_unmasked, shifted1_unmasked);
    HH_ADD_FENCE(shifted2);
    HH_COMPILER_FENCE;

    const uint64x2_t new_low_bits2 = vshlq_n_u128(top_bits2, 8);
    out = veorq_u64(out, shifted2);
    // The result must be as if the upper two bits of the input had been clear,
    // otherwise we're no longer computing a reduction.
    const uint64x2_t shifted1 = vbicq_u64(shifted1_unmasked, sign_bit128);
    HH_COMPILER_FENCE;

    const uint64x2_t new_low_bits1 = vshlq_n_u128(top_bits1, 8);
    out = veorq_u64(out, new_low_bits2);
    out = veorq_u64(out, shifted1);
    out = veorq_u64(out, new_low_bits1);

    return out;
}

template <bool bswap, unsigned output_words>
static HH_INLINE void Finalize( const highwayhash_state_t * state, uint8_t * out ) {
    if (output_words == 1) {
        uint64x2_t sum0 = vaddq_u64(state->v0L, state->mul0L); HH_ADD_FENCE(sum0);
        uint64x2_t sum1 = vaddq_u64(state->v1L, state->mul1L); HH_ADD_FENCE(sum1);
        uint64x2_t hash = vaddq_u64(sum0, sum1);               HH_ADD_FENCE(hash);
        if (bswap) {
            hash = Vbswap64_u64(hash);
        }
        vst1_u8(out, vreinterpret_u8_u64(vget_low_u64(hash)));
    } else if (output_words == 2) {
        uint64x2_t sum0 = vaddq_u64(state->v0L, state->mul0L); HH_ADD_FENCE(sum0);
        uint64x2_t sum1 = vaddq_u64(state->v1H, state->mul1H); HH_ADD_FENCE(sum1);
        uint64x2_t hash = vaddq_u64(sum0, sum1);               HH_ADD_FENCE(hash);
        if (bswap) {
            hash = Vbswap64_u64(hash);
        }
        vst1q_u8(out, vreinterpretq_u8_u64(hash));
    } else {
        dump_state(state);
        uint64x2_t sum0L = vaddq_u64(state->v0L, state->mul0L); HH_ADD_FENCE(sum0L);
        uint64x2_t sum1L = vaddq_u64(state->v1L, state->mul1L); HH_ADD_FENCE(sum1L);
        uint64x2_t sum0H = vaddq_u64(state->v0H, state->mul0H); HH_ADD_FENCE(sum0H);
        uint64x2_t sum1H = vaddq_u64(state->v1H, state->mul1H); HH_ADD_FENCE(sum1H);
        uint64x2_t hashL = ModularReduction(sum1L, sum0L);
        uint64x2_t hashH = ModularReduction(sum1H, sum0H);
        if (bswap) {
            hashL = Vbswap64_u64(hashL);
            hashH = Vbswap64_u64(hashH);
        }
        vst1q_u8(out,      vreinterpretq_u8_u64(hashL));
        vst1q_u8(out + 16, vreinterpretq_u8_u64(hashH));
    }
}
