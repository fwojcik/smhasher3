/*
 * XXH3 ARM-specific code
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (C) 2012-2021 Yann Collet
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * You can contact the author at:
 *   - xxHash homepage: https://www.xxhash.com
 *   - xxHash source repository: https://github.com/Cyan4973/xxHash
 */

/*
 * The NEON code path is actually partially scalar when running on AArch64. This
 * is to optimize the pipelining and can have up to 15% speedup depending on the
 * CPU, and it also mitigates some GCC codegen issues.
 *
 * See XXH3_NEON_LANES for configuring this and details about this optimization.
 */
/*
 * NEON's setup for vmlal_u32 is a little more complicated than it is on
 * SSE2, AVX2, and VSX.
 *
 * While PMULUDQ and VMULEUW both perform a mask, VMLAL.U32 performs an upcast.
 *
 * To do the same operation, the 128-bit 'Q' register needs to be split into
 * two 64-bit 'D' registers, performing this operation::
 *
 *   [                a                 |                 b                ]
 *            |              '---------. .--------'                |
 *            |                         x                          |
 *            |              .---------' '--------.                |
 *   [ a & 0xFFFFFFFF | b & 0xFFFFFFFF ],[    a >> 32     |     b >> 32    ]
 *
 * Due to significant changes in aarch64, the fastest method for aarch64 is
 * completely different than the fastest method for ARMv7-A.
 *
 * ARMv7-A treats D registers as unions overlaying Q registers, so modifying
 * D11 will modify the high half of Q5. This is similar to how modifying AH
 * will only affect bits 8-15 of AX on x86.
 *
 * VZIP takes two registers, and puts even lanes in one register and odd lanes
 * in the other.
 *
 * On ARMv7-A, this strangely modifies both parameters in place instead of
 * taking the usual 3-operand form.
 *
 * Therefore, if we want to do this, we can simply use a D-form VZIP.32 on the
 * lower and upper halves of the Q register to end up with the high and low
 * halves where we want - all in one instruction.
 *
 *   vzip.32   d10, d11       @ d10 = { d10[0], d11[0] }; d11 = { d10[1], d11[1] }
 *
 * Unfortunately we need inline assembly for this: Instructions modifying two
 * registers at once is not possible in GCC or Clang's IR, and they have to
 * create a copy.
 *
 * aarch64 requires a different approach.
 *
 * In order to make it easier to write a decent compiler for aarch64, many
 * quirks were removed, such as conditional execution.
 *
 * NEON was also affected by this.
 *
 * aarch64 cannot access the high bits of a Q-form register, and writes to a
 * D-form register zero the high bits, similar to how writes to W-form scalar
 * registers (or DWORD registers on x86_64) work.
 *
 * The formerly free vget_high intrinsics now require a vext (with a few
 * exceptions)
 *
 * Additionally, VZIP was replaced by ZIP1 and ZIP2, which are the equivalent
 * of PUNPCKL* and PUNPCKH* in SSE, respectively, in order to only modify one
 * operand.
 *
 * The equivalent of the VZIP.32 on the lower and upper halves would be this
 * mess:
 *
 *   ext     v2.4s, v0.4s, v0.4s, #2 // v2 = { v0[2], v0[3], v0[0], v0[1] }
 *   zip1    v1.2s, v0.2s, v2.2s     // v1 = { v0[0], v2[0] }
 *   zip2    v0.2s, v0.2s, v1.2s     // v0 = { v0[1], v2[1] }
 *
 * Instead, we use a literal downcast, vmovn_u64 (XTN), and vshrn_n_u64 (SHRN):
 *
 *   shrn    v1.2s, v0.2d, #32  // v1 = (uint32x2_t)(v0 >> 32);
 *   xtn     v0.2s, v0.2d       // v0 = (uint32x2_t)(v0 & 0xFFFFFFFF);
 *
 * This is available on ARMv7-A, but is less efficient than a single VZIP.32.
 */

/* https://github.com/gcc-mirror/gcc/blob/38cf91e5/gcc/config/arm/arm.c#L22486 */
/* https://github.com/llvm-mirror/llvm/blob/2c4ca683/lib/Target/ARM/ARMAsmPrinter.cpp#L399 */
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__thumb__) || defined(_M_ARM))
  #define XXH_SPLIT_IN_PLACE(in, outLo, outHi)            \
      do {                                                \
      /* Undocumented GCC/Clang operand modifier: */      \
      /*     %e0 = lower D half, %f0 = upper D half */    \
      __asm__ ("vzip.32  %e0, %f0" : "+w" (in));                                                \
      (outLo) = vget_low_u32(vreinterpretq_u32_u64(in));  \
      (outHi) = vget_high_u32(vreinterpretq_u32_u64(in)); \
      } while (0)
#else
  #define XXH_SPLIT_IN_PLACE(in, outLo, outHi) \
      do {                                     \
      (outLo) = vmovn_u64(in);                 \
      (outHi) = vshrn_n_u64((in), 32);         \
      } while (0)
#endif

/*
 * `vld1q_u64` but faster and alignment-safe.
 *
 * On AArch64, unaligned access is always safe, but on ARMv7-a, it is only
 * *conditionally* safe (`vld1` has an alignment bit like `movdq[ua]` in x86).
 *
 * GCC for AArch64 sees `vld1q_u8` as an intrinsic instead of a load, so it
 * prohibits load-store optimizations. Therefore, a direct dereference is used.
 *
 * Otherwise, `vld1q_u8` is used with `vreinterpretq_u8_u64` to do a safe
 * unaligned load.
 */
#if defined(__aarch64__) && defined(__GNUC__) && !defined(__clang__)

/* silence -Wcast-align */
static FORCE_INLINE uint64x2_t XXH_vld1q_u64( void const * ptr ) {
    return *(uint64x2_t const *)ptr;
}

#else

static FORCE_INLINE uint64x2_t XXH_vld1q_u64( void const * ptr ) {
    return vreinterpretq_u64_u8(vld1q_u8((uint8_t const *)ptr));
}

#endif

// Controls the NEON to scalar ratio for XXH3
//
// On AArch64, SMHasher's XXH3 will run 6 lanes using NEON and 2 lanes
// on scalar by default.
//
// This can be set to 2, 4, 6, or 8. ARMv7 will default to all 8 NEON
// lanes, as the emulated 64-bit arithmetic is too slow.
//
// Modern ARM CPUs are _very_ sensitive to how their pipelines are used.
//
// For example, the Cortex-A73 can dispatch 3 micro-ops per cycle, but it can't
// have more than 2 NEON (F0/F1) micro-ops. If you are only using NEON instructions,
// you are only using 2/3 of the CPU bandwidth.
//
// This is even more noticable on the more advanced cores like the A76 which
// can dispatch 8 micro-ops per cycle, but still only 2 NEON micro-ops at once.
//
// Therefore, XXH3_NEON_LANES lanes will be processed using NEON, and
// the remaining lanes will use scalar instructions. This improves the
// bandwidth and also gives the integer pipelines something to do
// besides twiddling loop counters and pointers.
//
// This change benefits CPUs with large micro-op buffers without negatively affecting
// other CPUs:
//
//  | Chipset               | Dispatch type       | NEON only | 6:2 hybrid | Diff. |
//  |:----------------------|:--------------------|----------:|-----------:|------:|
//  | Snapdragon 730 (A76)  | 2 NEON/8 micro-ops  |  8.8 GB/s |  10.1 GB/s |  ~16% |
//  | Snapdragon 835 (A73)  | 2 NEON/3 micro-ops  |  5.1 GB/s |   5.3 GB/s |   ~5% |
//  | Marvell PXA1928 (A53) | In-order dual-issue |  1.9 GB/s |   1.9 GB/s |    0% |
//
// It also seems to fix some bad codegen on GCC, making it almost as fast as clang.
//
// XXH_ACC_NB is #defined already, back in the main file.
#if (defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64) || defined(_M_ARM64EC))
  #define XXH3_NEON_LANES 6
#else
  #define XXH3_NEON_LANES XXH_ACC_NB
#endif

/*
 * The bulk processing loop for NEON.
 *
 * The NEON code path is actually partially scalar when running on AArch64. This
 * is to optimize the pipelining and can have up to 15% speedup depending on the
 * CPU, and it also mitigates some GCC codegen issues.
 *
 * See XXH3_NEON_LANES for configuring this and details about this optimization.
 */
template <bool bswap>
static FORCE_INLINE void XXH3_accumulate_512_neon( void * RESTRICT acc, const void * RESTRICT input,
        const void * RESTRICT secret ) {
    uint64x2_t    * const xacc    = (uint64x2_t *   )acc;
    /* We don't use a uint32x4_t pointer because it causes bus errors on ARMv7. */
    uint8_t const * const xinput  = (const uint8_t *)input;
    uint8_t const * const xsecret = (const uint8_t *)secret;

    /* AArch64 uses both scalar and neon at the same time */
    for (size_t i = XXH3_NEON_LANES; i < XXH_ACC_NB; i++) {
        XXH3_scalarRound<bswap>(acc, input, secret, i);
    }
    for (size_t i = 0; i < XXH3_NEON_LANES / 2; i++) {
        uint64x2_t acc_vec  = xacc[i];
        /* data_vec = xinput[i]; */
        uint64x2_t data_vec = XXH_vld1q_u64(xinput  + (i * 16));
        /* key_vec  = xsecret[i];  */
        uint64x2_t key_vec  = XXH_vld1q_u64(xsecret + (i * 16));
        if (bswap) {
            data_vec = Vbswap64_u64(data_vec);
            key_vec  = Vbswap64_u64(key_vec );
        }
        uint64x2_t data_key;
        uint32x2_t data_key_lo, data_key_hi;
        /* acc_vec_2 = swap(data_vec) */
        uint64x2_t acc_vec_2 = vextq_u64(data_vec, data_vec, 1);
        /* data_key = data_vec ^ key_vec; */
        data_key = veorq_u64(data_vec, key_vec);
        /*
         * data_key_lo = (uint32x2_t) (data_key & 0xFFFFFFFF);
         * data_key_hi = (uint32x2_t) (data_key >> 32);
         * data_key = UNDEFINED;
         */
        XXH_SPLIT_IN_PLACE(data_key, data_key_lo, data_key_hi);
        /* acc_vec_2 += (uint64x2_t) data_key_lo * (uint64x2_t) data_key_hi; */
        acc_vec_2 = vmlal_u32(acc_vec_2, data_key_lo, data_key_hi);
        /* xacc[i] += acc_vec_2; */
        acc_vec   = vaddq_u64(acc_vec, acc_vec_2);
        xacc[i]   = acc_vec;
    }
}

template <bool bswap>
static FORCE_INLINE void XXH3_scrambleAcc_neon( void * RESTRICT acc, const void * RESTRICT secret ) {
    uint64x2_t *    xacc    = (uint64x2_t *   )acc;
    uint8_t const * xsecret = (uint8_t const *)secret;
    uint32x2_t      prime   = vdup_n_u32(XXH_PRIME32_1);

    /* AArch64 uses both scalar and neon at the same time */
    for (size_t i = XXH3_NEON_LANES; i < XXH_ACC_NB; i++) {
        XXH3_scalarScrambleRound<bswap>(acc, secret, i);
    }
    for (size_t i = 0; i < XXH3_NEON_LANES / 2; i++) {
        /* xacc[i] ^= (xacc[i] >> 47); */
        uint64x2_t acc_vec  = xacc[i];
        uint64x2_t shifted  = vshrq_n_u64(acc_vec, 47);
        uint64x2_t data_vec = veorq_u64(acc_vec, shifted);

        /* xacc[i] ^= xsecret[i]; */
        uint64x2_t key_vec = XXH_vld1q_u64(xsecret + (i * 16));
        if (bswap) {
            key_vec = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(key_vec)));
        }
        uint64x2_t data_key = veorq_u64(data_vec, key_vec);

        /* xacc[i] *= XXH_PRIME32_1 */
        uint32x2_t data_key_lo, data_key_hi;
        /*
         * data_key_lo = (uint32x2_t) (xacc[i] & 0xFFFFFFFF);
         * data_key_hi = (uint32x2_t) (xacc[i] >> 32);
         * xacc[i] = UNDEFINED;
         */
        XXH_SPLIT_IN_PLACE(data_key, data_key_lo, data_key_hi);
        {
            /*
             * prod_hi = (data_key >> 32) * XXH_PRIME32_1;
             *
             * Avoid vmul_u32 + vshll_n_u32 since Clang 6 and 7 will
             * incorrectly "optimize" this:
             *   tmp     = vmul_u32(vmovn_u64(a), vmovn_u64(b));
             *   shifted = vshll_n_u32(tmp, 32);
             * to this:
             *   tmp     = "vmulq_u64"(a, b); // no such thing!
             *   shifted = vshlq_n_u64(tmp, 32);
             *
             * However, unlike SSE, Clang lacks a 64-bit multiply routine
             * for NEON, and it scalarizes two 64-bit multiplies instead.
             *
             * vmull_u32 has the same timing as vmul_u32, and it avoids
             * this bug completely.
             * See https://bugs.llvm.org/show_bug.cgi?id=39967
             */
            uint64x2_t prod_hi = vmull_u32(data_key_hi, prime);
            /* xacc[i] = prod_hi << 32; */
            prod_hi = vshlq_n_u64(prod_hi, 32);
            /* xacc[i] += (prod_hi & 0xFFFFFFFF) * XXH_PRIME32_1; */
            xacc[i] = vmlal_u32(prod_hi, data_key_lo, prime);
        }
    }
}
