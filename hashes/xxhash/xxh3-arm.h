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

/* https://github.com/gcc-mirror/gcc/blob/38cf91e5/gcc/config/arm/arm.c#L22486 */
/* https://github.com/llvm-mirror/llvm/blob/2c4ca683/lib/Target/ARM/ARMAsmPrinter.cpp#L399 */
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__arm__) || defined(__thumb__) || defined(_M_ARM))
  #define XXH_SPLIT_IN_PLACE(in, outLo, outHi)            \
      do {                                                \
      /* Undocumented GCC/Clang operand modifier: */      \
      /*     %e0 = lower D half, %f0 = upper D half */    \
      __asm__ ("vzip.32  %e0, %f0" : "+w" (in));          \
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
// This can be set to 2, 4, 6, or 8.
//
// ARM Cortex CPUs are _very_ sensitive to how their pipelines are used.
//
// For example, the Cortex-A73 can dispatch 3 micro-ops per cycle, but only
// 2 of those can be NEON. If you are only using NEON instructions, you are
// only using 2/3 of the CPU bandwidth.
//
// This is even more noticable on the more advanced cores like the
// Cortex-A76 which can dispatch 8 micro-ops per cycle, but still only 2
// NEON micro-ops at once.
//
// Therefore, to make the most out of the pipeline, it is beneficial to run
// 6 NEON lanes and 2 scalar lanes, which is chosen by default.
//
// This does not apply to Apple processors or 32-bit processors, which run
// better with full NEON. These will default to 8. Additionally,
// size-optimized builds run 8 lanes.
//
// This change benefits CPUs with large micro-op buffers without negatively affecting
// most other CPUs:
//
//  | Chipset               | Dispatch type       | NEON only | 6:2 hybrid | Diff. |
//  |:----------------------|:--------------------|----------:|-----------:|------:|
//  | Snapdragon 730 (A76)  | 2 NEON/8 micro-ops  |  8.8 GB/s |  10.1 GB/s |  ~16% |
//  | Snapdragon 835 (A73)  | 2 NEON/3 micro-ops  |  5.1 GB/s |   5.3 GB/s |   ~5% |
//  | Marvell PXA1928 (A53) | In-order dual-issue |  1.9 GB/s |   1.9 GB/s |    0% |
//  | Apple M1              | 4 NEON/8 micro-ops  | 37.3 GB/s |  36.1 GB/s |  ~-3% |
//
// It also seems to fix some bad codegen on GCC, making it almost as fast as clang.
//
// XXH_ACC_NB is #defined already, back in the main file.
#if (defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64) || defined(_M_ARM64EC)) && !defined(__APPLE__)
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
 *
 * NEON's 32-bit to 64-bit long multiply takes a half vector of 32-bit
 * integers instead of the other platforms which mask full 64-bit vectors,
 * so the setup is more complicated than just shifting right.
 *
 * Additionally, there is an optimization for 4 lanes at once noted below.
 *
 * Since, as stated, the most optimal amount of lanes for Cortexes is 6,
 * there needs to be *three* versions of the accumulate operation used
 * for the remaining 2 lanes.
 */
template <bool bswap>
static FORCE_INLINE void XXH3_accumulate_512_neon( void * RESTRICT acc, const void * RESTRICT input,
        const void * RESTRICT secret ) {
    XXH_ASSERT((((size_t)acc) & 15) == 0);
    uint64x2_t    * const xacc    = (uint64x2_t *   )acc;
    /* We don't use a uint32x4_t pointer because it causes bus errors on ARMv7. */
    uint8_t const * const xinput  = (const uint8_t *)input;
    uint8_t const * const xsecret = (const uint8_t *)secret;
    size_t i;

    /* Scalar lanes use the normal scalarRound routine */
    for (i = XXH3_NEON_LANES; i < XXH_ACC_NB; i++) {
        XXH3_scalarRound<bswap>(acc, input, secret, i);
    }
    i = 0;
    /* 4 NEON lanes at a time. */
    for (; i+1 < XXH3_NEON_LANES / 2; i+=2) {
        /* data_vec = xinput[i]; */
        uint64x2_t data_vec_1 = XXH_vld1q_u64(xinput  + (i * 16));
        uint64x2_t data_vec_2 = XXH_vld1q_u64(xinput  + ((i+1) * 16));
        /* key_vec  = xsecret[i];  */
        uint64x2_t key_vec_1  = XXH_vld1q_u64(xsecret + (i * 16));
        uint64x2_t key_vec_2  = XXH_vld1q_u64(xsecret + ((i+1) * 16));
        if (bswap) {
            data_vec_1 = Vbswap64_u64(data_vec_1);
            data_vec_2 = Vbswap64_u64(data_vec_2);
            key_vec_1  = Vbswap64_u64(key_vec_1 );
            key_vec_2  = Vbswap64_u64(key_vec_2 );
        }
        /* data_swap = swap(data_vec) */
        uint64x2_t data_swap_1 = vextq_u64(data_vec_1, data_vec_1, 1);
        uint64x2_t data_swap_2 = vextq_u64(data_vec_2, data_vec_2, 1);
        /* data_key = data_vec ^ key_vec; */
        uint64x2_t data_key_1 = veorq_u64(data_vec_1, key_vec_1);
        uint64x2_t data_key_2 = veorq_u64(data_vec_2, key_vec_2);

        /*
         * If we reinterpret the 64x2 vectors as 32x4 vectors, we can use a
         * de-interleave operation for 4 lanes in 1 step with `vuzpq_u32` to
         * get one vector with the low 32 bits of each lane, and one vector
         * with the high 32 bits of each lane.
         *
         * This compiles to two instructions on AArch64 and has a paired vector
         * result, which is an artifact from ARMv7a's version which modified both
         * vectors in place.
         *
         *  [ dk11L | dk11H | dk12L | dk12H ] -> [ dk11L | dk12L | dk21L | dk22L ]
         *  [ dk21L | dk21H | dk22L | dk22H ] -> [ dk11H | dk12H | dk21H | dk22H ]
         */
        uint32x4x2_t unzipped = vuzpq_u32(
                                          vreinterpretq_u32_u64(data_key_1),
                                          vreinterpretq_u32_u64(data_key_2)
                                          );
        /* data_key_lo = data_key & 0xFFFFFFFF */
        uint32x4_t data_key_lo = unzipped.val[0];
        /* data_key_hi = data_key >> 32 */
        uint32x4_t data_key_hi = unzipped.val[1];
        /*
         * Then, we can split the vectors horizontally and multiply which, as for most
         * widening intrinsics, have a variant that works on both high half vectors
         * for free on AArch64.
         *
         * sum = data_swap + (u64x2) data_key_lo * (u64x2) data_key_hi
         */
        uint32x2_t data_key_lo_1 = vget_low_u32(data_key_lo);
        uint32x2_t data_key_hi_1 = vget_low_u32(data_key_hi);

        uint64x2_t sum_1 = vmlal_u32(data_swap_1, data_key_lo_1, data_key_hi_1);
        /* Assume that the compiler is smart enough to convert this to UMLAL2 */
        uint32x2_t data_key_lo_2 = vget_high_u32(data_key_lo);
        uint32x2_t data_key_hi_2 = vget_high_u32(data_key_hi);

        uint64x2_t sum_2 = vmlal_u32(data_swap_2, data_key_lo_2, data_key_hi_2);
        /* Prevent Clang from reordering the vaddq before the vmlal. */
        XXH_COMPILER_GUARD_W(sum_1);
        XXH_COMPILER_GUARD_W(sum_2);
        /* xacc[i] = acc_vec + sum; */
        xacc[i]   = vaddq_u64(xacc[i], sum_1);
        xacc[i+1] = vaddq_u64(xacc[i+1], sum_2);
    }
    /* Operate on the remaining NEON lanes 2 at a time. */
    for (; i < XXH3_NEON_LANES / 2; i++) {
        uint64x2_t acc_vec  = xacc[i];
        /* data_vec = xinput[i]; */
        uint64x2_t data_vec = XXH_vld1q_u64(xinput  + (i * 16));
        /* key_vec  = xsecret[i];  */
        uint64x2_t key_vec  = XXH_vld1q_u64(xsecret + (i * 16));
        if (bswap) {
            data_vec = Vbswap64_u64(data_vec);
            key_vec  = Vbswap64_u64(key_vec );
        }
        /* acc_vec_2 = swap(data_vec) */
        uint64x2_t data_swap = vextq_u64(data_vec, data_vec, 1);
        /* data_key = data_vec ^ key_vec; */
        uint64x2_t data_key = veorq_u64(data_vec, key_vec);
        /* For two lanes, just use VMOVN and VSHRN. */
        /* data_key_lo = data_key & 0xFFFFFFFF; */
        uint32x2_t data_key_lo = vmovn_u64(data_key);
        /* data_key_hi = data_key >> 32; */
        uint32x2_t data_key_hi = vshrn_n_u64(data_key, 32);
        /* sum = data_swap + (u64x2) data_key_lo * (u64x2) data_key_hi; */
        uint64x2_t sum = vmlal_u32(data_swap, data_key_lo, data_key_hi);
        /* Prevent Clang from reordering the vaddq before the vmlal */
        XXH_COMPILER_GUARD_W(sum);
        /* xacc[i] = acc_vec + sum; */
        xacc[i] = vaddq_u64 (xacc[i], sum);
    }
}


template <bool bswap>
static FORCE_INLINE void XXH3_scrambleAcc_neon( void * RESTRICT acc, const void * RESTRICT secret ) {
    XXH_ASSERT((((size_t)acc) & 15) == 0);
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
            key_vec = Vbswap64_u64(key_vec);
        }
        uint64x2_t data_key = veorq_u64(data_vec, key_vec);

        /* xacc[i] *= XXH_PRIME32_1 */
        uint32x2_t data_key_lo = vmovn_u64(data_key);
        uint32x2_t data_key_hi = vshrn_n_u64(data_key, 32);
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
