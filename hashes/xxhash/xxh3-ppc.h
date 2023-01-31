/*
 * XXH3 PPC-specific code
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
 * VSX and Z Vector helpers.
 *
 * This is very messy, and any pull requests to clean this up are welcome.
 *
 * There are a lot of problems with supporting VSX and s390x, due to
 * inconsistent intrinsics, spotty coverage, and multiple endiannesses.
 */

typedef __vector unsigned long long  xxh_u64x2;
typedef __vector unsigned char       xxh_u8x16;
typedef __vector unsigned int        xxh_u32x4;

#if defined(__POWER9_VECTOR__) || (defined(__clang__) && defined(__s390x__))
  #define XXH_vec_revb vec_revb
#else

// A polyfill for POWER9's vec_revb().
static FORCE_INLINE xxh_u64x2 XXH_vec_revb( xxh_u64x2 val ) {
    xxh_u8x16 const vByteSwap = {
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08
    };

    return vec_perm(val, val, vByteSwap);
}

#endif

// Performs an unaligned vector load and byte swaps it on big endian.
template <bool bswap>
static FORCE_INLINE xxh_u64x2 XXH_vec_loadu( const void * ptr ) {
    xxh_u64x2 ret;

    memcpy(&ret, ptr, sizeof(xxh_u64x2));
    if (bswap) {
        ret = XXH_vec_revb(ret);
    }
    return ret;
}

/*
 * vec_mulo and vec_mule are very problematic intrinsics on PowerPC
 *
 * These intrinsics weren't added until GCC 8, despite existing for a while,
 * and they are endian dependent. Also, their meaning swap depending on version.
 *
 */
#if defined(__s390x__)
/* s390x is always big endian, no issue on this platform */
  #define XXH_vec_mulo vec_mulo
  #define XXH_vec_mule vec_mule
#elif defined(__clang__) && XXH_HAS_BUILTIN(__builtin_altivec_vmuleuw)
/* Clang has a better way to control this, we can just use the builtin which doesn't swap. */
  #define XXH_vec_mulo __builtin_altivec_vmulouw
  #define XXH_vec_mule __builtin_altivec_vmuleuw
#else

/* gcc needs inline assembly */

/* Adapted from https://github.com/google/highwayhash/blob/master/highwayhash/hh_vsx.h. */
static FORCE_INLINE xxh_u64x2 XXH_vec_mulo( xxh_u32x4 a, xxh_u32x4 b ) {
    xxh_u64x2 result;

    __asm__ ("vmulouw %0, %1, %2" : "=v" (result) : "v" (a), "v" (b));
    return result;
}

static FORCE_INLINE xxh_u64x2 XXH_vec_mule( xxh_u32x4 a, xxh_u32x4 b ) {
    xxh_u64x2 result;

    __asm__ ("vmuleuw %0, %1, %2" : "=v" (result) : "v" (a), "v" (b));
    return result;
}

#endif /* XXH_vec_mulo, XXH_vec_mule */

template <bool bswap>
static FORCE_INLINE void XXH3_accumulate_512_vsx( void * RESTRICT acc, const void * RESTRICT input,
        const void * RESTRICT secret ) {
    /* presumed aligned */
    uint32_t        * const xacc    = (uint32_t *       )acc;
    xxh_u64x2 const * const xinput  = (xxh_u64x2 const *)input;   /* no alignment restriction */
    xxh_u64x2 const * const xsecret = (xxh_u64x2 const *)secret;  /* no alignment restriction */
    xxh_u64x2 const         v32     = { 32, 32 };

    for (size_t i = 0; i < XXH_STRIPE_LEN / sizeof(xxh_u64x2); i++) {
        /* data_vec = xinput[i]; */
        xxh_u64x2 const data_vec = XXH_vec_loadu<bswap>(xinput  + i);
        /* key_vec = xsecret[i]; */
        xxh_u64x2 const key_vec  = XXH_vec_loadu<bswap>(xsecret + i);
        xxh_u64x2 const data_key = data_vec ^ key_vec;
        /* shuffled = (data_key << 32) | (data_key >> 32); */
        xxh_u32x4 const shuffled = (xxh_u32x4)vec_rl(data_key, v32);
        /* product = ((xxh_u64x2)data_key & 0xFFFFFFFF) * ((xxh_u64x2)shuffled & 0xFFFFFFFF); */
        xxh_u64x2 const product  = XXH_vec_mulo((xxh_u32x4)data_key, shuffled);
        /* acc_vec = xacc[i]; */
        xxh_u64x2 acc_vec        = (xxh_u64x2)vec_xl(0, xacc + 4 * i);
        acc_vec += product;

        /* swap high and low halves */
#if defined(__s390x__)
        acc_vec += vec_permi(data_vec, data_vec, 2);
#else
        acc_vec += vec_xxpermdi(data_vec, data_vec, 2);
#endif
        /* xacc[i] = acc_vec; */
        vec_xst((xxh_u32x4)acc_vec, 0, xacc + 4 * i);
    }
    __sync_synchronize();
}

template <bool bswap>
static FORCE_INLINE void XXH3_scrambleAcc_vsx( void * RESTRICT acc, const void * RESTRICT secret ) {
    XXH_ASSERT((((size_t)acc) & 15) == 0);
    xxh_u64x2       * const xacc    = (xxh_u64x2 *      )acc;
    const xxh_u64x2 * const xsecret = (const xxh_u64x2 *)secret;
    /* constants */
    xxh_u64x2 const v32   = { 32, 32 };
    xxh_u64x2 const v47   = { 47, 47 };
    xxh_u32x4 const prime = { XXH_PRIME32_1, XXH_PRIME32_1, XXH_PRIME32_1, XXH_PRIME32_1 };

    for (size_t i = 0; i < XXH_STRIPE_LEN / sizeof(xxh_u64x2); i++) {
        /* xacc[i] ^= (xacc[i] >> 47); */
        xxh_u64x2 const acc_vec  = xacc[i];
        xxh_u64x2 const data_vec = acc_vec ^ (acc_vec >> v47);

        /* xacc[i] ^= xsecret[i]; */
        xxh_u64x2 const key_vec  = XXH_vec_loadu<bswap>(xsecret + i);
        xxh_u64x2 const data_key = data_vec ^ key_vec;

        /* xacc[i] *= XXH_PRIME32_1 */
        /* prod_lo = ((xxh_u64x2)data_key & 0xFFFFFFFF) * ((xxh_u64x2)prime & 0xFFFFFFFF);  */
        xxh_u64x2 const prod_even = XXH_vec_mule((xxh_u32x4)data_key, prime);
        /* prod_hi = ((xxh_u64x2)data_key >> 32) * ((xxh_u64x2)prime >> 32);  */
        xxh_u64x2 const prod_odd  = XXH_vec_mulo((xxh_u32x4)data_key, prime);
        xacc[i] = prod_odd + (prod_even << v32);
    }
}
