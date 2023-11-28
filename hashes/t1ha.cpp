/*
 *  Copyright (c) 2016-2020 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2020 Leonid Yuriev <leo@yuriev.ru>,
 *  The 1Hippeus project (t1h).
 *
 *  Portions Copyright (c) 2022 Frank J. T. Wojcik
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty. In no event will the authors be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgement in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

/*
 * t1ha = { Fast Positive Hash, aka "Позитивный Хэш" }
 * by [Positive Technologies](https://www.ptsecurity.ru)
 *
 * Briefly, it is a 64-bit Hash Function:
 *  1. Created for 64-bit little-endian platforms, in predominantly for x86_64,
 *     but portable and without penalties it can run on any 64-bit CPU.
 *  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash
 *     and all others portable hash-functions (which do not use specific
 *     hardware tricks).
 *  3. Not suitable for cryptography.
 *
 * The Future will (be) Positive. Всё будет хорошо.
 *
 * ACKNOWLEDGEMENT:
 * The t1ha was originally developed by Leonid Yuriev (Леонид Юрьев)
 * for The 1Hippeus project - zerocopy messaging in the spirit of Sparta!
 */

/*
 * This software has been extensively modified for use in
 * SMHasher3. The modifications are mostly conversion of preprocessor
 * macros into templatized C++ functions, and the corresponding
 * introduction of a "mode" enum for use in those templates. There
 * have also been changes to work with SMHasher3's Platform.h and
 * Mathmult.h.
 *
 * Performance and hash results should match the original code.
 */
#include "Platform.h"
#include "Hashlib.h"

#include "Mathmult.h"

#if defined(HAVE_X86_64_AES)
  #include "Intrinsics.h"
#endif

#include <cassert>

//------------------------------------------------------------
#define T1HA_USE_ALIGNED_ONESHOT_READ 1

#define T1HA_UNALIGNED_ACCESS__UNABLE    0
#define T1HA_UNALIGNED_ACCESS__SLOW      1   // Unused in SMHasher3
#define T1HA_UNALIGNED_ACCESS__EFFICIENT 2

#if defined(i386) || defined(__386) || defined(__i386) || defined(__i386__) || \
    defined(i486) || defined(__i486) || defined(__i486__) ||                   \
    defined(i586) | defined(__i586) || defined(__i586__) || defined(i686) ||   \
    defined(__i686) || defined(__i686__) || defined(_M_IX86) ||                \
    defined(_X86_) || defined(__THW_INTEL__) || defined(__I86__) ||            \
    defined(__INTEL__) || defined(__x86_64) || defined(__x86_64__) ||          \
    defined(__amd64__) || defined(__amd64) || defined(_M_X64) ||               \
    defined(_M_AMD64) || defined(__IA32__) || defined(__INTEL__)
  #define T1HA_SYS_UNALIGNED_ACCESS T1HA_UNALIGNED_ACCESS__EFFICIENT
#else
  #define T1HA_SYS_UNALIGNED_ACCESS T1HA_UNALIGNED_ACCESS__UNABLE
#endif

#if defined(__ARM_FEATURE_UNALIGNED)
  #define T1HA_SYS_ARM_UNALIGNED 1
#else
  #define T1HA_SYS_ARM_UNALIGNED 0
#endif

//------------------------------------------------------------
#if defined(__SANITIZE_ADDRESS__)
  #undef T1HA_USE_ALIGNED_ONESHOT_READ
  #define T1HA_USE_ALIGNED_ONESHOT_READ 0
  #undef T1HA_SYS_UNALIGNED_ACCESS
  #define T1HA_SYS_UNALIGNED_ACCESS T1HA_UNALIGNED_ACCESS__UNABLE
#endif

#if !defined(PAGESIZE)
  #define PAGESIZE 4096
#endif

#if T1HA_USE_ALIGNED_ONESHOT_READ &&                              \
    T1HA_SYS_UNALIGNED_ACCESS != T1HA_UNALIGNED_ACCESS__UNABLE && \
    defined(PAGESIZE) && PAGESIZE > 42
  #define T1HA_USE_UNALIGNED_ONESHOT_READ 1
  #define can_read_underside(ptr, size) \
      ((size) <= sizeof(uintptr_t) && ((PAGESIZE - (size)) & (uintptr_t)(ptr)) != 0)
#else
  #define T1HA_USE_UNALIGNED_ONESHOT_READ 0
  #define can_read_underside(ptr, size) false
#endif

#define ALIGNMENT_16 2
#define ALIGNMENT_32 4
#if defined(HAVE_32BIT_PLATFORM)
  #define ALIGNMENT_64 4
#else
  #define ALIGNMENT_64 8
#endif

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
  #define __GNUC_PREREQ(maj, min) \
      ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
  #define __GNUC_PREREQ(maj, min) 0
#endif

#if !defined(__has_builtin)
  #define __has_builtin(x) (0)
#endif
#if !defined(__has_attribute)
  #define __has_attribute(x) (0)
#endif

#if __GNUC_PREREQ(4, 8) || __has_builtin(__builtin_assume_aligned)

  #define read_aligned(ptr, bits) \
      (*(const uint ## bits ## _t *)__builtin_assume_aligned(ptr, ALIGNMENT_ ## bits))

#elif (__GNUC_PREREQ(3, 3) || __has_attribute(aligned)) && !defined(__clang__)

  #define read_aligned(ptr, bits) \
      (*(const uint ## bits ## _t __attribute__((aligned(ALIGNMENT_ ## bits))) *)(ptr))

#elif __has_attribute(assume_aligned)

static __always_inline const
uint16_t * __attribute__((assume_aligned(ALIGNMENT_16))) cast_aligned_16( const void * ptr ) {
    return (const uint16_t *)ptr;
}

static __always_inline const
uint32_t * __attribute__((assume_aligned(ALIGNMENT_32))) cast_aligned_32( const void * ptr ) {
    return (const uint32_t *)ptr;
}

static __always_inline const
uint64_t * __attribute__((assume_aligned(ALIGNMENT_64))) cast_aligned_64( const void * ptr ) {
    return (const uint64_t *)ptr;
}

  #define read_aligned(ptr, bits) (*cast_aligned_ ## bits(ptr))

#elif defined(_MSC_VER)

  #define read_aligned(ptr, bits) \
      (*(const __declspec(align(ALIGNMENT_ ## bits)) uint ## bits ## _t *)(ptr))

#else

  #define read_aligned(ptr, bits) (*(const uint ## bits ## _t *)(ptr))

#endif /* read_aligned */

//------------------------------------------------------------
// 'magic' primes
static const uint64_t prime_0   = UINT64_C(0xEC99BF0D8372CAAB);
static const uint64_t prime_1   = UINT64_C(0x82434FE90EDCEF39);
static const uint64_t prime_2   = UINT64_C(0xD4F06DB99D67BE4B);
static const uint64_t prime_3   = UINT64_C(0xBD9CACC22C6E9571);
static const uint64_t prime_4   = UINT64_C(0x9C06FAF4D023E3AB);
static const uint64_t prime_5   = UINT64_C(0xC060724A8424F345);
static const uint64_t prime_6   = UINT64_C(0xCB5AF53AE3AAAC31);

static const uint32_t prime32_0 = UINT32_C(0x92D78269);
static const uint32_t prime32_1 = UINT32_C(0xCA9B4735);
static const uint32_t prime32_2 = UINT32_C(0xA4ABA1C3);
static const uint32_t prime32_3 = UINT32_C(0xF6499843);
static const uint32_t prime32_4 = UINT32_C(0x86F0FD61);
static const uint32_t prime32_5 = UINT32_C(0xCA2DA6FB);
static const uint32_t prime32_6 = UINT32_C(0xC4BB3575);

//------------------------------------------------------------
enum t1ha_modes {
    MODE_LE_NATIVE,
    MODE_LE_BSWAP,
    MODE_BE_NATIVE,
    MODE_BE_BSWAP
};

#define MODE_NATIVE(m) (((m) == MODE_LE_NATIVE) || ((m) == MODE_BE_NATIVE))
#define MODE_BSWAP(m)  (((m) == MODE_LE_BSWAP)  || ((m) == MODE_BE_BSWAP))
#define MODE_BE_SYS(m) (((m) == MODE_BE_BSWAP)  || ((m) == MODE_BE_NATIVE))
#define MODE_LE_SYS(m) (((m) == MODE_LE_NATIVE) || ((m) == MODE_LE_BSWAP))
#define MODE_BE_OUT(m) (((m) == MODE_LE_BSWAP)  || ((m) == MODE_BE_NATIVE))
#define MODE_LE_OUT(m) (((m) == MODE_LE_NATIVE) || ((m) == MODE_BE_BSWAP))

//------------------------------------------------------------
template <enum t1ha_modes mode, bool aligned>
static FORCE_INLINE uint32_t fetch16( const void * v ) {
    constexpr bool force_aligned = (T1HA_SYS_UNALIGNED_ACCESS != T1HA_UNALIGNED_ACCESS__UNABLE) ||
        T1HA_SYS_ARM_UNALIGNED;

    if (aligned) { assert(((uintptr_t)v) % ALIGNMENT_16 == 0); }

    if (aligned || force_aligned) {
        return COND_BSWAP(read_aligned(v, 16), MODE_BSWAP(mode));
    }

    const uint8_t * p = (const uint8_t *)v;
    if (MODE_BE_OUT(mode)) {
        return (uint16_t)p[0] << 8 | p[1];
    } else {
        return p[0] | (uint16_t)p[1] << 8;
    }
}

template <enum t1ha_modes mode, bool aligned>
static FORCE_INLINE uint32_t fetch32( const void * v ) {
    constexpr bool force_aligned = (T1HA_SYS_UNALIGNED_ACCESS != T1HA_UNALIGNED_ACCESS__UNABLE) ||
        T1HA_SYS_ARM_UNALIGNED;

    if (aligned) { assert(((uintptr_t)v) % ALIGNMENT_32 == 0); }

    if (aligned || force_aligned) {
        return COND_BSWAP(read_aligned(v, 32), MODE_BSWAP(mode));
    }

    if (MODE_BE_OUT(mode)) {
        return (uint32_t)fetch16<mode, false>(v) << 16 |
               fetch16<mode, false>((const uint8_t *)v + 2);
    } else {
        return fetch16<mode, false>(v) |
               (uint32_t)fetch16<mode, false>((const uint8_t *)v + 2) << 16;
    }
}

template <enum t1ha_modes mode, bool aligned>
static FORCE_INLINE uint64_t fetch64( const void * v ) {
    constexpr bool force_aligned = (T1HA_SYS_UNALIGNED_ACCESS != T1HA_UNALIGNED_ACCESS__UNABLE);

    if (aligned) { assert(((uintptr_t)v) % ALIGNMENT_64 == 0); }

    if (aligned || force_aligned) {
        return COND_BSWAP(read_aligned(v, 64), MODE_BSWAP(mode));
    }

    if (MODE_BE_OUT(mode)) {
        return (uint64_t)fetch32<mode, false>(v) << 32 |
               fetch32<mode, false>((const uint8_t *)v + 4);
    } else {
        return fetch32<mode, false>(v) |
               (uint64_t)fetch32<mode, false>((const uint8_t *)v + 4) << 32;
    }
}

//------------------------------------------------------------
template <enum t1ha_modes mode, bool aligned>
static FORCE_INLINE uint32_t tail32( const void * v, size_t tail ) {
    constexpr bool        unaligned_wordwise = (T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__EFFICIENT);
    const uint8_t * const p = (const uint8_t *)v;
    uint32_t r = 0;

    if (aligned && T1HA_USE_ALIGNED_ONESHOT_READ) {
        /* We can perform a 'oneshot' read, which is little bit faster. */
        const unsigned shift = ((4 - tail) & 3) << 3;
        if (MODE_LE_OUT(mode)) {
            return fetch32<mode, true>(p) & ((~UINT32_C(0)) >> shift);
        } else {
            return fetch32<mode, true>(p) >> shift;
        }
    } else if (!aligned && T1HA_USE_UNALIGNED_ONESHOT_READ) {
        /*
         * On some systems we can perform a 'oneshot' read, which is
         * little bit faster. Thanks Marcin Å»ukowski
         * <marcin.zukowski@gmail.com> for the reminder.
         */
        const unsigned offset = (4 - tail) & 3;
        const unsigned shift  = offset << 3;
        if (MODE_LE_OUT(mode)) {
            if (likely(can_read_underside(p, 4))) {
                return fetch32<mode, false>(p - offset) >> shift;
            }
            return fetch32<mode, false>(p) & ((~UINT32_C(0)) >> shift);
        } else {
            if (likely(can_read_underside(p, 4))) {
                return fetch32<mode, false>(p - offset) & ((~UINT32_C(0)) >> shift);
            }
            return fetch32<mode, false>(p) >> shift;
        }
    }

    if ((mode == MODE_LE_NATIVE) && (aligned || unaligned_wordwise)) {
        switch (tail & 3) {
        case 3:
                r = (uint32_t)p[2] << 16;
        /* fall through */
        case 2:
                return r + fetch16<mode, aligned>(p);
        case 1:
                return p[0];
        case 0:
                return fetch32<mode, aligned>(v);
        }
    }

    if ((mode == MODE_BE_NATIVE) && (aligned || unaligned_wordwise)) {
        /*
         * For most CPUs this code is better when not needed
         * copying for alignment or byte reordering.
         */
        switch (tail & 3) {
        case 3:
                return fetch16<mode, aligned>(p) << 8 | p[2];
        case 2:
                return fetch16<mode, aligned>(p);
        case 1:
                return p[0];
        case 0:
                return fetch32<mode, aligned>(p);
        }
    }

    if ((mode == MODE_BE_BSWAP) ||
            ((mode == MODE_LE_NATIVE) && !aligned && !unaligned_wordwise)) {
        switch (tail & 3) {
        case 0:
                r  += p[3];
                r <<= 8;
        /* fall through */
        case 3:
                r  += p[2];
                r <<= 8;
        /* fall through */
        case 2:
                r  += p[1];
                r <<= 8;
        /* fall through */
        case 1:
                return r + p[0];
        }
    }

    if ((mode == MODE_LE_BSWAP) ||
            ((mode == MODE_BE_NATIVE) && !aligned && !unaligned_wordwise)) {
        switch (tail & 3) {
        case 0:
                return p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 |
                       (uint32_t)p[0] << 24;
        case 3:
                return p[2] | (uint32_t)p[1] << 8 | (uint32_t)p[0] << 16;
        case 2:
                return p[1] | (uint32_t)p[0] << 8;
        case 1:
                return p[0];
        }
    }

    unreachable();
    return 0;
}

//------------------------------------------------------------
template <enum t1ha_modes mode, bool aligned>
static FORCE_INLINE uint64_t tail64( const void * v, size_t tail ) {
    constexpr bool        unaligned_wordwise = (T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__EFFICIENT);
    const uint8_t * const p = (const uint8_t *)v;
    uint64_t r = 0;

    if (aligned && T1HA_USE_ALIGNED_ONESHOT_READ) {
        /* We can perform a 'oneshot' read, which is little bit faster. */
        const unsigned shift = ((8 - tail) & 7) << 3;
        if (MODE_LE_OUT(mode)) {
            return fetch64<mode, true>(p) & ((~UINT64_C(0)) >> shift);
        } else {
            return fetch64<mode, true>(p) >> shift;
        }
    } else if (!aligned && T1HA_USE_UNALIGNED_ONESHOT_READ) {
        /*
         * On some systems we can perform a 'oneshot' read, which is
         * little bit faster. Thanks Marcin Å»ukowski
         * <marcin.zukowski@gmail.com> for the reminder.
         */
        const unsigned offset = (8 - tail) & 7;
        const unsigned shift  = offset << 3;
        if (MODE_LE_OUT(mode)) {
            if (likely(can_read_underside(p, 8))) {
                return fetch64<mode, false>(p - offset) >> shift;
            }
            return fetch64<mode, false>(p) & ((~UINT64_C(0)) >> shift);
        } else {
            if (likely(can_read_underside(p, 8))) {
                return fetch64<mode, false>(p - offset) & ((~UINT64_C(0)) >> shift);
            }
            return fetch64<mode, false>(p) >> shift;
        }
    }

    if ((mode == MODE_LE_NATIVE) && (aligned || unaligned_wordwise)) {
        /* For most CPUs this code is better when not needed byte reordering. */
        switch (tail & 7) {
        case 0:
                return fetch64<mode, aligned>(p);
        case 7:
                r = (uint64_t)p[6] << 8;
        /* fall through */
        case 6:
                r  += p        [5];
                r <<= 8;
        /* fall through */
        case 5:
                r  += p        [4];
                r <<= 32;
        /* fall through */
        case 4:
                return r + fetch32<mode, aligned>(p);
        case 3:
                r = (uint64_t)p[2] << 16;
        /* fall through */
        case 2:
                return r + fetch16<mode, aligned>(p);
        case 1:
                return p[0];
        }
    }

    if ((mode == MODE_BE_NATIVE) && (aligned || unaligned_wordwise)) {
        /* For most CPUs this code is better when not byte reordering. */
        switch (tail & 7) {
        case 1:
                return p[0];
        case 2:
                return fetch16<mode, aligned>(p);
        case 3:
                return (uint32_t)fetch16<mode, aligned>(p) << 8 | p[2];
        case 4:
                return fetch32<mode, aligned>(p);
        case 5:
                return (uint64_t)fetch32<mode, aligned>(p) << 8 | p[4];
        case 6:
                return (uint64_t)fetch32<mode, aligned>(p) << 16 | fetch16<mode, aligned>(p + 4);
        case 7:
                return (uint64_t)fetch32<mode, aligned>(p) << 24 |
                       (uint32_t)fetch16<mode, aligned>(p + 4) << 8 | p[6];
        case 0:
                return fetch64<mode, aligned>(p);
        }
    }

    if ((mode == MODE_BE_BSWAP) ||
            ((mode == MODE_LE_NATIVE) && !aligned && !unaligned_wordwise)) {
        switch (tail & 7) {
        case 0:
                r = p  [7] << 8;
        /* fall through */
        case 7:
                r  += p[6];
                r <<= 8;
        /* fall through */
        case 6:
                r  += p[5];
                r <<= 8;
        /* fall through */
        case 5:
                r  += p[4];
                r <<= 8;
        /* fall through */
        case 4:
                r  += p[3];
                r <<= 8;
        /* fall through */
        case 3:
                r  += p[2];
                r <<= 8;
        /* fall through */
        case 2:
                r  += p[1];
                r <<= 8;
        /* fall through */
        case 1:
                return r + p[0];
        }
    }

    if ((mode == MODE_LE_BSWAP) ||
            ((mode == MODE_BE_NATIVE) && !aligned && !unaligned_wordwise)) {
        switch (tail & 7) {
        case 1:
                return p[0];
        case 2:
                return p[1] | (uint32_t)p[0] << 8;
        case 3:
                return p[2] | (uint32_t)p[1] << 8 | (uint32_t)p[0] << 16;
        case 4:
                return p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 |
                       (uint32_t)p[0] << 24;
        case 5:
                return p[4] | (uint32_t)p[3] << 8 | (uint32_t)p[2] << 16 |
                       (uint32_t)p[1] << 24 | (uint64_t)p[0] << 32;
        case 6:
                return p[5] | (uint32_t)p[4] << 8 | (uint32_t)p[3] << 16 |
                       (uint32_t)p[2] << 24 | (uint64_t)p[1] << 32 | (uint64_t)p[0] << 40;
        case 7:
                return p[6] | (uint32_t)p[5] << 8 | (uint32_t)p[4] << 16 |
                       (uint32_t)p[3] << 24 | (uint64_t)p[2] << 32 | (uint64_t)p[1] << 40 |
                       (uint64_t)p[0] << 48;
        case 0:
                return p[7] | (uint32_t)p[6] << 8 | (uint32_t)p[5] << 16 |
                       (uint32_t)p[4] << 24 | (uint64_t)p[3] << 32 | (uint64_t)p[2] << 40 |
                       (uint64_t)p[1] << 48 | (uint64_t)p[0] << 56;
        }
    }

    unreachable();
    return 0;
}

//------------------------------------------------------------
// T1HA0 (non-AES version)
static FORCE_INLINE void mixup32( uint32_t * a, uint32_t * b, uint32_t v, uint32_t prime ) {
    uint32_t rlo, rhi;

    MathMult::mult32_64(rlo, rhi, *b + v, prime);
    *a ^= rlo;
    *b += rhi;
}

static FORCE_INLINE uint64_t final32( uint32_t a, uint32_t b ) {
    uint64_t l = (b ^ ROTR32(a, 13)) | (uint64_t)a << 32;

    l *= prime_0;
    l ^= l >> 41;
    l *= prime_4;
    l ^= l >> 47;
    l *= prime_6;
    return l;
}

template <enum t1ha_modes mode, bool aligned32>
static uint64_t t1ha0_32_impl( const void * data, size_t len, uint64_t seed ) {
    uint32_t a         = ROTR32((uint32_t)len, 17) + (uint32_t)seed;
    uint32_t b         = (uint32_t)len ^ (uint32_t)(seed >> 32);

    const uint32_t * v = (const uint32_t *)data;

    if (unlikely(len > 16)) {
        uint32_t         c      = ~a;
        uint32_t         d      = ROTR32(b, 5);
        const uint32_t * detent =
                (const uint32_t *)((const uint8_t *)data + len - 15);
        do {
            const uint32_t w0 = fetch32<mode, aligned32>(v + 0);
            const uint32_t w1 = fetch32<mode, aligned32>(v + 1);
            const uint32_t w2 = fetch32<mode, aligned32>(v + 2);
            const uint32_t w3 = fetch32<mode, aligned32>(v + 3);
            v += 4;
            prefetch(v);

            const uint32_t d13 = w1 + ROTR32(w3 + d, 17);
            const uint32_t c02 = w0 ^ ROTR32(w2 + c, 11);
            d ^= ROTR32(a + w0, 3);
            c ^= ROTR32(b + w1, 7);
            b  = prime32_1 * (c02 + w3);
            a  = prime32_0 * (d13 ^ w2);
        } while (likely(v < detent));

        c   += a;
        d   += b;
        a   ^= prime32_6 * (ROTR32(c    , 16) + d);
        b   ^= prime32_5 * (c + ROTR32(d, 16)    );

        len &= 15;
    }

    switch (len) {
    default:
             mixup32(&a, &b, fetch32<mode, aligned32>(v++)  , prime32_4);
    /* fall through */
    case 12:
    case 11:
    case 10:
    case  9:
             mixup32(&b, &a, fetch32<mode, aligned32>(v++)  , prime32_3);
    /* fall through */
    case  8:
    case  7:
    case  6:
    case  5:
             mixup32(&a, &b, fetch32<mode, aligned32>(v++)  , prime32_2);
    /* fall through */
    case  4:
    case  3:
    case  2:
    case  1:
             mixup32(&b, &a, tail32<mode, aligned32>(v, len), prime32_1);
    /* fall through */
    case  0:
             return final32(a, b);
    }
}

//------------------------------------------------------------
// T1HA1

/* xor high and low parts of full 128-bit product */
static FORCE_INLINE uint64_t mux64( uint64_t v, uint64_t prime ) {
    uint64_t l, h;

    MathMult::mult64_128(l, h, v, prime);
    return l ^ h;
}

/* xor-mul-xor mixer */
static FORCE_INLINE uint64_t mix64( uint64_t v, uint64_t p ) {
    v *= p;
    return v ^ ROTR64(v, 41);
}

static FORCE_INLINE uint64_t final_weak_avalanche( uint64_t a, uint64_t b ) {
    /*
     * LY: for performance reason on a some not high-end CPUs
     * I replaced the second mux64() operation by mix64().
     * Unfortunately this approach fails the "strict avalanche criteria",
     * see test results at https://github.com/demerphq/smhasher.
     */
    return mux64(ROTR64(a + b, 17), prime_4) + mix64(a ^ b, prime_0);
}

template <enum t1ha_modes mode, bool aligned64>
static uint64_t t1ha1_impl( const void * data, size_t len, uint64_t seed ) {
    const uint64_t * v = (const uint64_t *)data;
    uint64_t         a = seed;
    uint64_t         b = len;

    if (unlikely(len > 32)) {
        uint64_t         c      = ROTR64(len, 17) + seed;
        uint64_t         d      = len ^ ROTR64(seed, 17);
        const uint64_t * detent =
                (const uint64_t *)((const uint8_t *)data + len - 31);
        do {
            const uint64_t w0 = fetch64<mode, aligned64>(v + 0);
            const uint64_t w1 = fetch64<mode, aligned64>(v + 1);
            const uint64_t w2 = fetch64<mode, aligned64>(v + 2);
            const uint64_t w3 = fetch64<mode, aligned64>(v + 3);
            v += 4;
            prefetch(v);

            const uint64_t d02 = w0 ^ ROTR64(w2 + d, 17);
            const uint64_t c13 = w1 ^ ROTR64(w3 + c, 17);
            d -= b ^ ROTR64(w1, 31);
            c += a ^ ROTR64(w0, 41);
            b ^= prime_0 * (c13 + w2);
            a ^= prime_1 * (d02 + w3);
        } while (likely(v < detent));

        a   ^= prime_6 * (ROTR64(c    , 17) + d);
        b   ^= prime_5 * (c + ROTR64(d, 17)    );
        len &= 31;
    }

    switch (len) {
    default:
             b += mux64(fetch64<mode, aligned64>(v++)  , prime_4);
    /* fall through */
    case 24:
    case 23:
    case 22:
    case 21:
    case 20:
    case 19:
    case 18:
    case 17:
             a += mux64(fetch64<mode, aligned64>(v++)  , prime_3);
    /* fall through */
    case 16:
    case 15:
    case 14:
    case 13:
    case 12:
    case 11:
    case 10:
    case  9:
             b += mux64(fetch64<mode, aligned64>(v++)  , prime_2);
    /* fall through */
    case  8:
    case  7:
    case  6:
    case  5:
    case  4:
    case  3:
    case  2:
    case  1:
             a += mux64(tail64<mode, aligned64>(v, len), prime_1);
    /* fall through */
    case  0:
             return final_weak_avalanche(a, b);
    }
}

//------------------------------------------------------------
// T1HA2

// XXX T1HA_ALIGN_PREFIX and T1HA_ALIGN_SUFFIX were not ported
typedef union t1ha_state256 {
    uint8_t   bytes[32];
    uint32_t  u32[8];
    uint64_t  u64[4];
    struct {
        uint64_t  a, b, c, d;
    }  n;
} t1ha_state256_t;

typedef struct t1ha_context {
    t1ha_state256_t  state;
    t1ha_state256_t  buffer;
    size_t           partial;
    uint64_t         total;
} t1ha_context_t;

static FORCE_INLINE void init_ab( t1ha_state256_t * s, uint64_t x, uint64_t y ) {
    s->n.a = x;
    s->n.b = y;
}

static FORCE_INLINE void init_cd( t1ha_state256_t * s, uint64_t x, uint64_t y ) {
    s->n.c = ROTR64(y, 23) + ~x;
    s->n.d = ~y + ROTR64(x, 19);
}

static FORCE_INLINE void squash( t1ha_state256_t * s ) {
    s->n.a ^= prime_6 * (s->n.c + ROTR64(s->n.d, 23)         );
    s->n.b ^= prime_5 * (ROTR64(s->n.c         , 19) + s->n.d);
}

static FORCE_INLINE void mixup64( uint64_t * RESTRICT a, uint64_t * RESTRICT b, uint64_t v, uint64_t prime ) {
    uint64_t l, h;

    MathMult::mult64_128(l, h, *b + v, prime);
    *a ^= l;
    *b += h;
}

static FORCE_INLINE uint64_t final64( uint64_t a, uint64_t b ) {
    uint64_t x = (a + ROTR64(b, 41)    ) * prime_0;
    uint64_t y = (ROTR64(a    , 23) + b) * prime_6;

    return mux64(x ^ y, prime_5);
}

static FORCE_INLINE uint64_t final128( uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t * h ) {
    mixup64(&a, &b, ROTR64(c, 41) ^ d, prime_0);
    mixup64(&b, &c, ROTR64(d, 23) ^ a, prime_6);
    mixup64(&c, &d, ROTR64(a, 19) ^ b, prime_5);
    mixup64(&d, &a, ROTR64(b, 31) ^ c, prime_4);
    *h = c + d;
    return a ^ b;
}

template <enum t1ha_modes mode, bool aligned64>
static void T1HA2_UPDATE( t1ha_state256_t * const s, const uint64_t * v ) {
    const uint64_t w0  = fetch64<mode, aligned64>(v + 0);
    const uint64_t w1  = fetch64<mode, aligned64>(v + 1);
    const uint64_t w2  = fetch64<mode, aligned64>(v + 2);
    const uint64_t w3  = fetch64<mode, aligned64>(v + 3);

    const uint64_t d02 = w0 + ROTR64(w2 + s->n.d, 56);
    const uint64_t c13 = w1 + ROTR64(w3 + s->n.c, 19);

    s->n.d ^= s->n.b + ROTR64(w1, 38);
    s->n.c ^= s->n.a + ROTR64(w0, 57);
    s->n.b ^= prime_6 * (c13 + w2);
    s->n.a ^= prime_5 * (d02 + w3);
}

template <enum t1ha_modes mode, bool aligned64>
static const void * T1HA2_LOOP( t1ha_state256_t * const state, const void * data, size_t len ) {
    const void * detent = (const uint8_t *)data + len - 31;

    do {
        const uint64_t * v = (const uint64_t *)data;
        data = v + 4;
        prefetch(data);
        T1HA2_UPDATE<mode, aligned64>(state, v);
    } while (likely(data < detent));
    return data;
}

template <enum t1ha_modes mode, bool aligned64, bool use_ABCD>
static uint64_t T1HA2_TAIL( t1ha_state256_t * const s, const void * data,
        size_t len, uint64_t * RESTRICT extra_result = NULL ) {
    const uint64_t * v = (const uint64_t *)data;
    uint64_t         val;

    switch (len) {
    default:
             if (use_ABCD) {
                 mixup64(&s->n.a, &s->n.d, fetch64<mode, aligned64>(v++), prime_4);
             } else {
                 mixup64(&s->n.a, &s->n.b, fetch64<mode, aligned64>(v++), prime_4);
             }
    /* fall through */
    case 24:
    case 23:
    case 22:
    case 21:
    case 20:
    case 19:
    case 18:
    case 17:
             // ".b, .a" for either value of use_ABCD
             mixup64(&s->n.b, &s->n.a, fetch64<mode, aligned64>(v++), prime_3);
    /* fall through */
    case 16:
    case 15:
    case 14:
    case 13:
    case 12:
    case 11:
    case 10:
    case  9:
             if (use_ABCD) {
                 mixup64(&s->n.c, &s->n.b, fetch64<mode, aligned64>(v++), prime_2);
             } else {
                 mixup64(&s->n.a, &s->n.b, fetch64<mode, aligned64>(v++), prime_2);
             }
    /* fall through */
    case  8:
    case  7:
    case  6:
    case  5:
    case  4:
    case  3:
    case  2:
    case  1:
             val = tail64<mode, aligned64>(v, len);
             if (use_ABCD) {
                 mixup64(&s->n.d, &s->n.c, val, prime_1);
             } else {
                 mixup64(&s->n.b, &s->n.a, val, prime_1);
             }
    /* fall through */
    case  0:
             if (use_ABCD) {
                 return final128(s->n.a, s->n.b, s->n.c, s->n.d, extra_result);
             } else {
                 return final64(s->n.a, s->n.b);
             }
    }
}

static void t1ha2_init( t1ha_context_t * ctx, uint64_t seed_x, uint64_t seed_y ) {
    init_ab(&ctx->state, seed_x, seed_y);
    init_cd(&ctx->state, seed_x, seed_y);
    ctx->partial = 0;
    ctx->total   = 0;
}

template <enum t1ha_modes mode>
static void t1ha2_update( t1ha_context_t * RESTRICT ctx, const void * RESTRICT data, size_t length ) {
    ctx->total += length;

    if (ctx->partial) {
        const size_t left  = 32 - ctx->partial;
        const size_t chunk = (length >= left) ? left : length;
        memcpy(ctx->buffer.bytes + ctx->partial, data, chunk);
        ctx->partial += chunk;
        if (ctx->partial < 32) {
            assert(left >= length);
            return;
        }
        ctx->partial = 0;
        data         = (const uint8_t *)data + chunk;
        length      -= chunk;
        T1HA2_UPDATE<mode, true>(&ctx->state, ctx->buffer.u64);
    }

    if (length >= 32) {
        if ((T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__EFFICIENT) ||
                ((((uintptr_t)data) & (ALIGNMENT_64 - 1)) != 0)) {
            data = T1HA2_LOOP<mode, false>(&ctx->state, data, length);
        } else {
            data = T1HA2_LOOP<mode,  true>(&ctx->state, data, length);
        }
        length &= 31;
    }

    if (length) {
        memcpy(ctx->buffer.bytes, data, ctx->partial = length);
    }
}

template <enum t1ha_modes mode>
static uint64_t t1ha2_final( t1ha_context_t * RESTRICT ctx, uint64_t * RESTRICT extra_result ) {
    uint64_t bits = (ctx->total << 3) ^ (UINT64_C(1) << 63);

    bits = COND_BSWAP(bits, MODE_BE_SYS(mode));
    t1ha2_update<mode>(ctx, &bits, 8);

    if (likely(!extra_result)) {
        squash(&ctx->state);
        return T1HA2_TAIL<mode, true, false>(&ctx->state, ctx->buffer.u64, ctx->partial);
    }

    return T1HA2_TAIL<mode, true, true>(&ctx->state, ctx->buffer.u64, ctx->partial, extra_result);
}

//------------------------------------------------------------
// T1HA0 (AES versions)
#if defined(HAVE_X86_64_AES)

// versionA is t1ha0_ia32aes_avx1/t1ha0_ia32aes_noavx, which appear to
// be identical. versionB is t1ha0_ia32aes_avx2, which does not appear
// to need AVX2. ¯\_(ツ)_/¯
template <enum t1ha_modes mode, bool versionB>
static uint64_t t1ha0_aes_impl( const void * data, size_t len, uint64_t seed ) {
    uint64_t a = seed;
    uint64_t b = len;

    if (unlikely(len > 32)) {
        __m128i x = _mm_set_epi64x(a, b);
        __m128i y;

        if (versionB) {
            const __m128i *       v      = (const __m128i *)data;
            const __m128i * const detent =
                    (const __m128i *)((const uint8_t *)data + (len & ~15ul));
            y    = _mm_aesenc_si128(x, _mm_set_epi64x(prime_0, prime_1));
            data = detent;

            if (len & 16) {
                x = _mm_add_epi64(x, _mm_loadu_si128(v++));
                y = _mm_aesenc_si128(x, y);
            }
            len &= 15;

            if (v + 7 < detent) {
                __m128i salt = y;
                do {
                    __m128i t = _mm_aesenc_si128(_mm_loadu_si128(v++), salt);
                    t    = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
                    t    = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
                    t    = _mm_aesdec_si128(t, _mm_loadu_si128(v++));

                    t    = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
                    t    = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
                    t    = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
                    t    = _mm_aesdec_si128(t, _mm_loadu_si128(v++));

                    salt = _mm_add_epi64(salt, _mm_set_epi64x(prime_5, prime_6));
                    t    = _mm_aesenc_si128(x, t);
                    x    = _mm_add_epi64(y, x);
                    y    = t;
                } while (v + 7 < detent);
            }

            while (v < detent) {
                __m128i v0y = _mm_add_epi64(y, _mm_loadu_si128(v++));
                __m128i v1x = _mm_sub_epi64(x, _mm_loadu_si128(v++));
                x = _mm_aesdec_si128(x, v0y);
                y = _mm_aesdec_si128(y, v1x);
            }
        } else {
            const __m128i * RESTRICT       v      = (const __m128i *)data;
            const __m128i * RESTRICT const detent =
                    (const __m128i *)((const uint8_t *)data + len - 127);
            y = _mm_aesenc_si128(x, _mm_set_epi64x(prime_5, prime_6));

            while (v < detent) {
                __m128i v0     = _mm_loadu_si128(v + 0);
                __m128i v1     = _mm_loadu_si128(v + 1);
                __m128i v2     = _mm_loadu_si128(v + 2);
                __m128i v3     = _mm_loadu_si128(v + 3);
                __m128i v4     = _mm_loadu_si128(v + 4);
                __m128i v5     = _mm_loadu_si128(v + 5);
                __m128i v6     = _mm_loadu_si128(v + 6);
                __m128i v7     = _mm_loadu_si128(v + 7);

                __m128i v0y    = _mm_aesenc_si128(v0, y);
                __m128i v2x6   = _mm_aesenc_si128(v2, _mm_xor_si128(x, v6));
                __m128i v45_67 =
                        _mm_xor_si128(_mm_aesenc_si128(v4, v5), _mm_add_epi64(v6, v7));

                __m128i v0y7_1 = _mm_aesdec_si128(_mm_sub_epi64(v7, v0y), v1);
                __m128i v2x6_3 = _mm_aesenc_si128(v2x6, v3);

                x  = _mm_aesenc_si128(v45_67, _mm_add_epi64(x, y)      );
                y  = _mm_aesenc_si128(v2x6_3, _mm_xor_si128(v0y7_1, v5));
                v += 8;
            }

            if (len & 64) {
                __m128i v0y = _mm_add_epi64(y, _mm_loadu_si128(v++));
                __m128i v1x = _mm_sub_epi64(x, _mm_loadu_si128(v++));
                x = _mm_aesdec_si128(x, v0y);
                y = _mm_aesdec_si128(y, v1x);

                __m128i v2y = _mm_add_epi64(y, _mm_loadu_si128(v++));
                __m128i v3x = _mm_sub_epi64(x, _mm_loadu_si128(v++));
                x = _mm_aesdec_si128(x, v2y);
                y = _mm_aesdec_si128(y, v3x);
            }

            if (len & 32) {
                __m128i v0y = _mm_add_epi64(y, _mm_loadu_si128(v++));
                __m128i v1x = _mm_sub_epi64(x, _mm_loadu_si128(v++));
                x = _mm_aesdec_si128(x, v0y);
                y = _mm_aesdec_si128(y, v1x);
            }

            if (len & 16) {
                y = _mm_add_epi64(x, y);
                x = _mm_aesdec_si128(x, _mm_loadu_si128(v++));
            }

            data = v;
            len &= 15;
        }

        x = _mm_add_epi64(_mm_aesdec_si128(x, _mm_aesenc_si128(y, x)), y);
  #if defined(HAVE_32BIT_PLATFORM)
    #if defined(HAVE_SSE_4_1)
        a =     (uint32_t)_mm_extract_epi32(x, 0)  |
                (uint64_t)_mm_extract_epi32(x, 1) << 32;
        b =     (uint32_t)_mm_extract_epi32(x, 2)  |
                (uint64_t)_mm_extract_epi32(x, 3) << 32;
    #else
        a  =    (uint32_t)_mm_cvtsi128_si32(x);
        a |= (uint64_t)_mm_cvtsi128_si32(_mm_shuffle_epi32(x, 1)) << 32;
        x  = _mm_unpackhi_epi64(x, x);
        b  =    (uint32_t)_mm_cvtsi128_si32(x);
        b |= (uint64_t)_mm_cvtsi128_si32(_mm_shuffle_epi32(x, 1)) << 32;
    #endif
        _mm_empty();
  #else /* HAVE_32BIT_PLATFORM */
    #if defined(HAVE_SSE_4_1)
        a = _mm_extract_epi64(x, 0);
        b = _mm_extract_epi64(x, 1);
    #else
        a = _mm_cvtsi128_si64(x);
        b = _mm_cvtsi128_si64(_mm_unpackhi_epi64(x, x));
    #endif
    #if defined(HAVE_AVX)
        _mm256_zeroall();
    #endif
  #endif
    }

    const uint64_t * v = (const uint64_t *)data;
    switch (len) {
    default:
             mixup64(&a, &b, fetch64<mode, false>(v++)  , prime_4);
    /* fall through */
    case 24:
    case 23:
    case 22:
    case 21:
    case 20:
    case 19:
    case 18:
    case 17:
             mixup64(&b, &a, fetch64<mode, false>(v++)  , prime_3);
    /* fall through */
    case 16:
    case 15:
    case 14:
    case 13:
    case 12:
    case 11:
    case 10:
    case  9:
             mixup64(&a, &b, fetch64<mode, false>(v++)  , prime_2);
    /* fall through */
    case  8:
    case  7:
    case  6:
    case  5:
    case  4:
    case  3:
    case  2:
    case  1:
             mixup64(&b, &a, tail64<mode, false>(v, len), prime_1);
    /* fall through */
    case  0:
             return final64(a, b);
    }
}

#endif

template <enum t1ha_modes mode>
static void t1ha0( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t hash;

    // If unaligned access is fast, don't worry about
    // checking/handling pointer alignments. Otherwise, use
    // aligned-specific code if possible.
    if ((T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__EFFICIENT) ||
            ((((uintptr_t)in) & (ALIGNMENT_32 - 1)) != 0)) {
        hash = t1ha0_32_impl<mode, false>(in, len, (uint64_t)seed);
    } else {
        hash = t1ha0_32_impl<mode,  true>(in, len, (uint64_t)seed);
    }
    // To get old 0xDA6A4061 verification value for BE mode, replace
    // "MODE_BSWAP(mode)" with "MODE_BE_SYS(mode)", as the old code wrote
    // the hash value out in native (little-endian) byte format even
    // for the big-endian hash.
    PUT_U64<MODE_BSWAP(mode)>(hash, (uint8_t *)out, 0);
}

template <enum t1ha_modes mode>
static void t1ha1( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t hash;

    // If unaligned access is fast, don't worry about
    // checking/handling pointer alignments. Otherwise, use
    // aligned-specific code if possible.
    if ((T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__EFFICIENT) ||
            ((((uintptr_t)in) & (ALIGNMENT_64 - 1)) != 0)) {
        hash = t1ha1_impl<mode, false>(in, len, (uint64_t)seed);
    } else {
        hash = t1ha1_impl<mode,  true>(in, len, (uint64_t)seed);
    }
    // To get the old 0x93F864DE verification value for BE mode,
    // replace "MODE_BSWAP(mode)" with "MODE_BE_SYS(mode)", as the old
    // code wrote the hash value out in native (little-endian) byte
    // format even for the big-endian hash.
    PUT_U64<MODE_BSWAP(mode)>(hash, (uint8_t *)out, 0);
}

template <enum t1ha_modes mode, bool xwidth>
static void t1ha2( const void * in, const size_t len, const seed_t seed, void * out ) {
    alignas(16) t1ha_state256_t state;
    uint64_t   hash, xhash = 0;
    uint64_t   length        = (uint64_t)len;
    const bool use_unaligned =
            (T1HA_SYS_UNALIGNED_ACCESS == T1HA_UNALIGNED_ACCESS__EFFICIENT) ||
            ((((uintptr_t)in) & (ALIGNMENT_64 - 1)) != 0);

    init_ab(&state, (uint64_t)seed, length);
    if (unlikely(length > 32)) {
        init_cd(&state, (uint64_t)seed, length);
        if (use_unaligned) {
            in = T1HA2_LOOP<mode, false>(&state, in, length);
        } else {
            in = T1HA2_LOOP<mode,  true>(&state, in, length);
        }
        if (!xwidth) {
            squash(&state);
        }
        length &= 31;
    } else if (xwidth) {
        init_cd(&state, (uint64_t)seed, length);
    }
    if (use_unaligned) {
        hash = xwidth ?
                    T1HA2_TAIL<mode, false,  true>(&state, in, length, &xhash) :
                    T1HA2_TAIL<mode, false, false>(&state, in, length);
    } else {
        hash = xwidth ?
                    T1HA2_TAIL<mode, true,  true>(&state, in, length, &xhash) :
                    T1HA2_TAIL<mode, true, false>(&state, in, length);
    }
    PUT_U64<MODE_BSWAP(mode)>(hash, (uint8_t *)out, 0);
    if (xwidth) {
        PUT_U64<MODE_BSWAP(mode)>(xhash, (uint8_t *)out, 8);
    }
}

// t1ha published selftest code uses the seed twice during
// initialization, while published SMHasher validation codes use it
// once. Default to once so SMHasher3 tests are consistent, but allow
// selftests to use published KAT tables.
template <enum t1ha_modes mode, bool xwidth, bool selftest_seeding = false>
static void t1ha2_incr( const void * in, const size_t len, const seed_t seed, void * out ) {
    alignas(16) t1ha_context_t ctx;
    uint64_t hash, xhash = 0;

    t1ha2_init(&ctx, seed, selftest_seeding ? seed : 0);
    t1ha2_update<mode>(&ctx, in, len);
    hash = t1ha2_final<mode>(&ctx, (xwidth ? &xhash : NULL));

    PUT_U64<MODE_BSWAP(mode)>(hash, (uint8_t *)out, 0);
    if (xwidth) {
        PUT_U64<MODE_BSWAP(mode)>(xhash, (uint8_t *)out, 8);
    }
}

#if defined(HAVE_X86_64_AES)

template <bool bswap>
static void t1ha0_aesA( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t hash;

    hash = t1ha0_aes_impl<MODE_LE_NATIVE, false>(in, len, (uint64_t)seed);
    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}

template <bool bswap>
static void t1ha0_aesB( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t hash;

    hash = t1ha0_aes_impl<MODE_LE_NATIVE, true>(in, len, (uint64_t)seed);
    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}

#endif

//------------------------------------------------------------
static const uint8_t t1ha_test_pattern      [64] = {
       0,    1,    2,    3,    4,    5,    6,    7 , 0xFF, 0x7F, 0x3F,
    0x1F,  0xF,    8,   16,   32,   64, 0x80, 0xFE , 0xFC, 0xF8, 0xF0,
    0xE0, 0xC0, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF , 0x55, 0xAA,   11,
      17,   19,   23,   29,   37,   42,   43,   'a',  'b',  'c',  'd',
     'e',  'f',  'g',  'h',  'i',  'j',  'k',  'l' ,  'm',  'n',  'o',
     'p',  'q',  'r',  's',  't',  'u',  'v',  'w' ,  'x'
};

static const uint64_t t1ha_refval_32le      [81] = {
    0,
    UINT64_C(0xC92229C10FAEA50E), UINT64_C(0x3DF1354B0DFDC443), UINT64_C(0x968F016D60417BB3), UINT64_C(0x85AAFB50C6DA770F),
    UINT64_C(0x66CCE3BB6842C7D6), UINT64_C(0xDDAA39C11537C226), UINT64_C(0x35958D281F0C9C8C), UINT64_C(0x8C5D64B091DE608E),
    UINT64_C(0x4094DF680D39786B), UINT64_C(0x1014F4AA2A2EDF4D), UINT64_C(0x39D21891615AA310), UINT64_C(0x7EF51F67C398C7C4),
    UINT64_C(0x06163990DDBF319D), UINT64_C(0xE229CAA00C8D6F3F), UINT64_C(0xD2240B4B0D54E0F5), UINT64_C(0xEA2E7E905DDEAF94),
    UINT64_C(0x8D4F8A887183A5CE), UINT64_C(0x44337F9A63C5820C), UINT64_C(0x94938D1E86A9B797), UINT64_C(0x96E9CABA5CA210CC),
    UINT64_C(0x6EFBB9CC9E8F7708), UINT64_C(0x3D12EA0282FB8BBC), UINT64_C(0x5DA781EE205A2C48), UINT64_C(0xFA4A51A12677FE12),
    UINT64_C(0x81D5F04E20660B28), UINT64_C(0x57258D043BCD3841), UINT64_C(0x5C9BEB62059C1ED2), UINT64_C(0x57A02162F9034B33),
    UINT64_C(0xBA2A13E457CE19B8), UINT64_C(0xE593263BF9451F3A), UINT64_C(0x0BC1175539606BC5), UINT64_C(0xA3E2929E9C5F289F),
    UINT64_C(0x86BDBD06835E35F7), UINT64_C(0xA180950AB48BAADC), UINT64_C(0x7812C994D9924028), UINT64_C(0x308366011415F46B),
    UINT64_C(0x77FE9A9991C5F959), UINT64_C(0x925C340B70B0B1E3), UINT64_C(0xCD9C5BA4C41E2E10), UINT64_C(0x7CC4E7758B94CD93),
    UINT64_C(0x898B235962EA4625), UINT64_C(0xD7E3E5BF22893286), UINT64_C(0x396F4CDD33056C64), UINT64_C(0x740AB2E32F17CD9F),
    UINT64_C(0x60D12FF9CD15B321), UINT64_C(0xBEE3A6C9903A81D8), UINT64_C(0xB47040913B33C35E), UINT64_C(0x19EE8C2ACC013CFF),
    UINT64_C(0x5DEC94C5783B55C4), UINT64_C(0x78DC122D562C5F1D), UINT64_C(0x6520F008DA1C181E), UINT64_C(0x77CAF155A36EBF7C),
    UINT64_C(0x0A09E02BDB883CA6), UINT64_C(0xFD5D9ADA7E3FB895), UINT64_C(0xC6F5FDD9EEAB83B5), UINT64_C(0x84589BB29F52A92A),
    UINT64_C(0x9B2517F13F8E9814), UINT64_C(0x6F752AF6A52E31EC), UINT64_C(0x8E717799E324CE8A), UINT64_C(0x84D90AEF39262D58),
    UINT64_C(0x79C27B13FC28944D), UINT64_C(0xE6D6DF6438E0044A), UINT64_C(0x51B603E400D79CA4), UINT64_C(0x6A902B28C588B390),
    UINT64_C(0x8D7F8DE9E6CB1D83), UINT64_C(0xCF1A4DC11CA7F044), UINT64_C(0xEF02E43C366786F1), UINT64_C(0x89915BCDBCFBE30F),
    UINT64_C(0x5928B306F1A9CC7F), UINT64_C(0xA8B59092996851C5), UINT64_C(0x22050A20427E8B25), UINT64_C(0x6E6D64018941E7EE),
    UINT64_C(0x9798C898B81AE846), UINT64_C(0x80EF218CDC30124A), UINT64_C(0xFCE45E60D55B0284), UINT64_C(0x4010E735D3147C35),
    UINT64_C(0xEB647D999FD8DC7E), UINT64_C(0xD3544DCAB14FE907), UINT64_C(0xB588B27D8438700C), UINT64_C(0xA49EBFC43E057A4C)
};

static const uint64_t t1ha_refval_32be      [81] = {
    0,
    UINT64_C(0xC92229C10FAEA50E), UINT64_C(0x0FE212630DD87E0F), UINT64_C(0x968F016D60417BB3), UINT64_C(0xE6B12B2C889913AB),
    UINT64_C(0xAA3787887A9DA368), UINT64_C(0x06EE7202D53CEF39), UINT64_C(0x6149AFB2C296664B), UINT64_C(0x86C893210F9A5805),
    UINT64_C(0x8379E5DA988AA04C), UINT64_C(0x24763AA7CE411A60), UINT64_C(0x9CF9C64B395A4CF8), UINT64_C(0xFFC192C338DDE904),
    UINT64_C(0x094575BAB319E5F5), UINT64_C(0xBBBACFE7728C6511), UINT64_C(0x36B8C3CEBE4EF409), UINT64_C(0xAA0BA8A3397BA4D0),
    UINT64_C(0xF9F85CF7124EE653), UINT64_C(0x3ADF4F7DF2A887AE), UINT64_C(0xAA2A0F5964AA9A7A), UINT64_C(0xF18B563F42D36EB8),
    UINT64_C(0x034366CEF8334F5C), UINT64_C(0xAE2E85180E330E5F), UINT64_C(0xA5CE9FBFDF5C65B8), UINT64_C(0x5E509F25A9CA9B0B),
    UINT64_C(0xE30D1358C2013BD2), UINT64_C(0xBB3A04D5EB8111FE), UINT64_C(0xB04234E82A15A28D), UINT64_C(0x87426A56D0EA0E2F),
    UINT64_C(0x095086668E07F9F8), UINT64_C(0xF4CD3A43B6A6AEA5), UINT64_C(0x73F9B9B674D472A6), UINT64_C(0x558344229A1E4DCF),
    UINT64_C(0x0AD4C95B2279181A), UINT64_C(0x5E3D19D80821CA6B), UINT64_C(0x652492D25BEBA258), UINT64_C(0xEFA84B02EAB849B1),
    UINT64_C(0x81AD2D253059AC2C), UINT64_C(0x1400CCB0DFB2F457), UINT64_C(0x5688DC72A839860E), UINT64_C(0x67CC130E0FD1B0A7),
    UINT64_C(0x0A851E3A94E21E69), UINT64_C(0x2EA0000B6A073907), UINT64_C(0xAE9776FF9BF1D02E), UINT64_C(0xC0A96B66B160631C),
    UINT64_C(0xA93341DE4ED7C8F0), UINT64_C(0x6FBADD8F5B85E141), UINT64_C(0xB7D295F1C21E0CBA), UINT64_C(0x6D6114591B8E434F),
    UINT64_C(0xF5B6939B63D97BE7), UINT64_C(0x3C80D5053F0E5DB4), UINT64_C(0xAC520ACC6B73F62D), UINT64_C(0xD1051F5841CF3966),
    UINT64_C(0x62245AEA644AE760), UINT64_C(0x0CD56BE15497C62D), UINT64_C(0x5BB93435C4988FB6), UINT64_C(0x5FADB88EB18DB512),
    UINT64_C(0xC897CAE2242475CC), UINT64_C(0xF1A094EF846DC9BB), UINT64_C(0x2B1D8B24924F79B6), UINT64_C(0xC6DF0C0E8456EB53),
    UINT64_C(0xE6A40128303A9B9C), UINT64_C(0x64D37AF5EFFA7BD9), UINT64_C(0x90FEB70A5AE2A598), UINT64_C(0xEC3BA5F126D9FF4B),
    UINT64_C(0x3121C8EC3AC51B29), UINT64_C(0x3B41C4D422166EC1), UINT64_C(0xB4878DDCBF48ED76), UINT64_C(0x5CB850D77CB762E4),
    UINT64_C(0x9A27A43CC1DD171F), UINT64_C(0x2FDFFC6F99CB424A), UINT64_C(0xF54A57E09FDEA7BB), UINT64_C(0x5F78E5EE2CAB7039),
    UINT64_C(0xB8BA95883DB31CBA), UINT64_C(0x131C61EB84AF86C3), UINT64_C(0x84B1F64E9C613DA7), UINT64_C(0xE94C1888C0C37C02),
    UINT64_C(0xEA08F8BFB2039CDE), UINT64_C(0xCCC6D04D243EC753), UINT64_C(0x8977D105298B0629), UINT64_C(0x7AAA976494A5905E)
};

static const uint64_t t1ha_refval_64le      [81] = {
    0,
    UINT64_C(0x6A580668D6048674), UINT64_C(0xA2FE904AFF0D0879), UINT64_C(0xE3AB9C06FAF4D023), UINT64_C(0x6AF1C60874C95442),
    UINT64_C(0xB3557E561A6C5D82), UINT64_C(0x0AE73C696F3D37C0), UINT64_C(0x5EF25F7062324941), UINT64_C(0x9B784F3B4CE6AF33),
    UINT64_C(0x6993BB206A74F070), UINT64_C(0xF1E95DF109076C4C), UINT64_C(0x4E1EB70C58E48540), UINT64_C(0x5FDD7649D8EC44E4),
    UINT64_C(0x559122C706343421), UINT64_C(0x380133D58665E93D), UINT64_C(0x9CE74296C8C55AE4), UINT64_C(0x3556F9A5757AB6D0),
    UINT64_C(0xF62751F7F25C469E), UINT64_C(0x851EEC67F6516D94), UINT64_C(0xED463EE3848A8695), UINT64_C(0xDC8791FEFF8ED3AC),
    UINT64_C(0x2569C744E1A282CF), UINT64_C(0xF90EB7C1D70A80B9), UINT64_C(0x68DFA6A1B8050A4C), UINT64_C(0x94CCA5E8210D2134),
    UINT64_C(0xF5CC0BEABC259F52), UINT64_C(0x40DBC1F51618FDA7), UINT64_C(0x0807945BF0FB52C6), UINT64_C(0xE5EF7E09DE70848D),
    UINT64_C(0x63E1DF35FEBE994A), UINT64_C(0x2025E73769720D5A), UINT64_C(0xAD6120B2B8A152E1), UINT64_C(0x2A71D9F13959F2B7),
    UINT64_C(0x8A20849A27C32548), UINT64_C(0x0BCBC9FE3B57884E), UINT64_C(0x0E028D255667AEAD), UINT64_C(0xBE66DAD3043AB694),
    UINT64_C(0xB00E4C1238F9E2D4), UINT64_C(0x5C54BDE5AE280E82), UINT64_C(0x0E22B86754BC3BC4), UINT64_C(0x016707EBF858B84D),
    UINT64_C(0x990015FBC9E095EE), UINT64_C(0x8B9AF0A3E71F042F), UINT64_C(0x6AA56E88BD380564), UINT64_C(0xAACE57113E681A0F),
    UINT64_C(0x19F81514AFA9A22D), UINT64_C(0x80DABA3D62BEAC79), UINT64_C(0x715210412CABBF46), UINT64_C(0xD8FA0B9E9D6AA93F),
    UINT64_C(0x6C2FC5A4109FD3A2), UINT64_C(0x5B3E60EEB51DDCD8), UINT64_C(0x0A7C717017756FE7), UINT64_C(0xA73773805CA31934),
    UINT64_C(0x4DBD6BB7A31E85FD), UINT64_C(0x24F619D3D5BC2DB4), UINT64_C(0x3E4AF35A1678D636), UINT64_C(0x84A1A8DF8D609239),
    UINT64_C(0x359C862CD3BE4FCD), UINT64_C(0xCF3A39F5C27DC125), UINT64_C(0xC0FF62F8FD5F4C77), UINT64_C(0x5E9F2493DDAA166C),
    UINT64_C(0x17424152BE1CA266), UINT64_C(0xA78AFA5AB4BBE0CD), UINT64_C(0x7BFB2E2CEF118346), UINT64_C(0x647C3E0FF3E3D241),
    UINT64_C(0x0352E4055C13242E), UINT64_C(0x6F42FC70EB660E38), UINT64_C(0x0BEBAD4FABF523BA), UINT64_C(0x9269F4214414D61D),
    UINT64_C(0x1CA8760277E6006C), UINT64_C(0x7BAD25A859D87B5D), UINT64_C(0xAD645ADCF7414F1D), UINT64_C(0xB07F517E88D7AFB3),
    UINT64_C(0xB321C06FB5FFAB5C), UINT64_C(0xD50F162A1EFDD844), UINT64_C(0x1DFD3D1924FBE319), UINT64_C(0xDFAEAB2F09EF7E78),
    UINT64_C(0xA7603B5AF07A0B1E), UINT64_C(0x41CD044C0E5A4EE3), UINT64_C(0xF64D2F86E813BF33), UINT64_C(0xFF9FDB99305EB06A)
};

static const uint64_t t1ha_refval_64be      [81] = {
    0,
    UINT64_C(0x6A580668D6048674), UINT64_C(0xDECC975A0E3B8177), UINT64_C(0xE3AB9C06FAF4D023), UINT64_C(0xE401FA8F1B6AF969),
    UINT64_C(0x67DB1DAE56FB94E3), UINT64_C(0x1106266A09B7A073), UINT64_C(0x550339B1EF2C7BBB), UINT64_C(0x290A2BAF590045BB),
    UINT64_C(0xA182C1258C09F54A), UINT64_C(0x137D53C34BE7143A), UINT64_C(0xF6D2B69C6F42BEDC), UINT64_C(0x39643EAF2CA2E4B4),
    UINT64_C(0x22A81F139A2C9559), UINT64_C(0x5B3D6AEF0AF33807), UINT64_C(0x56E3F80A68643C08), UINT64_C(0x9E423BE502378780),
    UINT64_C(0xCDB0986F9A5B2FD5), UINT64_C(0xD5B3C84E7933293F), UINT64_C(0xE5FB8C90399E9742), UINT64_C(0x5D393C1F77B2CF3D),
    UINT64_C(0xC8C82F5B2FF09266), UINT64_C(0xACA0230CA6F7B593), UINT64_C(0xCB5805E2960D1655), UINT64_C(0x7E2AD5B704D77C95),
    UINT64_C(0xC5E903CDB8B9EB5D), UINT64_C(0x4CC7D0D21CC03511), UINT64_C(0x8385DF382CFB3E93), UINT64_C(0xF17699D0564D348A),
    UINT64_C(0xF77EE7F8274A4C8D), UINT64_C(0xB9D8CEE48903BABE), UINT64_C(0xFE0EBD2A82B9CFE9), UINT64_C(0xB49FB6397270F565),
    UINT64_C(0x173735C8C342108E), UINT64_C(0xA37C7FBBEEC0A2EA), UINT64_C(0xC13F66F462BB0B6E), UINT64_C(0x0C04F3C2B551467E),
    UINT64_C(0x76A9CB156810C96E), UINT64_C(0x2038850919B0B151), UINT64_C(0xCEA19F2B6EED647B), UINT64_C(0x6746656D2FA109A4),
    UINT64_C(0xF05137F221007F37), UINT64_C(0x892FA9E13A3B4948), UINT64_C(0x4D57B70D37548A32), UINT64_C(0x1A7CFB3D566580E6),
    UINT64_C(0x7CB30272A45E3FAC), UINT64_C(0x137CCFFD9D51423F), UINT64_C(0xB87D96F3B82DF266), UINT64_C(0x33349AEE7472ED37),
    UINT64_C(0x5CC0D3C99555BC07), UINT64_C(0x4A8F4FA196D964EF), UINT64_C(0xE82A0D64F281FBFA), UINT64_C(0x38A1BAC2C36823E1),
    UINT64_C(0x77D197C239FD737E), UINT64_C(0xFB07746B4E07DF26), UINT64_C(0xC8A2198E967672BD), UINT64_C(0x5F1A146D143FA05A),
    UINT64_C(0x26B877A1201AB7AC), UINT64_C(0x74E5B145214723F8), UINT64_C(0xE9CE10E3C70254BC), UINT64_C(0x299393A0C05B79E8),
    UINT64_C(0xFD2D2B9822A5E7E2), UINT64_C(0x85424FEA50C8E50A), UINT64_C(0xE6839E714B1FFFE5), UINT64_C(0x27971CCB46F9112A),
    UINT64_C(0xC98695A2E0715AA9), UINT64_C(0x338E1CBB4F858226), UINT64_C(0xFC6B5C5CF7A8D806), UINT64_C(0x8973CAADDE8DA50C),
    UINT64_C(0x9C6D47AE32EBAE72), UINT64_C(0x1EBF1F9F21D26D78), UINT64_C(0x80A9704B8E153859), UINT64_C(0x6AFD20A939F141FB),
    UINT64_C(0xC35F6C2B3B553EEF), UINT64_C(0x59529E8B0DC94C1A), UINT64_C(0x1569DF036EBC4FA1), UINT64_C(0xDA32B88593C118F9),
    UINT64_C(0xF01E4155FF5A5660), UINT64_C(0x765A2522DCE2B185), UINT64_C(0xCEE95554128073EF), UINT64_C(0x60F072A5CA51DE2F)
};

static const uint64_t t1ha_refval_2atonce   [81] = {
    0,
    UINT64_C(0x772C7311BE32FF42), UINT64_C(0x444753D23F207E03), UINT64_C(0x71F6DF5DA3B4F532), UINT64_C(0x555859635365F660),
    UINT64_C(0xE98808F1CD39C626), UINT64_C(0x2EB18FAF2163BB09), UINT64_C(0x7B9DD892C8019C87), UINT64_C(0xE2B1431C4DA4D15A),
    UINT64_C(0x1984E718A5477F70), UINT64_C(0x08DD17B266484F79), UINT64_C(0x4C83A05D766AD550), UINT64_C(0x92DCEBB131D1907D),
    UINT64_C(0xD67BC6FC881B8549), UINT64_C(0xF6A9886555FBF66B), UINT64_C(0x6E31616D7F33E25E), UINT64_C(0x36E31B7426E3049D),
    UINT64_C(0x4F8E4FAF46A13F5F), UINT64_C(0x03EB0CB3253F819F), UINT64_C(0x636A7769905770D2), UINT64_C(0x3ADF3781D16D1148),
    UINT64_C(0x92D19CB1818BC9C2), UINT64_C(0x283E68F4D459C533), UINT64_C(0xFA83A8A88DECAA04), UINT64_C(0x8C6F00368EAC538C),
    UINT64_C(0x7B66B0CF3797B322), UINT64_C(0x5131E122FDABA3FF), UINT64_C(0x6E59FF515C08C7A9), UINT64_C(0xBA2C5269B2C377B0),
    UINT64_C(0xA9D24FD368FE8A2B), UINT64_C(0x22DB13D32E33E891), UINT64_C(0x7B97DFC804B876E5), UINT64_C(0xC598BDFCD0E834F9),
    UINT64_C(0xB256163D3687F5A7), UINT64_C(0x66D7A73C6AEF50B3), UINT64_C(0x25A7201C85D9E2A3), UINT64_C(0x911573EDA15299AA),
    UINT64_C(0x5C0062B669E18E4C), UINT64_C(0x17734ADE08D54E28), UINT64_C(0xFFF036E33883F43B), UINT64_C(0xFE0756E7777DF11E),
    UINT64_C(0x37972472D023F129), UINT64_C(0x6CFCE201B55C7F57), UINT64_C(0xE019D1D89F02B3E1), UINT64_C(0xAE5CC580FA1BB7E6),
    UINT64_C(0x295695FB7E59FC3A), UINT64_C(0x76B6C820A40DD35E), UINT64_C(0xB1680A1768462B17), UINT64_C(0x2FB6AF279137DADA),
    UINT64_C(0x28FB6B4366C78535), UINT64_C(0xEC278E53924541B1), UINT64_C(0x164F8AAB8A2A28B5), UINT64_C(0xB6C330AEAC4578AD),
    UINT64_C(0x7F6F371070085084), UINT64_C(0x94DEAD60C0F448D3), UINT64_C(0x99737AC232C559EF), UINT64_C(0x6F54A6F9CA8EDD57),
    UINT64_C(0x979B01E926BFCE0C), UINT64_C(0xF7D20BC85439C5B4), UINT64_C(0x64EDB27CD8087C12), UINT64_C(0x11488DE5F79C0BE2),
    UINT64_C(0x25541DDD1680B5A4), UINT64_C(0x8B633D33BE9D1973), UINT64_C(0x404A3113ACF7F6C6), UINT64_C(0xC59DBDEF8550CD56),
    UINT64_C(0x039D23C68F4F992C), UINT64_C(0x5BBB48E4BDD6FD86), UINT64_C(0x41E312248780DF5A), UINT64_C(0xD34791CE75D4E94F),
    UINT64_C(0xED523E5D04DCDCFF), UINT64_C(0x7A6BCE0B6182D879), UINT64_C(0x21FB37483CAC28D8), UINT64_C(0x19A1B66E8DA878AD),
    UINT64_C(0x6F804C5295B09ABE), UINT64_C(0x2A4BE5014115BA81), UINT64_C(0xA678ECC5FC924BE0), UINT64_C(0x50F7A54A99A36F59),
    UINT64_C(0x0FD7E63A39A66452), UINT64_C(0x5AB1B213DD29C4E4), UINT64_C(0xF3ED80D9DF6534C5), UINT64_C(0xC736B12EF90615FD)
};

static const uint64_t t1ha_refval_2atonce128[81] = {
    UINT64_C(0x4EC7F6A48E33B00A),
    UINT64_C(0xB7B7FAA5BD7D8C1E), UINT64_C(0x3269533F66534A76), UINT64_C(0x6C3EC6B687923BFC), UINT64_C(0xC096F5E7EFA471A9),
    UINT64_C(0x79D8AFB550CEA471), UINT64_C(0xCEE0507A20FD5119), UINT64_C(0xFB04CFFC14A9F4BF), UINT64_C(0xBD4406E923807AF2),
    UINT64_C(0x375C02FF11010491), UINT64_C(0xA6EA4C2A59E173FF), UINT64_C(0xE0A606F0002CADDF), UINT64_C(0xE13BEAE6EBC07897),
    UINT64_C(0xF069C2463E48EA10), UINT64_C(0x75BEE1A97089B5FA), UINT64_C(0x378F22F8DE0B8085), UINT64_C(0x9C726FC4D53D0D8B),
    UINT64_C(0x71F6130A2D08F788), UINT64_C(0x7A9B20433FF6CF69), UINT64_C(0xFF49B7CD59BF6D61), UINT64_C(0xCCAAEE0D1CA9C6B3),
    UINT64_C(0xC77889D86039D2AD), UINT64_C(0x7B378B5BEA9B0475), UINT64_C(0x6520BFA79D59AD66), UINT64_C(0x2441490CB8A37267),
    UINT64_C(0xA715A66B7D5CF473), UINT64_C(0x9AE892C88334FD67), UINT64_C(0xD2FFE9AEC1D2169A), UINT64_C(0x790B993F18B18CBB),
    UINT64_C(0xA0D02FBCF6A7B1AD), UINT64_C(0xA90833E6F151D0C1), UINT64_C(0x1AC7AFA37BD79BE0), UINT64_C(0xD5383628B2881A24),
    UINT64_C(0xE5526F9D63F9F8F1), UINT64_C(0xC1F165A01A6D1F4D), UINT64_C(0x6CCEF8FF3FCFA3F2), UINT64_C(0x2030F18325E6DF48),
    UINT64_C(0x289207230E3FB17A), UINT64_C(0x077B66F713A3C4B9), UINT64_C(0x9F39843CAF871754), UINT64_C(0x512FDA0F808ACCF3),
    UINT64_C(0xF4D9801CD0CD1F14), UINT64_C(0x28A0C749ED323638), UINT64_C(0x94844CAFA671F01C), UINT64_C(0xD0E261876B8ACA51),
    UINT64_C(0x8FC2A648A4792EA2), UINT64_C(0x8EF87282136AF5FE), UINT64_C(0x5FE6A54A9FBA6B40), UINT64_C(0xA3CC5B8FE6223D54),
    UINT64_C(0xA8C3C0DD651BB01C), UINT64_C(0x625E9FDD534716F3), UINT64_C(0x1AB2604083C33AC5), UINT64_C(0xDE098853F8692F12),
    UINT64_C(0x4B0813891BD87624), UINT64_C(0x4AB89C4553D182AD), UINT64_C(0x92C15AA2A3C27ADA), UINT64_C(0xFF2918D68191F5D9),
    UINT64_C(0x06363174F641C325), UINT64_C(0x667112ADA74A2059), UINT64_C(0x4BD605D6B5E53D7D), UINT64_C(0xF2512C53663A14C8),
    UINT64_C(0x21857BCB1852667C), UINT64_C(0xAFBEBD0369AEE228), UINT64_C(0x7049340E48FBFD6B), UINT64_C(0x50710E1924F46954),
    UINT64_C(0x869A75E04A976A3F), UINT64_C(0x5A41ABBDD6373889), UINT64_C(0xA781778389B4B188), UINT64_C(0x21A3AFCED6C925B6),
    UINT64_C(0x107226192EC10B42), UINT64_C(0x62A862E84EC2F9B1), UINT64_C(0x2B15E91659606DD7), UINT64_C(0x613934D1F9EC5A42),
    UINT64_C(0x4DC3A96DC5361BAF), UINT64_C(0xC80BBA4CB5F12903), UINT64_C(0x3E3EDAE99A7D6987), UINT64_C(0x8F97B2D55941DCB0),
    UINT64_C(0x4C9787364C3E4EC1), UINT64_C(0xEF0A2D07BEA90CA7), UINT64_C(0x5FABF32C70AEEAFB), UINT64_C(0x3356A5CFA8F23BF4)
};

static const uint64_t t1ha_refval_2stream   [81] = {
    UINT64_C(0x3C8426E33CB41606),
    UINT64_C(0xFD74BE70EE73E617), UINT64_C(0xF43DE3CDD8A20486), UINT64_C(0x882FBCB37E8EA3BB), UINT64_C(0x1AA2CDD34CAA3D4B),
    UINT64_C(0xEE755B2BFAE07ED5), UINT64_C(0xD4E225250D92E213), UINT64_C(0xA09B49083205965B), UINT64_C(0xD47B21724EF9EC9E),
    UINT64_C(0xAC888FC3858CEE11), UINT64_C(0x94F820D85736F244), UINT64_C(0x1707951CCA920932), UINT64_C(0x8E0E45603F7877F0),
    UINT64_C(0x9FD2592C0E3A7212), UINT64_C(0x9A66370F3AE3D427), UINT64_C(0xD33382D2161DE2B7), UINT64_C(0x9A35BE079DA7115F),
    UINT64_C(0x73457C7FF58B4EC3), UINT64_C(0xBE8610BD53D7CE98), UINT64_C(0x65506DFE5CCD5371), UINT64_C(0x286A321AF9D5D9FA),
    UINT64_C(0xB81EF9A7EF3C536D), UINT64_C(0x2CFDB5E6825C6E86), UINT64_C(0xB2A58CBFDFDD303A), UINT64_C(0xD26094A42B950635),
    UINT64_C(0xA34D666A5F02AD9A), UINT64_C(0x0151E013EBCC72E5), UINT64_C(0x9254A6EA7FCB6BB5), UINT64_C(0x10C9361B3869DC2B),
    UINT64_C(0xD7EC55A060606276), UINT64_C(0xA2FF7F8BF8976FFD), UINT64_C(0xB5181BB6852DCC88), UINT64_C(0x0EE394BB6178BAFF),
    UINT64_C(0x3A8B4B400D21B89C), UINT64_C(0xEC270461970960FD), UINT64_C(0x615967FAB053877E), UINT64_C(0xFA51BF1CFEB4714C),
    UINT64_C(0x29FDA8383070F375), UINT64_C(0xC3B663061BC52EDA), UINT64_C(0x192BBAF1F1A57923), UINT64_C(0x6D193B52F93C53AF),
    UINT64_C(0x7F6F5639FE87CA1E), UINT64_C(0x69F7F9140B32EDC8), UINT64_C(0xD0F2416FB24325B6), UINT64_C(0x62C0E37FEDD49FF3),
    UINT64_C(0x57866A4B809D373D), UINT64_C(0x9848D24BD935E137), UINT64_C(0xDFC905B66734D50A), UINT64_C(0x9A938DD194A68529),
    UINT64_C(0x8276C44DF0625228), UINT64_C(0xA4B35D00AD67C0AB), UINT64_C(0x3D9CB359842DB452), UINT64_C(0x4241BFA8C23B267F),
    UINT64_C(0x650FA517BEF15952), UINT64_C(0x782DE2ABD8C7B1E1), UINT64_C(0x4EAE456166CA3E15), UINT64_C(0x40CDF3A02614E337),
    UINT64_C(0xAD84092C46102172), UINT64_C(0x0C68479B03F9A167), UINT64_C(0x7E1BA046749E181C), UINT64_C(0x3F3AB41A697382C1),
    UINT64_C(0xC5E5DD6586EBFDC4), UINT64_C(0xFF926CD4EB02555C), UINT64_C(0x035CFE67F89E709B), UINT64_C(0x89F06AB6464A1B9D),
    UINT64_C(0x8EFF58F3F7DEA758), UINT64_C(0x8B54AC657902089F), UINT64_C(0xC6C4F1F9F8DA4D64), UINT64_C(0xBDB729048AAAC93A),
    UINT64_C(0xEA76BA628F5E5CD6), UINT64_C(0x742159B728B8A979), UINT64_C(0x6D151CD3C720E53D), UINT64_C(0xE97FFF9368FCDC42),
    UINT64_C(0xCA5B38314914FBDA), UINT64_C(0xDD92C91D8B858EAE), UINT64_C(0x66E5F07CF647CBF2), UINT64_C(0xD4CF9B42F4985AFB),
    UINT64_C(0x72AE17AC7D92F6B7), UINT64_C(0xB8206B22AB0472E1), UINT64_C(0x385876B5CFD42479), UINT64_C(0x03294A249EBE6B26)
};

static const uint64_t t1ha_refval_2stream128[81] = {
    UINT64_C(0xCD2801D3B92237D6),
    UINT64_C(0x10E4D47BD821546D), UINT64_C(0x9100704B9D65CD06), UINT64_C(0xD6951CB4016313EF), UINT64_C(0x24DB636F96F474DA),
    UINT64_C(0x3F4AF7DF3C49E422), UINT64_C(0xBFF25B8AF143459B), UINT64_C(0xA157EC13538BE549), UINT64_C(0xD3F5F52C47DBD419),
    UINT64_C(0x0EF3D7D735AF1575), UINT64_C(0x46B7B892823F7B1B), UINT64_C(0xEE22EA4655213289), UINT64_C(0x56AD76F02FE929BC),
    UINT64_C(0x9CF6CD1AC886546E), UINT64_C(0xAF45CE47AEA0B933), UINT64_C(0x535F9DC09F3996B7), UINT64_C(0x1F0C3C01694AE128),
    UINT64_C(0x18495069BE0766F7), UINT64_C(0x37E5FFB3D72A4CB1), UINT64_C(0x6D6C2E9299F30709), UINT64_C(0x4F39E693F50B41E3),
    UINT64_C(0xB11FC4EF0658E116), UINT64_C(0x48BFAACB78E5079B), UINT64_C(0xE1B4C89C781B3AD0), UINT64_C(0x81D2F34888D333A1),
    UINT64_C(0xF6D02270D2EA449C), UINT64_C(0xC884C3C2C3CE1503), UINT64_C(0x711AE16BA157A9B9), UINT64_C(0x1E6140C642558C9D),
    UINT64_C(0x35AB3D238F5DC55B), UINT64_C(0x33F07B6AEF051177), UINT64_C(0xE57336776EEFA71C), UINT64_C(0x6D445F8318BA3752),
    UINT64_C(0xD4F5F6631934C988), UINT64_C(0xD5E260085727C4A2), UINT64_C(0x5B54B41EC180B4FA), UINT64_C(0x7F5D75769C15A898),
    UINT64_C(0xAE5A6DB850CA33C6), UINT64_C(0x038CCB8044663403), UINT64_C(0xDA16310133DC92B8), UINT64_C(0x6A2FFB7AB2B7CE2B),
    UINT64_C(0xDC1832D9229BAE20), UINT64_C(0x8C62C479F5ABC9E4), UINT64_C(0x5EB7B617857C9CCB), UINT64_C(0xB79CF7D749A1E80D),
    UINT64_C(0xDE7FAC3798324FD3), UINT64_C(0x8178911813685D06), UINT64_C(0x6A726CBD394D4410), UINT64_C(0x6CBE6B3280DA1113),
    UINT64_C(0x6829BA4410CF1148), UINT64_C(0xFA7E417EB26C5BC6), UINT64_C(0x22ED87884D6E3A49), UINT64_C(0x15F1472D5115669D),
    UINT64_C(0x2EA0B4C8BF69D318), UINT64_C(0xDFE87070AA545503), UINT64_C(0x6B4C14B5F7144AB9), UINT64_C(0xC1ED49C06126551A),
    UINT64_C(0x351919FC425C3899), UINT64_C(0x7B569C0FA6F1BD3E), UINT64_C(0x713AC2350844CFFD), UINT64_C(0xE9367F9A638C2FF3),
    UINT64_C(0x97F17D325AEA0786), UINT64_C(0xBCB907CC6CF75F91), UINT64_C(0x0CB7517DAF247719), UINT64_C(0xBE16093CC45BE8A9),
    UINT64_C(0x786EEE97359AD6AB), UINT64_C(0xB7AFA4F326B97E78), UINT64_C(0x2694B67FE23E502E), UINT64_C(0x4CB492826E98E0B4),
    UINT64_C(0x838D119F74A416C7), UINT64_C(0x70D6A91E4E5677FD), UINT64_C(0xF3E4027AD30000E6), UINT64_C(0x9BDF692795807F77),
    UINT64_C(0x6A371F966E034A54), UINT64_C(0x8789CF41AE4D67EF), UINT64_C(0x02688755484D60AE), UINT64_C(0xD5834B3A4BF5CE42),
    UINT64_C(0x9405FC61440DE25D), UINT64_C(0x35EB280A157979B6), UINT64_C(0x48D40D6A525297AC), UINT64_C(0x6A87DC185054BADA)
};

#if defined(HAVE_X86_64_AES)
static const uint64_t t1ha_refval_ia32aes_a [81] = {
    0,
    UINT64_C(0x772C7311BE32FF42), UINT64_C(0xB231AC660E5B23B5), UINT64_C(0x71F6DF5DA3B4F532), UINT64_C(0x555859635365F660),
    UINT64_C(0xE98808F1CD39C626), UINT64_C(0x2EB18FAF2163BB09), UINT64_C(0x7B9DD892C8019C87), UINT64_C(0xE2B1431C4DA4D15A),
    UINT64_C(0x1984E718A5477F70), UINT64_C(0x08DD17B266484F79), UINT64_C(0x4C83A05D766AD550), UINT64_C(0x92DCEBB131D1907D),
    UINT64_C(0xD67BC6FC881B8549), UINT64_C(0xF6A9886555FBF66B), UINT64_C(0x6E31616D7F33E25E), UINT64_C(0x36E31B7426E3049D),
    UINT64_C(0x4F8E4FAF46A13F5F), UINT64_C(0x03EB0CB3253F819F), UINT64_C(0x636A7769905770D2), UINT64_C(0x3ADF3781D16D1148),
    UINT64_C(0x92D19CB1818BC9C2), UINT64_C(0x283E68F4D459C533), UINT64_C(0xFA83A8A88DECAA04), UINT64_C(0x8C6F00368EAC538C),
    UINT64_C(0x7B66B0CF3797B322), UINT64_C(0x5131E122FDABA3FF), UINT64_C(0x6E59FF515C08C7A9), UINT64_C(0xBA2C5269B2C377B0),
    UINT64_C(0xA9D24FD368FE8A2B), UINT64_C(0x22DB13D32E33E891), UINT64_C(0x7B97DFC804B876E5), UINT64_C(0xC598BDFCD0E834F9),
    UINT64_C(0xB256163D3687F5A7), UINT64_C(0x66D7A73C6AEF50B3), UINT64_C(0xBB34C6A4396695D2), UINT64_C(0x7F46E1981C3256AD),
    UINT64_C(0x4B25A9B217A6C5B4), UINT64_C(0x7A0A6BCDD2321DA9), UINT64_C(0x0A1F55E690A7B44E), UINT64_C(0x8F451A91D7F05244),
    UINT64_C(0x624D5D3C9B9800A7), UINT64_C(0x09DDC2B6409DDC25), UINT64_C(0x3E155765865622B6), UINT64_C(0x96519FAC9511B381),
    UINT64_C(0x512E58482FE4FBF0), UINT64_C(0x1AB260EA7D54AE1C), UINT64_C(0x67976F12CC28BBBD), UINT64_C(0x0607B5B2E6250156),
    UINT64_C(0x7E700BEA717AD36E), UINT64_C(0x06A058D9D61CABB3), UINT64_C(0x57DA5324A824972F), UINT64_C(0x1193BA74DBEBF7E7),
    UINT64_C(0xC18DC3140E7002D4), UINT64_C(0x9F7CCC11DFA0EF17), UINT64_C(0xC487D6C20666A13A), UINT64_C(0xB67190E4B50EF0C8),
    UINT64_C(0xA53DAA608DF0B9A5), UINT64_C(0x7E13101DE87F9ED3), UINT64_C(0x7F8955AE2F05088B), UINT64_C(0x2DF7E5A097AD383F),
    UINT64_C(0xF027683A21EA14B5), UINT64_C(0x9BB8AEC3E3360942), UINT64_C(0x92BE39B54967E7FE), UINT64_C(0x978C6D332E7AFD27),
    UINT64_C(0xED512FE96A4FAE81), UINT64_C(0x9E1099B8140D7BA3), UINT64_C(0xDFD5A5BE1E6FE9A6), UINT64_C(0x1D82600E23B66DD4),
    UINT64_C(0x3FA3C3B7EE7B52CE), UINT64_C(0xEE84F7D2A655EF4C), UINT64_C(0x2A4361EC769E3BEB), UINT64_C(0x22E4B38916636702),
    UINT64_C(0x0063096F5D39A115), UINT64_C(0x6C51B24DAAFA5434), UINT64_C(0xBAFB1DB1B411E344), UINT64_C(0xFF529F161AE0C4B0),
    UINT64_C(0x1290EAE3AC0A686F), UINT64_C(0xA7B0D4585447D1BE), UINT64_C(0xAED3D18CB6CCAD53), UINT64_C(0xFC73D46F8B41BEC6)
};

static const uint64_t t1ha_refval_ia32aes_b [81] = {
    0,
    UINT64_C(0x772C7311BE32FF42), UINT64_C(0x4398F62A8CB6F72A), UINT64_C(0x71F6DF5DA3B4F532), UINT64_C(0x555859635365F660),
    UINT64_C(0xE98808F1CD39C626), UINT64_C(0x2EB18FAF2163BB09), UINT64_C(0x7B9DD892C8019C87), UINT64_C(0xE2B1431C4DA4D15A),
    UINT64_C(0x1984E718A5477F70), UINT64_C(0x08DD17B266484F79), UINT64_C(0x4C83A05D766AD550), UINT64_C(0x92DCEBB131D1907D),
    UINT64_C(0xD67BC6FC881B8549), UINT64_C(0xF6A9886555FBF66B), UINT64_C(0x6E31616D7F33E25E), UINT64_C(0x36E31B7426E3049D),
    UINT64_C(0x4F8E4FAF46A13F5F), UINT64_C(0x03EB0CB3253F819F), UINT64_C(0x636A7769905770D2), UINT64_C(0x3ADF3781D16D1148),
    UINT64_C(0x92D19CB1818BC9C2), UINT64_C(0x283E68F4D459C533), UINT64_C(0xFA83A8A88DECAA04), UINT64_C(0x8C6F00368EAC538C),
    UINT64_C(0x7B66B0CF3797B322), UINT64_C(0x5131E122FDABA3FF), UINT64_C(0x6E59FF515C08C7A9), UINT64_C(0xBA2C5269B2C377B0),
    UINT64_C(0xA9D24FD368FE8A2B), UINT64_C(0x22DB13D32E33E891), UINT64_C(0x7B97DFC804B876E5), UINT64_C(0xC598BDFCD0E834F9),
    UINT64_C(0xB256163D3687F5A7), UINT64_C(0x66D7A73C6AEF50B3), UINT64_C(0xE810F88E85CEA11A), UINT64_C(0x4814F8F3B83E4394),
    UINT64_C(0x9CABA22D10A2F690), UINT64_C(0x0D10032511F58111), UINT64_C(0xE9A36EF5EEA3CD58), UINT64_C(0xC79242DE194D9D7C),
    UINT64_C(0xC3871AA0435EE5C8), UINT64_C(0x52890BED43CCF4CD), UINT64_C(0x07A1D0861ACCD373), UINT64_C(0x227B816FF0FEE9ED),
    UINT64_C(0x59FFBF73AACFC0C4), UINT64_C(0x09AB564F2BEDAD0C), UINT64_C(0xC05F744F2EE38318), UINT64_C(0x7B50B621D547C661),
    UINT64_C(0x0C1F71CB4E68E5D1), UINT64_C(0x0E33A47881D4DBAA), UINT64_C(0xF5C3BF198E9A7C2E), UINT64_C(0x16328FD8C0F68A91),
    UINT64_C(0xA3E399C9AB3E9A59), UINT64_C(0x163AE71CBCBB18B8), UINT64_C(0x18F17E4A8C79F7AB), UINT64_C(0x9250E2EA37014B45),
    UINT64_C(0x7BBBB111D60B03E4), UINT64_C(0x3DAA4A3071A0BD88), UINT64_C(0xA28828D790A2D6DC), UINT64_C(0xBC70FC88F64BE3F1),
    UINT64_C(0xA3E48008BA4333C7), UINT64_C(0x739E435ACAFC79F7), UINT64_C(0x42BBB360BE007CC6), UINT64_C(0x4FFB6FD2AF74EC92),
    UINT64_C(0x2A799A2994673146), UINT64_C(0xBE0A045B69D48E9F), UINT64_C(0x549432F54FC6A278), UINT64_C(0x371D3C60369FC702),
    UINT64_C(0xDB4557D415B08CA7), UINT64_C(0xE8692F0A83850B37), UINT64_C(0x022E46AEB36E9AAB), UINT64_C(0x117AC9B814E4652D),
    UINT64_C(0xA361041267AE9048), UINT64_C(0x277CB51C961C3DDA), UINT64_C(0xAFFC96F377CB8A8D), UINT64_C(0x83CC79FA01DD1BA7),
    UINT64_C(0xA494842ACF4B802C), UINT64_C(0xFC6D9CDDE2C34A3F), UINT64_C(0x4ED6863CE455F7A7), UINT64_C(0x630914D0DB7AAE98)
};

#endif

static uint64_t testno;

static FORCE_INLINE bool probe( void (* hash)(const void * in, const size_t len, const seed_t seed,
        void * out), const uint64_t reference, bool bswap, const void * data, unsigned len, uint64_t seed ) {
    uint8_t result[32];

    hash(data, len, seed, &result);
    const uint64_t actual = bswap ? GET_U64<true>(result, 0) : GET_U64<false>(result, 0);
    testno++;
    if (actual != reference) {
        printf("Test %" PRIu64 " %016" PRIx64 " != %016" PRIx64 "\n", testno, actual, reference);
    }
    return actual != reference;
}

static bool t1ha_selfcheck( void (* hash)(const void * in, const size_t len, const seed_t seed,
        void * out), const uint64_t * reference_values, bool bswap ) {
    bool failed = false;

    testno = 0;

    const uint64_t zero = 0;
    failed |= probe(hash, /* empty-zero */ *reference_values++, bswap, NULL, 0, zero );
    failed |= probe(hash, /* empty-all1 */ *reference_values++, bswap, NULL, 0, ~zero);
    failed |= probe(hash, /* bin64-zero */ *reference_values++, bswap, t1ha_test_pattern, 64, zero);

    uint64_t seed = 1;
    for (int i = 1; i < 64; i++) {
        /* bin%i-1p%i */
        failed |= probe(hash, *reference_values++, bswap, t1ha_test_pattern, i, seed);
        seed  <<= 1;
    }

    seed = ~zero;
    for (int i = 1; i <= 7; i++) {
        seed  <<= 1;
        /* align%i_F%i */
        failed |= probe(hash, *reference_values++, bswap, t1ha_test_pattern + i, 64 - i, seed);
    }

    uint8_t pattern_long[512];
    for (size_t i = 0; i < sizeof(pattern_long); ++i) {
        pattern_long[i] = (uint8_t)i;
    }
    for (int i = 0; i <= 7; i++) {
        /* long-%05i */
        failed |= probe(hash, *reference_values++, bswap, pattern_long + i, 128 + i * 17, seed);
    }

    return failed;
}

static bool t1ha0_selftest( void ) {
    bool failed = false;

    failed |= t1ha_selfcheck(isLE() ?
                t1ha0<MODE_LE_NATIVE> :
                t1ha0<MODE_BE_BSWAP >, t1ha_refval_32le, isLE() ? false : true);

    failed |= t1ha_selfcheck(isLE() ?
                t1ha0<MODE_LE_BSWAP > :
                t1ha0<MODE_BE_NATIVE>, t1ha_refval_32be, isBE() ? false : true);

    if (failed) {
        printf("t1ha0 self-test FAILED!\n");
    }
    return !failed;
}

static bool t1ha1_selftest( void ) {
    bool failed = false;

    failed |= t1ha_selfcheck(isLE() ?
                t1ha1<MODE_LE_NATIVE> :
                t1ha1<MODE_BE_BSWAP >, t1ha_refval_64le, isLE() ? false : true);

    failed |= t1ha_selfcheck(isLE() ?
                t1ha1<MODE_LE_BSWAP > :
                t1ha1<MODE_BE_NATIVE>, t1ha_refval_64be, isBE() ? false : true);

    if (failed) {
        printf("t1ha1 self-test FAILED!\n");
    }
    return !failed;
}

static bool t1ha2_selftest( void ) {
    bool failed = false;

    failed |= t1ha_selfcheck(isLE()     ?
                t1ha2<MODE_LE_NATIVE, false> :
                t1ha2<MODE_BE_BSWAP, false>, t1ha_refval_2atonce   , isLE() ? false : true);

    failed |= t1ha_selfcheck(isLE()    ?
                t1ha2<MODE_LE_NATIVE, true > :
                t1ha2<MODE_BE_BSWAP, true >, t1ha_refval_2atonce128, isLE() ? false : true);

    if (failed) {
        printf("t1ha2 self-test FAILED!\n");
    }
    return !failed;
}

static bool t1ha2_incr_selftest( void ) {
    bool failed = false;

    failed |= t1ha_selfcheck(isLE()     ?
                t1ha2_incr<MODE_LE_NATIVE, false, true> :
                t1ha2_incr<MODE_BE_BSWAP, false, true>, t1ha_refval_2stream   , isLE() ? false : true);

    failed |= t1ha_selfcheck(isLE()    ?
                t1ha2_incr<MODE_LE_NATIVE, true , true> :
                t1ha2_incr<MODE_BE_BSWAP, true , true>, t1ha_refval_2stream128, isLE() ? false : true);

    if (failed) {
        printf("t1ha2-incr self-test FAILED!\n");
    }
    return !failed;
}

#if defined(HAVE_X86_64_AES)

static bool t1ha0_aes_selftest( void ) {
    bool failed = false;

    failed |= t1ha_selfcheck(t1ha0_aesA<false>, t1ha_refval_ia32aes_a, false);

    failed |= t1ha_selfcheck(t1ha0_aesB<false>, t1ha_refval_ia32aes_b, false);

    if (failed) {
        printf("t1ha0-aes self-test FAILED!\n");
    }
    return !failed;
}

#endif

const char * t1ha_impl_str[] = {
    "1N+a0",
    "1N+a1",
    "1N+a2",
    "1Y+a0",
    "1Y+a1",
    "1Y+a2",
    "1N+a0+aes",
    "1N+a1+aes",
    "1N+a2+aes",
    "1Y+a0+aes",
    "1Y+a1+aes",
    "1Y+a2+aes",
};

REGISTER_FAMILY(t1ha,
   $.src_url    = "https://web.archive.org/web/20211209095620/https://github.com/erthink/t1ha",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(t1ha0,
   $.desc       = "Fast Positive Hash #0 (portable, 32-bit core)",
   $.impl       = t1ha_impl_str[T1HA_SYS_UNALIGNED_ACCESS + 3 * (T1HA_USE_ALIGNED_ONESHOT_READ)],
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB          |
         FLAG_IMPL_MULTIPLY               |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_ZLIB,
   $.bits = 64,
   $.verification_LE = 0x7F7D7B29,
   $.verification_BE = 0x6B552A17, // To get old 0xDA6A4061 value, see above
   $.hashfn_native   = isLE () ? t1ha0<MODE_LE_NATIVE> : t1ha0<MODE_BE_NATIVE>,
   $.hashfn_bswap    = isLE () ? t1ha0<MODE_LE_BSWAP> : t1ha0<MODE_BE_BSWAP>,
   $.initfn          = t1ha0_selftest
 );

REGISTER_HASH(t1ha1,
   $.desc       = "Fast Positive Hash #1 (portable, 64-bit core)",
   $.impl       = t1ha_impl_str[T1HA_SYS_UNALIGNED_ACCESS + 3 * (T1HA_USE_ALIGNED_ONESHOT_READ)],
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB          |
         FLAG_IMPL_MULTIPLY_64_128        |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_ZLIB,
   $.bits = 64,
   $.verification_LE = 0xD6836381,
   $.verification_BE = 0xB895E54F, // To get old 0x93F864DE value, see above
   $.hashfn_native   = isLE () ? t1ha1<MODE_LE_NATIVE> : t1ha1<MODE_BE_NATIVE>,
   $.hashfn_bswap    = isLE () ? t1ha1<MODE_LE_BSWAP> : t1ha1<MODE_BE_BSWAP>,
   $.initfn          = t1ha1_selftest
 );

REGISTER_HASH(t1ha2_64,
   $.desc       = "Fast Positive Hash #2 (portable, 64-bit core)",
   $.impl       = t1ha_impl_str[T1HA_SYS_UNALIGNED_ACCESS + 3 * (T1HA_USE_ALIGNED_ONESHOT_READ)],
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB          |
         FLAG_IMPL_TYPE_PUNNING           |
         FLAG_IMPL_MULTIPLY_64_128        |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_ZLIB,
   $.bits = 64,
   $.verification_LE = 0x8F16C948,
   $.verification_BE = 0x061CB08C,
   $.hashfn_native   = isLE () ? t1ha2<MODE_LE_NATIVE, false> : t1ha2<MODE_BE_NATIVE, false>,
   $.hashfn_bswap    = isLE () ? t1ha2<MODE_LE_BSWAP, false> : t1ha2<MODE_BE_BSWAP, false>,
   $.initfn          = t1ha2_selftest
 );

REGISTER_HASH(t1ha2_128,
   $.desc       = "Fast Positive Hash #2 (portable, 64-bit core)",
   $.impl       = t1ha_impl_str[T1HA_SYS_UNALIGNED_ACCESS + 3 * (T1HA_USE_ALIGNED_ONESHOT_READ)],
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB          |
         FLAG_IMPL_TYPE_PUNNING           |
         FLAG_IMPL_MULTIPLY_64_128        |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_ZLIB,
   $.bits = 128,
   $.verification_LE = 0xB44C43A1,
   $.verification_BE = 0x95EB2DA8,
   $.hashfn_native   = isLE () ? t1ha2<MODE_LE_NATIVE, true> : t1ha2<MODE_BE_NATIVE, true>,
   $.hashfn_bswap    = isLE () ? t1ha2<MODE_LE_BSWAP, true> : t1ha2<MODE_BE_BSWAP, true>,
   $.initfn          = t1ha2_selftest
 );

REGISTER_HASH(t1ha2_64__incr,
   $.desc       = "Fast Positive Hash #2 (portable, 64-bit core, incremental version)",
   $.impl       = t1ha_impl_str[T1HA_SYS_UNALIGNED_ACCESS + 3 * (T1HA_USE_ALIGNED_ONESHOT_READ)],
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB          |
         FLAG_IMPL_TYPE_PUNNING           |
         FLAG_IMPL_MULTIPLY_64_128        |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_INCREMENTAL            |
         FLAG_IMPL_INCREMENTAL_DIFFERENT  |
         FLAG_IMPL_LICENSE_ZLIB,
   $.bits = 64,
   $.verification_LE = 0xDED9B580,
   $.verification_BE = 0xB355A009,
   $.hashfn_native   = isLE () ? t1ha2_incr<MODE_LE_NATIVE, false> : t1ha2_incr<MODE_BE_NATIVE, false>,
   $.hashfn_bswap    = isLE () ? t1ha2_incr<MODE_LE_BSWAP, false> : t1ha2_incr<MODE_BE_BSWAP, false>,
   $.initfn          = t1ha2_incr_selftest
 );

REGISTER_HASH(t1ha2_128__incr,
   $.desc       = "Fast Positive Hash #2 (portable, 64-bit core, incremental version)",
   $.impl       = t1ha_impl_str[T1HA_SYS_UNALIGNED_ACCESS + 3 * (T1HA_USE_ALIGNED_ONESHOT_READ)],
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB          |
         FLAG_IMPL_TYPE_PUNNING           |
         FLAG_IMPL_MULTIPLY_64_128        |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_INCREMENTAL            |
         FLAG_IMPL_INCREMENTAL_DIFFERENT  |
         FLAG_IMPL_LICENSE_ZLIB,
   $.bits = 128,
   $.verification_LE = 0xE929E756,
   $.verification_BE = 0x3898932B,
   $.hashfn_native   = isLE () ? t1ha2_incr<MODE_LE_NATIVE, true> : t1ha2_incr<MODE_BE_NATIVE, true>,
   $.hashfn_bswap    = isLE () ? t1ha2_incr<MODE_LE_BSWAP, true> : t1ha2_incr<MODE_BE_BSWAP, true>,
   $.initfn          = t1ha2_incr_selftest
 );

#if defined(HAVE_X86_64_AES)
REGISTER_HASH(t1ha0__aesA,
   $.desc       = "Fast Positive Hash #0a (AES-NI)",
   $.impl       = t1ha_impl_str[6 + T1HA_SYS_UNALIGNED_ACCESS + 3 * (T1HA_USE_ALIGNED_ONESHOT_READ)],
   $.hash_flags =
         FLAG_HASH_AES_BASED,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB          |
         FLAG_IMPL_MULTIPLY_64_128        |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_ZLIB,
   $.bits = 64,
   $.verification_LE = 0xF07C4DA5,
   $.verification_BE = 0x6848847F,
   $.hashfn_native   = t1ha0_aesA<false>,
   $.hashfn_bswap    = t1ha0_aesA<true>,
   $.initfn          = t1ha0_aes_selftest
 );

REGISTER_HASH(t1ha0__aesB,
   $.desc       = "Fast Positive Hash #0b (AES-NI)",
   $.impl       = t1ha_impl_str[6 + T1HA_SYS_UNALIGNED_ACCESS + 3 * (T1HA_USE_ALIGNED_ONESHOT_READ)],
   $.hash_flags =
         FLAG_HASH_AES_BASED,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB          |
         FLAG_IMPL_MULTIPLY_64_128        |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_ZLIB,
   $.bits = 64,
   $.verification_LE = 0x8B38C599,
   $.verification_BE = 0x010611E9,
   $.hashfn_native   = t1ha0_aesB<false>,
   $.hashfn_bswap    = t1ha0_aesB<true>,
   $.initfn          = t1ha0_aes_selftest
 );
#endif
