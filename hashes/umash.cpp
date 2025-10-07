/*
 * UMASH
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (C) 2023       jason
 * Copyright 2020-2022 Backtrace I/O, Inc.
 * Copyright 2022 Paul Khuong
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "Platform.h"
#include "Hashlib.h"

#if defined(HAVE_X86_64_CLMUL)
  #include "Intrinsics.h"
  #include <cassert>

/* We only use 128-bit vector, as pairs of 64-bit integers. */
typedef __m128i v128;

//------------------------------------------------------------
  #include "Mathmult.h"

static inline void mul128( uint64_t x, uint64_t y, uint64_t & hi, uint64_t & lo ) {
    MathMult::mult64_128(lo, hi, x, y);
}

// This is an efficient and portable replacement for GCC's
// __builtin_uaddl_overflow(). XXX The builtin detection might happen
// later, but for now this is good enough.
static inline bool add_overflow( uint64_t x, uint64_t y, uint64_t * sumlo ) {
// #if defined(HAVE_BUILTIN_UADD)
//    return __builtin_uaddl_overflow(x, y, sumlo);
// #else
    uint64_t c = 0;

    x     += y;
    c     += (x < y);
    *sumlo = x;
    return (c == 0) ? false : true;
// #endif
}

static NEVER_INLINE uint64_t add_mod_slow_slow_path( uint64_t sum, uint64_t fixup ) {
    /* Reduce sum, mod 2**64 - 8. */
    sum  = (sum >= (uint64_t)-8) ? sum + 8 : sum;
    /* sum < 2**64 - 8, so this doesn't overflow. */
    sum += fixup;
    /* Reduce again. */
    sum  = (sum >= (uint64_t)-8) ? sum + 8 : sum;
    return sum;
}

static inline uint64_t add_mod_slow( uint64_t x, uint64_t y ) {
    uint64_t sum;
    uint64_t fixup = 0;

    /* x + y \equiv sum + fixup */
    if (add_overflow(x, y, &sum)) {
        fixup = 8;
    }

    /*
     * We must ensure `sum + fixup < 2**64 - 8`.
     *
     * We want a conditional branch here, but not in the
     * overflowing add: overflows happen roughly half the time on
     * pseudorandom inputs, but `sum < 2**64 - 16` is almost
     * always true, for pseudorandom `sum`.
     */
    if (likely(sum < (uint64_t)-16)) {
        return sum + fixup;
    }

    /*
     * Some compilers like to compile the likely branch above with
     * conditional moves or predication.  Insert a compiler barrier
     * in the slow path here to force a branch.
     */
  #if defined(HAVE_X86_64_ASM)
    __asm__ ("" : "+r"(sum));
  #endif

    return add_mod_slow_slow_path(sum, fixup);
}

static inline uint64_t add_mod_fast( uint64_t x, uint64_t y ) {
    uint64_t sum;

    /* If `sum` overflows, `sum + 8` does not. */
    return add_overflow(x, y, &sum) ? sum + 8 : sum;
}

static inline uint64_t mul_mod_fast( uint64_t m, uint64_t x ) {
    uint64_t hi, lo;

    mul128(m, x, hi, lo);
    return add_mod_fast(lo, 8 * hi);
}

static inline uint64_t horner_double_update( uint64_t acc, uint64_t m0, uint64_t m1, uint64_t x, uint64_t y ) {
    acc = add_mod_fast(acc, x);
    return add_mod_slow(mul_mod_fast(m0, acc), mul_mod_fast(m1, y));
}

static inline v128 v128_create( uint64_t lo, uint64_t hi ) {
    return _mm_set_epi64x(hi, lo);
}

static inline uint64_t v128_getlo( v128 x ) {
    return _mm_cvtsi128_si64(x);
}

static inline uint64_t v128_gethi( v128 x ) {
    return _mm_extract_epi64(x, 1);
}

/* Shift each 64-bit lane left by one bit. */
static inline v128 v128_shift( v128 x ) {
    return _mm_add_epi64(x, x);
}

/* Computes the 128-bit carryless product of x and y. */
static inline v128 v128_clmul( uint64_t x, uint64_t y ) {
    return _mm_clmulepi64_si128(_mm_cvtsi64_si128(x), _mm_cvtsi64_si128(y), 0x00);
}

/* Computes the 128-bit carryless product of the high and low halves of x. */
static inline v128 v128_clmul_cross( v128 x ) {
    return _mm_clmulepi64_si128(x, x, 0x01);
}

//------------------------------------------------------------
enum {
    UMASH_OH_PARAM_COUNT            = 32,
    UMASH_OH_TWISTING_COUNT         = 2,
    BLOCK_SIZE                      = (sizeof(uint64_t) * UMASH_OH_PARAM_COUNT),
    UMASH_MULTIPLE_BLOCKS_THRESHOLD = 1024,
    SPLIT_ACCUMULATOR_MAX_FIXUP     = 3,
    OH_SHORT_HASH_SHIFT             = 4,
};

  #define ARRAY_SIZE(ARR) (sizeof(ARR) / sizeof(ARR[0]))

/*
 * A single UMASH params struct stores the parameters for a pair of
 * independent `UMASH` functions.
 */
struct umash_params {
    /*
     * Each uint64_t[2] array consists of {f^2, f}, where f is a
     * random multiplier in mod 2**61 - 1.
     */
    uint64_t  poly[2][2];
    /*
     * The second (twisted) OH function uses an additional
     * 128-bit constant stored in the last two elements.
     */
    uint64_t  oh[UMASH_OH_PARAM_COUNT + UMASH_OH_TWISTING_COUNT];
    /*
     * The seed value that the params were derived from. This is added
     * for SMHasher3, so that the seed input parameter to the hash
     * invocation can be used instead for a pointer to the
     * thread-local umash_params table. It lets this umash
     * implementation be thread-safe.
     */
    uint64_t  base_seed;
};

/*
 * A fingerprint consists of two independent `UMASH` hash values.
 */
struct umash_fp {
    uint64_t  hash[2];
};

/*
 * Returns `then` if `cond` is true, `otherwise` if false.
 *
 * This noise helps compiler emit conditional moves.
 */
static inline const void * select_ptr( bool cond, const void * then, const void * otherwise ) {
    const void * ret;

  #if defined(HAVE_X86_64_ASM)
    /* Force strict evaluation of both arguments. */
    __asm__ ("" ::"r"(then), "r"(otherwise));
  #endif

    ret = (cond) ? then : otherwise;

  #if defined(HAVE_X86_64_ASM)
    /* And also force the result to be materialised with a blackhole. */
    __asm__ ("" : "+r"(ret));
  #endif

    return ret;
}

//------------------------------------------------------------
// SHORT -- [0, 8] byte inputs
template <bool bswap>
static inline uint64_t vec_to_u64( const void * data, size_t n_bytes ) {
    const uint8_t zeros[2] = { 0 };
    uint32_t      hi, lo;

    /*
     * If there are at least 4 bytes to read, read the first 4 in
     * `lo`, and the last 4 in `hi`.  This covers the whole range,
     * since `n_bytes` is at most 8.
     */
    if (likely(n_bytes >= sizeof(lo))) {
        memcpy(&lo, data, sizeof(lo));
        memcpy(&hi, (const uint8_t *)data + n_bytes - sizeof(hi), sizeof(hi));
    } else {
        /* 0 <= n_bytes < 4.  Decode the size in binary. */
        uint16_t word;
        uint8_t  byte;

        /*
         * If the size is odd, load the first byte in `byte`;
         * otherwise, load in a zero.
         */
        memcpy(&byte, select_ptr(n_bytes & 1, data, zeros), 1);
        lo = byte;

        /*
         * If the size is 2 or 3, load the last two bytes in `word`;
         * otherwise, load in a zero.
         */
        memcpy(&word, select_ptr(n_bytes & 2, (const uint8_t *)data + n_bytes - 2, zeros), 2);
        /*
         * We have now read `bytes[0 ... n_bytes - 1]`
         * exactly once without overwriting any data.
         */
        hi = word;
    }

    /*
     * Mix `hi` with the `lo` bits: SplitMix64 seems to have
     * trouble with the top 4 bits.
     */
    return COND_BSWAP(((uint64_t)hi << 32) | (lo + hi), bswap);
}

template <bool bswap>
static uint64_t umash_short( const uint64_t * params, uint64_t seed, const void * data, size_t n_bytes ) {
    uint64_t h;

    seed += params[n_bytes];
    h     = vec_to_u64<bswap>(data, n_bytes);
    h    ^= h >> 30;
    h    *= UINT64_C(0xbf58476d1ce4e5b9);
    h     = (h ^ seed) ^ (h >> 27);
    h    *= UINT64_C(0x94d049bb133111eb);
    h    ^= h >> 31;
    return h;
}

template <bool bswap>
static struct umash_fp umash_fp_short( const uint64_t * params, uint64_t seed, const void * data, size_t n_bytes ) {
    struct umash_fp ret;
    uint64_t        h;

    ret.hash[0] = seed + params[n_bytes];
    ret.hash[1] = seed + params[n_bytes + OH_SHORT_HASH_SHIFT];

    h  = vec_to_u64<bswap>(data, n_bytes);
    h ^= h >> 30;
    h *= UINT64_C(0xbf58476d1ce4e5b9);
    h ^= h >> 27;

#define TAIL(i)                                      \
    do {                                             \
        ret.hash[i] ^= h;                            \
        ret.hash[i] *= UINT64_C(0x94d049bb133111eb); \
        ret.hash[i] ^= ret.hash[i] >> 31;            \
    } while (0)

    TAIL(0);
    TAIL(1);
  #undef TAIL

    return ret;
}

//------------------------------------------------------------
// MEDIUM -- [9, 16] byte inputs
static inline uint64_t finalize( uint64_t x ) {
    return (x ^ ROTL64(x, 8)) ^ ROTL64(x, 33);
}

template <bool bswap>
static uint64_t umash_medium( const uint64_t multipliers[2], const uint64_t * oh,
        uint64_t seed, const void * data, size_t n_bytes ) {
    uint64_t enh_hi, enh_lo;

    {
        const uint8_t * data8 = (const uint8_t *)data;
        uint64_t        x, y;

        x  = GET_U64<bswap>(data8,       0);
        y  = GET_U64<bswap>(data8, n_bytes - 8);
        x += oh[0];
        y += oh[1];

        mul128(x, y, enh_hi, enh_lo);
        enh_hi += seed ^ n_bytes;
    }

    enh_hi ^= enh_lo;
    return finalize(horner_double_update(
            /*acc=*/ 0, multipliers[0], multipliers[1], enh_lo, enh_hi));
}

template <bool bswap>
static struct umash_fp umash_fp_medium( const uint64_t multipliers[2][2], const uint64_t * oh,
        uint64_t seed, const void * data, size_t n_bytes ) {
    struct umash_fp ret;
    const uint64_t  offset = seed ^ n_bytes;
    uint64_t        enh_hi, enh_lo;
    v128            v;
    uint64_t        lrc[2] = { oh[UMASH_OH_PARAM_COUNT], oh[UMASH_OH_PARAM_COUNT + 1] };
    uint64_t        x, y;
    uint64_t        a, b;

    /* Expand the 9-16 bytes to 16. */
    const uint8_t * data8 = (const uint8_t *)data;

    x       = GET_U64<bswap>(data8,       0);
    y       = GET_U64<bswap>(data8, n_bytes - 8);

    a       = oh[0];
    b       = oh[1];

    lrc[0] ^= x ^ a;
    lrc[1] ^= y ^ b;
    v       = v128_clmul(lrc[0], lrc[1]);

    a      += x;
    b      += y;

    mul128(a, b, enh_hi, enh_lo);
    enh_hi     += offset;
    enh_hi     ^= enh_lo;

    ret.hash[0] = finalize(horner_double_update(
            /*acc=*/ 0, multipliers[0][0], multipliers[0][1], enh_lo, enh_hi));

    ret.hash[1] = finalize(horner_double_update(/*acc=*/ 0, multipliers[1][0], multipliers[1][1],
            enh_lo ^ v128_getlo(v), enh_hi ^ v128_gethi(v)));

    return ret;
}

//------------------------------------------------------------
// LONG -- [17, size_t) byte inputs
struct umash_oh {
    uint64_t  bits[2];
};

struct split_accumulator {
    uint64_t  base;
    uint64_t  fixup;
};

static inline uint64_t split_accumulator_eval( struct split_accumulator acc ) {
    return add_mod_slow(acc.base, 8 * acc.fixup);
}

static inline struct split_accumulator split_accumulator_update( const struct split_accumulator acc,
        const uint64_t m0, const uint64_t m1, uint64_t h0, const uint64_t h1 ) {
    uint64_t partial;
    uint64_t lo0, hi0, lo1, hi1;
    uint64_t hi, sum;
    int8_t   fixup;

    mul128(m1, h1, hi1, lo1);

    /* partial \eqv (acc.base + h0 + 8 * acc.fixup)  mod 2**64 - 8 */
    if (unlikely(h0 > UINT64_C(-8) * (SPLIT_ACCUMULATOR_MAX_FIXUP + 1))) {
        h0 = add_mod_slow(h0, 8 * acc.fixup);
    } else {
        /*
         * h0 is a hash value, so it's unlikely to be
         * extremely high.  In the common case, this addition
         * doesn't overflows.
         */
        h0 += 8 * acc.fixup;
    }

    partial = add_mod_fast(acc.base, h0);

    mul128(partial, m0, hi0, lo0);

    fixup = add_overflow(lo0, lo1, &sum);

    assert(hi0 < (UINT64_C(1) << 61));
    assert(hi1 < (UINT64_C(1) << 61));
    /* hi0 and hi1 < 2**61, so this addition never overflows. */
    hi     = hi0 + hi1;

    fixup += (hi & (UINT64_C(1) << 61)) != 0;
    hi    *= 8;

    fixup += add_overflow(sum, hi, &sum);

    split_accumulator ret = {
        sum,
        /* Avoid sign extension: we know `fixup` is non-negative. */
        (uint8_t)fixup,
    };
    return ret;
}

// This is umash_multiple_blocks_generic().
template <bool bswap>
static uint64_t umash_multiple_blocks( uint64_t initial, const uint64_t multipliers[2], const uint64_t * oh_ptr,
        uint64_t seed, const void * blocks, size_t n_blocks ) {
    const uint64_t m0 = multipliers[0];
    const uint64_t m1 = multipliers[1];
    const uint64_t kx = oh_ptr[UMASH_OH_PARAM_COUNT - 2];
    const uint64_t ky = oh_ptr[UMASH_OH_PARAM_COUNT - 1];
    struct split_accumulator ret;

    ret.base = initial; ret.fixup = 0;

    assert(n_blocks > 0);

    do {
        const uint8_t * data = (const uint8_t *)blocks;
        struct umash_oh oh;
        v128            acc  = { 0, 0 };

        blocks = (const uint8_t *)blocks + BLOCK_SIZE;

        /*
         * FORCE() makes sure the compiler computes the value
         * of `acc` at that program points.  Forcing a full
         * computation prevents the compiler from evaluating
         * the inner loop's xor-reduction tree widely: the
         * bottleneck is in the carryless multiplications.
         */
  #define FORCE() ((void)0)

#define PH(I)                                              \
        do {                                               \
            v128 x, k;                                     \
                                                           \
            x = _mm_loadu_si128((const v128 *)data);       \
            if (bswap) { x = mm_bswap64(x); }              \
            data = data + sizeof(x);                       \
                                                           \
            k = _mm_loadu_si128((const v128 *)&oh_ptr[I]); \
            x = _mm_xor_si128(x, k);                       \
            acc = _mm_xor_si128(acc,v128_clmul_cross(x));  \
        } while (0)

        PH(0);
        PH(2);
        FORCE();

        PH(4);
        PH(6);
        FORCE();

        PH( 8);
        PH(10);
        FORCE();

        PH(12);
        PH(14);
        FORCE();

        PH(16);
        PH(18);
        FORCE();

        PH(20);
        PH(22);
        FORCE();

        PH(24);
        PH(26);
        FORCE();

        PH(28);

  #undef PH
  #undef FORCE

        memcpy(&oh, &acc, sizeof(oh));

        /* Final ENH chunk. */
        {
            uint64_t x, y, enh_hi, enh_lo;

            x  = GET_U64<bswap>(data, 0);
            y  = GET_U64<bswap>(data, 8);

            x += kx;
            y += ky;

            mul128(x, y, enh_hi, enh_lo);
            enh_hi     += seed;

            oh.bits[0] ^= enh_lo;
            oh.bits[1] ^= enh_hi ^ enh_lo;
        }

        ret = split_accumulator_update(ret, m0, m1, oh.bits[0], oh.bits[1]);
    } while (--n_blocks);

    return split_accumulator_eval(ret);
}

template <bool bswap>
static struct umash_fp umash_fprint_multiple_blocks( struct umash_fp initial, const uint64_t multipliers[2][2],
        const uint64_t * oh, uint64_t seed, const void * blocks, size_t n_blocks ) {
    const v128 lrc_init =
            v128_create(oh[UMASH_OH_PARAM_COUNT], oh[UMASH_OH_PARAM_COUNT + 1]);
    const uint64_t m00  = multipliers[0][0];
    const uint64_t m01  = multipliers[0][1];
    const uint64_t m10  = multipliers[1][0];
    const uint64_t m11  = multipliers[1][1];
    struct split_accumulator acc0, acc1;

    acc0.base = initial.hash[0]; acc0.fixup = 0;
    acc1.base = initial.hash[1]; acc1.fixup = 1;

    do {
        struct umash_oh compressed[2];
        v128            acc         = { 0, 0 }; /* Base umash */
        v128            acc_shifted = { 0, 0 }; /* Accumulates shifted values */
        v128            lrc         = lrc_init;
        const uint8_t * data        = (const uint8_t *)blocks;

        blocks = (const uint8_t *)blocks + BLOCK_SIZE;

  #define FORCE() ((void)0)

#define TWIST(I)                                         \
        do {                                             \
            v128 x, k;                                   \
                                                         \
            x = _mm_loadu_si128((const v128 *)data);     \
            if (bswap) { x = mm_bswap64(x); }            \
            data = data + sizeof(x);                     \
                                                         \
            k = _mm_loadu_si128((const v128 *)&oh[I]);   \
                                                         \
            x = _mm_xor_si128(x, k);                     \
            lrc = _mm_xor_si128(lrc, x);                 \
                                                         \
            x = v128_clmul_cross(x);                     \
                                                         \
            acc = _mm_xor_si128(acc, x);                 \
                                                         \
            if (I == 28)                                 \
                break;                                   \
                                                         \
            acc_shifted = _mm_xor_si128(acc_shifted, x); \
            acc_shifted = v128_shift(acc_shifted);       \
        } while (0)

        TWIST(0);
        FORCE();
        TWIST(2);
        FORCE();
        TWIST(4);
        FORCE();
        TWIST(6);
        FORCE();
        TWIST(8);
        FORCE();
        TWIST(10);
        FORCE();
        TWIST(12);
        FORCE();
        TWIST(14);
        FORCE();
        TWIST(16);
        FORCE();
        TWIST(18);
        FORCE();
        TWIST(20);
        FORCE();
        TWIST(22);
        FORCE();
        TWIST(24);
        FORCE();
        TWIST(26);
        FORCE();
        TWIST(28);
        FORCE();

  #undef TWIST
  #undef FORCE

        {
            v128 x, k;

            x   = _mm_loadu_si128((const v128 *)data);
            if (bswap) { x = mm_bswap64(x); }
            k   = _mm_loadu_si128((const v128 *)&oh[30]);

            lrc = _mm_xor_si128(lrc, _mm_xor_si128(x, k));
        }

        acc_shifted = _mm_xor_si128(acc_shifted, acc);
        acc_shifted = v128_shift(acc_shifted);

        acc_shifted = _mm_xor_si128(acc_shifted, v128_clmul_cross(lrc));

        memcpy(&compressed[0], &acc        , sizeof(compressed[0]));
        memcpy(&compressed[1], &acc_shifted, sizeof(compressed[1]));

        {
            uint64_t x, y, kx, ky, enh_hi, enh_lo;

            x  = GET_U64<bswap>(data, 0);
            y  = GET_U64<bswap>(data, 8);

            kx = x + oh[30];
            ky = y + oh[31];

            mul128(kx, ky, enh_hi, enh_lo);
            enh_hi += seed;

            enh_hi ^= enh_lo;
            compressed[0].bits[0] ^= enh_lo;
            compressed[0].bits[1] ^= enh_hi;

            compressed[1].bits[0] ^= enh_lo;
            compressed[1].bits[1] ^= enh_hi;
        }

        acc0 = split_accumulator_update(acc0, m00, m01, compressed[0].bits[0], compressed[0].bits[1]);
        acc1 = split_accumulator_update(acc1, m10, m11, compressed[1].bits[0], compressed[1].bits[1]);
    } while (--n_blocks);

    umash_fp ret = { { split_accumulator_eval(acc0), split_accumulator_eval(acc1) } };
    return ret;
}

template <bool bswap>
static struct umash_oh oh_varblock( const uint64_t * params, uint64_t tag, const void * block, size_t n_bytes ) {
    struct umash_oh ret;
    v128            acc = { 0, 0 };

    /* The final block processes `remaining > 0` bytes. */
    size_t          remaining      = 1 + ((n_bytes - 1        ) % sizeof(v128)   );
    size_t          end_full_pairs =      (n_bytes - remaining) / sizeof(uint64_t);
    const uint8_t * last_ptr       = (const uint8_t *)block + n_bytes - sizeof(v128);
    size_t          i;

    for (i = 0; i < end_full_pairs; i += 2) {
        v128 x, k;

        x     = _mm_loadu_si128((const v128 *)block);
        if (bswap) { x = mm_bswap64(x); }
        block = (const uint8_t *)block + sizeof(x);

        k     = _mm_loadu_si128((const v128 *)&params[i]);
        x     = _mm_xor_si128(x, k);
        acc   = _mm_xor_si128(acc, v128_clmul_cross(x));
    }

    memcpy(&ret, &acc, sizeof(ret));

    /* Compress the final (potentially partial) pair. */
    {
        uint64_t x, y, enh_hi, enh_lo;

        x            = GET_U64<bswap>(last_ptr, 0);
        y            = GET_U64<bswap>(last_ptr, 8);

        x           += params[i];
        y           += params[i + 1];
        mul128(x, y, enh_hi, enh_lo);
        enh_hi      += tag;

        ret.bits[0] ^= enh_lo;
        ret.bits[1] ^= enh_hi ^ enh_lo;
    }

    return ret;
}

template <bool bswap>
static void oh_varblock_fprint( struct umash_oh dst[2], const uint64_t * params,
        uint64_t tag, const void * block, size_t n_bytes ) {
    v128 acc         = { 0, 0 }; /* Base umash */
    v128 acc_shifted = { 0, 0 }; /* Accumulates shifted values */
    v128 lrc;
    /* The final block processes `remaining > 0` bytes. */
    size_t          remaining      = 1 + ((n_bytes - 1        ) % sizeof(v128)   );
    size_t          end_full_pairs =      (n_bytes - remaining) / sizeof(uint64_t);
    const uint8_t * last_ptr       = (const uint8_t *)block + n_bytes - sizeof(v128);
    size_t          i;

    lrc = v128_create(params[UMASH_OH_PARAM_COUNT], params[UMASH_OH_PARAM_COUNT + 1]);
    for (i = 0; i < end_full_pairs; i += 2) {
        v128 x, k;

        x     = _mm_loadu_si128((const v128 *)block);
        if (bswap) { x = mm_bswap64(x); }
        block = (const uint8_t *)block + sizeof(x);

        k     = _mm_loadu_si128((const v128 *)&params[i]);

        x     = _mm_xor_si128(x, k);
        lrc   = _mm_xor_si128(lrc, x);

        x     = v128_clmul_cross(x);

        acc   = _mm_xor_si128(acc, x);
        if (i + 2 >= end_full_pairs) {
            break;
        }

        acc_shifted = _mm_xor_si128(acc_shifted, x);
        acc_shifted = v128_shift(acc_shifted);
    }

    /*
     * Update the LRC for the last chunk before treating it
     * specially.
     */
    {
        v128 x, k;

        x   = _mm_loadu_si128((const v128 *)last_ptr);
        if (bswap) { x = mm_bswap64(x); }
        k   = _mm_loadu_si128((const v128 *)&params[end_full_pairs]);

        lrc = _mm_xor_si128(lrc, _mm_xor_si128(x, k));
    }

    acc_shifted = _mm_xor_si128(acc_shifted, acc);
    acc_shifted = v128_shift(acc_shifted);

    acc_shifted = _mm_xor_si128(acc_shifted, v128_clmul_cross(lrc));

    memcpy(&dst[0], &acc        , sizeof(dst[0]));
    memcpy(&dst[1], &acc_shifted, sizeof(dst[1]));

    {
        uint64_t x, y, kx, ky, enh_hi, enh_lo;

        x  = GET_U64<bswap>(last_ptr, 0);
        y  = GET_U64<bswap>(last_ptr, 8);

        kx = x + params[end_full_pairs    ];
        ky = y + params[end_full_pairs + 1];

        mul128(kx, ky, enh_hi, enh_lo);
        enh_hi         += tag;

        enh_hi         ^= enh_lo;
        dst[0].bits[0] ^= enh_lo;
        dst[0].bits[1] ^= enh_hi;

        dst[1].bits[0] ^= enh_lo;
        dst[1].bits[1] ^= enh_hi;
    }
}

template <bool bswap>
static uint64_t umash_long( const uint64_t multipliers[2], const uint64_t * oh,
        uint64_t seed, const void * data, size_t n_bytes ) {
    uint64_t acc = 0;

    // This invokes the optional routines for very long inputs
    if (unlikely(n_bytes >= UMASH_MULTIPLE_BLOCKS_THRESHOLD)) {
        size_t       n_block = n_bytes / BLOCK_SIZE;
        const void * remaining;

        n_bytes  %= BLOCK_SIZE;
        remaining = (const uint8_t *)data + (n_block * BLOCK_SIZE);
        acc       = umash_multiple_blocks<bswap>(acc, multipliers, oh, seed, data, n_block);

        data      = remaining;
        if (n_bytes == 0) {
            goto finalize;
        }

        goto last_block;
    }

    while (n_bytes > BLOCK_SIZE) {
        struct umash_oh compressed;

        compressed = oh_varblock<bswap>(oh, seed, data, BLOCK_SIZE);
        data       = (const uint8_t *)data + BLOCK_SIZE;
        n_bytes   -= BLOCK_SIZE;

        acc        = horner_double_update(acc, multipliers[0], multipliers[1], compressed.bits[0], compressed.bits[1]);
    }

  last_block:
    /* Do the final block. */
    {
        struct umash_oh compressed;

        seed      ^= (uint8_t)n_bytes;
        compressed = oh_varblock<bswap>(oh, seed, data, n_bytes);
        acc        = horner_double_update(acc, multipliers[0], multipliers[1], compressed.bits[0], compressed.bits[1]);
    }

  finalize:
    return finalize(acc);
}

template <bool bswap>
static struct umash_fp umash_fp_long( const uint64_t multipliers[2][2], const uint64_t * oh,
        uint64_t seed, const void * data, size_t n_bytes ) {
    struct umash_oh compressed[2];
    struct umash_fp ret;
    uint64_t        acc[2] = { 0, 0 };

    // This invokes the optional routines for very long inputs
    if (unlikely(n_bytes >= UMASH_MULTIPLE_BLOCKS_THRESHOLD)) {
        struct umash_fp poly    = { { 0, 0 } };
        size_t          n_block = n_bytes / BLOCK_SIZE;
        const void *    remaining;

        n_bytes  %= BLOCK_SIZE;
        remaining = (const uint8_t *)data + (n_block * BLOCK_SIZE);
        poly      = umash_fprint_multiple_blocks<bswap>(poly, multipliers, oh, seed, data, n_block);

        acc[0]    = poly.hash[0];
        acc[1]    = poly.hash[1];

        data      = remaining;
        if (n_bytes == 0) {
            goto finalize;
        }

        goto last_block;
    }

    while (n_bytes > BLOCK_SIZE) {
        oh_varblock_fprint<bswap>(compressed, oh, seed, data, BLOCK_SIZE);

#define UPDATE(i)                                                                   \
        acc[i] = horner_double_update(acc[i], multipliers[i][0], multipliers[i][1], \
                compressed[i].bits[0], compressed[i].bits[1])

        UPDATE(0);
        UPDATE(1);
  #undef UPDATE

        data     = (const uint8_t *)data + BLOCK_SIZE;
        n_bytes -= BLOCK_SIZE;
    }

  last_block:
    oh_varblock_fprint<bswap>(compressed, oh, seed ^ (uint8_t)n_bytes, data, n_bytes);

#define FINAL(i)                                                 \
    do {                                                         \
        acc[i] = horner_double_update(acc[i], multipliers[i][0], \
                multipliers[i][1], compressed[i].bits[0],        \
                compressed[i].bits[1]);                          \
    } while (0)

    FINAL(0);
    FINAL(1);
  #undef FINAL

  finalize:
    ret.hash[0] = finalize(acc[0]);
    ret.hash[1] = finalize(acc[1]);
    return ret;
}

//------------------------------------------------------------
// This is hardcoded to which == 0.
template <bool bswap>
static uint64_t umash_full( const struct umash_params * params, uint64_t seed, const void * data, size_t n_bytes ) {
    /*
     * It's not that short inputs are necessarily more likely, but
     * we want to make sure they fall through correctly to
     * minimise latency.
     */
    if (likely(n_bytes <= sizeof(v128))) {
        if (likely(n_bytes <= sizeof(uint64_t))) {
            return umash_short<bswap>(params->oh, seed, data, n_bytes);
        } else {
            return umash_medium<bswap>(params->poly[0], params->oh, seed, data, n_bytes);
        }
    } else {
        return umash_long<bswap>(params->poly[0], params->oh, seed, data, n_bytes);
    }
}

template <bool bswap>
static struct umash_fp umash_fprint( const struct umash_params * params,
        uint64_t seed, const void * data, size_t n_bytes ) {
    if (likely(n_bytes <= sizeof(v128))) {
        if (likely(n_bytes <= sizeof(uint64_t))) {
            return umash_fp_short<bswap>(params->oh, seed, data, n_bytes);
        } else {
            return umash_fp_medium<bswap>(params->poly, params->oh, seed, data, n_bytes);
        }
    } else {
        return umash_fp_long<bswap>(params->poly, params->oh, seed, data, n_bytes);
    }
}

//------------------------------------------------------------
static void core_salsa20( uint8_t * out, const uint8_t in[16], const uint8_t key[32], const uint8_t constant[16] ) {
    enum { ROUNDS = 20 };
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;

    j0  =  x0 = GET_U32<false>(constant,  0);
    j1  =  x1 = GET_U32<false>(key     ,  0);
    j2  =  x2 = GET_U32<false>(key     ,  4);
    j3  =  x3 = GET_U32<false>(key     ,  8);
    j4  =  x4 = GET_U32<false>(key     , 12);
    j5  =  x5 = GET_U32<false>(constant,  4);
    j6  =  x6 = GET_U32<false>(in      ,  0);
    j7  =  x7 = GET_U32<false>(in      ,  4);
    j8  =  x8 = GET_U32<false>(in      ,  8);
    j9  =  x9 = GET_U32<false>(in      , 12);
    j10 = x10 = GET_U32<false>(constant,  8);
    j11 = x11 = GET_U32<false>(key     , 16);
    j12 = x12 = GET_U32<false>(key     , 20);
    j13 = x13 = GET_U32<false>(key     , 24);
    j14 = x14 = GET_U32<false>(key     , 28);
    j15 = x15 = GET_U32<false>(constant, 12);

    for (size_t i = 0; i < ROUNDS; i += 2) {
        x4  ^= ROTL32(x0 + x12 ,  7);
        x8  ^= ROTL32(x4 + x0  ,  9);
        x12 ^= ROTL32(x8 + x4  , 13);
        x0  ^= ROTL32(x12 + x8 , 18);
        x9  ^= ROTL32(x5 + x1  ,  7);
        x13 ^= ROTL32(x9 + x5  ,  9);
        x1  ^= ROTL32(x13 + x9 , 13);
        x5  ^= ROTL32(x1 + x13 , 18);
        x14 ^= ROTL32(x10 + x6 ,  7);
        x2  ^= ROTL32(x14 + x10,  9);
        x6  ^= ROTL32(x2 + x14 , 13);
        x10 ^= ROTL32(x6 + x2  , 18);
        x3  ^= ROTL32(x15 + x11,  7);
        x7  ^= ROTL32(x3 + x15 ,  9);
        x11 ^= ROTL32(x7 + x3  , 13);
        x15 ^= ROTL32(x11 + x7 , 18);
        x1  ^= ROTL32(x0 + x3  ,  7);
        x2  ^= ROTL32(x1 + x0  ,  9);
        x3  ^= ROTL32(x2 + x1  , 13);
        x0  ^= ROTL32(x3 + x2  , 18);
        x6  ^= ROTL32(x5 + x4  ,  7);
        x7  ^= ROTL32(x6 + x5  ,  9);
        x4  ^= ROTL32(x7 + x6  , 13);
        x5  ^= ROTL32(x4 + x7  , 18);
        x11 ^= ROTL32(x10 + x9 ,  7);
        x8  ^= ROTL32(x11 + x10,  9);
        x9  ^= ROTL32(x8 + x11 , 13);
        x10 ^= ROTL32(x9 + x8  , 18);
        x12 ^= ROTL32(x15 + x14,  7);
        x13 ^= ROTL32(x12 + x15,  9);
        x14 ^= ROTL32(x13 + x12, 13);
        x15 ^= ROTL32(x14 + x13, 18);
    }

    x0  += j0;
    x1  += j1;
    x2  += j2;
    x3  += j3;
    x4  += j4;
    x5  += j5;
    x6  += j6;
    x7  += j7;
    x8  += j8;
    x9  += j9;
    x10 += j10;
    x11 += j11;
    x12 += j12;
    x13 += j13;
    x14 += j14;
    x15 += j15;

    PUT_U32<false>(x0 , out,  0);
    PUT_U32<false>(x1 , out,  4);
    PUT_U32<false>(x2 , out,  8);
    PUT_U32<false>(x3 , out, 12);
    PUT_U32<false>(x4 , out, 16);
    PUT_U32<false>(x5 , out, 20);
    PUT_U32<false>(x6 , out, 24);
    PUT_U32<false>(x7 , out, 28);
    PUT_U32<false>(x8 , out, 32);
    PUT_U32<false>(x9 , out, 36);
    PUT_U32<false>(x10, out, 40);
    PUT_U32<false>(x11, out, 44);
    PUT_U32<false>(x12, out, 48);
    PUT_U32<false>(x13, out, 52);
    PUT_U32<false>(x14, out, 56);
    PUT_U32<false>(x15, out, 60);
}

static void salsa20_stream( void * dst, size_t len, const uint8_t nonce[8], const uint8_t key[32] ) {
    static const uint8_t sigma[17] = "expand 32-byte k";
    uint8_t in[16];

    if (len == 0) {
        return;
    }

    memcpy(in, nonce, 8);
    memset(in + 8, 0, 8);

    while (len >= 64) {
        core_salsa20((uint8_t *)dst, in, key, sigma);

        unsigned int u = 1;
        for (size_t i = 8; i < 16; i++) {
            u    += in[i];
            in[i] = u;
            u   >>= 8;
        }

        dst  = (uint8_t *)dst + 64;
        len -= 64;
    }

    if (len > 0) {
        uint8_t block[64];
        core_salsa20(block, in, key, sigma);
        memcpy(dst, block, len);
    }
}

static bool value_is_repeated( const uint64_t * values, size_t n, uint64_t needle ) {
    for (size_t i = 0; i < n; i++) {
        if (values[i] == needle) {
            return true;
        }
    }
    return false;
}

static bool umash_params_prepare( struct umash_params * params ) {
    static const uint64_t modulo = (UINT64_C(1) << 61) - 1;
    /*
     * The polynomial parameters have two redundant fields (for
     * the pre-squared multipliers).  Use them as our source of
     * extra entropy if needed.
     */
    uint64_t buf[]   = { params->poly[0][0], params->poly[1][0] };
    size_t   buf_idx = 0;

#define GET_RANDOM(DST)                 \
    do {                                \
        if (buf_idx >= ARRAY_SIZE(buf)) \
            return false;               \
                                        \
        (DST) = buf[buf_idx++];         \
    } while (0)

    /* Check the polynomial multipliers: we don't want 0s. */
    for (size_t i = 0; i < ARRAY_SIZE(params->poly); i++) {
        uint64_t f = params->poly[i][1];

        while (true) {
            /*
             * Zero out bits and use rejection sampling to
             * guarantee uniformity.
             */
            f &= (UINT64_C(1) << 61) - 1;
            if ((f != 0) && (f < modulo)) {
                break;
            }

            GET_RANDOM(f);
        }

        /* We can work in 2**64 - 8 and reduce after the fact. */
        params->poly[i][0] = mul_mod_fast(f, f) % modulo;
        params->poly[i][1] = f;
    }

    /* Avoid repeated OH noise values. */
    for (size_t i = 0; i < ARRAY_SIZE(params->oh); i++) {
        while (value_is_repeated(params->oh, i, params->oh[i])) {
            GET_RANDOM(params->oh[i]);
        }
    }

    return true;
}

static void umash_params_derive( struct umash_params * params, uint64_t bits, const void * key ) {
    uint8_t umash_key[33] = "Do not use UMASH VS adversaries.";

    params->base_seed = bits;

    if (key != NULL) {
        memcpy(umash_key, key, sizeof(umash_key));
    }

    while (true) {
        uint8_t nonce[8];

        for (size_t i = 0; i < 8; i++) {
            nonce[i] = bits >> (8 * i);
        }

        /*
         * The "- sizeof(uint64_t)" is so that params->base_seed
         * doesn't get overwritten.
         */
        salsa20_stream(params, sizeof(*params) - sizeof(uint64_t), nonce, umash_key);
        if (umash_params_prepare(params)) {
            return;
        }

        /*
         * This should practically never fail, so really
         * shouldn't happen multiple times.  If it does, an
         * infinite loop is as good as anything else.
         */
        bits++;
    }
}

//------------------------------------------------------------
// Because use of umash_slow_reseed() is optional here, it needs a
// separate thread-local table. If the global one were used instead,
// it would need to become thread-local, which would break it for the
// case where the (reseed == false) versions are used in threaded
// mode. This is because the (now) thread-local global table would
// never be initialized in the thread, and so would be all zeroes.

static thread_local struct umash_params umash_params_local;

static uintptr_t umash_slow_reseed( const seed_t seed ) {
    umash_params_derive(&umash_params_local, seed, NULL);
    return (uintptr_t)(&umash_params_local);
}

static struct umash_params umash_params_global;

static bool umash_init( void ) {
    umash_params_derive(&umash_params_global, 0, NULL);
    umash_slow_reseed(0);
    return true;
}

template <bool reseed, bool bswap>
static void UMASH( const void * in, const size_t len, const seed_t seed, void * out ) {
    const struct umash_params * params = reseed ?
                (const struct umash_params *)(uintptr_t)seed :
                &umash_params_global;
    const uint64_t hseed = reseed ? params->base_seed : (uint64_t)seed;
    uint64_t       hash  = umash_full<bswap>(params, hseed, in, len);

    PUT_U64<false>(hash, (uint8_t *)out, 0);
}

template <bool reseed, bool bswap>
static void UMASH_FP( const void * in, const size_t len, const seed_t seed, void * out ) {
    const struct umash_params * params = reseed ?
                (const struct umash_params *)(uintptr_t)seed :
                &umash_params_global;
    const uint64_t  hseed = reseed ? params->base_seed : (uint64_t)seed;
    struct umash_fp hash  = umash_fprint<bswap>(params, hseed, in, len);

    PUT_U64<false>(hash.hash[0], (uint8_t *)out, 0);
    PUT_U64<false>(hash.hash[1], (uint8_t *)out, 8);
}

#endif
//------------------------------------------------------------
REGISTER_FAMILY(umash,
   $.src_url    = "https://github.com/backtrace-labs/umash",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

#if defined(HAVE_X86_64_CLMUL)

REGISTER_HASH(UMASH_64,
   $.desc       = "UMASH-64 (which == 0)",
   $.impl       = "hwclmul",
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE        |
         FLAG_HASH_CLMUL_BASED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128     |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x36A264CD,
   $.verification_BE = 0x84DA635B,
   $.hashfn_native   = UMASH<false, false>,
   $.hashfn_bswap    = UMASH<false, true>,
   $.initfn          = umash_init
 );

REGISTER_HASH(UMASH_64__reseed,
   $.desc       = "UMASH-64 (which == 0, with full reseeding)",
   $.impl       = "hwclmul",
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE        |
         FLAG_HASH_CLMUL_BASED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128     |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x161495C6,
   $.verification_BE = 0xF18B8420,
   $.hashfn_native   = UMASH<true, false>,
   $.hashfn_bswap    = UMASH<true, true>,
   $.seedfn          = umash_slow_reseed,
   $.initfn          = umash_init
 );

REGISTER_HASH(UMASH_128,
   $.desc       = "UMASH-128",
   $.impl       = "hwclmul",
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE        |
         FLAG_HASH_CLMUL_BASED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128     |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x63857D05,
   $.verification_BE = 0xE87FFB4B,
   $.hashfn_native   = UMASH_FP<false, false>,
   $.hashfn_bswap    = UMASH_FP<false, true>,
   $.initfn          = umash_init
 );

REGISTER_HASH(UMASH_128__reseed,
   $.desc       = "UMASH-128 (with full reseeding)",
   $.impl       = "hwclmul",
   $.hash_flags =
         FLAG_HASH_LOOKUP_TABLE        |
         FLAG_HASH_CLMUL_BASED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128     |
         FLAG_IMPL_ROTATE              |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x36D4EC95,
   $.verification_BE = 0x9F870C9C,
   $.hashfn_native   = UMASH_FP<true, false>,
   $.hashfn_bswap    = UMASH_FP<true, true>,
   $.seedfn          = umash_slow_reseed,
   $.initfn          = umash_init
 );

#endif
