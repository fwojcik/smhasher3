/*
 * MUM and MIR hashes
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2016 Vladimir Makarov <vmakarov@gcc.gnu.org>
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

#include "Mathmult.h"

//-----------------------------------------------------------------------------
// Multiply 64-bit V and P and return sum of high and low parts of the
// result.
//
// On systems without a 64*64->128 multiply instruction, this
// computation is done via 64*64->64-bit multiplies. However, since
// true mathematical precision is not needed, an alternative mode of
// hash operation is to ignore the carry bits, leading to a similar
// but slightly different result, which is faster to compute if no
// 128-bit multiply result is available.
//
// The code has been reworked to allow both forms to always be
// calculable on every platform.
template <bool exact>
static inline uint64_t _mum( uint64_t v, uint64_t p ) {
    uint64_t hi, lo;

    if (exact) {
        MathMult::mult64_128(lo, hi, v, p);
    } else {
        MathMult::mult64_128_nocarry(lo, hi, v, p);
    }

    /*
     * We could use XOR here too but, for some reasons, on Haswell and
     * Power7 using an addition improves hashing performance by 10% for
     * small strings.
     */
    return hi + lo;
}

//-----------------------------------------------------------------------------
// MUM hash internals

/*
 * Here are different primes randomly generated with the equal
 * probability of their bit values.  They are used to randomize input
 * values.
 */
static const uint64_t _mum_block_start_prime = UINT64_C(0xc42b5e2e6480b23b);
static const uint64_t _mum_unroll_prime      = UINT64_C(0x7b51ec3d22f7096f);
static const uint64_t _mum_tail_prime        = UINT64_C(0xaf47d47c99b1461b);
static const uint64_t _mum_finish_prime1     = UINT64_C(0xa9a7ae7ceff79f3f);
static const uint64_t _mum_finish_prime2     = UINT64_C(0xaf47d47c99b1461b);

static const uint64_t _mum_primes[] = {
    UINT64_C(0x9ebdcae10d981691), UINT64_C(0x32b9b9b97a27ac7d),
    UINT64_C(0x29b5584d83d35bbd), UINT64_C(0x4b04e0e61401255f),
    UINT64_C(0x25e8f7b1f1c9d027), UINT64_C(0x80d4c8c000f3e881),
    UINT64_C(0xbd1255431904b9dd), UINT64_C(0x8a3bd4485eee6d81),
    UINT64_C(0x3bc721b2aad05197), UINT64_C(0x71b1a19b907d6e33),
    UINT64_C(0x525e6c1084a8534b), UINT64_C(0x9e4c2cd340c1299f),
    UINT64_C(0xde3add92e94caa37), UINT64_C(0x7e14eadb1f65311d),
    UINT64_C(0x3f5aa40f89812853), UINT64_C(0x33b15a3b587d15c9),
};

// Since unroll_power actually affects hash *values*, not just speed,
// it needs to be a template parameter, so all versions of the hash
// can be tested on all platforms.
template <uint32_t version, uint32_t unroll_power, bool bswap, bool exactmul>
// _MUM_OPTIMIZE("unroll-loops")
static inline uint64_t _mum_hash_aligned( uint64_t seed, const void * key, size_t len ) {
    const uint32_t  _MUM_UNROLL_FACTOR = 1 << unroll_power;
    const uint8_t * str = (const uint8_t *)key;
    uint64_t        u64, result;
    size_t          i;
    size_t          n;

    if ((version == 1) || (version == 3)) {
        result = _mum<exactmul>(seed, _mum_block_start_prime);
    } else {
        result = seed;
    }
    while (len > _MUM_UNROLL_FACTOR * sizeof(uint64_t)) {
        /*
         * This loop could be vectorized when we have vector insns for
         * 64x64->128-bit multiplication.  AVX2 currently only have a
         * vector insn for 4 32x32->64-bit multiplication.
         */
        if ((version == 1) || (version == 2)) {
            for (i = 0; i < _MUM_UNROLL_FACTOR; i++) {
                result ^= _mum<exactmul>(GET_U64<bswap>(str, i * 8) , _mum_primes[i]);
            }
        } else {
            for (i = 0; i < _MUM_UNROLL_FACTOR; i += 2) {
                result ^= _mum<exactmul>(GET_U64<bswap>(str, i * 8) ^ _mum_primes[i],
                        GET_U64<bswap>(str, i * 8 + 8) ^ _mum_primes[i + 1]);
            }
        }
        len   -= _MUM_UNROLL_FACTOR * sizeof(uint64_t);
        str   += _MUM_UNROLL_FACTOR * sizeof(uint64_t);
        /*
         * We will use the same prime numbers on the next iterations --
         * randomize the state.
         */
        result = _mum<exactmul>(result, _mum_unroll_prime);
    }
    n = len / sizeof(uint64_t);
    for (i = 0; i < n; i++) {
        result ^= _mum<exactmul>(GET_U64<bswap>(str, i * 8), _mum_primes[i]);
    }
    len -= n * sizeof(uint64_t); str += n * sizeof(uint64_t);
    switch (len) {
    case 7:
            u64  = GET_U32<bswap>(str, 0);
            u64 |= (uint64_t)str[4] << 32;
            u64 |= (uint64_t)str[5] << 40;
            u64 |= (uint64_t)str[6] << 48;
            return result ^ _mum<exactmul>(u64, _mum_tail_prime);
    case 6:
            u64  = GET_U32<bswap>(str, 0);
            u64 |= (uint64_t)str[4] << 32;
            u64 |= (uint64_t)str[5] << 40;
            return result ^ _mum<exactmul>(u64, _mum_tail_prime);
    case 5:
            u64  = GET_U32<bswap>(str, 0);
            u64 |= (uint64_t)str[4] << 32;
            return result ^ _mum<exactmul>(u64, _mum_tail_prime);
    case 4:
            u64 =  GET_U32<bswap>(str, 0);
            return result ^ _mum<exactmul>(u64, _mum_tail_prime);
    case 3:
            u64  = str[0];
            u64 |= (uint64_t)str[1] <<  8;
            u64 |= (uint64_t)str[2] << 16;
            return result ^ _mum<exactmul>(u64, _mum_tail_prime);
    case 2:
            u64  = str          [0];
            u64 |= (uint64_t)str[1] <<  8;
            return result ^ _mum<exactmul>(u64, _mum_tail_prime);
    case 1:
            u64 = str           [0];
            return result ^ _mum<exactmul>(u64, _mum_tail_prime);
    }
    return result;
}

/* Final randomization of H.  */
template <uint32_t version, bool exactmul>
static inline uint64_t _mum_final( uint64_t h ) {
    if (version == 1) {
        h ^= _mum<exactmul>(h, _mum_finish_prime1);
        h ^= _mum<exactmul>(h, _mum_finish_prime2);
    } else if (version == 2) {
        h ^= ROTL64(h, 33);
        h ^= _mum<exactmul>(h, _mum_finish_prime1);
    } else {
        h = _mum<exactmul>(h, h);
    }
    return h;
}

//-----------------------------------------------------------------------------
// MUM hash externals for SMHasher3

template <uint32_t version, uint32_t unroll_power, bool bswap, bool exactmul>
static void mum_aligned( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h;

    h = _mum_hash_aligned<version, unroll_power, bswap, exactmul>(seed + len, in, len);
    h = _mum_final<version, exactmul>(h);
    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

// fwojcik: I believe the fact that the realign versions of the
// hash can have different hashes than the aligned version is
// unintended behavior. The differences come only from 2 places:
//    1) v1 and v3 of the hash have a per-block MUM step, and
//    2) _mum_hash_aligned() uses "while (len > ....." instead of
//      "while (len >= .....".
// Based on this, I'm removing the realign variants for now.
#if defined(NOTYET)

template <uint32_t version, uint32_t unroll_power, bool bswap, bool exactmul>
static void mum_realign( const void * in, const size_t olen, const seed_t seed, void * out ) {
    const uint8_t * str = (const uint8_t *)in;
    const uint32_t  _MUM_BLOCK_LEN = 1024;
    uint64_t        buf[_MUM_BLOCK_LEN / sizeof(uint64_t)];
    size_t          len = olen;
    uint64_t        h   = seed + olen;

    while (len != 0) {
        size_t block_len = len < _MUM_BLOCK_LEN ? len : _MUM_BLOCK_LEN;
        memmove(buf, str, block_len);
        h    = _mum_hash_aligned<version, unroll_power, bswap, exactmul>(h, buf, block_len);
        len -= block_len;
        str += block_len;
    }
    h = _mum_final<version, exactmul>(h);
    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

#endif

//-----------------------------------------------------------------------------
// MIR hash internals

/*
 * Simple high-quality multiplicative hash passing demerphq-smhsher,
 * faster than spooky, city, or xxhash for strings less 100 bytes.
 * Hash for the same key can be different on different architectures.
 * To get machine-independent hash, use mir_hash_strict which is about
 * 1.5 times slower than mir_hash.
 */
template <bool exact>
static inline uint64_t mir_mum( uint64_t v, uint64_t c ) {
    if (exact) { return _mum<true>(v, c); }
    uint64_t v1 = v >> 32, v2 = (uint32_t)v, c1 = c >> 32, c2 = (uint32_t)c, rm = v2 * c1 + v1 * c2;
    return v1 * c1 + (rm >> 32) + v2 * c2 + (rm << 32);
}

static const uint64_t p1 = UINT64_C(0x65862b62bdf5ef4d), p2 = UINT64_C(0x288eea216831e6a7);

template <bool exactmul>
static inline uint64_t mir_round( uint64_t state, uint64_t v ) {
    state ^= mir_mum<exactmul>(v, p1);
    return state ^ mir_mum<exactmul>(state, p2);
}

template <bool bswap>
static inline uint64_t mir_get_key_part( const uint8_t * v, size_t len ) {
    size_t   i, start = 0;
    uint64_t tail = 0;

    if (len >= sizeof(uint32_t)) {
        tail  = ((uint64_t)(GET_U32<bswap>(v, 0))) << 32;
        start = 4;
    }
    for (i = start; i < len; i++) { tail = (tail >> 8) | ((uint64_t)v[i] << 56); }
    return tail;
}

//-----------------------------------------------------------------------------
// MIR hash externals for SMHasher3

// The bswap and exactmul booleans cover all possible sets of hash
// values from the original mir_hash() in both "strict" mode and
// "relaxed" mode, regardless of machine endianness.
template <bool bswap, bool exactmul>
static void mir_hash( const void * in, const size_t olen, const seed_t seed, void * out ) {
    const uint8_t * v   = (const uint8_t *)in;
    uint64_t        r   = seed + olen;
    size_t          len = olen;

    for (; len >= 16; len -= 16, v += 16) {
        r ^= mir_mum<exactmul>(GET_U64<bswap>(v, 0), p1);
        r ^= mir_mum<exactmul>(GET_U64<bswap>(v, 8), p2);
        r ^= mir_mum<exactmul>(r, p1);
    }
    if (len >= 8) {
        r   ^= mir_mum<exactmul>(GET_U64<bswap>(v, 0), p1);
        len -= 8, v += 8;
    }
    if (len != 0) {
        r ^= mir_mum<exactmul>(mir_get_key_part<bswap>(v, len), p2);
    }
    r = mir_round<exactmul>(r, r);
    PUT_U64<bswap>(r, (uint8_t *)out, 0);
}

//-----------------------------------------------------------------------------
// Also https://github.com/vnmakarov/mir/blob/master/mir-hash.h
REGISTER_FAMILY(mum_mir,
   $.src_url    = "https://github.com/vnmakarov/mum-hash",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(mum1__exact__unroll1,
   $.desc       = "Mum-hash v1, unroll 2^1, exact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xCB93DE58,
   $.verification_BE = 0xE820D0FB,
   $.hashfn_native   = mum_aligned<1, 1, false, true>,
   $.hashfn_bswap    = mum_aligned<1, 1, true, true>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mum1__exact__unroll2,
   $.desc       = "Mum-hash v1, unroll 2^2, exact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x3EEAE2D4,
   $.verification_BE = 0xF23A691C,
   $.hashfn_native   = mum_aligned<1, 2, false, true>,
   $.hashfn_bswap    = mum_aligned<1, 2, true, true>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mum1__exact__unroll3,
   $.desc       = "Mum-hash v1, unroll 2^3, exact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x7C0A2F98,
   $.verification_BE = 0x210F4BEB,
   $.hashfn_native   = mum_aligned<1, 3, false, true>,
   $.hashfn_bswap    = mum_aligned<1, 3, true, true>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mum1__exact__unroll4,
   $.desc       = "Mum-hash v1, unroll 2^4, exact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x280B2CC6,
   $.verification_BE = 0x0609C4A6,
   $.hashfn_native   = mum_aligned<1, 4, false, true>,
   $.hashfn_bswap    = mum_aligned<1, 4, true, true>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mum1__inexact__unroll1,
   $.desc       = "Mum-hash v1, unroll 2^1, inexact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x689214DF,
   $.verification_BE = 0x14FBDFDD,
   $.hashfn_native   = mum_aligned<1, 1, false, false>,
   $.hashfn_bswap    = mum_aligned<1, 1, true, false>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mum1__inexact__unroll2,
   $.desc       = "Mum-hash v1, unroll 2^2, inexact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xA973C6C0,
   $.verification_BE = 0x9C12DFA3,
   $.hashfn_native   = mum_aligned<1, 2, false, false>,
   $.hashfn_bswap    = mum_aligned<1, 2, true, false>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mum1__inexact__unroll3,
   $.desc       = "Mum-hash v1, unroll 2^3, inexact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x5FC8FC51,
   $.verification_BE = 0x907AB469,
   $.hashfn_native   = mum_aligned<1, 3, false, false>,
   $.hashfn_bswap    = mum_aligned<1, 3, true, false>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mum1__inexact__unroll4,
   $.desc       = "Mum-hash v1, unroll 2^4, inexact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x2EF256D3,
   $.verification_BE = 0xBF27AAE6,
   $.hashfn_native   = mum_aligned<1, 4, false, false>,
   $.hashfn_bswap    = mum_aligned<1, 4, true, false>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

#if defined(NOTYET)
REGISTER_HASH(mum1_realign__exact__unroll1,
   $.desc       = "Mum-hash v1, unroll 2^1, exact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x9E323D13,
   $.verification_BE = 0x2E655802,
   $.hashfn_native   = mum_realign<1, 1, false, true>,
   $.hashfn_bswap    = mum_realign<1, 1, true, true>
 );

REGISTER_HASH(mum1_realign__exact__unroll2,
   $.desc       = "Mum-hash v1, unroll 2^2, exact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x139A630F,
   $.verification_BE = 0x2281185A,
   $.hashfn_native   = mum_realign<1, 2, false, true>,
   $.hashfn_bswap    = mum_realign<1, 2, true, true>
 );

REGISTER_HASH(mum1_realign__exact__unroll3,
   $.desc       = "Mum-hash v1, unroll 2^3, exact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x0F1AC6C6,
   $.verification_BE = 0xE8BF6CE3,
   $.hashfn_native   = mum_realign<1, 3, false, true>,
   $.hashfn_bswap    = mum_realign<1, 3, true, true>
 );

REGISTER_HASH(mum1_realign__exact__unroll4,
   $.desc       = "Mum-hash v1, unroll 2^4, exact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xF47885FE,
   $.verification_BE = 0xA7961551,
   $.hashfn_native   = mum_realign<1, 4, false, true>,
   $.hashfn_bswap    = mum_realign<1, 4, true, true>
 );

REGISTER_HASH(mum1_realign__inexact__unroll1,
   $.desc       = "Mum-hash v1, unroll 2^1, inexact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xE11FC923,
   $.verification_BE = 0x99623861,
   $.hashfn_native   = mum_realign<1, 1, false, false>,
   $.hashfn_bswap    = mum_realign<1, 1, true, false>
 );

REGISTER_HASH(mum1_realign__inexact__unroll2,
   $.desc       = "Mum-hash v1, unroll 2^2, inexact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xBAFC050E,
   $.verification_BE = 0x9678D798,
   $.hashfn_native   = mum_realign<1, 2, false, false>,
   $.hashfn_bswap    = mum_realign<1, 2, true, false>
 );

REGISTER_HASH(mum1_realign__inexact__unroll3,
   $.desc       = "Mum-hash v1, unroll 2^3, inexact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x56FA3D86,
   $.verification_BE = 0x8EDC90F0,
   $.hashfn_native   = mum_realign<1, 3, false, false>,
   $.hashfn_bswap    = mum_realign<1, 3, true, false>
 );

REGISTER_HASH(mum1_realign__inexact__unroll4,
   $.desc       = "Mum-hash v1, unroll 2^4, inexact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x59787144,
   $.verification_BE = 0xFCAEA377,
   $.hashfn_native   = mum_realign<1, 4, false, false>,
   $.hashfn_bswap    = mum_realign<1, 4, true, false>
 );
#endif

REGISTER_HASH(mum2__exact__unroll1,
   $.desc       = "Mum-hash v2, unroll 2^1, exact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x9B36F94C,
   $.verification_BE = 0x50F10B41,
   $.hashfn_native   = mum_aligned<2, 1, false, true>,
   $.hashfn_bswap    = mum_aligned<2, 1, true, true>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mum2__exact__unroll2,
   $.desc       = "Mum-hash v2, unroll 2^2, exact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x40427228,
   $.verification_BE = 0x43DB198B,
   $.hashfn_native   = mum_aligned<2, 2, false, true>,
   $.hashfn_bswap    = mum_aligned<2, 2, true, true>,
   $.badseeddesc     = "All seeds have byte pairs which produce collisions on some lengths (e.g. 0x08 vs. 0x7f on 32-byte keys)"
 );

REGISTER_HASH(mum2__exact__unroll3,
   $.desc       = "Mum-hash v2, unroll 2^3, exact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xB5D1CB5C,
   $.verification_BE = 0xA718EDE8,
   $.hashfn_native   = mum_aligned<2, 3, false, true>,
   $.hashfn_bswap    = mum_aligned<2, 3, true, true>,
   $.badseeddesc     = "All seeds have byte pairs which produce collisions on some lengths (e.g. 0x08 vs. 0x7f on 32-byte keys)"
 );

REGISTER_HASH(mum2__exact__unroll4,
   $.desc       = "Mum-hash v2, unroll 2^4, exact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x59AEDABF,
   $.verification_BE = 0x3B1A2832,
   $.hashfn_native   = mum_aligned<2, 4, false, true>,
   $.hashfn_bswap    = mum_aligned<2, 4, true, true>,
   $.badseeddesc     = "All seeds have byte pairs which produce collisions on some lengths (e.g. 0x08 vs. 0x7f on 32-byte keys)"
 );

REGISTER_HASH(mum2__inexact__unroll1,
   $.desc       = "Mum-hash v2, unroll 2^1, inexact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x1CC6D1E3,
   $.verification_BE = 0x297D8E45,
   $.hashfn_native   = mum_aligned<2, 1, false, false>,
   $.hashfn_bswap    = mum_aligned<2, 1, true, false>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mum2__inexact__unroll2,
   $.desc       = "Mum-hash v2, unroll 2^2, inexact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x62325A27,
   $.verification_BE = 0x5324AEEA,
   $.hashfn_native   = mum_aligned<2, 2, false, false>,
   $.hashfn_bswap    = mum_aligned<2, 2, true, false>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mum2__inexact__unroll3,
   $.desc       = "Mum-hash v2, unroll 2^3, inexact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xF4DD9947,
   $.verification_BE = 0x98C9448F,
   $.hashfn_native   = mum_aligned<2, 3, false, false>,
   $.hashfn_bswap    = mum_aligned<2, 3, true, false>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mum2__inexact__unroll4,
   $.desc       = "Mum-hash v2, unroll 2^4, inexact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x62C46C55,
   $.verification_BE = 0x0E9DDA53,
   $.hashfn_native   = mum_aligned<2, 4, false, false>,
   $.hashfn_bswap    = mum_aligned<2, 4, true, false>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

#if defined(NOTYET)
REGISTER_HASH(mum2_realign__exact__unroll1,
   $.desc       = "Mum-hash v2, unroll 2^1, exact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x3A8751BE,
   $.verification_BE = 0xA3C3C380,
   $.hashfn_native   = mum_realign<2, 1, false, true>,
   $.hashfn_bswap    = mum_realign<2, 1, true, true>
 );

REGISTER_HASH(mum2_realign__exact__unroll2,
   $.desc       = "Mum-hash v2, unroll 2^2, exact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x7C85EF5A,
   $.verification_BE = 0xE99D6D79,
   $.hashfn_native   = mum_realign<2, 2, false, true>,
   $.hashfn_bswap    = mum_realign<2, 2, true, true>
 );

REGISTER_HASH(mum2_realign__exact__unroll3,
   $.desc       = "Mum-hash v2, unroll 2^3, exact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x93F25600,
   $.verification_BE = 0xE13A6F00,
   $.hashfn_native   = mum_realign<2, 3, false, true>,
   $.hashfn_bswap    = mum_realign<2, 3, true, true>
 );

REGISTER_HASH(mum2_realign__exact__unroll4,
   $.desc       = "Mum-hash v2, unroll 2^4, exact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xA0DC8DF8,
   $.verification_BE = 0x6B746384,
   $.hashfn_native   = mum_realign<2, 4, false, true>,
   $.hashfn_bswap    = mum_realign<2, 4, true, true>
 );

REGISTER_HASH(mum2_realign__inexact__unroll1,
   $.desc       = "Mum-hash v2, unroll 2^1, inexact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x2D06BA6A,
   $.verification_BE = 0xF0F929DF,
   $.hashfn_native   = mum_realign<2, 1, false, false>,
   $.hashfn_bswap    = mum_realign<2, 1, true, false>
 );

REGISTER_HASH(mum2_realign__inexact__unroll2,
   $.desc       = "Mum-hash v2, unroll 2^2, inexact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xF645F70A,
   $.verification_BE = 0xC384782D,
   $.hashfn_native   = mum_realign<2, 2, false, false>,
   $.hashfn_bswap    = mum_realign<2, 2, true, false>
 );

REGISTER_HASH(mum2_realign__inexact__unroll3,
   $.desc       = "Mum-hash v2, unroll 2^3, inexact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xA8F0601A,
   $.verification_BE = 0x5F5895AB,
   $.hashfn_native   = mum_realign<2, 3, false, false>,
   $.hashfn_bswap    = mum_realign<2, 3, true, false>
 );

REGISTER_HASH(mum2_realign__inexact__unroll4,
   $.desc       = "Mum-hash v2, unroll 2^4, inexact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x53A9484D,
   $.verification_BE = 0x4C6EBD7D,
   $.hashfn_native   = mum_realign<2, 4, false, false>,
   $.hashfn_bswap    = mum_realign<2, 4, true, false>
 );
#endif

REGISTER_HASH(mum3__exact__unroll1,
   $.desc       = "Mum-hash v3, unroll 2^1, exact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x3D14C6E2,
   $.verification_BE = 0x360A792D,
   $.hashfn_native   = mum_aligned<3, 1, false, true>,
   $.hashfn_bswap    = mum_aligned<3, 1, true, true>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mum3__exact__unroll2,
   $.desc       = "Mum-hash v3, unroll 2^2, exact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x3A556EB2,
   $.verification_BE = 0x752891D0,
   $.hashfn_native   = mum_aligned<3, 2, false, true>,
   $.hashfn_bswap    = mum_aligned<3, 2, true, true>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes)"
 );

REGISTER_HASH(mum3__exact__unroll3,
   $.desc       = "Mum-hash v3, unroll 2^3, exact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x8BD72B8C,
   $.verification_BE = 0xDD8DD247,
   $.hashfn_native   = mum_aligned<3, 3, false, true>,
   $.hashfn_bswap    = mum_aligned<3, 3, true, true>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes)"
 );

REGISTER_HASH(mum3__exact__unroll4,
   $.desc       = "Mum-hash v3, unroll 2^4, exact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x0AD998DF,
   $.verification_BE = 0x05832709,
   $.hashfn_native   = mum_aligned<3, 4, false, true>,
   $.hashfn_bswap    = mum_aligned<3, 4, true, true>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mum3__inexact__unroll1,
   $.desc       = "Mum-hash v3, unroll 2^1, inexact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x475D666B,
   $.verification_BE = 0xE75B31F7,
   $.hashfn_native   = mum_aligned<3, 1, false, false>,
   $.hashfn_bswap    = mum_aligned<3, 1, true, false>,
   $.badseeddesc     = "All seeds give zero hashes on keys of all zero bytes if len+seed==0"
 );

REGISTER_HASH(mum3__inexact__unroll2,
   $.desc       = "Mum-hash v3, unroll 2^2, inexact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xF6E13B23,
   $.verification_BE = 0x7B00F4F6,
   $.hashfn_native   = mum_aligned<3, 2, false, false>,
   $.hashfn_bswap    = mum_aligned<3, 2, true, false>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes)"
 );

REGISTER_HASH(mum3__inexact__unroll3,
   $.desc       = "Mum-hash v3, unroll 2^3, inexact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xB5560703,
   $.verification_BE = 0x1220D737,
   $.hashfn_native   = mum_aligned<3, 3, false, false>,
   $.hashfn_bswap    = mum_aligned<3, 3, true, false>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes)"
 );

REGISTER_HASH(mum3__inexact__unroll4,
   $.desc       = "Mum-hash v3, unroll 2^4, inexact mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xE96A20C0,
   $.verification_BE = 0xE784308C,
   $.hashfn_native   = mum_aligned<3, 4, false, false>,
   $.hashfn_bswap    = mum_aligned<3, 4, true, false>,
   $.badseeddesc     = "All seeds collide on keys of all 0x00 versus all 0xFF for some lengths (e.g. 32 bytes, 80 bytes)"
 );

#if defined(NOTYET)
REGISTER_HASH(mum3_realign__exact__unroll1,
   $.desc       = "Mum-hash v3, unroll 2^1, exact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x26B6E56E,
   $.verification_BE = 0x3395CE6B,
   $.hashfn_native   = mum_realign<3, 1, false, true>,
   $.hashfn_bswap    = mum_realign<3, 1, true, true>
 );

REGISTER_HASH(mum3_realign__exact__unroll2,
   $.desc       = "Mum-hash v3, unroll 2^2, exact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x6A60097E,
   $.verification_BE = 0xF7ABC648,
   $.hashfn_native   = mum_realign<3, 2, false, true>,
   $.hashfn_bswap    = mum_realign<3, 2, true, true>
 );

REGISTER_HASH(mum3_realign__exact__unroll3,
   $.desc       = "Mum-hash v3, unroll 2^3, exact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xD45801EE,
   $.verification_BE = 0x1D6D8F1C,
   $.hashfn_native   = mum_realign<3, 3, false, true>,
   $.hashfn_bswap    = mum_realign<3, 3, true, true>
 );

REGISTER_HASH(mum3_realign__exact__unroll4,
   $.desc       = "Mum-hash v3, unroll 2^4, exact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x65C49B24,
   $.verification_BE = 0xE1C2CEEC,
   $.hashfn_native   = mum_realign<3, 4, false, true>,
   $.hashfn_bswap    = mum_realign<3, 4, true, true>
 );

REGISTER_HASH(mum3_realign__inexact__unroll1,
   $.desc       = "Mum-hash v3, unroll 2^1, inexact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xFB3DE98D,
   $.verification_BE = 0xBBF8D76F,
   $.hashfn_native   = mum_realign<3, 1, false, false>,
   $.hashfn_bswap    = mum_realign<3, 1, true, false>
 );

REGISTER_HASH(mum3_realign__inexact__unroll2,
   $.desc       = "Mum-hash v3, unroll 2^2, inexact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xBFD7CE56,
   $.verification_BE = 0x134317BB,
   $.hashfn_native   = mum_realign<3, 2, false, false>,
   $.hashfn_bswap    = mum_realign<3, 2, true, false>
 );

REGISTER_HASH(mum3_realign__inexact__unroll3,
   $.desc       = "Mum-hash v3, unroll 2^3, inexact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x68CB735E,
   $.verification_BE = 0x47E5152C,
   $.hashfn_native   = mum_realign<3, 3, false, false>,
   $.hashfn_bswap    = mum_realign<3, 3, true, false>
 );

REGISTER_HASH(mum3_realign__inexact__unroll4,
   $.desc       = "Mum-hash v3, unroll 2^4, inexact mult, for aligned-only reads",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x4975BD5E,
   $.verification_BE = 0x8A467520,
   $.hashfn_native   = mum_realign<3, 4, false, false>,
   $.hashfn_bswap    = mum_realign<3, 4, true, false>
 );
#endif

REGISTER_HASH(mir__exact,
   $.desc       = "MIR-hash, exact 128-bit mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128      |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x00A393C8,
   $.verification_BE = 0x39F99A44,
   $.hashfn_native   = mir_hash<false, true>,
   $.hashfn_bswap    = mir_hash<true, true>,
   $.badseeddesc     = "All seeds produce many collisions on certain key lengths (e.g. 32 bytes, 80 bytes)"
 );

REGISTER_HASH(mir__inexact,
   $.desc       = "MIR-hash, inexact 128-bit mult",
   $.hash_flags =
         0,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64      |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x422A66FC,
   $.verification_BE = 0xA9A6A383,
   $.hashfn_native   = mir_hash<false, false>,
   $.hashfn_bswap    = mir_hash<true, false>,
   $.seedfixfn       = excludeBadseeds,
   $.badseeddesc     = "All seeds give zero hashes on keys of all zero bytes if len+seed==0"
 );
