/*
 * Floppsyhash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2017 The Dosyago Corporation & Cris Stringfellow
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include "Platform.h"
#include "Hashlib.h"

#include <math.h> // For pow()

//-----------------------------------------------------------------------------
// Some useful constant(s). These are not guaranteed to be available from
// math.h or cmath, so we simply define them here, instead of having
// additional platform detection (for things like _USE_MATH_DEFINES) and
// fallback code.
#if !defined(M_PI)
  #define M_PI           3.14159265358979323846
#endif

#if !defined(M_E)
  #define M_E            2.7182818284590452354
#endif

//------------------------------------------------------------
// Cross-platform bitwise-exact floating point math is not guaranteed to be possible
// in C++, even with the guarantees of IEEE 754. This code has been altered to get as
// close as I know how. These settings, along with their build-system counterparts,
// try to instruct the compiler to avoid some specific math "shortcuts" that can lead
// to diverging results. Further, this code has been reworked so that every statement
// contains no more than 1 floating point operation. Some compilers take this as a
// hint that increased fidelity is wanted, or have a compiler option to do so.
//
// Any additional tricks to increase compatibility are welcome!

#pragma fp_contract (off)
#pragma STDC FP_CONTRACT OFF
static_assert(std::numeric_limits<double>::is_iec559, "IEEE 754 floating point required");

//------------------------------------------------------------
// Q function : Continued Egyptian Fraction update function
template <bool old>
static FORCE_INLINE void q( double * state, double key_val, double numerator, double denominator ) {
    double frac = numerator / denominator;

    state[0] += frac;
    state[0]  = 1.0       / state[0];

    if (!old) { key_val += M_PI; }
    state[1] += key_val;
    state[1]  = numerator / state[1];
}

// round function : process the message
template <bool old>
static FORCE_INLINE void round( const uint8_t * msg, size_t len, double * state ) {
    double numerator = 1.0;

    // Loop
    for (size_t i = 0; i < len; i++) {
        double val = (double)msg[i];
        double tmp;
        if (old) {
            tmp =  (double)(msg[i] + i + 1);
        } else {
            tmp  = val * M_E;
            tmp += (double)(i + 1);
        }
        double denominator = tmp / state[1];

        q<old>(state, val, numerator, denominator);

        numerator = denominator + 1.0;
    }

    if (old) {
        double tmp;
        tmp       = M_PI + state[1];
        state[0] *= tmp;
        tmp       = M_E  + state[0];
        state[1] *= tmp;
    }
}

// setup function : setup the state
static FORCE_INLINE void setup( double * state, double init = 0 ) {
    if (init == 0) {
        state[0] = (double)3.0;
        state[1] = (double)1.0 / 7.0;
    } else {
        double tmp = 1.0 / init;
        tmp     += init;
        state[0] = pow(tmp, 1.0 / 3.0);
        state[1] = pow(tmp, 1.0 / 7.0);
    }
}

//------------------------------------------------------------
// static_assert(sizeof(double) == 8);
template <bool old, bool bswap>
static void floppsyhash( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * data = (const uint8_t *)in;
    double          state[2];
    uint8_t         seedbuf[4];

    PUT_U32<bswap>((uint32_t)seed, seedbuf, 0);

    setup(state, (double)(uint32_t)seed);
    if (!old) {
        round<false>(seedbuf, 4, state);
    }
    round<old>(data, len, state);

    uint32_t state32[4];
    memcpy(&state32[0], &state[0], 8);
    memcpy(&state32[2], &state[1], 8);

    uint32_t h[2];
    if (isLE()) {
        h[0] = state32[0] + state32[3];
        h[1] = state32[1] + state32[2];
    } else {
        h[1] = state32[0] + state32[3];
        h[0] = state32[1] + state32[2];
    }

    PUT_U32<bswap>(h[0], (uint8_t *)out, 0);
    PUT_U32<bswap>(h[1], (uint8_t *)out, 4);
}

//------------------------------------------------------------
REGISTER_FAMILY(floppsy,
   $.src_url    = "https://github.com/dosyago/floppsy",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(floppsyhash,
   $.desc       = "Floppsyhash v1.1.10 (floating-point hash using continued Egyptian fractions)",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED      |
         FLAG_HASH_FLOATING_POINT,
   $.impl_flags =
         FLAG_IMPL_VERY_SLOW    |
         FLAG_IMPL_MULTIPLY     |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x5F9F6226,
   $.verification_BE = 0x4D4F96F0,
   $.hashfn_native   = floppsyhash<false, false>,
   $.hashfn_bswap    = floppsyhash<false, true>
 );

REGISTER_HASH(floppsyhash__old,
   $.desc       = "Floppsyhash (old version, fka \"tifuhash\")",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED      |
         FLAG_HASH_FLOATING_POINT,
   $.impl_flags =
         FLAG_IMPL_VERY_SLOW    |
         FLAG_IMPL_MULTIPLY     |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x644236D4,
   $.verification_BE = 0x7A3D2F7E,
   $.hashfn_native   = floppsyhash<true, false>,
   $.hashfn_bswap    = floppsyhash<true, true>
 );
