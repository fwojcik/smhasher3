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
#include "Types.h"
#include "Hashlib.h"

#include <math.h> // For M_E and M_PI

//------------------------------------------------------------
// Q function : Continued Egyptian Fraction update function
template < bool old>
static FORCE_INLINE void q(double * state, double key_val,
        double numerator, double denominator) {
    state[0] += numerator / denominator;
    state[0] = 1.0 / state[0];

    state[1] += old ? key_val : key_val + M_PI;
    state[1] = numerator / state[1];
}

// round function : process the message
template < bool old>
static FORCE_INLINE void round(const uint8_t * msg, size_t len, double * state) {
    double numerator = 1.0;

    // Loop
    for (size_t i = 0; i < len; i++ ) {
        double val = (double)msg[i];
        double denominator = ((old ? val : (M_E * val)) + i + 1.0) / state[1];

        q<old>(state, val, numerator, denominator);

        numerator = denominator + 1.0;
    }

    if (old) {
        state[0] *= M_PI + state[1];
        state[1] *= M_E + state[0];
    }
}

// setup function : setup the state
static FORCE_INLINE void setup(double * state, double init = 0) {
  state[0] += init != 0 ? pow(init + 1.0/init, 1.0/3) : 3.0;
  state[1] += init != 0 ? pow(init + 1.0/init, 1.0/7) : 1.0/7;
}

//------------------------------------------------------------
//static_assert(sizeof(double) == 8);
template < bool old, bool bswap >
void floppsyhash(const void * in, const size_t len, const seed_t seed, void * out) {
    const uint8_t * data = (const uint8_t *)in;
    double state[2];
    uint8_t seedbuf[4];

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
REGISTER_FAMILY(floppsy);

REGISTER_HASH(floppsyhash,
  $.desc = "Floppsyhash (floating-point hash using continued Egyptian fractions)",
  $.hash_flags =
        FLAG_HASH_SMALL_SEED      |
        FLAG_HASH_FLOATING_POINT  ,
  $.impl_flags =
        FLAG_IMPL_VERY_SLOW    |
        FLAG_IMPL_MULTIPLY     |
        FLAG_IMPL_DIVIDE       |
        FLAG_IMPL_LICENSE_MIT,
  $.bits = 64,
  $.verification_LE = 0x0605658C,
  $.verification_BE = 0x986CF0C5,
  $.hashfn_native = floppsyhash<false,false>,
  $.hashfn_bswap = floppsyhash<false,true>
);

REGISTER_HASH(floppsyhash_old,
  $.desc = "Floppsyhash (old version, fka \"tifuhash\")",
  $.hash_flags =
        FLAG_HASH_SMALL_SEED      |
        FLAG_HASH_FLOATING_POINT  ,
  $.impl_flags =
        FLAG_IMPL_VERY_SLOW    |
        FLAG_IMPL_MULTIPLY     |
        FLAG_IMPL_DIVIDE       |
        FLAG_IMPL_LICENSE_MIT,
  $.bits = 64,
  $.verification_LE = 0x644236D4,
  $.verification_BE = 0x7A3D2F7E,
  $.hashfn_native = floppsyhash<true,false>,
  $.hashfn_bswap = floppsyhash<true,true>
);
