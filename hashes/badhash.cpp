/*
 * BadHash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2014-2021 Reini Urban
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

template < bool bswap >
void BadHash(const void * in, const size_t len, const seed_t seed, void * out) {
    const uint8_t *       data = (const uint8_t *)in;
    const uint8_t * const end  = &data[len];
    uint32_t h                 = seed;

    while (data < end) {
        h ^= h >> 3;
        h ^= h << 5;
        h ^= *data++;
    }

    h = COND_BSWAP(h, bswap);
    memcpy(out, &h, sizeof(h));
}

REGISTER_FAMILY(badhash);

REGISTER_HASH(badhash,
  $.desc = "very simple XOR shift",
  $.hash_flags = FLAG_HASH_MOCK,
  $.impl_flags = FLAG_IMPL_LICENSE_MIT,
  $.bits = 32,
  $.verification_LE = 0xAB432E23,
  $.verification_BE = 0x241F49BE,
  $.hashfn_native = BadHash<false>,
  $.hashfn_bswap = BadHash<true>,
  $.seedfixfn = excludeBadseeds,
  $.badseeds = { 0 },
  $.sort_order = 20
);
