/*
 * DoNothing hash
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

static void DoNothingHash(const void * in, const size_t len, const seed_t seed, void * out) {
}

REGISTER_FAMILY(donothing);

REGISTER_HASH(donothing32,
  $.desc = "Do-Nothing function (measure call overhead)",
  $.hash_flags = FLAG_HASH_MOCK,
  $.impl_flags = FLAG_IMPL_LICENSE_MIT,
  $.bits = 32,
  $.verification = 0x0,
  $.hashfn_native = DoNothingHash,
  $.hashfn_bswap = DoNothingHash
);

REGISTER_HASH(donothing64,
  $.desc = "Do-Nothing function (measure call overhead)",
  $.hash_flags = FLAG_HASH_MOCK,
  $.impl_flags = FLAG_IMPL_LICENSE_MIT,
  $.bits = 64,
  $.verification = 0x0,
  $.hashfn_native = DoNothingHash,
  $.hashfn_bswap = DoNothingHash
);

REGISTER_HASH(donothing128,
  $.desc = "Do-Nothing function (measure call overhead)",
  $.hash_flags = FLAG_HASH_MOCK,
  $.impl_flags = FLAG_IMPL_LICENSE_MIT,
  $.bits = 128,
  $.verification = 0x0,
  $.hashfn_native = DoNothingHash,
  $.hashfn_bswap = DoNothingHash
);
