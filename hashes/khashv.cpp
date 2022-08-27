/*
MIT License
Copyright (c) 2022 Keith-Cancel
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#include "Platform.h"
#include "Hashlib.h"
#include "Intrinsics.h"
#include "khashv/khashv.h"

//------------------------------------------------------------

static thread_local khashvSeed khashv_32_seed;
static thread_local khashvSeed khashv_64_seed;

static uintptr_t khashv32_init_seed(const seed_t seed ) {
    khashv_prep_seed64(&khashv_32_seed, (uint64_t)seed);
    return (uintptr_t)(&khashv_32_seed);
}

static uintptr_t khashv64_init_seed(const seed_t seed ) {
    khashv_prep_seed64(&khashv_64_seed, (uint64_t)seed);
    return (uintptr_t)(&khashv_64_seed);
}

static void khashv32_test(const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t hash = khashv32((khashvSeed*)(uintptr_t)seed, (const uint8_t*)in, len);
    hash = COND_BSWAP(hash, isBE());
    PUT_U32<false>(hash, (uint8_t *)out, 0);
}

static void khashv64_test(const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t hash = khashv64((khashvSeed*)(uintptr_t)seed, (const uint8_t*)in, len);
    hash = COND_BSWAP(hash, isBE());
    PUT_U64<false>(hash, (uint8_t *)out, 0);
}

REGISTER_FAMILY(khashv,
   $.src_url    = "https://github.com/Keith-Cancel/k-hashv",
   $.src_status = HashFamilyInfo::SRC_ACTIVE
 );

REGISTER_HASH(khashv_32,
   $.desc       = "K-Hashv vectorizable, 32-bit output",
   $.hash_flags =
        FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
        FLAG_IMPL_CANONICAL_BOTH |
        FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0xB69DF8EB,
   $.verification_BE = 0xB69DF8EB,
   $.seedfn          = khashv32_init_seed,
   $.hashfn_native   = khashv32_test,
   $.hashfn_bswap    = khashv32_test
);

REGISTER_HASH(khashv_64,
    $.desc       = "K-Hashv vectorizable, 64-bit output",
    $.hash_flags =
            FLAG_HASH_ENDIAN_INDEPENDENT,
    $.impl_flags =
            FLAG_IMPL_CANONICAL_BOTH |
            FLAG_IMPL_LICENSE_MIT,
    $.bits = 64,
    $.verification_LE = 0xA6B7E55B,
    // Should be the same on BE systems. It just won't be vectorized with GCCs
    // vectorization built-ins since that code has and ifdef on endianess.
    $.verification_BE = 0xA6B7E55B,
    $.seedfn          = khashv64_init_seed,
    $.hashfn_native   = khashv64_test,
    $.hashfn_bswap    = khashv64_test
);
