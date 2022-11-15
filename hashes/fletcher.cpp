/*
 * Fletcher's checksum-based hashes
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2019-2021 Reini Urban
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

//------------------------------------------------------------
// Hash based on 1 lane of ZFS's fletcher2 checksum. ZFS is always
// guaranteed blocks of multiples-of-128 bytes for checksums, so it
// does two of these on alternate sets of words.
template <bool fullhash, bool bswap>
static void fletcher2( const uint8_t * key, size_t len, uint64_t seed, uint8_t * out ) {
    const uint8_t * const endc = key + len;
    const uint8_t * const endw = key + (len & ~7);
    // Legacy homegrown seeding for SMHasher3
    uint64_t A = seed, B = 0;

    for (; key < endw; key += 8) {
        A += GET_U64<bswap>(key, 0);
        B += A;
    }
    if (len & 7) {
        for (; key < endc; key++) {
            A += *key;
            B += A;
        }
    }
    PUT_U64<bswap>(B, out, 0);
    if (fullhash) {
        PUT_U64<bswap>(A, out, 8);
    }
}

// Hash based on 1 lane of ZFS's fletcher4 checksum. ZFS is always
// guaranteed blocks of multiples-of-128 bytes for checksums, so it
// does two of these on alternate sets of words.
template <bool fullhash, bool bswap>
static void fletcher4( const uint8_t * key, size_t len, uint64_t seed, uint8_t * out ) {
    const uint8_t * const endc = key + len;
    const uint8_t * const endw = key + (len & ~3);
    // Legacy homegrown seeding for SMHasher3
    uint64_t A = seed, B = 0, C = 0, D = 0;

    for (; key < endw; key += 4) {
        A += GET_U32<bswap>(key, 0);
        B += A;
        C += B;
        D += C;
    }
    if (len & 3) {
        for (; key < endc; key++) {
            A += *key;
            B += A;
            C += B;
            D += C;
        }
    }
    PUT_U64<bswap>(D, out, 0);
    if (fullhash) {
        PUT_U64<bswap>(A, out,  8);
        PUT_U64<bswap>(B, out, 16);
        PUT_U64<bswap>(C, out, 24);
    }
}

//------------------------------------------------------------
// The actual Fletcher's checksum algorithm on 32 bits and 64
// bits. Note that the modulo reductions are NOT simple AND-masks or
// overflow operations. This is important to the mathematical
// operation of the checksum, and it was excluded from the ZFS
// implementations.
template <bool bswap>
static uint32_t fletcher32( const uint8_t * key, size_t len, uint64_t seed ) {
    // Legacy homegrown seeding for SMHasher3
    uint32_t c0 = (uint32_t)(seed + len), c1 = (uint32_t)((seed >> 32) + len);

    while (len > 1) {
        // 360 16-bit blocks can be processed without the possibility
        // of c0 or c1 overflowing.
        size_t blklen = (len > 720) ? 720 : (len & ~1);
        const uint8_t * const endw = key + blklen;
        for (; key < endw; key += 2) {
            c0 += GET_U16<bswap>(key, 0);
            c1 += c0;
        }
        len -= blklen;
        c0   = c0 % 65535;
        c1   = c1 % 65535;
    }
    if (len) {
        c0 += *key;
        c1 += c0;
        c0  = c0 % 65535;
        c1  = c1 % 65535;
    }

    return c1 << 16 | c0;
}

template <bool bswap>
static uint64_t fletcher64( const uint8_t * key, size_t len, uint64_t seed ) {
    // Legacy homegrown seeding for SMHasher3
    uint64_t c0 = seed + len, c1 = seed + len;

    while (len > 3) {
        // 92681 32-bit blocks can be processed without the possibility
        // of c0 or c1 overflowing.
        size_t blklen = (len > 370724) ? 370724 : (len & ~3);
        const uint8_t * const endw = key + blklen;
        for (; key < endw; key += 4) {
            c0 += GET_U32<bswap>(key, 0);
            c1 += c0;
        }
        len -= blklen;
        c0   = c0 % 4294967295;
        c1   = c1 % 4294967295;
    }
    if (len > 0) {
        do {
            c0 += *key++;
            c1 += c0;
            len--;
        } while (len > 0);
        c0 = c0 % 4294967295;
        c1 = c1 % 4294967295;
    }

    return c1 << 32 | c0;
}

//------------------------------------------------------------
template <bool bswap>
static void fletcher2_64( const void * in, const size_t len, const seed_t seed, void * out ) {
    fletcher2<false, bswap>((const uint8_t *)in, len, (uint64_t)seed, (uint8_t *)out);
}

template <bool bswap>
static void fletcher2_128( const void * in, const size_t len, const seed_t seed, void * out ) {
    fletcher2<true, bswap>((const uint8_t *)in, len, (uint64_t)seed, (uint8_t *)out);
}

template <bool bswap>
static void fletcher4_64( const void * in, const size_t len, const seed_t seed, void * out ) {
    fletcher4<false, bswap>((const uint8_t *)in, len, (uint64_t)seed, (uint8_t *)out);
}

template <bool bswap>
static void fletcher4_256( const void * in, const size_t len, const seed_t seed, void * out ) {
    fletcher4<true, bswap>((const uint8_t *)in, len, (uint64_t)seed, (uint8_t *)out);
}

template <bool bswap>
static void fletcher32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t h = fletcher32<bswap>((const uint8_t *)in, len, (uint64_t)seed);

    PUT_U32<bswap>(h, (uint8_t *)out, 0);
}

template <bool bswap>
static void fletcher64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t h = fletcher64<bswap>((const uint8_t *)in, len, (uint64_t)seed);

    PUT_U64<bswap>(h, (uint8_t *)out, 0);
}

//------------------------------------------------------------
REGISTER_FAMILY(fletcher,
   $.src_url    = "https://github.com/rurban/smhasher/blob/master/Hashes.cpp",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(fletcher2__64,
   $.desc       = "fletcher2 from ZFS (one lane, best 64 bits)",
   $.sort_order = 10,
   $.hash_flags =
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x890767C0,
   $.verification_BE = 0x8FC6FD34,
   $.hashfn_native   = fletcher2_64<false>,
   $.hashfn_bswap    = fletcher2_64<true>,
   $.badseeddesc     = "All seeds collide for keys of all zero for some lengths (e.g. 3 bytes vs. 6, 15 vs. 18"
 );

REGISTER_HASH(fletcher2,
   $.desc       = "fletcher2 from ZFS (one lane, all 128 bits)",
   $.hash_flags =
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x70FD3480,
   $.verification_BE = 0xFC346DA5,
   $.hashfn_native   = fletcher2_128<false>,
   $.hashfn_bswap    = fletcher2_128<true>,
   $.badseeddesc     = "All seeds collide for keys of all zero for some lengths (e.g. 3 bytes vs. 6, 15 vs. 18)"
 );

REGISTER_HASH(fletcher4__64,
   $.desc       = "fletcher4 from ZFS (one lane, best 64 bits)",
   $.sort_order = 20,
   $.hash_flags =
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x47660EB7,
   $.verification_BE = 0xA502FD23,
   $.hashfn_native   = fletcher4_64<false>,
   $.hashfn_bswap    = fletcher4_64<true>,
   $.badseeddesc     = "All seeds collide for keys of all zero for some lengths (e.g. 3 bytes vs. 6, 15 vs. 18)"
 );

REGISTER_HASH(fletcher4,
   $.desc       = "fletcher4 from ZFS (one lane, all 256 bits)",
   $.hash_flags =
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_SANITY_FAILS |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 256,
   $.verification_LE = 0x1F1358EF,
   $.verification_BE = 0x94EECE23,
   $.hashfn_native   = fletcher4_256<false>,
   $.hashfn_bswap    = fletcher4_256<true>,
   $.badseeddesc     = "All seeds collide for keys of all zero for some lengths (e.g. 3 bytes vs. 6, 15 vs. 18)"
 );

REGISTER_HASH(Fletcher_32,
   $.desc       = "Fletcher's checksum, 32-bit, IV == len",
   $.hash_flags =
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_MODULUS      |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 32,
   $.verification_LE = 0x4FE14644,
   $.verification_BE = 0x05853CCE,
   $.hashfn_native   = fletcher32<false>,
   $.hashfn_bswap    = fletcher32<true>
 );

REGISTER_HASH(Fletcher_64,
   $.desc       = "Fletcher's checksum, 64-bit, IV == len",
   $.sort_order = 0,
   $.hash_flags =
         FLAG_HASH_NO_SEED,
   $.impl_flags =
         FLAG_IMPL_MODULUS      |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0x2E16C3AA,
   $.verification_BE = 0x1E644927,
   $.hashfn_native   = fletcher64<false>,
   $.hashfn_bswap    = fletcher64<true>,
   $.badseeddesc     = "Many seeds collide for keys of all 0x00 versus all 0xFF"
 );
