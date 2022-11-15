/*
 * Discohash (aka BEBB4185)
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2020-2021 Reini Urban
 * Copyright (c) 2020 Cris Stringfellow
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

static const uint32_t STATE     = 32; // Must be divisible by 8
static const uint32_t STATE64   = STATE >> 3;
static const uint32_t STATEM    = STATE - 1;
static const uint32_t HSTATE64M = (STATE64 >> 1) - 1;
static const uint32_t STATE64M  = STATE64 - 1;
static const uint64_t P         = UINT64_C(  0xFFFFFFFFFFFFFFFF) - 58;
static const uint64_t Q         = UINT64_C(13166748625691186689);

//--------
// State mix function
static FORCE_INLINE uint8_t ROTR8( uint8_t v, int n ) {
    n = n & 7U;
    if (n) {
        v = (v >> n) | (v << (8 - n));
    }
    return v;
}

static FORCE_INLINE void mix( uint64_t * ds, const uint32_t A ) {
    const uint32_t B = A + 1;

    ds[A] *= P;
    ds[A]  = ROTR64(ds[A], 23);
    ds[A] *= Q;
    // ds[A] = ROTR64(ds[A], 23);

    ds[B] ^= ds[A];

    ds[B] *= P;
    ds[B]  = ROTR64(ds[B], 23);
    ds[B] *= Q;
    // ds[B] = ROTR64(ds[B], 23);
}

//---------
// Hash round function

// The reread parameter is needed because sometimes the same array is
// read-from and written-to via different pointers (m8 and ds), but it
// usually isn't. This lets those cases avoid a possible bswap().
//
// The oldver parameter "fixes" a possibly-unintentional behavior
// change, details of which are below.
template <bool bswap, bool reread, bool oldver>
static FORCE_INLINE void round( uint64_t * ds, const uint8_t * m8, uint32_t len ) {
    uint32_t index;
    uint32_t sindex   = 0;
    uint32_t Len      = len >> 3;
    uint64_t counter  = UINT64_C(0xfaccadaccad09997);
    uint8_t  counter8 = 137;

    // #pragma omp parallel for
    for (index = 0; index < Len; index++) {
        uint64_t blk = GET_U64<bswap>(m8, index * 8);
        ds[sindex] += ROTR64(blk + index + counter + 1, 23);
        if (reread) { blk = GET_U64<bswap>(m8, index * 8); }
        counter    += ~blk + 1;
        if (sindex == HSTATE64M) {
            mix(ds, 0);
        } else if (sindex == STATE64M) {
            mix(ds, 2);
            sindex = -1;
        }
        sindex++;
    }

    mix(ds, 1);

    // In commit 73bfb9e31e68a31dc49ba53dbd33ca72e4c931a8 titled
    // "Added pragmas and changed loop format to fit omp
    // requirements." the author moved the initialization of index
    // into the for loop below. This also changed the way sindex is
    // calculated, as index was no longer modified before sindex was
    // set to be index&(STATEM). This appears to be unintentional, so
    // both the original "old" behavior and the latest "new" behavior
    // are implemented here.
    Len = index << 3;
    if (oldver) {
        sindex = Len & (STATEM);
    } else {
        sindex = index & (STATEM);
    }

    // #pragma omp parallel for
    for (index = Len; index < len; index++) {
        ((uint8_t *)ds)[bswap ? (sindex ^ 7) : sindex] += ROTR8(m8[index] + index + counter8 + 1, 23);
        // I also wonder if this was intended to be m8[index], to
        // mirror the primary 8-byte loop above...
        //
        // Regardless, m8[sindex] can never read past EOB here, which
        // is the important thing. This is because the maximum value
        // of sindex is (len & ~7) if oldver == true, and (len >> 3)
        // if oldver == false.
        counter8 += ~m8[sindex] + 1;
        mix(ds, index % STATE64M);
        if (sindex >= STATEM) {
            sindex = -1;
        }
        sindex++;
    }

    mix(ds, 0);
    mix(ds, 1);
    mix(ds, 2);
}

//---------
// main hash function

template <uint32_t hashsize, bool bswap, bool oldver>
static void BEBB4185( const void * in, const size_t len, const seed_t seed, void * out ) {
    const uint8_t * key8Arr = (const uint8_t *)in;
    uint8_t *       out8    = (uint8_t *      )out;
    uint32_t        seedbuf[4];

    if (len >= UINT32_C(0xffffffff)) { return; }

    // the cali number from the Matrix (1999)
    uint32_t seed32 = seed;
    if (!bswap) {
        seedbuf[0]  = 0xc5550690;
        seedbuf[0] -= seed32;
        seedbuf[1]  =   1 + seed32;
        seedbuf[2]  = ~(1 - seed32);
        seedbuf[3]  =  (1 + seed32) * 0xf00dacca;
    } else {
        seedbuf[1]  = 0xc5550690;
        seedbuf[1] -= seed32;
        seedbuf[0]  =   1 + seed32;
        seedbuf[3]  = ~(1 - seed32);
        seedbuf[2]  =  (1 + seed32) * 0xf00dacca;
    }

    uint64_t ds[STATE / 8];
    // nothing up my sleeve
    ds[0] = UINT64_C(0x123456789abcdef0);
    ds[1] = UINT64_C(0x0fedcba987654321);
    ds[2] = UINT64_C(0xaccadacca80081e5);
    ds[3] = UINT64_C(0xf00baaf00f00baaa);

    // The mixing in of the seed array does not need bswap set, since
    // the if() above will order the bytes correctly for that
    // variable. The mixing of the state with itself also doesn't need
    // bswap set, because the endianness of the data will naturally
    // always match the endianness of the ds[] values.
    round<bswap, false, oldver>(ds, key8Arr           , (uint32_t)len);
    round<false, false, oldver>(ds, (uint8_t *)seedbuf,            16);
    round<false,  true, oldver>(ds, (uint8_t *)ds     , STATE        );

    /*
     *
     * printf("ds = %#018" PRIx64 " %#018" PRIx64 " %#018" PRIx64 " %#018" PRIx64 "\n",
     * ds[0], ds[1], ds[2], ds[3] );
     *
     */

    uint64_t h[STATE64] = { 0 };

    h[0]  = ds[2];
    h[1]  = ds[3];

    h[0] += h [1];

    if (hashsize == 128) {
        h[2]  = ds[0];
        h[3]  = ds[1];

        h[2] += h [3];
        PUT_U64<bswap>(h[2], out8, 8);
    }
    if (hashsize >= 64) {
        PUT_U64<bswap>(h[0], out8, 0);
    }
}

REGISTER_FAMILY(discohash,
   $.src_url    = "https://github.com/crisdosyago/discohash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

// Yes, none of these have any bad seeds! The state was inadvertently
// shared across threads, giving bad test results. It has been changed to
// be on the stack instead.
REGISTER_HASH(Discohash__old,
   $.desc       = "Discohash (aka BEBB4185) prior version",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_SLOW             |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xBEBB4185,
   $.verification_BE = 0x4B5579AD,
   $.hashfn_native   = BEBB4185<64, false, true>,
   $.hashfn_bswap    = BEBB4185<64, true, true>
 );

REGISTER_HASH(Discohash,
   $.desc       = "Discohash (aka BEBB4185)",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_SLOW             |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 64,
   $.verification_LE = 0xFBA72400,
   $.verification_BE = 0x286DD52C,
   $.hashfn_native   = BEBB4185<64, false, false>,
   $.hashfn_bswap    = BEBB4185<64, true, false>
 );

REGISTER_HASH(Discohash_128__old,
   $.desc       = "Discohash (aka BEBB4185) prior version",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_SLOW             |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x000ED2A6,
   $.verification_BE = 0x3110ECFA,
   $.hashfn_native   = BEBB4185<128, false, true>,
   $.hashfn_bswap    = BEBB4185<128, true, true>
 );

REGISTER_HASH(Discohash_128,
   $.desc       = "Discohash (aka BEBB4185)",
   $.hash_flags =
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_64   |
         FLAG_IMPL_ROTATE           |
         FLAG_IMPL_SLOW             |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0x231868B1,
   $.verification_BE = 0xEB4228F3,
   $.hashfn_native   = BEBB4185<128, false, false>,
   $.hashfn_bswap    = BEBB4185<128, true, false>
 );
