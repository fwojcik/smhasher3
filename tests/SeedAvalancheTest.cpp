/*
 * SMHasher3
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (C) 2023       jason
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 *     Copyright (c) 2010-2012 Austin Appleby
 *     Copyright (c) 2019-2021 Reini Urban
 *     Copyright (c) 2020      Yann Collet
 *
 *     Permission is hereby granted, free of charge, to any person
 *     obtaining a copy of this software and associated documentation
 *     files (the "Software"), to deal in the Software without
 *     restriction, including without limitation the rights to use,
 *     copy, modify, merge, publish, distribute, sublicense, and/or
 *     sell copies of the Software, and to permit persons to whom the
 *     Software is furnished to do so, subject to the following
 *     conditions:
 *
 *     The above copyright notice and this permission notice shall be
 *     included in all copies or substantial portions of the Software.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *     HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *     WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *     FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *     OTHER DEALINGS IN THE SOFTWARE.
 */
#include "Platform.h"
#include "Hashinfo.h"
#include "TestGlobals.h"
#include "Random.h"
#include "Reporting.h"
#include "Histogram.h"
#include "Instantiate.h"
#include "VCode.h"

#include "SeedAvalancheTest.h"

#include <math.h>

#if defined(HAVE_THREADS)
  #include <atomic>
typedef std::atomic<unsigned> a_uint;
#else
typedef unsigned a_uint;
#endif

//-----------------------------------------------------------------------------
// Flipping a single bit of a seed should cause an "avalanche" of changes in
// the hash function's output. Ideally, each output bits should flip 50% of
// the time - if the probability of an output bit flipping is not 50%, that bit
// is "biased". Too much bias means that patterns applied to the input will
// cause "echoes" of the patterns in the output, which in turn can cause the
// hash function to fail to create an even, random distribution of hash values.

template <typename hashtype, unsigned seedbytes>
static void calcBiasRange( const HashInfo * hinfo, std::vector<uint32_t> & bins, const unsigned keybytes,
        const uint8_t * keys, const uint8_t * seeds, a_uint & irepp, const unsigned reps, const flags_t flags ) {
    const HashFn hash    = hinfo->hashFn(g_hashEndian);

    hashtype A, B;
    unsigned irep;
    seed_t   iseed;
    uint64_t baseseed = 0;

    while ((irep = irepp++) < reps) {
        if (REPORT(PROGRESS, flags)) {
            progressdots(irep, 0, reps - 1, 18);
        }

        const uint8_t * keyptr = &keys[keybytes * irep];
        memcpy(&baseseed, &seeds[seedbytes * irep], seedbytes);
        iseed = hinfo->getFixedSeed((seed_t)baseseed);

        seed_t hseed = hinfo->Seed(iseed, HashInfo::SEED_FORCED, 1);
        hash(keyptr, keybytes, hseed, &A);

        uint32_t * cursor = &bins[0];
        for (unsigned iBit = 0; iBit < 8 * seedbytes; iBit++) {
            iseed ^= UINT64_C(1) << iBit;
            hseed  = hinfo->Seed(iseed, HashInfo::SEED_FORCED, 1);
            hash(keyptr, keybytes, hseed, &B);
            iseed ^= UINT64_C(1) << iBit;

            B ^= A;

            cursor = HistogramHashBits(B, cursor);
        }
    }
}

//-----------------------------------------------------------------------------

template <typename hashtype, unsigned seedbits>
static bool SeedAvalancheImpl( const HashInfo * hinfo, const unsigned keybytes,
        const unsigned reps, flags_t flags ) {
    const unsigned seedbytes = seedbits / 8;
    const unsigned hashbits  = hashtype::bitlen;
    const unsigned arraysize = seedbits * hashbits;

    Rand r( {860319, keybytes} );
    enum RandSeqType seqtype = reps > r.seq_maxelem(SEQ_DIST_3, seedbytes) ? SEQ_DIST_2 : SEQ_DIST_3;
    RandSeq rs = r.get_seq(seqtype, seedbytes);

    printf("Testing %3d-byte keys, %6d reps", keybytes, reps);

    std::vector<uint8_t> keys( reps * keybytes );
    r.rand_n(&keys[0], reps * keybytes);
    addVCodeInput(&keys[0], reps * keybytes);

    std::vector<uint8_t> seeds( reps * seedbytes );
    rs.write(&seeds[0], 0, reps);
    addVCodeInput(&seeds[0], reps * seedbytes);

    a_uint irep( 0 );

    std::vector<std::vector<uint32_t>> bins( g_NCPU );
    for (unsigned i = 0; i < g_NCPU; i++) {
        bins[i].resize(arraysize);
    }

    if (g_NCPU == 1) {
        calcBiasRange<hashtype, seedbytes>(hinfo, bins[0], keybytes, &keys[0], &seeds[0], irep, reps, flags);
    } else {
#if defined(HAVE_THREADS)
        std::vector<std::thread> t(g_NCPU);
        for (unsigned i = 0; i < g_NCPU; i++) {
            t[i] = std::thread {
                calcBiasRange<hashtype, seedbytes>, hinfo, std::ref(bins[i]),
                keybytes, &keys[0], &seeds[0], std::ref(irep), reps, flags
            };
        }
        for (unsigned i = 0; i < g_NCPU; i++) {
            t[i].join();
        }
        for (unsigned i = 1; i < g_NCPU; i++) {
            for (unsigned b = 0; b < arraysize; b++) {
                bins[0][b] += bins[i][b];
            }
        }
#endif
    }

    //----------

    bool result = true;

    result &= ReportBias(&bins[0][0], reps, arraysize, hashbits, flags);

    recordTestResult(result, "SeedAvalanche", keybytes);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool SeedAvalancheTest( const HashInfo * hinfo, bool extra, flags_t flags ) {
    bool result   = true;

    printf("[[[ Seed Avalanche Tests ]]]\n\n");

    std::set<unsigned> keyBytesvec = { 4, 8, 16, 24, 32, 64, 128 };
    if (extra) {
        keyBytesvec.insert({ 3, 6, 12, 20, 28 });
    }

    if (hinfo->is32BitSeed()) {
        for (unsigned keyBytes: keyBytesvec) {
            result &= SeedAvalancheImpl<hashtype, 32>(hinfo, keyBytes, 300000, flags);
        }
    } else {
        for (unsigned keyBytes: keyBytesvec) {
            result &= SeedAvalancheImpl<hashtype, 64>(hinfo, keyBytes, 300000, flags);
        }
    }

    printf("\n%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(SeedAvalancheTest, HASHTYPELIST);
