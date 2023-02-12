/*
 * SMHasher3
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
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
#include "Analyze.h"
#include "Histogram.h"
#include "Instantiate.h"
#include "VCode.h"

#include "SeedAvalancheTest.h"

#include <math.h>

#if defined(HAVE_THREADS)
  #include <atomic>
typedef std::atomic<int> a_int;
#else
typedef int a_int;
#endif

//-----------------------------------------------------------------------------
// Flipping a single bit of a seed should cause an "avalanche" of changes in
// the hash function's output. Ideally, each output bits should flip 50% of
// the time - if the probability of an output bit flipping is not 50%, that bit
// is "biased". Too much bias means that patterns applied to the input will
// cause "echoes" of the patterns in the output, which in turn can cause the
// hash function to fail to create an even, random distribution of hash values.

template <typename hashtype, int seedbytes>
static void calcBiasRange( const HashInfo * hinfo, std::vector<uint32_t> & bins, const int keybytes,
        const uint8_t * inputs, a_int & irepp, const int reps, const bool verbose ) {
    const HashFn hash    = hinfo->hashFn(g_hashEndian);
    const int    keybits = keybytes * 8;

    hashtype A, B;
    int      irep;
    uint64_t iseed = 0;

    while ((irep = irepp++) < reps) {
        if (verbose) {
            progressdots(irep, 0, reps - 1, 10);
        }

        const uint8_t * bufptr = &inputs[(keybytes + seedbytes) * irep];
        memcpy(&iseed, bufptr + keybytes, seedbytes);
        seed_t hseed = hinfo->Seed(iseed, false);

        hash(bufptr, keybytes, hseed, &A);

        uint32_t * cursor = &bins[0];

        for (int iBit = 0; iBit < 8 * seedbytes; iBit++) {
            iseed ^= UINT64_C(1) << iBit;
            hseed  = hinfo->Seed(iseed, false);
            hash(bufptr, keybytes, hseed, &B);
            iseed ^= UINT64_C(1) << iBit;

            B ^= A;

            cursor = HistogramHashBits(B, cursor);
        }
    }
}

//-----------------------------------------------------------------------------

template <typename hashtype, int seedbits>
static bool SeedAvalancheImpl( const HashInfo * hinfo, const int keybytes,
        const int reps, bool drawDiagram, bool drawdots ) {
    Rand r( 48273 + keybytes );

    const int seedbytes = seedbits / 8;

    const int hashbytes = sizeof(hashtype);
    const int hashbits  = hashbytes * 8;

    const int arraysize = seedbits * hashbits;

    printf("Testing %4d-byte keys, %6d reps.......", keybytes, reps);

    std::vector<uint8_t> inputs( reps * (keybytes + seedbytes) );
    r.rand_p(&inputs[0], reps * (keybytes + seedbytes));
    addVCodeInput(&inputs[0], reps * (keybytes + seedbytes));

    a_int irep( 0 );

    std::vector<std::vector<uint32_t>> bins( g_NCPU );
    for (unsigned i = 0; i < g_NCPU; i++) {
        bins[i].resize(arraysize);
    }

    if (g_NCPU == 1) {
        calcBiasRange<hashtype, seedbytes>(hinfo, bins[0], keybytes, &inputs[0], irep, reps, drawdots);
    } else {
#if defined(HAVE_THREADS)
        std::thread t[g_NCPU];
        for (int i = 0; i < g_NCPU; i++) {
            t[i] = std::thread {
                calcBiasRange<hashtype, seedbytes>, hinfo, std::ref(bins[i]),
                keybytes, &inputs[0], std::ref(irep), reps, drawdots
            };
        }
        for (int i = 0; i < g_NCPU; i++) {
            t[i].join();
        }
        for (int i = 1; i < g_NCPU; i++) {
            for (int b = 0; b < arraysize; b++) {
                bins[0][b] += bins[i][b];
            }
        }
#endif
    }

    //----------

    bool result = true;

    result &= ReportBias(&bins[0][0], reps, arraysize, hashbits, drawDiagram);

    recordTestResult(result, "SeedAvalanche", keybytes);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool SeedAvalancheTest( const HashInfo * hinfo, const bool verbose, const bool extra ) {
    bool result   = true;
    bool drawdots = true; // .......... progress dots

    printf("[[[ Seed Avalanche Tests ]]]\n\n");

    std::set<int> keyBytesvec = { 4, 8, 16, 24, 32, 64, 128 };
    if (extra) {
        keyBytesvec.insert({ 3, 6, 12, 20, 28 });
    }

    if (hinfo->is32BitSeed()) {
        for (int keyBytes: keyBytesvec) {
            result &= SeedAvalancheImpl<hashtype, 32>(hinfo, keyBytes, 300000, verbose, drawdots);
        }
    } else {
        for (int keyBytes: keyBytesvec) {
            result &= SeedAvalancheImpl<hashtype, 64>(hinfo, keyBytes, 300000, verbose, drawdots);
        }
    }

    printf("\n%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(SeedAvalancheTest, HASHTYPELIST);
