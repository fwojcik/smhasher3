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
 *     Copyright (c) 2019      Yann Collet
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
#include "Stats.h" // for chooseUpToK
#include "Random.h"
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "DifferentialTest.h"

#include <map>
#include <math.h>

#if defined(HAVE_THREADS)
  #include <atomic>
typedef std::atomic<int> a_int;
#else
typedef int a_int;
#endif

//-----------------------------------------------------------------------------
// Sort through the differentials, ignoring collisions that only
// occured once (these could be false positives). If we find identical
// hash counts of 3 or more (2+ collisions), the differential test fails.

template <class keytype>
static bool ProcessDifferentials( std::map<keytype, uint32_t> & diffcounts, int reps, bool dumpCollisions ) {
    int totalcount = 0;
    int ignore     = 0;

    bool result    = true;

    if (diffcounts.size()) {
        for (std::pair<keytype, uint32_t> dc: diffcounts) {
            uint32_t count = dc.second;

            totalcount += count;

            if (count == 1) {
                ignore++;
            } else {
                result = false;

                if (dumpCollisions) {
                    double pct = 100 * (double(count) / double(reps));
                    dc.first.printbits("");
                    printf(" - %4.2f%%\n", pct);
                }
            }
        }
    }

    printf("%d total collisions, of which %d single collisions were ignored", totalcount, ignore);

    addVCodeResult(totalcount);
    addVCodeResult(ignore    );

    if (result == false) {
        printf(" !!!!!");
    }

    printf("\n\n");

    return result;
}

//-----------------------------------------------------------------------------
// Check all possible keybits-choose-N differentials for collisions, report
// ones that occur significantly more often than expected.

// Random collisions can happen with probability 1 in 2^32 - if we do more than
// 2^32 tests, we'll probably see some spurious random collisions, so don't report
// them.

template <bool recursemore, typename keytype, typename hashtype>
static void DiffTestRecurse( const HashFn hash, const seed_t seed, keytype & k1, keytype & k2, hashtype & h1,
        hashtype & h2, int start, int bitsleft, std::map<keytype, uint32_t> & diffcounts ) {
    const int bits = sizeof(keytype) * 8;

    assume(start < bits);
    for (int i = start; i < bits; i++) {
        keytype k2_prev = k2;

        k2.flipbit(i);

        bitsleft--;

        hash(&k2, sizeof(k2), seed, &h2);

        if (h1 == h2) {
            ++diffcounts[k1 ^ k2];
        }

        if (recursemore && likely((i + 1) < bits)) {
            if (bitsleft > 1) {
                DiffTestRecurse<true>(hash, seed, k1, k2, h1, h2, i + 1, bitsleft, diffcounts);
            } else {
                DiffTestRecurse<false>(hash, seed, k1, k2, h1, h2, i + 1, bitsleft, diffcounts);
            }
        }

        // k2.flipbit(i);
        k2 = k2_prev;
        bitsleft++;
    }
}

//-----------------------------------------------------------------------------

template <typename keytype, typename hashtype>
static void DiffTestImplThread( const HashFn hash, const seed_t seed, std::map<keytype, uint32_t> & diffcounts,
        const uint8_t * keys, int diffbits, a_int & irepp, const int reps ) {
    const int keybytes = sizeof(keytype);

    keytype  k1, k2;
    hashtype h1, h2;

    h1 = h2 = 0;

    int irep;
    while ((irep = irepp++) < reps) {
        progressdots(irep, 0, reps - 1, 10);

        memcpy(&k1, &keys[keybytes * irep], sizeof(k1));
        k2 = k1;

        hash(&k1, sizeof(k1), seed, (void *)&h1);

        DiffTestRecurse<true, keytype, hashtype>(hash, seed, k1, k2, h1, h2, 0, diffbits, diffcounts);
    }
}

//-----------------------------------------------------------------------------

template <typename keytype, typename hashtype>
static bool DiffTestImpl( HashFn hash, const seed_t seed, int diffbits, int reps, bool dumpCollisions ) {
    const int keybytes = sizeof(keytype);
    const int keybits  = sizeof(keytype ) * 8;
    const int hashbits = sizeof(hashtype) * 8;

    double diffcount   = chooseUpToK(keybits, diffbits);
    double testcount   = (diffcount * double(reps));
    double expected    = testcount / pow(2.0, double(hashbits));

    printf("Testing %0.f up-to-%d-bit differentials in %d-bit keys -> %d bit hashes.\n",
            diffcount, diffbits, keybits, hashbits);
    printf("%d reps, %0.f total tests, expecting %2.2f random collisions", reps, testcount, expected);

    Rand r( 100 );
    std::vector<uint8_t> keys( reps * keybytes );

    for (int i = 0; i < reps; i++) {
        r.rand_p(&keys[i * keybytes], keybytes);
    }
    addVCodeInput(&keys[0], reps * keybytes);

    a_int irep( 0 );

    std::vector<std::map<keytype, uint32_t>> diffcounts( g_NCPU );

    if ((g_NCPU == 1) || (reps < 10)) {
        DiffTestImplThread<keytype, hashtype>(hash, seed, diffcounts[0], &keys[0], diffbits, irep, reps);
    } else {
#if defined(HAVE_THREADS)
        std::thread t[g_NCPU];
        for (int i = 0; i < g_NCPU; i++) {
            t[i] = std::thread {
                DiffTestImplThread<keytype, hashtype>, hash, seed, std::ref(diffcounts[i]),
                &keys[0], diffbits, std::ref(irep), reps
            };
        }
        for (int i = 0; i < g_NCPU; i++) {
            t[i].join();
        }
        for (int i = 1; i < g_NCPU; i++) {
            for (std::pair<keytype, uint32_t> dc: diffcounts[i]) {
                diffcounts[0][dc.first] += dc.second;
            }
        }
#endif
    }

    for (std::pair<keytype, uint32_t> dc: diffcounts[0]) {
        addVCodeOutput(&dc.first , sizeof(keytype) );
        addVCodeOutput(&dc.second, sizeof(uint32_t));
    }

    printf("\n");

    bool result = true;

    result &= ProcessDifferentials(diffcounts[0], reps, dumpCollisions);

    recordTestResult(result, "Differential", diffbits);

    return result;
}

//----------------------------------------------------------------------------

template <typename hashtype>
bool DiffTest( const HashInfo * hinfo, const bool verbose, const bool extra ) {
    const HashFn hash           = hinfo->hashFn(g_hashEndian);
    bool         dumpCollisions = verbose;
    bool         result         = true;

    // Do fewer reps with slow or very bad hashes
    bool slowhash = hinfo->bits > 128 || hinfo->isSlow();
    int  reps     = hinfo->isMock() ? 2 : ((slowhash && !extra) ? 100 : 1000);

    printf("[[[ Diff 'Differential' Tests (deprecated) ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed);

    result &= DiffTestImpl<Blob< 64>, hashtype>(hash, seed, 5, reps, dumpCollisions);
    result &= DiffTestImpl<Blob<128>, hashtype>(hash, seed, 4, reps, dumpCollisions);
    result &= DiffTestImpl<Blob<256>, hashtype>(hash, seed, 3, reps, dumpCollisions);

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(DiffTest, HASHTYPELIST);
