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

#include "BitIndependenceTest.h"

#include <math.h>

#if defined(HAVE_THREADS)
  #include <atomic>
  #define FETCH_ADD(v, n) v.fetch_add(n)
typedef std::atomic<int> a_int;
#else
  #define FETCH_ADD(v, n) ((v += n) - n)
typedef int a_int;
#endif

//-----------------------------------------------------------------------------
// Seed BIC test
//
// See BitIndependenceTest.cpp for many comments on how the
// math/recordkeeping here works.

template <typename hashtype>
static void BicTestBatch( const HashInfo * hinfo, size_t reps, a_int & iseedbit, size_t batch_size,
        size_t keybytes, uint32_t * popcount0, uint32_t * andcount0 ) {
    const HashFn hash         = hinfo->hashFn(g_hashEndian);
    const size_t seedbits     = hinfo->is32BitSeed() ? 32 : 64;
    const size_t hashbytes    = sizeof(hashtype);
    const size_t hashbits     = hashbytes * 8;
    const size_t hashbitpairs = hashbits / 2 * hashbits;
    hashtype     h1, h2;
    size_t       startseedbit;
    Rand         r;

    std::vector<uint8_t> keys( keybytes * reps );

    while ((startseedbit = FETCH_ADD(iseedbit, batch_size)) < seedbits) {
        const size_t stopseedbit = std::min(startseedbit + batch_size, seedbits);

        for (size_t seedbit = startseedbit; seedbit < stopseedbit; seedbit++) {
            uint32_t * pop_cursor_base = &popcount0[seedbit * hashbits    ];
            uint32_t * and_cursor_base = &andcount0[seedbit * hashbitpairs];
            uint8_t *  key_cursor      = &keys[0];

            progressdots(seedbit, 0, seedbits - 1, 10);

            r.reseed((uint64_t)(4557191 + keybytes * 8193 + seedbit));
            r.rand_p(key_cursor, keybytes * reps);

            for (size_t irep = 0; irep < reps; irep++) {
                uint32_t * pop_cursor = pop_cursor_base;
                uint32_t * and_cursor = and_cursor_base;
                ExtBlob    key( key_cursor, keybytes );
                uint64_t   iseed;
                seed_t     hseed;

                r.rand_p(&iseed, sizeof(iseed));
                hseed  = hinfo->Seed(iseed, false, 3);
                hash(key, keybytes, hseed, &h1);

                iseed ^= UINT64_C(1) << seedbit;
                hseed  = hinfo->Seed(iseed, false, 3);
                hash(key, keybytes, hseed, &h2);

                key_cursor += keybytes;

                h2 = h1 ^ h2;

                // First count how often each output bit changes
                pop_cursor = HistogramHashBits(h2, pop_cursor);

                // Then count how often each pair of output bits changed together
                for (size_t out1 = 0; out1 < hashbits - 1; out1++) {
                    if (h2.getbit(out1) == 0) {
                        and_cursor += hashbits - 1 - out1;
                        continue;
                    }
                    and_cursor = HistogramHashBits(h2, and_cursor, out1 + 1);
                }
            }
        }
    }
}

template <typename hashtype>
static bool BicTestImpl( const HashInfo * hinfo, const size_t keybytes, const size_t reps, bool verbose = false ) {
    const size_t hashbytes    = sizeof(hashtype);
    const size_t hashbits     = hashbytes * 8;
    const size_t hashbitpairs = hashbits / 2 * hashbits;
    const size_t seedbits     = hinfo->is32BitSeed() ? 32 : 64;

    printf("Testing %4zd-byte keys, %7zd reps  ", keybytes, reps);

    // The andcount array needs 1 element as a buffer due to how
    // HistogramHashBits accesses memory prior to the cursor.
    std::vector<uint32_t> popcount( seedbits * hashbits        , 0 );
    std::vector<uint32_t> andcount( seedbits * hashbitpairs + 1, 0 );
    a_int iseedbit( 0 );

    if (g_NCPU == 1) {
        BicTestBatch<hashtype>(hinfo, reps, iseedbit, seedbits, keybytes, &popcount[0], &andcount[1]);
    } else {
#if defined(HAVE_THREADS)
        // Giving each thread a batch size of 2 seedbits is consistently best on my box
        std::thread t[g_NCPU];
        for (int i = 0; i < g_NCPU; i++) {
            t[i] = std::thread {
                BicTestBatch<hashtype>, hinfo, reps, std::ref(iseedbit),
                2, keybytes, &popcount[0], &andcount[1]
            };
        }
        for (int i = 0; i < g_NCPU; i++) {
            t[i].join();
        }
#endif
    }

    bool result = ReportChiSqIndep(&popcount[0], &andcount[1], seedbits, hashbits, reps, verbose);

    recordTestResult(result, "SeedBIC", keybytes);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool SeedBicTest( const HashInfo * hinfo, const bool verbose, const bool extra ) {
    size_t reps   = (hinfo->bits > 128 || hinfo->isVerySlow()) ? 100000 : 600000;
    bool   result = true;

    printf("[[[ Seed 'Bit Independence Criteria' Tests ]]]\n\n");

    // std::set<size_t> keylens = { 3, 4, 5, 6, 7, 8, 32, 128, 1024 };
    // std::set<size_t> keylens = { 3, 4, 6, 7, 8, 11, 15, 28, 52, 256, 1024 };
    std::set<size_t> keylens = { 3, 8, 11, 15 };
    if (extra && !hinfo->isSlow()) {
        keylens.insert({ 4, 6, 28, 52, 1024 });
    }
    for (const auto keylen: keylens) {
        if (keylen <= 16) {
            result &= BicTestImpl<hashtype>(hinfo, keylen, reps * 2, verbose);
        } else {
            result &= BicTestImpl<hashtype>(hinfo, keylen, reps, verbose);
        }
    }

    printf("\n%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(SeedBicTest, HASHTYPELIST);
