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
// BIC test
//
// This test checks to see if hash output bits tend to change independently or not,
// depending on the input bits. For each possible combination of output bits, it
// hashes a random inputs, flips a single bit of the input, hashes that, and sees
// which bits changed. This is repeated a number of times, and is also repeated for
// each keybit. A new set of test keys is randomly generated for each (keybit, output
// bit 1, output bit 2) tuple. The test then looks for whichever of those tuples had
// the highest deviation from expected values.
//
// Note that these expected values are not necessarily exactly equal to the test
// count divided by 4. This is because some individual bits may, by chance and/or due
// to bias in the hash, not be split exactly evenly across 0 and 1 outputs. The
// chi-square test of independence handles this explicitly.
//
// To be efficient, this implementation counts each bit pair possibility in neat but
// confusing ways. Each (key bit, output bit A, output bit B) tuple needs, in some
// sense, 4 numbers. These numbers form a table which looks like:
//
//   -------------------------------------
//   | bit x   changed | bit x unchanged |
//   | bit y   changed | bit y   changed |
//   |      [11]       |      [01]       |
//   -------------------------------------
//   | bit x   changed | bit x unchanged |
//   | bit y unchanged | bit y unchanged |
//   |      [10]       |      [00]       |
//   -------------------------------------
//
// Instead of keeping 4 integers per tuple, this implementation only keeps 1: the
// value of the '[11]' box. But it also keeps track of one number per (key bit,
// output bit) tuple, which is how many times that bit changed for the given
// keybit. These 2 sets of numbers take up less space than the full table would,
// they are much cheaper to compute than the full table would be, and they can be
// used to reconstruct the values in each of those 4 boxes in the full table.
//
// The value of box [11] is the number of times bits x and y changed together.
// These values make up the andcount[] vector.
//
// The sum of boxes [11] and [01] is the number of times bit y changed.
// The sum of boxes [11] and [10] is the number of times bit x changed.
// These values make up the popcount[] vector.
//
// The sum of all the boxes is the number of tests, which is a known constant.
//
// The value in box [11] is andcount[x, y].
// The value in box [10] is therefore popcount[x] - andcount[x, y].
// The value in box [01] is therefore popcount[y] - andcount[x, y].
// The value in box [00] is therefore testcount - box[11] - box[10] - box[01].
//
// The technically-correct value for hashbitpairs is "hashbits / 2 * (hashbits - 1)",
// but the formulations currently used allow for space between rows of data in the
// andcount vector, which will allow for threads to separate themselves using the
// keybit index alone, since it won't ever share a cacheline with data from a
// different keybit.

template <typename hashtype>
static void BicTestBatch( HashFn hash, const seed_t seed, size_t reps, a_int & ikeybit, size_t batch_size,
        size_t keybytes, uint32_t * popcount0, uint32_t * andcount0 ) {
    const size_t keybits      = keybytes * 8;
    const size_t hashbytes    = sizeof(hashtype);
    const size_t hashbits     = hashbytes * 8;
    const size_t hashbitpairs = hashbits / 2 * hashbits;
    hashtype     h1, h2;
    size_t       startkeybit;
    Rand         r;

    std::vector<uint8_t> keys( keybytes * reps );

    while ((startkeybit = FETCH_ADD(ikeybit, batch_size)) < keybits) {
        const size_t stopkeybit = std::min(startkeybit + batch_size, keybits);

        for (size_t keybit = startkeybit; keybit < stopkeybit; keybit++) {
            uint32_t * pop_cursor_base = &popcount0[keybit * hashbits    ];
            uint32_t * and_cursor_base = &andcount0[keybit * hashbitpairs];
            uint8_t  *      key_cursor = &keys[0];

            progressdots(keybit, 0, keybits - 1, 10);

            r.reseed((uint64_t)(1798473 + keybytes * 8193 + keybit));
            r.rand_p(key_cursor, keybytes * reps);

            for (size_t irep = 0; irep < reps; irep++) {
                uint32_t * pop_cursor = pop_cursor_base;
                uint32_t * and_cursor = and_cursor_base;

                ExtBlob key( key_cursor, keybytes );
                hash(key, keybytes, seed, &h1);
                key.flipbit(keybit);
                hash(key, keybytes, seed, &h2);
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
static bool BicTestImpl( HashFn hash, const seed_t seed, const size_t keybytes,
        const size_t reps, bool verbose = false ) {
    const size_t keybits      = keybytes * 8;
    const size_t hashbytes    = sizeof(hashtype);
    const size_t hashbits     = hashbytes * 8;
    const size_t hashbitpairs = hashbits / 2 * hashbits;

    printf("Testing %4zd-byte keys, %7zd reps  ", keybytes, reps);

    // The andcount array needs 1 element as a buffer due to how
    // HistogramHashBits accesses memory prior to the cursor.
    std::vector<uint32_t> popcount( keybits * hashbits        , 0 );
    std::vector<uint32_t> andcount( keybits * hashbitpairs + 1, 0 );
    a_int ikeybit( 0 );

    if (g_NCPU == 1) {
        BicTestBatch<hashtype>(hash, seed, reps, ikeybit, keybits, keybytes, &popcount[0], &andcount[1]);
    } else {
#if defined(HAVE_THREADS)
        // Giving each thread a batch size of 2 keybits is consistently best on my box
        std::thread t[g_NCPU];
        for (int i = 0; i < g_NCPU; i++) {
            t[i] = std::thread {
                BicTestBatch<hashtype>, hash, seed, reps, std::ref(ikeybit),
                2, keybytes, &popcount[0], &andcount[1]
            };
        }
        for (int i = 0; i < g_NCPU; i++) {
            t[i].join();
        }
#endif
    }

    bool result = ReportChiSqIndep(&popcount[0], &andcount[1], keybits, hashbits, reps, verbose);

    recordTestResult(result, "BIC", keybytes);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool BicTest( const HashInfo * hinfo, const bool verbose, const bool extra ) {
    const HashFn hash   = hinfo->hashFn(g_hashEndian);
    size_t       reps   = (hinfo->bits > 128 || hinfo->isVerySlow()) ? 100000 : 600000;
    bool         result = true;

    printf("[[[ BIC 'Bit Independence Criteria' Tests ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed, false, 3);

    // std::set<size_t> keylens = { 3, 6, 11, 15, 16, 18, 31, 52, 80, 200 };
    // std::set<size_t> keylens = { 3, 6, 11, 15, 16, 18, 28, 31, 52, 67, 80, 200 };
    std::set<size_t> keylens = { 3, 8, 11, 15 };
    if (extra && !hinfo->isSlow()) {
        keylens.insert({ 4, 6, 28, 52 });
    }
    for (const auto keylen: keylens) {
        if (keylen <= 16) {
            result &= BicTestImpl<hashtype>(hash, seed, keylen, reps * 2, verbose);
        } else {
            result &= BicTestImpl<hashtype>(hash, seed, keylen, reps, verbose);
        }
    }

    printf("\n%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(BicTest, HASHTYPELIST);
