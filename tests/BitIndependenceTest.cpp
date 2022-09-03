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
#include "Stats.h"
#include "Random.h"
#include "Analyze.h"
#include "Histogram.h"
#include "Instantiate.h"
#include "VCode.h"

#include "BitIndependenceTest.h"

#include <math.h>

//-----------------------------------------------------------------------------
// BIC test
//
// The choices for VCode inputs may seem strange here, but they were
// chosen in anticipation of threading this test.

template <typename hashtype>
static bool BicTest4( HashFn hash, const seed_t seed, const size_t keybytes, const size_t reps, bool verbose = false ) {
    const size_t keybits      = keybytes * 8;
    const size_t hashbytes    = sizeof(hashtype);
    const size_t hashbits     = hashbytes * 8;
    const size_t hashbitpairs = hashbits / 2 * (hashbits - 1);
    Rand r( 11938 );

    // Generate all the keys to be tested. We use malloc() because C++ things insist
    // on zero-initializing this memory, even though we're going to fill the array
    // with data immediately.
    //
    // This test works exactly the same as in SMHasher, except that the test keys are
    // different. To replicate SMHasher's results exactly, make an array to hold a
    // single key right here, then use r.rand_p() to fill it each loop by replacing
    // the "ExtBlob key(keyptr, keybytes)" and "keyptr += keybytes" lines below.
    uint8_t * const keys = (uint8_t *)malloc(keybytes * keybits * reps);
    uint8_t * keyptr = keys;
    r.rand_p(keyptr, keybytes * keybits * reps);
    addVCodeInput(keyptr, keybytes * keybits * reps);

    hashtype h1, h2;

    printf("Testing %3d-bit keys, %7d reps", keybits, reps);

    // This test checks to see if hash output bits tend to change independently or
    // not, depending on the input bits. For each possible combination of output
    // bits, it hashes a random inputs, flips a single bit of the input, hashes that,
    // and sees which bits changed. This is repeated a number of times, and is also
    // repeated for each keybit. A new set of test keys is randomly generated for
    // each (keybit, output bit 1, output bit 2) tuple. The test then looks for
    // whichever of those tuples had the highest deviation from average.
    //
    // For a random set of outputs, each pairing of bits should show that they are
    // independent of each other. That is, every possible combination of results (00,
    // 01, 10, 11) should be equally likely, and that should be true no matter which
    // input bit was changed.
    //
    // To be efficient, this implementation counts these possibilities in neat but
    // confusing ways. Each (keybit, output bit 1, output bit 2) tuple needs, in some
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
    // value of the '[11]' box. But it also keeps track of one number per (keybit,
    // output bit) tuple, which is how many times that bit changed for the given
    // keybit. These 2 sets of numbers take up less space than the full table would,
    // and they are much cheaper to compute than than the full table would be, and
    // they can be used to reconstruct each of those 4 boxes in the full table.
    //
    // The value of box [11] is the number of times bits x and y changed together.
    // These values make up the andcount[] vector.
    //
    // The sum of boxes [11] and [01] is the number of times bit y changed.
    // The sum of boxes [11] and [10] is the number of times bit x changed.
    // These values are in the popcount[] vector.
    //
    // The sum of all the boxes is the number of tests, which is a known constant.
    //
    // The value in box [11] is andcount[x, y].
    // The value in box [10] is therefore popcount[x] - andcount[x, y].
    // The value in box [01] is therefore popcount[y] - andcount[x, y].
    // The value in box [00] is therefore testcount - box[11] - box[10] - box[01].

    std::vector<uint32_t> popcount( keybits * hashbits    , 0 );
    std::vector<uint32_t> andcount( keybits * hashbitpairs, 0 );
    uint32_t * pop_cursor = &popcount[0];
    uint32_t * and_cursor = &andcount[0];

    for (size_t keybit = 0; keybit < keybits; keybit++) {
        uint32_t * pop_cursor_base = pop_cursor;
        uint32_t * and_cursor_base = and_cursor;
#if defined(DEBUG)
        if (pop_cursor != &popcount[keybit * hashbits]) {
            printf("bit %d   P %p != %p\n", keybit, pop_cursor, &popcount[keybit * hashbits]);
        }
        if (and_cursor != &andcount[keybit * hashbitpairs]) {
            printf("bit %d   A %p != %p\n", keybit, and_cursor, &andcount[keybit * hashbitpairs]);
        }
#endif

        progressdots(keybit, 0, keybits - 1, 10);

        for (size_t irep = 0; irep < reps; irep++) {
            pop_cursor = pop_cursor_base;
            and_cursor = and_cursor_base;

            ExtBlob key(keyptr, keybytes);
            hash(key, keybytes, seed, &h1);
            key.flipbit(keybit);
            hash(key, keybytes, seed, &h2);
            keyptr += keybytes;

            hashtype d = h1 ^ h2;

            // First count how often each output bit changes
            pop_cursor = HistogramHashBits(d, pop_cursor);

            // Then count how often each pair of output bits changed together
            for (size_t out1 = 0; out1 < hashbits - 1; out1++) {
                if (d.getbit(out1) == 0) {
                    and_cursor += hashbits - 1 - out1;
                    continue;
                }
                and_cursor = HistogramHashBits(d, and_cursor, out1 + 1);
            }
        }
    }

    free(keys);

    double   maxChiSq = 0;
    size_t   maxK    = 0;
    size_t   maxA    = 0;
    size_t   maxB    = 0;

    pop_cursor = &popcount[0];
    and_cursor = &andcount[0];

    for (size_t keybit = 0; keybit < keybits; keybit++) {
        uint32_t * pop_cursor_base = pop_cursor;

        for (size_t out1 = 0; out1 < hashbits - 1; out1++) {
            pop_cursor = pop_cursor_base++;
            uint32_t popcount_y = *pop_cursor++;

            for (size_t out2 = out1 + 1; out2 < hashbits; out2++) {
                uint32_t boxes[4];
                boxes[3] = *and_cursor++;
                boxes[2] = *pop_cursor++ - boxes[3];
                boxes[1] = popcount_y - boxes[3];
                boxes[0] = reps - boxes[3] - boxes[2] - boxes[1];

                double chisq = chiSqIndepValue(boxes, reps);
                if (maxChiSq < chisq) {
                    maxChiSq = chisq;
                    maxK     = keybit;
                    maxA     = out1;
                    maxB     = out2;
                }
            }
        }
    }

    addVCodeOutput(&popcount[0], keybits * hashbits     * sizeof(popcount[0]));
    addVCodeOutput(&andcount[0], keybits * hashbitpairs * sizeof(andcount[0]));
    addVCodeResult((uint64_t)maxChiSq);
    addVCodeResult(maxK);
    addVCodeResult(maxA);
    addVCodeResult(maxB);

    // For performance reasons, the analysis loop is coded to use the popcount and
    // andcount arrays in linear order. But for human-oriented printouts, we want to
    // iterate over them differently, and so reporting is now done here in its own
    // loop, separate from analysis.
    if (verbose) {
        size_t xyoffset = 0;
        for (size_t out1 = 0; out1 < hashbits - 1; out1++) {
            for (size_t out2 = out1 + 1; out2 < hashbits; out2++) {
                printf("Output bits (%3d,%3d) - ", out1, out2);
                for (int keybit = 0; keybit < keybits; keybit++) {
                    uint32_t * pop_cursor = &popcount[keybit * hashbits];
                    uint32_t * and_cursor = &andcount[keybit * hashbitpairs + xyoffset];

                    // Find worst bias for this tuple, out of all 4 boxes
                    uint32_t boxes[4];
                    boxes[3] = *and_cursor;
                    boxes[2] = pop_cursor[out2] - boxes[3];
                    boxes[1] = pop_cursor[out1] - boxes[3];
                    boxes[0] = reps - boxes[3] - boxes[2] - boxes[1];

                    const double chisq = chiSqIndepValue(boxes, reps);
                    const double p_value = chiSqPValue(chisq);
                    const int log2_pvalue = GetLog2PValue(p_value);

                    if (verbose) {
                        if (log2_pvalue < 8) {
                            printf(".");
                        } else if (log2_pvalue < 12) {
                            printf("o");
                        } else if (log2_pvalue < 16) {
                            printf("O");
                        } else {
                            printf("X");
                        }
                    }
                }
                // Finished keybit
                printf("\n");
                xyoffset++;
            }
            // Finished out2
            printf("\n");
        }
        // Finished out1
    }

    bool result = ReportChiSqIndep(maxChiSq, keybits * hashbitpairs, maxK, maxA, maxB);

    recordTestResult(result, "BIC", keybits);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool BicTest( const HashInfo * hinfo, const bool verbose ) {
    const HashFn hash      = hinfo->hashFn(g_hashEndian);
    bool         result    = true;
    bool         fewerreps = (hinfo->bits > 64 || hinfo->isVerySlow()) ? true : false;

    printf("[[[ BIC 'Bit Independence Criteria' Tests ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed);

    if (fewerreps) {
        result &= BicTest4<hashtype>(hash, seed, 16, 100000, verbose);
    } else {
        const size_t reps = 64000000 / hinfo->bits;
        result &= BicTest4<hashtype>(hash, seed, 11, reps, verbose);
    }

    recordTestResult(result, "BIC", (const char *)NULL);

    printf("\n%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(BicTest, HASHTYPELIST);
