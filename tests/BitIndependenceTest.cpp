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
#include "Instantiate.h"
#include "VCode.h"

#include "BitIndependenceTest.h"

#include <math.h>

//-----------------------------------------------------------------------------
// BIC test variant - store all intermediate data in a table, draw diagram
// afterwards (much faster)

// The choices for VCode inputs may seem strange here, but they were
// chosen in anticipation of threading this test.

template <typename keytype, typename hashtype>
static bool BicTest3( HashFn hash, const seed_t seed, const int reps, bool verbose = false ) {
    const int keybytes  = sizeof(keytype);
    const int keybits   = keybytes * 8;
    const int hashbytes = sizeof(hashtype);
    const int hashbits  = hashbytes * 8;
    const int pagesize  = hashbits * hashbits * 4;

    Rand r( 11938 );

    double maxBias = 0;
    int    maxK    = 0;
    int    maxA    = 0;
    int    maxB    = 0;

    keytype  key;
    hashtype h1, h2;

    std::vector<int> bins( keybits * pagesize, 0 );

    for (int keybit = 0; keybit < keybits; keybit++) {
        progressdots(keybit, 0, keybits - 1, 10);

        int * page = &bins[keybit * pagesize];

        for (int irep = 0; irep < reps; irep++) {
            r.rand_p(&key, keybytes);
            addVCodeInput(&key  , keybytes);
            addVCodeInput(keybit);

            hash(&key, keybytes, seed, &h1);
            key.flipbit(keybit);
            hash(&key, keybytes, seed, &h2);

            hashtype d = h1 ^ h2;

            for (int out1 = 0; out1 < hashbits - 1; out1++) {
                int * b    = &page[(out1 * hashbits + out1 + 1) * 4];
                for (int out2 = out1 + 1; out2 < hashbits; out2++) {
                    uint32_t x = d.getbit(out1) | (d.getbit(out2) << 1);
                    b[x]++;
                    b += 4;
                }
            }
        }
    }

    printf("\n");

    for (int out1 = 0; out1 < hashbits - 1; out1++) {
        for (int out2 = out1 + 1; out2 < hashbits; out2++) {
            if (verbose) { printf("(%3d,%3d) - ", out1, out2); }

            for (int keybit = 0; keybit < keybits; keybit++) {
                int * page  = &bins[keybit * pagesize];
                int * bins  = &page[(out1 * hashbits + out2) * 4];

                double bias = 0;

                for (int b = 0; b < 4; b++) {
                    double b2 = double(bins[b]) / double(reps / 2);
                    b2 = fabs(b2 * 2 - 1);

                    if (b2 > bias) { bias = b2; }
                }

                if (bias > maxBias) {
                    maxBias = bias;
                    maxK    = keybit;
                    maxA    = out1;
                    maxB    = out2;
                }

                if (verbose) {
                    if (bias < 0.01) {
                        printf(".");
                    } else if (bias < 0.05) {
                        printf("o");
                    } else if (bias < 0.33) {
                        printf("O");
                    } else {
                        printf("X");
                    }
                }
            }

            // Finished keybit
            if (verbose) { printf("\n"); }
        }

        if (verbose) {
            for (int i = 0; i < keybits + 12; i++) { printf("-"); }
            printf("\n");
        }
    }

    addVCodeOutput(&bins[0], keybits * pagesize * sizeof(bins[0]));
    addVCodeResult((uint32_t)(maxBias * 1000.0));
    addVCodeResult(maxK);
    addVCodeResult(maxA);
    addVCodeResult(maxB);

    printf("Max bias %f - (%3d : %3d,%3d)\n", maxBias, maxK, maxA, maxB);

    // Bit independence is harder to pass than avalanche, so we're a bit more lax here.
    bool result = (maxBias < 0.05);
    return result;
}

template <typename keytype, typename hashtype>
static bool BicTest4( HashFn hash, const seed_t seed, const int reps, bool verbose = false ) {
    const int keybytes  = sizeof(keytype);
    const int keybits   = keybytes * 8;
    const int hashbytes = sizeof(hashtype);
    const int hashbits  = hashbytes * 8;

    Rand r( 11938 );

    double maxBias = 0;
    int    maxK    = 0;
    int    maxA    = 0;
    int    maxB    = 0;

    keytype  key;
    hashtype h1, h2;

    std::vector<uint32_t> popcount( keybits * hashbits, 0 );
    std::vector<uint32_t> andcount( keybits * hashbits / 2 * (hashbits - 1), 0 );
    uint32_t * pop_cursor = &popcount[0];
    uint32_t * and_cursor = &andcount[0];

    for (size_t keybit = 0; keybit < keybits; keybit++) {
        uint32_t * pop_cursor_base = pop_cursor;
        uint32_t * and_cursor_base = and_cursor;
#if defined(DEBUG)
        if (pop_cursor != &popcount[keybit * hashbits]) {
            printf("bit %d   P %p != %p\n", keybit, pop_cursor, &popcount[keybit * hashbits]);
        }
        if (and_cursor != &andcount[keybit * hashbits / 2 * (hashbits - 1)]) {
            printf("bit %d   A %p != %p\n", keybit, and_cursor, &andcount[keybit * hashbits / 2 * (hashbits - 1)]);
        }
#endif

        progressdots(keybit, 0, keybits - 1, 10);

        for (size_t irep = 0; irep < reps; irep++) {
            pop_cursor = pop_cursor_base;
            and_cursor = and_cursor_base;

            r.rand_p(&key, keybytes);
            addVCodeInput(&key  , keybytes);
            addVCodeInput(keybit);

            hash(&key, keybytes, seed, &h1);
            key.flipbit(keybit);
            hash(&key, keybytes, seed, &h2);

            hashtype d = h1 ^ h2;

            // First count how often each output bit changes
            for (size_t oByte = 0; oByte < hashbytes; oByte++) {
                uint8_t byte = d[oByte];
                for (size_t oBit = 0; oBit < 8; oBit++) {
                    (*pop_cursor++) += byte & 1;
                    byte >>= 1;
                }
            }

            // Then count how often each pair of output bits changed together
            for (size_t out1 = 0; out1 < hashbits - 1; out1++) {
                if (d.getbit(out1) == 0) {
                    and_cursor += hashbits - 1 - out1;
                    continue;
                }
                for (size_t out2 = out1 + 1; out2 < hashbits; out2++) {
                    uint32_t x = d.getbit(out2);
                    (*and_cursor++) += x;
                }
            }
        }
    }

    printf("\n");

    // The set of "boxes" for each pair of bits looks like:
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
    // The value of box [11] is the number of times bits x and y changed together.
    // These values are in the andcount[] vector.
    //
    // The sum of boxes [11] and [01] is the number of times bit y changed.
    // The sum of boxes [11] and [10] is the number of times bit x changed.
    // These values are in the popcount[] vector.
    //
    // The sum of all the boxes is the number of tests, which is a known constant.
    //
    // The value in box [10] is therefore popcount[x] - andcount[x, y].
    // The value in box [01] is therefore popcount[y] - andcount[x, y].
    // The value in box [00] is therefore total - box[11] - box[10] - box[01].

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

                double bias = 0;
                for (int b = 0; b < 4; b++) {
                    double b2 = double(boxes[b]) / double(reps / 2);
                    b2 = fabs(b2 * 2 - 1);

                    if (b2 > bias) { bias = b2; }
                }

                if (bias > maxBias) {
                    maxBias = bias;
                    maxK    = keybit;
                    maxA    = out1;
                    maxB    = out2;
                }
            }
        }
    }

    addVCodeResult((uint32_t)(maxBias * 1000.0));
    addVCodeResult(maxK);
    addVCodeResult(maxA);
    addVCodeResult(maxB);

    printf("Max bias %f - (%3d : %3d,%3d)\n", maxBias, maxK, maxA, maxB);

    // Bit independence is harder to pass than avalanche, so we're a bit more lax here.
    bool result = (maxBias < 0.05);
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

    if (1) {
        result &= BicTest3<Blob<32>, hashtype>(hash, seed, 100, verbose);
        result &= BicTest4<Blob<32>, hashtype>(hash, seed, 100, verbose);
    } else if (fewerreps) {
        result &= BicTest3<Blob<128>, hashtype>(hash, seed, 100000, verbose);
    } else {
        const long reps = 64000000 / hinfo->bits;
        // result &= BicTest<uint64_t,hashtype>(hash,2000000);
        result &= BicTest3<Blob<88>, hashtype>(hash, seed, (int)reps, verbose);
    }

    recordTestResult(result, "BIC", (const char *)NULL);

    printf("\n%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(BicTest, HASHTYPELIST);

//-----------------------------------------------------------------------------
// Some old implementations; currently unused.

#if 0
//----------------------------------------------------------------------------
// Tests the Bit Independence Criteron. Stricter than Avalanche, but slow and
// not really all that useful.

template <typename keytype, typename hashtype>
void BicTest1( HashFn hash, const int keybit, const int reps, double & maxBias, int & maxA, int & maxB, bool verbose ) {
    Rand r( 11938 );

    const int keybytes  = sizeof(keytype);
    const int hashbytes = sizeof(hashtype);
    const int hashbits  = hashbytes * 8;

    std::vector<int> bins( hashbits * hashbits * 4, 0 );

    keytype  key;
    hashtype h1, h2;

    for (int irep = 0; irep < reps; irep++) {
        if (verbose) {
            if (irep % (reps / 10) == 0) { printf("."); }
        }

        r.rand_p(&key, keybytes);
        hash(&key, keybytes, g_seed, &h1);

        key.flipbit(keybit);
        hash(&key, keybytes, g_seed, &h2);

        hashtype d = h1 ^ h2;

        for (int out1 = 0; out1 < hashbits; out1++) {
            for (int out2 = 0; out2 < hashbits; out2++) {
                if (out1 == out2) { continue; }

                uint32_t b = getbit(d, out1) | (getbit(d, out2) << 1);

                bins[(out1 * hashbits + out2) * 4 + b]++;
            }
        }
    }

    if (verbose) { printf("\n"); }

    maxBias = 0;

    for (int out1 = 0; out1 < hashbits; out1++) {
        for (int out2 = 0; out2 < hashbits; out2++) {
            if (out1 == out2) {
                if (verbose) { printf("\\"); }
                continue;
            }

            double bias = 0;

            for (int b = 0; b < 4; b++) {
                double b2 = double(bins[(out1 * hashbits + out2) * 4 + b]) / double(reps / 2);
                b2 = fabs(b2 * 2 - 1);

                if (b2 > bias) { bias = b2; }
            }

            if (bias > maxBias) {
                maxBias = bias;
                maxA    = out1;
                maxB    = out2;
            }

            if (verbose) {
                if     (bias < 0.01) { printf("."); } else if (bias < 0.05) { printf("o"); } else if (bias < 0.33) {
                    printf("O");
                } else {
                    printf("X");
                }
            }
        }

        if (verbose) { printf("\n"); }
    }
}

//----------

template <typename keytype, typename hashtype>
bool BicTest1( HashFn hash, const int reps ) {
    const int keybytes = sizeof(keytype);
    const int keybits  = keybytes * 8;

    double maxBias     = 0;
    int    maxK        = 0;
    int    maxA        = 0;
    int    maxB        = 0;

    for (int i = 0; i < keybits; i++) {
        if (i % (keybits / 10) == 0) { printf("."); }

        double bias;
        int    a, b;

        BicTest1<keytype, hashtype>(hash, i, reps, bias, a, b, true);

        if (bias > maxBias) {
            maxBias = bias;
            maxK    = i;
            maxA    = a;
            maxB    = b;
        }
    }

    printf("Max bias %f - (%3d : %3d,%3d)\n", maxBias, maxK, maxA, maxB);

    // Bit independence is harder to pass than avalanche, so we're a bit more lax here.

    bool result = (maxBias < 0.05);

    return result;
}

//-----------------------------------------------------------------------------
// BIC test variant - iterate over output bits, then key bits. No temp storage,
// but slooooow

template <typename keytype, typename hashtype>
void BicTest2( HashFn hash, const int reps, bool verbose = true ) {
    const int keybytes  = sizeof(keytype);
    const int keybits   = keybytes * 8;
    const int hashbytes = sizeof(hashtype);
    const int hashbits  = hashbytes * 8;

    Rand r( 11938 );

    double maxBias = 0;
    int    maxK    = 0;
    int    maxA    = 0;
    int    maxB    = 0;

    keytype  key;
    hashtype h1, h2;

    for (int out1 = 0; out1 < hashbits - 1; out1++) {
        for (int out2 = out1 + 1; out2 < hashbits; out2++) {
            if (verbose) { printf("(%3d,%3d) - ", out1, out2); }

            for (int keybit = 0; keybit < keybits; keybit++) {
                int bins[4] = { 0, 0, 0, 0 };

                for (int irep = 0; irep < reps; irep++) {
                    r.rand_p(&key, keybytes);
                    hash(&key, keybytes, g_seed, &h1);
                    key.flipbit(keybit);
                    hash(&key, keybytes, g_seed, &h2);

                    hashtype d = h1 ^ h2;

                    uint32_t b = getbit(d, out1) | (getbit(d, out2) << 1);

                    bins[b]++;
                }

                double bias = 0;

                for (int b = 0; b < 4; b++) {
                    double b2 = double(bins[b]) / double(reps / 2);
                    b2 = fabs(b2 * 2 - 1);

                    if (b2 > bias) { bias = b2; }
                }

                if (bias > maxBias) {
                    maxBias = bias;
                    maxK    = keybit;
                    maxA    = out1;
                    maxB    = out2;
                }

                if (verbose) {
                    if     (bias < 0.05) { printf("."); } else if (bias < 0.10) { printf("o"); } else if (bias < 0.50) {
                        printf("O");
                    } else {
                        printf("X");
                    }
                }
            }

            // Finished keybit

            if (verbose) { printf("\n"); }
        }
    }

    printf("Max bias %f - (%3d : %3d,%3d)\n", maxBias, maxK, maxA, maxB);
}

#endif /* 0 */
