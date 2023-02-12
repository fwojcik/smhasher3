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
 *     Copyright (c) 2014-2021 Reini Urban
 *     Copyright (c) 2015      Ivan Kruglov
 *     Copyright (c) 2015      Paul G
 *     Copyright (c) 2016      Jason Schulz
 *     Copyright (c) 2016-2018 Leonid Yuriev
 *     Copyright (c) 2016      Sokolov Yura aka funny_falcon
 *     Copyright (c) 2016      Vlad Egorov
 *     Copyright (c) 2018      Jody Bruchon
 *     Copyright (c) 2019      Niko Rebenich
 *     Copyright (c) 2019-2020 Yann Collet
 *     Copyright (c) 2019-2021 data-man
 *     Copyright (c) 2019      王一 WangYi
 *     Copyright (c) 2020      Cris Stringfellow
 *     Copyright (c) 2020      HashTang
 *     Copyright (c) 2020      Jim Apple
 *     Copyright (c) 2020      Thomas Dybdahl Ahle
 *     Copyright (c) 2020      Tom Kaitchuck
 *     Copyright (c) 2021      Logan oos Even
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
#include "Instantiate.h"
#include "VCode.h"

#include "PopcountTest.h"

//-----------------------------------------------------------------------------
// Moment Chi-Square test, measuring the probability of the
// lowest 32 bits set over the whole key space. Not where the bits are, but how many.
// See e.g. https://www.statlect.com/fundamentals-of-probability/moment-generating-function

typedef uint32_t popcnt_hist[65];

// Copy the results into g_NCPU ranges of 2^32
static void PopcountThread( const HashInfo * hinfo, const seed_t seed, const int inputSize, const unsigned start,
        const unsigned end, const unsigned step, popcnt_hist & hist1, popcnt_hist & hist2 ) {
    const HashFn      hash     = hinfo->hashFn(g_hashEndian);
    long double const n        = (end - (start + 1)) / step;
    uint64_t          previous = 0;

#define INPUT_SIZE_MAX 256
    assert(inputSize <= INPUT_SIZE_MAX  );
    char key[INPUT_SIZE_MAX]       = { 0 };
#define HASH_SIZE_MAX 64
    char      hbuff[HASH_SIZE_MAX] = { 0 };
    const int hbits = std::min(hinfo->bits, 64U); // limited due to popcount8

    assert(sizeof(unsigned) <= inputSize);
    assert(start < end);
    // assert(step > 0);

    uint64_t i = start - step;
    memcpy(key, &i, sizeof(i));
    hash(key, inputSize, seed, hbuff);
    memcpy(&previous, hbuff, 8);

    for (uint64_t i = start; i <= end; i += step) {
        memcpy(key, &i, sizeof(i));
        hash(key, inputSize, seed, hbuff);

        // popcount8 assumed to work on 64-bit
        // note : ideally, one should rather popcount the whole hash
        uint64_t h;
        memcpy(&h, hbuff, 8);

        uint64_t setbits = popcount8(h);
        hist1[setbits]++;

        // derivative
        setbits  = popcount8(h ^ previous);
        hist2[setbits]++;
        previous = h;
    }
}

static bool PopcountResults( long double srefh, long double srefl, long double b1h,
        long double b1l, long double b0h, long double b0l ) {
    double worst;
    {
        double chi2 = (b1h - srefh) * (b1h - srefh) / (b1l + srefl);
        printf("From counting 1s : %9.2Lf, %9.2Lf  -  moment chisq %10.4f\n", b1h, b1l, chi2);
        worst = chi2;
    }
    {
        double chi2 = (b0h - srefh) * (b0h - srefh) / (b0l + srefl);
        printf("From counting 0s : %9.2Lf, %9.2Lf  -  moment chisq %10.4f\n", b0h, b0l, chi2);
        worst = std::max(worst, chi2);
    }

    // note : previous threshold : 3.84145882069413
    int const rank = (worst < 500.) + (worst < 50.) + (worst < 5.);

    assert(0 <= rank && rank <= 3);

    const char * rankstr[4] = { "FAIL !!!!", "pass", "Good", "Great" };
    printf("Test result:  %s\n", rankstr[rank]);

    addVCodeResult((uint32_t)(worst * 1000.0));

    return rank > 0;
}

static bool PopcountTestImpl( const HashInfo * hinfo, int inputSize, int step ) {
    const HashFn      hash  = hinfo->hashFn(g_hashEndian);
    const unsigned    mx    = 0xffffffff;
    const long double n     = UINT64_C(0x100000000) / step;
    const int         hbits = std::min(hinfo->bits, 64U); // limited due to popcount8

    assert(hbits <= HASH_SIZE_MAX * 8);
    assert(inputSize >= 4);

    printf("\nGenerating hashes from a linear sequence of %i-bit numbers "
            "with a step size of %d ... \n", inputSize * 8, step);

    /*
     * Notes on the ranking system.
     * Ideally, this test should report and sum all popcount values
     * and compare the resulting distribution to an ideal distribution.
     *
     * What happens here is quite simplified :
     * the test gives "points" for each popcount, and sum them all.
     * The metric (using N^5) is heavily influenced by the largest outliers.
     * For example, a 64-bit hash should have a popcount close to 32.
     * But a popcount==40 will tilt the metric upward
     * more than popcount==24 will tilt the metric downward.
     * In reality, both situations should be ranked similarly.
     *
     * To compensate, we measure both popcount1 and popcount0,
     * and compare to some pre-calculated "optimal" sums for the hash size.
     *
     * Another limitation of this test is that it only popcounts the first 64-bit.
     * For large hashes, bits beyond this limit are ignored.
     *
     * Derivative hash testing:
     * In this scenario, 2 consecutive hashes are xored,
     * and the outcome of this xor operation is then popcount controlled.
     * Obviously, the _order_ in which the hash values are generated becomes critical.
     *
     * This scenario comes from the prng world,
     * where derivative of the generated suite of random numbers is analyzed
     * to ensure the suite is truly "random".
     *
     * However, in almost all prng, the seed of next random number is the previous random number.
     *
     * This scenario is quite different: it introduces a fixed distance between 2 consecutive "seeds".
     * This is especially detrimental to algorithms relying on linear operations, such as multiplications.
     *
     * This scenario is relevant if the hash is used as a prng and generates values from a linearly increasing counter
     * as a seed.
     * It is not relevant for scenarios employing the hash as a prng
     * with the more classical method of using the previous random number as a seed for the next one.
     * This scenario has no relevance for classical usages of hash algorithms,
     * such as hash tables, bloom filters and such, were only the raw values are ever used.
     */

    long double srefh, srefl;
    switch (hbits / 8) {
    case 8:
            srefh = 38918200.;
            if (step == 2) {
                srefl = 273633.333333;
            } else if (step == 6) {
                srefl = 820900.0;
            } else {
                abort();
            }
            break;
    case 4:
            srefh = 1391290.;
            if (step == 2) {
                srefl = 686.6666667;
            } else if (step == 6) {
                srefl = 2060.0;
            } else {
                abort();
            }
            break;
    default:
             printf("hash size not covered \n");
             abort();
    }

    // Because of threading, the actual inputs can't be hashed into the
    // main thread's state, so just hash the parameters of the input data.
    addVCodeInput(         0); // start
    addVCodeInput(0xffffffff); // end
    addVCodeInput(      step); // step
    addVCodeInput( inputSize); // size

    popcnt_hist rawhash[g_NCPU];
    popcnt_hist xorhash[g_NCPU];
    memset(rawhash, 0, sizeof(rawhash));
    memset(xorhash, 0, sizeof(xorhash));

    const seed_t seed = hinfo->Seed(g_seed, false, 1);

    if (g_NCPU == 1) {
        PopcountThread(hinfo, seed, inputSize, 0, 0xffffffff, step, rawhash[0], xorhash[0]);
    } else {
#if defined(HAVE_THREADS)
        // split into g_NCPU threads
        std::thread t[g_NCPU];
        printf("%d threads starting... ", g_NCPU);

        const uint64_t len = UINT64_C(0x100000000) / (step * g_NCPU);
        for (int i = 0; i < g_NCPU; i++) {
            const uint32_t start = i * len * step;
            const uint32_t end   = (i < (g_NCPU - 1)) ? start + (len * step - 1) : 0xffffffff;
            // printf("thread[%d]: %d, 0x%x - 0x%x %d\n", i, inputSize, start, end, step);
            t[i] = std::thread {
                PopcountThread, hinfo, seed, inputSize, start, end, step, std::ref(rawhash[i]), std::ref(xorhash[i])
            };
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));

        for (int i = 0; i < g_NCPU; i++) {
            t[i].join();
        }

        printf(" done\n");
        for (int i = 1; i < g_NCPU; i++) {
            for (int j = 0; j <= hbits; j++) {
                rawhash[0][j] += rawhash[i][j];
                xorhash[0][j] += xorhash[i][j];
            }
        }
#endif
    }

    long double b0h = 0, b0l = 0, db0h = 0, db0l = 0;
    long double b1h = 0, b1l = 0, db1h = 0, db1l = 0;
    // b1h = SUM[ 1-bits**5 ]
    // b0h = SUM[ 0-bits**5 ]
    // b1l = SUM[ 1-bits**10 ]
    // b0l = SUM[ 0-bits**10 ]

    for (uint64_t j = 0; j <= hbits; j++) {
        long double mult1 = j * j * j * j * j;
        long double mult0 = (hbits - j) * (hbits - j) * (hbits - j) * (hbits - j) * (hbits - j);
        b1h  += mult1 *         (long double)rawhash[0][j];
        b0h  += mult0 *         (long double)rawhash[0][j];
        db1h += mult1 *         (long double)xorhash[0][j];
        db0h += mult0 *         (long double)xorhash[0][j];
        b1l  += mult1 * mult1 * (long double)rawhash[0][j];
        b0l  += mult0 * mult0 * (long double)rawhash[0][j];
        db1l += mult1 * mult1 * (long double)xorhash[0][j];
        db0l += mult0 * mult0 * (long double)xorhash[0][j];
    }

    b1h  /= n;  b1l = (b1l  / n - b1h  * b1h ) / n;
    db1h /= n; db1l = (db1l / n - db1h * db1h) / n;
    b0h  /= n;  b0l = (b0l  / n - b0h  * b0h ) / n;
    db0h /= n; db0l = (db0l / n - db0h * db0h) / n;

    bool result = true;

    printf("Ideal results    : %9.2Lf, %9.2Lf\n", srefh, srefl);

    printf("\nResults from literal hashes :\n"  );
    result &= PopcountResults(srefh, srefl, b1h, b1l, b0h, b0l);

    printf("\nResults from derivative hashes (XOR of 2 consecutive values) :\n");
    result &= PopcountResults(srefh, srefl, db1h, db1l, db0h, db0l);

    printf("\n");

    // Similar threading problems for the outputs, so just hash in the
    // summary data.
    addVCodeOutput(&rawhash[0][0], 65 * sizeof(rawhash[0][0]));
    addVCodeOutput(&xorhash[0][0], 65 * sizeof(xorhash[0][0]));

    recordTestResult(result, "Popcount", inputSize);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool PopcountTest( const HashInfo * hinfo, const bool extra ) {
    const int step   = ((hinfo->isVerySlow() || hinfo->bits > 128) && extra) ? 6 : 2;
    bool      result = true;

    printf("[[[ Popcount Tests (deprecated) ]]]\n");

    result &= PopcountTestImpl(hinfo, 4, step);
    if (extra) {
        result &= PopcountTestImpl(hinfo,  8, step);
        result &= PopcountTestImpl(hinfo, 16, step);
    }

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(PopcountTest, HASHTYPELIST);
