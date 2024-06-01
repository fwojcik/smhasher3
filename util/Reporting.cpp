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
 *     Copyright (c) 2015      Paul G
 *     Copyright (c) 2015-2021 Reini Urban
 *     Copyright (c) 2016      Vlad Egorov
 *     Copyright (c) 2019-2020 Yann Collet
 *     Copyright (c) 2020      Bradley Austin Davis
 *     Copyright (c) 2020      Paul Khuong
 *     Copyright (c) 2021      Jim Apple
 *     Copyright (c) 2021      Ori Livneh
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
#include "TestGlobals.h"
#include "Blobsort.h"
#include "Stats.h"
#include "Reporting.h"
#include "Instantiate.h"
#include "VCode.h"

#include <math.h>

//-----------------------------------------------------------------------------
// If score exceeds this improbability of happening, note a failing result
static const double FAILURE_PBOUND = exp2(-20); // 2**-20 == 1/1,048,576 =~ 0.00009537%
// If score exceeds this improbability of happening, note a warning
static const double WARNING_PBOUND = exp2(-16); // 2**-16 == 1/65,536  =~ 0.001526%, 16x as much as failure
// If these bounds seem overly generous, remember that SMHasher3 uses
// about 16,000 tests, so a 1/16,000 chance event will hit once per run on
// average, even with a perfect-quality hash function.

//-----------------------------------------------------------------------------
// Turn a hash index plus a testDelta configuration into the hash indexes
// of the two hashes used to compute a differential hash.

static std::pair<hidx_t, hidx_t> DifferentialIdxs( hidx_t idx, hidx_t nbH, unsigned testDeltaNum, bool testDeltaXaxis ) {
    hidx_t x, y, xp, yp;

    switch (testDeltaNum) {
    case  0: return std::make_pair(idx, 0);
    case  1: return std::make_pair(idx, idx + 1);
    case  2: return std::make_pair(idx << 1, (idx << 1) + 1);
    default:
        x = idx % testDeltaNum;
        y = idx / testDeltaNum;
        if (testDeltaXaxis) {
            xp = (x + 1) % testDeltaNum;
            yp = y;
        } else {
            xp = x;
            yp = (y + 1) % (nbH / testDeltaNum);
        }
        return std::make_pair(x + y * testDeltaNum, xp + yp * testDeltaNum);
    }
}

//-----------------------------------------------------------------------------
// Print a list of collisions
template <typename hashtype>
void PrintCollisions( const std::map<hashtype, uint32_t> & collisions, const size_t maxCollisions,
        const uint32_t maxPerCollision, const std::vector<hidx_t> & idxs, const KeyFn keyprint, const unsigned delta,
        const bool deltaXaxis, const hidx_t nbH, const uint32_t nbBits, const uint32_t prevBits, const bool reversebits ) {
    if (prevBits != nbBits) {
        printf("\n%d-bit or more collisions (excluding %d-bit or more) ", nbBits, prevBits);
    } else {
        printf("\n%d-bit collisions ", nbBits);
    }
    if (collisions.size() >= maxCollisions) {
        printf("(first %zd):\n", maxCollisions);
    } else {
        printf("(%zu):\n", collisions.size());
    }

    if (keyprint == NULL) {
        for (auto const coll: collisions) {
            const hashtype & hash = coll.first;
            printf("%6dx", coll.second);
            hash.printhex(" ", nbBits, reversebits);
        }
    } else {
        auto idxiter = idxs.begin();
        for (auto const coll: collisions) {
            const hashtype & hash = coll.first;
            const uint32_t collcount = coll.second;
            const uint32_t printcoll = std::min(collcount, maxPerCollision);
            if (collcount > maxPerCollision) {
                printf("\tfirst %d (of %d) results for ", maxPerCollision, collcount);
            } else {
                printf("\t%d results for ", collcount);
            }
            if (delta > 0) {
                hash.printhex("hash value XOR delta ", nbBits, reversebits);
            } else {
                hash.printhex("hash value ", nbBits, reversebits);
            }
            printf("\t\tSeed            \tKey\n");
            printf("\t\t--------------------------------------------------\n");
            for (uint32_t i = 0; i < printcoll; i++) {
                const hidx_t cur = *idxiter++;
                printf("\t\t");
                auto idxs = DifferentialIdxs(cur, nbH, delta, deltaXaxis);
                keyprint(idxs.first);
                if (delta > 0) {
                    printf("\tXOR\t");
                    keyprint(idxs.second);
                }
                printf("\n");
            }
        }
    }

    printf("\n");
}

INSTANTIATE(PrintCollisions, HASHTYPELIST);

//-----------------------------------------------------------------------------
template <typename hashtype>
void ShowOutliers( const std::vector<hashtype> & hashes, const std::vector<hidx_t> & hashidxs, const KeyFn keyprint,
        const unsigned delta, const bool deltaXaxis, const uint32_t maxEntries, const uint32_t maxPerEntry,
        const uint32_t bitOffset, const uint32_t bitWidth ) {

    // This count data could be gathered during TestDistribution, but
    // plumbing that in seems more invasive than I want to be right now. If
    // this ends up being a bottleneck, that can be revisited.
    const hidx_t nbH = hashes.size();
    const uint32_t nbC = 1 << bitWidth;
    std::vector<uint32_t> counts(nbC);
    for (uint32_t i = 0; i < nbH; i++) {
        prefetch(&hashes[i + 4]);
        uint32_t index = hashes[i].window(bitOffset, bitWidth);
        counts[index]++;
    }

    // Find the top 10 bin counts, including duplicates, and the number of
    // empty bins.
    constexpr unsigned nOutliers = 10;
    uint32_t zerocount = (counts[0] == 0) ? 1 : 0;
    std::vector<uint32_t> maxcounts(nOutliers);
    for (unsigned i = 0; i < nOutliers; i++) {
        maxcounts[i] = counts[0];
    }
    for (size_t i = 1; i < nbC; i++) {
        if (counts[i] == 0) {
            zerocount++;
            continue;
        }
        if (counts[i] > maxcounts[0]) {
            std::pop_heap(maxcounts.begin(), maxcounts.end(), std::greater<uint32_t>());
            maxcounts.back() = counts[i];
            std::push_heap(maxcounts.begin(), maxcounts.end(), std::greater<uint32_t>());
        }
    }

    // Find every hash which ended up in a bin with a count in the top
    // 10. This won't record more than maxPerEntry hashes per bin, nor any
    // hashes from more than maxEntries of those bins.
    const uint32_t maxbound = maxcounts[0];
    std::multimap<uint32_t, hidx_t> entries;
    for (uint32_t i = 0; i < nbH; i++) {
        prefetch(&hashes[i + 4]);
        uint32_t index = hashes[i].window(bitOffset, bitWidth);
        if (counts[index] < maxbound) {
            continue;
        }
        size_t count = entries.count(index);
        if (((count == 0) && (entries.size() < maxEntries)) ||
                (count < maxPerEntry)) {
            entries.insert({index, i});
        }
    }

    printf("Most common hash values for %d-bits slice @ offset %d (expected count == %f):\n",
            bitWidth, bitOffset, ldexp((double)nbH, -bitWidth));
    uint32_t prevhash  = 0xffffffff;
    int      hexdigits = (bitWidth + 3) / 4;
    if (keyprint == NULL) {
        for (auto const e: entries) {
            if ((e.first == prevhash) || (counts[e.first] < maxbound)) {
                continue;
            }
            prevhash = e.first;
            printf("\t\t%8dx 0x%0*x\n", counts[e.first], hexdigits, e.first);
        }
    } else {
        for (auto const e: entries) {
            if (e.first != prevhash) {
                const uint32_t keycount = counts[e.first];
                if (keycount < maxbound) {
                    continue;
                }
                if (keycount > maxPerEntry) {
                    printf("\tfirst %d (of %d) results for ", maxPerEntry, keycount);
                } else {
                    printf("\t%d results for ", keycount);
                }
                if (delta > 0) {
                    printf("hash value XOR delta slice 0x%0*x\n", hexdigits, e.first);
                } else {
                    printf("hash value slice 0x%0*x\n", hexdigits, e.first);
                }
                printf("\t\tSeed            \tKey\n");
                printf("\t\t--------------------------------------------------\n");
                prevhash = e.first;
            }
            printf("\t\t");
            auto idxs = DifferentialIdxs(hashidxs[e.second], nbH, delta, deltaXaxis);
            keyprint(idxs.first);
            if (delta > 0) {
                printf("\tXOR\t");
                keyprint(idxs.second);
            }
            printf("\n");
        }
    }

    if (zerocount > 0) {
        printf("Never-seen hash values for %d-bits slice @ offset %d (expected count == %f) ",
                bitWidth, bitOffset, GetMissingHashesExpected(nbH, bitWidth));
        if (zerocount > maxEntries) {
            printf("(first %d of %d values):\n", maxEntries, zerocount);
            zerocount = maxEntries;
        } else {
            printf("(%d values):\n", zerocount);
        }
        for (size_t i = 0; i < nbC; i++) {
            if (counts[i] != 0) {
                continue;
            }
            // The spaces here are so this matches the "\t\t%8dx 0x%0*x\n" above
            printf("\t\t          0x%0*zx\n", hexdigits, i);
            if (--zerocount == 0) {
                break;
            }
        }
    }
}

INSTANTIATE(ShowOutliers, HASHTYPELIST);

//----------------------------------------------------------------------------
// Graphically show individual log2(p_value) results.
//
// I'm not 100% sure if scaling should be applied to these values. Right
// now they aren't scaled. If it is ever decided they should be, the
// "trials" parameter can be passed to ScalePValue(). Maybe make this a
// command-line option? Probably not; there probably is a correct answer.
//
// This uses dots for numbers well below failure, numbers for p-values
// leading up to failure, and letters for p-values at or a bit beyond
// failure, and X for p-values well beyond failure.
static void plot( const double p_value, const size_t trials ) {
    const int OFFSET   = GetLog2PValue(FAILURE_PBOUND);
    const int DIGITS   = 9; // Use [1-9]
    const int CHARS    = 6; // Use [a-f]
    unused(trials);

    if (p_value > ldexp(FAILURE_PBOUND, DIGITS)) {
        putchar('.');
    } else if (p_value > FAILURE_PBOUND) {
        const int log2p = GetLog2PValue(p_value);
        putchar('1' + log2p + DIGITS - OFFSET);
    } else if (p_value > ldexp(FAILURE_PBOUND, -CHARS)) {
        const int log2p = GetLog2PValue(p_value);
        putchar('a' + log2p - OFFSET);
    } else {
        putchar('X');
    }
}

//-----------------------------------------------------------------------------
// Report on the fact that, in each of the specified number of trials,
// a fair coin was "flipped" coinflips times, and the worst bias
// (number of excess "heads" or "tails") over all those trials was the
// specified worstbiascnt.
bool ReportBias( const uint32_t * counts, const int coinflips, const int trials,
        const int hashbits, const flags_t flags ) {
    const int expected     = coinflips / 2;
    int       worstrawbias = 0;
    int       worstbias    = 0;
    int       worstbiasN   = 0;

    for (int i = 0; i < trials; i++) {
        int rawbias = (int)counts[i] - expected;
        int bias    = abs(rawbias);
        if (worstbias < bias) {
            worstbias    = bias;
            worstrawbias = rawbias;
            worstbiasN   = i;
        }
        bias = abs(bias);
    }
    const int worstbiasKeybit  = worstbiasN / hashbits;
    const int worstbiasHashbit = worstbiasN % hashbits;

    // Due to threading and memory complications, add the summed
    // avalanche results instead of the hash values. Not ideal, but the
    // "real" way is just too expensive.
    addVCodeOutput(counts, trials * sizeof(counts[0]));
    addVCodeResult(worstbias );
    addVCodeResult(worstbiasN);

    double p1value    = GetCoinflipBinomialPValue(coinflips, worstbias);
    double p_value    = ScalePValue(p1value, trials);
    int    logp_value = GetLog2PValue(p_value);
    double ratio      = (double)worstbias / (double)coinflips;
    double pct        = (ratio <= (5e-7)) ? 0.0 : ratio * 200.0;
    int    pctdigits  = (pct >= 99.995) ? 1 : (pct >= 9.995) ? 2 : 3;
    bool   result     = true;

    recordLog2PValue(logp_value);
    if (REPORT(MORESTATS, flags)) {
        if (p_value > 0.00001) {
            printf("max is %5.*f%% at bit %4d -> out %3d (^%2d) (p<%8.6f) (%+i)", pctdigits, pct,
                    worstbiasKeybit, worstbiasHashbit, logp_value, p_value, worstrawbias);
        } else {
            printf("max is %5.*f%% at bit %4d -> out %3d (^%2d) (p<%.2e) (%+i)", pctdigits, pct,
                    worstbiasKeybit, worstbiasHashbit, logp_value, p_value, worstrawbias);
        }
    } else {
        printf("max is %5.*f%% at bit %4d -> out %3d (^%2d)", pctdigits,
                pct, worstbiasKeybit, worstbiasHashbit, logp_value);
    }

    if (p_value <= FAILURE_PBOUND) {
        printf(" !!!!!\n");
        result = false;
    } else if (p_value <= WARNING_PBOUND) {
        printf(" !\n");
    } else {
        printf("\n");
    }

    if (REPORT(DIAGRAMS, flags)) {
        printf("[");
        for (int i = 0; i < trials; i++) {
            int    thisbias  = abs((int)counts[i] - expected);
            double thisp     = GetCoinflipBinomialPValue(coinflips, thisbias);
            plot(thisp, trials);
            if (((i % hashbits) == (hashbits - 1)) && (i < (trials - 1))) {
                printf("]\n[");
            }
        }
        printf("]\n");
    }
    return result;
}

//-----------------------------------------------------------------------------
// Reports on dependencies between hash output bit changes. For the math behind how
// we convert from the popcount[] and andcount[] arrays into full 2x2 contingency
// tables, see the comment in tests/BitIndependence.cpp.
bool ReportChiSqIndep( const uint32_t * popcount, const uint32_t * andcount, size_t keybits,
        size_t hashbits, size_t testcount, const flags_t flags ) {
    const size_t hashbitpairs     = hashbits / 2 * hashbits;
    const size_t realhashbitpairs = hashbits / 2 * (hashbits - 1);

    double maxChiSq   = 0;
    size_t maxKeybit  = 0;
    size_t maxOutbitA = 0;
    size_t maxOutbitB = 0;
    bool   result;

    for (size_t keybit = 0; keybit < keybits; keybit++) {
        const uint32_t * pop_cursor_base = &popcount[keybit * hashbits    ];
        const uint32_t * and_cursor      = &andcount[keybit * hashbitpairs];

        for (size_t out1 = 0; out1 < hashbits - 1; out1++) {
            const uint32_t * pop_cursor = pop_cursor_base++;
            uint32_t         popcount_y = *pop_cursor++;

            for (size_t out2 = out1 + 1; out2 < hashbits; out2++) {
                uint32_t boxes[4];
                boxes[3] = *and_cursor++;
                boxes[2] = *pop_cursor++ - boxes[3];
                boxes[1] = popcount_y    - boxes[3];
                boxes[0] = testcount - boxes[3] - boxes[2] - boxes[1];

                double chisq = ChiSqIndepValue(boxes, testcount);

                if (maxChiSq   < chisq) {
                    maxChiSq   = chisq;
                    maxKeybit  = keybit;
                    maxOutbitA = out1;
                    maxOutbitB = out2;
                }
            }
        }
    }

    addVCodeOutput(&popcount[0], keybits * hashbits     * sizeof(popcount[0]));
    addVCodeOutput(&andcount[0], keybits * hashbitpairs * sizeof(andcount[0]));
    addVCodeResult((uint64_t)maxChiSq);
    addVCodeResult(maxKeybit);
    addVCodeResult(maxOutbitA);
    addVCodeResult(maxOutbitB);

    const double p_value_raw = ChiSqPValue(maxChiSq, 1);
    const double p_value     = ScalePValue(p_value_raw, keybits * realhashbitpairs);
    const int    logp_value  = GetLog2PValue(p_value);
    const double cramer_v    = sqrt(maxChiSq / testcount);

    recordLog2PValue(logp_value);
    printf("max %6.4f at bit %4zd -> out (%3zd,%3zd)  (^%2d)", cramer_v, maxKeybit, maxOutbitA, maxOutbitB, logp_value);

    if (p_value <= FAILURE_PBOUND) {
        printf(" !!!!!\n");
        result = false;
    } else if (p_value <= WARNING_PBOUND) {
        printf(" !\n");
        result = true;
    } else {
        printf("\n");
        result = true;
    }

    // For performance reasons, the analysis loop is coded to use the popcount and
    // andcount arrays in linear order. But for human-oriented printouts, we want to
    // iterate over them differently, and so reporting is now done here in its own
    // loop, separate from analysis.
    if (REPORT(DIAGRAMS, flags)) {
        size_t xyoffset = 0;
        for (size_t out1 = 0; out1 < hashbits - 1; out1++) {
            for (size_t out2 = out1 + 1; out2 < hashbits; out2++) {
                printf("Output bits (%3zd,%3zd) - ", out1, out2);
                for (size_t keybit = 0; keybit < keybits; keybit++) {
                    const uint32_t * pop_cursor = &popcount[keybit * hashbits               ];
                    const uint32_t * and_cursor = &andcount[keybit * hashbitpairs + xyoffset];

                    // Find worst bias for this tuple, out of all 4 boxes
                    uint32_t boxes[4];
                    boxes[3] = *and_cursor;
                    boxes[2] = pop_cursor[out2] - boxes[3];
                    boxes[1] = pop_cursor[out1] - boxes[3];
                    boxes[0] = testcount - boxes[3] - boxes[2] - boxes[1];

                    const double chisq = ChiSqIndepValue(boxes, testcount);
                    const double p_val = ChiSqPValue(chisq, 1);
                    plot(p_val, keybits * realhashbitpairs);
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

    return result;
}

//-----------------------------------------------------------------------------
bool ReportCollisions( uint64_t const nbH, int collcount, unsigned hashsize, int * logpp,
        bool maxcoll, bool highbits, bool header, const flags_t flags ) {
    bool largehash = hashsize > (8 * sizeof(uint32_t));

    // The expected number depends on what collision statistic is being
    // reported on; "worst of N buckets" is very different than "sum
    // over N buckets".
    //
    // Also determine an upper-bound on the unlikelihood of the observed
    // collision count.
    double expected, p_value;

    if (maxcoll) {
        expected = EstimateMaxCollisions(nbH, hashsize);
        p_value  = EstimateMaxCollPValue(nbH, hashsize, collcount);
    } else {
        expected = EstimateNbCollisions(nbH, hashsize);
        p_value  = GetBoundedPoissonPValue(expected, collcount);
    }
    int logp_value = GetLog2PValue(p_value);
    if (logpp != NULL) {
        *logpp = logp_value;
    }

    // Since p-values are now used to determine pass/warning/failure
    // status, ratios are now solely for humans reading the results.
    //
    // If there were no collisions and none were expected, for a
    // suitably fuzzy value of "none", then a ratio of 1.00 ("test
    // exactly met expectations") is most sensible.
    //
    // If there were no collisions and there was a decent chance of
    // seeing one, then a ratio of 0.00 ("test saw 0% of expected
    // collisions") seems best.
    //
    // If there were any collisions, and the odds of seeing one were
    // quite low (arbitrarily chosen to be 0.01), then a ratio isn't
    // really meaningful, so we use +inf.
    //
    // A collision count matching the rounded expectation value is
    // treated as "exactly expected". For small hash sizes, if the
    // expected count has more than 0.1 after the decimal place and the
    // actual collision count is the next integer above the expected
    // one, then that case is also treated as "exactly expected".
    //
    // In all other cases, the true ratio is computed, but the value
    // will be bounded to not clutter the output in failure cases.
    double ratio;
    if (collcount == 0) {
        ratio = (expected < 0.1) ? 1.00 : 0.00;
    } else if (expected < 0.01) {
        ratio = INFINITY;
    } else if (collcount == (int)round(expected)) {
        ratio = 1.00;
    } else if (!largehash && (collcount == (int)round(expected + 0.4))) {
        ratio = 1.00;
    } else {
        ratio = double(collcount) / expected;
        if (ratio >= 999.95) {
            ratio = INFINITY;
        }
    }

    bool warning = false, failure = false;
    if (p_value <= FAILURE_PBOUND) {
        failure = true;
    } else if (p_value <= WARNING_PBOUND) {
        warning = true;
    } else if (isnan(ratio)) {
        warning = true;
    }

    recordLog2PValue(logp_value);

    if (!REPORT(QUIET, flags)) {
        if (header) {
            printf("Testing %s collisions (%s %3i-bit)", maxcoll ? "max" : "all", highbits ? "high" : "low ", hashsize);
        }

        // 8 integer digits would match the 10.1 float specifier
        // (10 characters - 1 decimal point - 1 digit after the decimal),
        // but some hashes greatly exceed expected collision counts.
        if (!isfinite(ratio)) {
            printf(" - Expected %10.1f, actual %10i  (------) ", expected, collcount);
        } else if (ratio < 9.0) {
            printf(" - Expected %10.1f, actual %10i  (%5.3fx) ", expected, collcount, ratio);
        } else {
            printf(" - Expected %10.1f, actual %10i  (%#.4gx) ", expected, collcount, ratio);
        }

        // Since ratios and p-value summaries are most important to humans,
        // and deltas and exact p-values add visual noise and variable line
        // widths and possibly field counts, they are now only printed out
        // in --verbose mode.
        if (REPORT(MORESTATS, flags)) {
            if (p_value > 0.00001) {
                printf("(^%2d) (p<%8.6f) (%+i)", logp_value, p_value, collcount - (int)round(expected));
            } else {
                printf("(^%2d) (p<%.2e) (%+i)", logp_value, p_value, collcount - (int)round(expected));
            }
        } else {
            printf("(^%2d)", logp_value);
        }

        if (failure) {
            printf(" !!!!!\n");
        } else if (warning) {
            printf(" !\n");
        } else {
            printf("\n");
        }
    }

    return !failure;
}

//-----------------------------------------------------------------------------
bool ReportBitsCollisions( uint64_t nbH, const int * collcounts, int minBits, int maxBits,
        int * logpp, int * maxbitsp, bool highbits, const flags_t flags ) {
    if ((maxBits <= 1) || (minBits > maxBits)) { return true; }

    int spacelen = 80;
    if (!REPORT(QUIET, flags)) {
        spacelen -=
                printf("Testing all collisions (%s %2i..%2i bits) - ", highbits ? "high" : "low ", minBits, maxBits);
    }

    double maxCollDev     = 0.0;
    int    maxCollDevBits = 0;
    int    maxCollDevNb   = 0;
    double maxCollDevExp  = 1.0;
    double maxPValue      = INFINITY;

    for (int b = minBits; b <= maxBits; b++) {
        int const    nbColls  = collcounts[b - minBits];
        double const expected = EstimateNbCollisions(nbH, b);
        assert(expected > 0.0);
        double const dev      = (double)nbColls / expected;
        double const p_value  = GetBoundedPoissonPValue(expected, nbColls);
        // printf("%d bits, %d/%f, p %f\n", b, nbColls, expected, p_value);
        if (p_value < maxPValue) {
            maxPValue      = p_value;
            maxCollDev     = dev;
            maxCollDevBits = b;
            maxCollDevNb   = nbColls;
            maxCollDevExp  = expected;
        }
    }

    double p_value    = ScalePValue(maxPValue, maxBits - minBits + 1);
    int    logp_value = GetLog2PValue(p_value);

    recordLog2PValue(logp_value);

    if (logpp != NULL) {
        *logpp = logp_value;
    }
    if (maxbitsp != NULL) {
        *maxbitsp = maxCollDevBits;
    }

    bool warning = false, failure = false;
    if (p_value <= FAILURE_PBOUND) {
        failure = true;
    } else if (p_value <= WARNING_PBOUND) {
        warning = true;
    }

    if (!REPORT(QUIET, flags)) {
        int          i_maxCollDevExp = (int)round(maxCollDevExp);
        spacelen -= printf("Worst is %2i bits: %i/%i ", maxCollDevBits, maxCollDevNb, i_maxCollDevExp);
        if (spacelen < 0) {
            spacelen = 0;
        }

        if (maxCollDev >= 999.95) {
            maxCollDev = INFINITY;
        }

        if (!isfinite(maxCollDev)) {
            printf("%.*s(------) ", spacelen, g_manyspaces);
        } else if (maxCollDev < 9.0) {
            printf("%.*s(%5.3fx) ", spacelen, g_manyspaces, maxCollDev);
        } else {
            printf("%.*s(%#.4gx) ", spacelen, g_manyspaces, maxCollDev);
        }

        if (REPORT(MORESTATS, flags)) {
            if (p_value > 0.00001) {
                printf("(^%2d) (p<%8.6f) (%+i)", logp_value, p_value, maxCollDevNb - i_maxCollDevExp);
            } else {
                printf("(^%2d) (p<%.2e) (%+i)", logp_value, p_value, maxCollDevNb - i_maxCollDevExp);
            }
        } else {
            printf("(^%2d)", logp_value);
        }

        if (failure) {
            printf(" !!!!!\n");
        } else if (warning) {
            printf(" !\n");
        } else {
            printf("\n");
        }
    }

    return !failure;
}

//-----------------------------------------------------------------------------
bool ReportDistribution( const std::vector<double> & scores, int tests, int hashbits, int maxwidth, int minwidth,
        int * logpp, int * worstStartp, int * worstWidthp, const flags_t flags ) {
    // Find the startbit with the worst bias. Only report on biases above 0.
    double worstN     = 0;
    int    worstStart = -1;
    int    worstWidth = -1;

    for (int startbit = 0; startbit < hashbits; startbit++) {
        const double * worstptr = &scores[startbit * (maxwidth - minwidth + 1)];
        for (int width = maxwidth; width >= minwidth; width--) {
            double n = *worstptr++;

            if (worstN    <= n) {
                worstN     = n;
                worstWidth = width;
                worstStart = startbit;
            }
        }
    }

    addVCodeResult((uint32_t)worstN);
    addVCodeResult(worstWidth      );
    addVCodeResult(worstStart      );

    double p_value    = ScalePValue(GetStdNormalPValue(worstN), tests);
    int    logp_value = GetLog2PValue(p_value);
    double mult       = normalizeScore(worstN, worstWidth);

    recordLog2PValue(logp_value);
    if (logpp != NULL) {
        *logpp = logp_value;
    }
    if (worstStartp != NULL) {
        *worstStartp = worstStart;
    }
    if (worstWidthp != NULL) {
        *worstWidthp = worstWidth;
    }

    bool warning = false, failure = false;
    if (p_value <= FAILURE_PBOUND) {
        failure = true;
    } else if (p_value <= WARNING_PBOUND) {
        warning = true;
    }

    if (!REPORT(QUIET, flags)) {
        if (worstStart == -1) {
            printf("No positive bias detected            %5.3fx  ", 0.0);
        } else if (mult < 9.0) {
            printf("Worst bias is %2d bits at bit %3d:    %5.3fx  ", worstWidth, worstStart, mult);
        } else {
            printf("Worst bias is %2d bits at bit %3d:    %#.4gx  ", worstWidth, worstStart, mult);
        }

        if (REPORT(MORESTATS, flags)) {
            if (p_value > 0.00001) {
                printf("(^%2d) (p<%8.6f) (%f)", logp_value, p_value, worstN);
            } else {
                printf("(^%2d) (p<%.2e) (%f)", logp_value, p_value, worstN);
            }
        } else {
            printf("(^%2d)", logp_value);
        }

        if (failure) {
            printf(" !!!!!\n");
        } else if (warning) {
            printf(" !\n");
        } else {
            printf("\n");
        }
    }

    if (REPORT(DIAGRAMS, flags)) {
        printf("[");
        for (int startbit = 0; startbit < hashbits; startbit++) {
            const double * worstptr = &scores[startbit * (maxwidth - minwidth + 1)];
            for (int width = maxwidth; width >= minwidth; width--) {
                plot(GetStdNormalPValue(*worstptr++), tests);
            }
            printf("]\n%s", ((startbit + 1) == hashbits) ? "" : "[");
        }
    }

    return !failure;
}
