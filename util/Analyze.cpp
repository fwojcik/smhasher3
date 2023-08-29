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
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include <cstring> // for memset
#include <math.h>

#if defined(HAVE_THREADS)
  #include <atomic>
  #define FETCH_ADD(v, n) v.fetch_add(n)
typedef std::atomic<int> a_int;
#else
  #define FETCH_ADD(v, n) ((v += n) - n)
typedef int a_int;
#endif

//----------------------------------------------------------------------------
// Compute the highest number of hash bits that makes sense to use for
// testing how evenly the hash distributes entries over all hash bins.
static int MaxDistBits( const uint64_t nbH ) {
    // If there aren't 5 keys per bin over 8 bins, then don't bother
    // testing distribution at all.
    if (nbH < (5 * 8)) {
        return 0;
    }
    int maxwidth = 24;
    // We need at least 5 keys per bin to reliably test distribution biases
    // down to 1%, so don't bother to test sparser distributions than that.
    while (nbH < (UINT64_C(5) << maxwidth)) {
        --maxwidth;
    }
    return maxwidth;
}

//----------------------------------------------------------------------------
// Compute the largest number of hash bits, not larger than maxbits, needed
// to expect at least minCollisions out of nbH values.
static int FindMaxBitsTargetCollisions( uint64_t nbH, int minCollisions, int maxbits ) {
    int nb;

    for (nb = maxbits; nb > 2; nb--) {
        double const nbColls = EstimateNbCollisions(nbH, nb);
        if (nbColls > minCollisions) { return nb; }
    }
    // assert(0);
    return nb;
}

//----------------------------------------------------------------------------
// Given a set of possible bit widths, compute which ones make sense to
// test by counting the total number of collisions across all buckets, and
// which ones make sense to test by counting the number of collisions in
// the single fullest bucket. If all bit widths qualify for "total sum of
// collisions", then threshBits gets set to 0.
static void FindCollBitBounds( std::set<int> & nbBitsvec, int origBits, uint64_t nbH,
        int & minBits, int & maxBits, int & threshBits ) {
    const int nlognBits = GetNLogNBound(nbH);

    minBits    = origBits + 1;
    maxBits    = 0;
    threshBits = 0;

    for (const int nbBits: nbBitsvec) {
        // If the nbBits value is too large for this hashtype, don't use it.
        if (nbBits >= origBits) {
            continue;
        }
        // If many hashes are being tested (compared to the hash width),
        // then the expected number of collisions will approach the number
        // of keys (indeed, it will converge to every hash bucket being
        // full, leaving nbH - 2**nbBits collisions). In those cases, it is
        // not very useful to count all collisions, so at some point of high
        // expected collisions, it is better to instead count the number of
        // keys in the fullest bucket. The cutoff here is if there are
        // (n*log(n)) hashes, where n is the number of hash buckets. This
        // cutoff is an inflection point where the "balls-into-bins"
        // statistics really start changing. ReportCollisions() will
        // estimate the correct key count for that differently, as it is a
        // different statistic.
        if (nbBits < nlognBits) {
            threshBits = std::max(threshBits, nbBits);
        }
        // Record the highest and lowest valid bit widths to test
        maxBits = std::max(maxBits, nbBits);
        minBits = std::min(minBits, nbBits);
    }
}

//-----------------------------------------------------------------------------
// Sort the hash list, count the total number of collisions and return the
// first N collisions for further processing. If requested, also count the
// number of times each collision occurs.
template <typename hashtype, bool indices>
hidx_t FindCollisionsImpl( std::vector<hashtype> & hashes, std::map<hashtype, uint32_t> & collisions,
        hidx_t maxCollisions, std::vector<hidx_t> & collisionidxs, std::vector<hidx_t> & hashidxs,
        uint32_t maxPerCollision ) {
    hidx_t collcount = 0, curcollcount = 0;

    if (indices) {
        blobsort(hashes.begin(), hashes.end(), hashidxs);
    } else {
        blobsort(hashes.begin(), hashes.end());
    }

    const hidx_t sz = hashes.size();
    for (hidx_t hnb = 1; hnb < sz; hnb++) {
        // Search until we find a collision
        if (hashes[hnb] != hashes[hnb - 1]) {
            continue;
        }

        // If we're only counting collisions, do that and move on
        collcount++;
        if (maxCollisions == 0) {
            continue;
        }

        // Otherwise, if this collision was already seen, then just
        // increment its count. Also record this key index if too many have
        // not yet been recorded.
        //
        // If the collision is new and if too many have not yet been
        // recorded, then record this one. The initial number of times this
        // colliding value was seen is 2; if it didn't occur twice, how
        // could it be a collision? :)
        auto it = collisions.find(hashes[hnb]);
        if (it != collisions.end()) {
            it->second++;
            if (indices) {
                if (curcollcount < maxPerCollision) {
                    collisionidxs.push_back(hashidxs[hnb]);
                    curcollcount++;
                }
            }
        } else if ((hidx_t)collisions.size() < maxCollisions) {
            collisions.emplace(std::pair<hashtype, uint32_t>{hashes[hnb], 2});
            if (indices) {
                collisionidxs.push_back(hashidxs[hnb - 1]);
                collisionidxs.push_back(hashidxs[hnb]);
                curcollcount = 2;
            }
        }
    }

    return collcount;
}

template <typename hashtype>
hidx_t FindCollisions( std::vector<hashtype> & hashes, std::map<hashtype, uint32_t> & collisions, hidx_t maxCollisions ) {
    std::vector<uint32_t> dummy;
    return FindCollisionsImpl<hashtype, false>(hashes, collisions, maxCollisions, dummy, dummy, 0);
}

INSTANTIATE(FindCollisions, HASHTYPELIST);

template <typename hashtype>
hidx_t FindCollisionsIndices( std::vector<hashtype> & hashes, std::map<hashtype, uint32_t> & collisions,
        hidx_t maxCollisions, std::vector<hidx_t> & collisionidxs, std::vector<hidx_t> & hashidxs,
        uint32_t maxPerCollision ) {
    return FindCollisionsImpl<hashtype, true>(hashes, collisions, maxCollisions,
            collisionidxs, hashidxs, maxPerCollision);
}

INSTANTIATE(FindCollisionsIndices, HASHTYPELIST);

// Look through the pre-sorted hash list for collisions in the first
// prefixLen bits, count them, and return the first N collisions for
// further processing. This also allows for excluding collisions in the
// first prevPrefixLen bits, for the case where they were reported on
// previously.
//
// This is just different enough from FindCollisions() to fully
// re-implement here, instead of diving further into template madness.
template <typename hashtype>
static hidx_t FindCollisionsPrefixesIndices( std::vector<hashtype> & hashes, std::map<hashtype, uint32_t> & collisions,
        hidx_t maxCollisions, uint32_t prefixLen, uint32_t prevPrefixLen, std::vector<hidx_t> & collisionidxs,
        const std::vector<hidx_t> & hashidxs, uint32_t maxPerCollision ) {
    hidx_t collcount = 0, curcollcount = 0;
    hashtype mask;

    assert(prefixLen > 0);
    mask.sethighbits(prefixLen);

    const size_t nbH = hashes.size();
    for (size_t hnb = 1; hnb < nbH; hnb++) {
        // Search until we find a collision in the first [prefixLen, prevPrefixLen) bits
        hashtype hdiff = hashes[hnb - 1] ^ hashes[hnb];
        uint32_t hzb   = hdiff.highzerobits();
        if ((hzb < prefixLen) || (hzb >= prevPrefixLen)) {
            continue;
        }

        collcount++;

        hashtype colliding_bits = hashes[hnb] & mask;
        auto it = collisions.find(colliding_bits);
        if (it != collisions.end()) {
            it->second++;
            if (curcollcount < maxPerCollision) {
                collisionidxs.push_back(hashidxs[hnb]);
                curcollcount++;
            }
        } else if ((hidx_t)collisions.size() < maxCollisions) {
            collisions.emplace(std::pair<hashtype, uint32_t>{colliding_bits, 2});
            collisionidxs.push_back(hashidxs[hnb - 1]);
            collisionidxs.push_back(hashidxs[hnb]);
            curcollcount = 2;
        }
    }

    return collcount;
}

//-----------------------------------------------------------------------------
// If calcmax is false, then this tallies the total number of collisions
// across all given hashes for each bit window in the range of [minHBits,
// maxHBits], considering only the high bits. In this mode, the value of
// threshHBits is ignored.
//
// If calcmax is true, then this tallies the total number of
// collisions across all the given hashes for each bit window in the
// range (threshHBits, maxHBits], and the peak/maximum number of
// collisions for each bit window in the range [minHBits,
// threshHBits], considering only the high bits in each case.
//
// This is possible to do in a single pass over all the hashes by
// counting the number of bits which match the next-lower hash value,
// since a collision for N bits is also a collision for N-k bits.
//
// This requires the vector of hashes to be sorted.
template <bool calcmax, typename hashtype>
static void CountRangedNbCollisionsImpl( std::vector<hashtype> & hashes,
        int minHBits, int maxHBits, int threshHBits, int * collcounts ) {
    assert(minHBits >= 1       );
    assert(minHBits <= maxHBits);
    assert(hashtype::bitlen >= (size_t)maxHBits);
    assert(!calcmax || (threshHBits >= minHBits));
    assert(!calcmax || (threshHBits <= maxHBits));

    const int collbins    = maxHBits - minHBits + 1;
    const int maxcollbins = calcmax ? threshHBits - minHBits + 1 : 0;
    int       prevcoll[maxcollbins + 1];
    int       maxcoll[maxcollbins + 1];

    memset(collcounts, 0, sizeof(collcounts[0]) * collbins );
    if (calcmax) {
        memset(prevcoll, 0, sizeof(prevcoll[0]) * maxcollbins);
        memset(maxcoll , 0, sizeof(maxcoll[0])  * maxcollbins);
    }

    const uint64_t nbH = hashes.size();
    for (uint64_t hnb = 1; hnb < nbH; hnb++) {
        hashtype hdiff = hashes[hnb - 1] ^ hashes[hnb];
        int      hzb   = hdiff.highzerobits();
        if (hzb >= minHBits) {
            if (hzb > maxHBits) {
                hzb = maxHBits;
            }
            collcounts[hzb - minHBits]++;
        }
        // If we don't care about maximum collision counts, or if this
        // hash is a collision for *all* bit widths where we do care about
        // maximums, then this is all that need be done for this hash.
        if (!calcmax) {
            continue;
        }
        if (hzb >= threshHBits) {
            continue;
        }
        // If we do care about maximum collision counts, then any window
        // sizes which are strictly larger than hzb have just encountered
        // a non-collision. For each of those window sizes, see how many
        // collisions there have been since the last non-collision, and
        // record it if that's the new peak.
        if (hzb < minHBits - 1) {
            hzb = minHBits - 1;
        }
        // coll is the total number of collisions so far, for the window
        // width corresponding to index i
        int coll = 0;
        for (int i = collbins - 1; i >= maxcollbins; i--) {
            coll += collcounts[i];
        }
        for (int i = maxcollbins - 1; i > hzb - minHBits; i--) {
            coll += collcounts[i];
            // See if this is the new peak for this window width
            maxcoll[i] = std::max(maxcoll[i], coll - prevcoll[i]);
            // Record the total number of collisions seen so far at this
            // non-collision, so that when the next non-collision happens we
            // can compute how many collisions there have been since this one.
            prevcoll[i] = coll;
        }
    }

    for (int i = collbins - 2; i >= 0; i--) {
        collcounts[i] += collcounts[i + 1];
    }
    if (calcmax) {
        for (int i = maxcollbins - 1; i >= 0; i--) {
            collcounts[i] = std::max(maxcoll[i], collcounts[i] - prevcoll[i]);
        }
    }
}

template <typename hashtype>
static void CountRangedNbCollisions( std::vector<hashtype> & hashes, int minHBits,
        int maxHBits, int threshHBits, int * collcounts ) {
    if (threshHBits == 0) {
        return CountRangedNbCollisionsImpl<false>(hashes, minHBits, maxHBits, 0, collcounts);
    } else {
        return CountRangedNbCollisionsImpl<true>(hashes, minHBits, maxHBits, threshHBits, collcounts);
    }
}

//----------------------------------------------------------------------------

template <typename hashtype>
static bool TestCollisions( std::vector<hashtype> & hashes, int * logpSumPtr, bool willTestDist,
        bool testMaxColl, bool testHighBits, bool testLowBits, bool verbose, bool drawDiagram ) {
    const unsigned hashbits   = hashtype::bitlen;
    const uint64_t nbH        = hashes.size();
    const uint32_t maxColl    = drawDiagram ? 1000 : 0;
    const uint32_t maxPerColl = drawDiagram ? 100 : 0;
    int  curlogp;
    bool result = true;

    if (verbose) {
        printf("Testing all collisions (     %3i-bit)", hashbits);
    }

    // Do all other compute-intensive stuff (as requested) before
    // displaying _any_ results, to be a little bit more human-friendly.

    addVCodeOutput(&hashes[0], hashtype::len * nbH);

    // Note that FindCollisions sorts the list of hashes!
    std::map<hashtype, uint32_t> collisions;
    std::vector<hidx_t>          collisionidxs;
    std::vector<hidx_t>          hashidxs;
    hidx_t                       collcount;
    if (drawDiagram) {
        collcount = FindCollisionsIndices(hashes, collisions, maxColl, collisionidxs, hashidxs, maxPerColl);
    } else {
        collcount = FindCollisions(hashes, collisions, maxColl);
    }
    addVCodeResult(collcount);

    // If analysis of partial collisions is requested, figure out which bit
    // widths make sense to test, and then test them.
    std::vector<hidx_t>              hashidxs_rev;
    std::vector<hashtype>            hashes_rev;
    std::set<int, std::greater<int>> nbBitsvec;
    std::vector<int>                 collcounts_fwd;
    std::vector<int>                 collcounts_rev;
    int minBits = 0, maxBits = 0, threshBits = 0, minTBits = 0, maxTBits = 0;

    if (testHighBits || testLowBits) {
        nbBitsvec.insert({ 224, 160, 128, 64, 32 });
        // cyan: The 12- and -8-bit tests are too small : tables are necessarily saturated.
        // It would be better to count the nb of collisions per Cell, and
        // compared the distribution of values against a random source.
        // But that would be a different test.
        //
        // rurban: No, these tests are for non-prime hash tables, using only
        //     the lower 5-10 bits
        //
        // fwojcik: Collision counting did not previously reflect
        // rurban's comment, as the code counted the sum of collisions
        // across _all_ buckets. So if there are many more hashes than
        // 2**nbBits, and the hash is even _slightly_ not broken, then
        // every n-bit truncated hash value will appear at least once, in
        // which case the "actual" value reported would always be
        // (hashes.size() - 2**nbBits). Checking the results in doc/
        // confirms this. cyan's comment was correct.
        //
        // Collision counting has now been modified to report on the
        // single bucket with the most collisions when fuller hash tables
        // are being tested, and ReportCollisions() computes an
        // appropriate "expected" statistic.
        if (testMaxColl) {
            nbBitsvec.insert({ 12, 8 });
        }

        // Compute the number of bits for a collision count of about 100
        const int hundredCollBits = FindMaxBitsTargetCollisions(nbH, 100, hashbits);
        if (EstimateNbCollisions(nbH, hundredCollBits) >= 100) {
            nbBitsvec.insert(hundredCollBits);
        }

        // Each bit width value in nbBitsvec is explicitly reported on. If
        // any of those values are less than the n*log(n) bound, then the
        // bin with the most collisions will be reported on, otherwise the
        // total sum of collisions across all bins will be reported on.
        //
        // There are also many more bit widths that a) are probably used in
        // the real world, and b) we can now cheaply analyze and report
        // on. Any bit width above the n*log(n) bound that has a reasonable
        // number of expected collisions is worth analyzing, so that range
        // of widths is computed here.
        //
        // This is slightly complicated by the fact that TestDistribution() may
        // also get invoked, which does an RMSE-based comparison to the
        // expected distribution over some range of bit width values. If that
        // will be invoked, then there's no point in doubly-reporting on
        // collision counts for those bit widths, so they get excluded here.
        const int nlognBits = GetNLogNBound(nbH);
        minTBits = willTestDist ? std::max(MaxDistBits(nbH) + 1, nlognBits) : nlognBits;
        maxTBits = FindMaxBitsTargetCollisions(nbH, 10, hashbits - 1);

        // Given the range of hash sizes we care about, compute all
        // collision counts for them, for high- and low-bits as requested.
        std::set<int> combinedBitsvec;
        combinedBitsvec.insert(nbBitsvec.begin(), nbBitsvec.end());
        for (int i = minTBits; i <= maxTBits; i++) {
            combinedBitsvec.insert(i);
        }
        FindCollBitBounds(combinedBitsvec, hashbits, nbH, minBits, maxBits, threshBits);

        // This is the actual testing; the counting of partial collisions
        if (testHighBits && (maxBits > 0)) {
            collcounts_fwd.resize(maxBits - minBits + 1);
            CountRangedNbCollisions(hashes, minBits, maxBits, threshBits, &collcounts_fwd[0]);
            if (collcounts_fwd.size() != 0) {
                addVCodeResult(&collcounts_fwd[0], sizeof(collcounts_fwd[0]) *
                        collcounts_fwd.size());
            }
        }

        if (testLowBits && (maxBits > 0)) {
            collcounts_rev.resize(maxBits - minBits + 1);

            if (drawDiagram) {
                hashes_rev.resize(nbH);
                for (size_t hnb = 0; hnb < nbH; hnb++) {
                    hashes_rev[hnb] = hashes[hnb];
                    hashes_rev[hnb].reversebits();
                }
                hashidxs_rev = hashidxs;

                blobsort(hashes_rev.begin(), hashes_rev.end(), hashidxs_rev);
            } else {
                hashes_rev   = std::move(hashes);
                hashidxs_rev = std::move(hashidxs);
                hashes.clear();
                hashidxs.clear();
                for (size_t hnb = 0; hnb < nbH; hnb++) {
                    hashes_rev[hnb].reversebits();
                }

                blobsort(hashes_rev.begin(), hashes_rev.end());
            }

            CountRangedNbCollisions(hashes_rev, minBits, maxBits, threshBits, &collcounts_rev[0]);

            if (collcounts_rev.size() != 0) {
                addVCodeResult(&collcounts_rev[0], sizeof(collcounts_rev[0]) *
                        collcounts_rev.size());
            }

            if (!drawDiagram) {
                for (size_t hnb = 0; hnb < nbH; hnb++) {
                    hashes_rev[hnb].reversebits();
                }
                hashes   = std::move(hashes_rev);
                hashidxs = std::move(hashidxs_rev);
                hashes_rev.clear();
                hashidxs_rev.clear();
            }
            // No need to re-sort, since TestDistribution doesn't care
        }
    }

    // Report on complete collisions, now that the heavy lifting is complete
    result &= ReportCollisions(nbH, collcount, hashbits, &curlogp, false, false, false, verbose, drawDiagram);
    if (logpSumPtr != NULL) {
        *logpSumPtr += curlogp;
    }
    if (!result && drawDiagram) {
        PrintCollisions(collisions, maxColl);
    }

    // Report on partial collisions, if requested
    if (testHighBits || testLowBits) {

        // Report explicitly on each bit width in nbBitsvec
        uint32_t prevBitsH = hashbits, prevBitsL = hashbits;
        for (const int nbBits: nbBitsvec) {
            if ((nbBits < minBits) || (nbBits > maxBits)) {
                continue;
            }
            bool reportMaxcoll = (testMaxColl && (nbBits <= threshBits)) ? true : false;
            if (testHighBits) {
                bool thisresult = ReportCollisions(nbH, collcounts_fwd[nbBits - minBits], nbBits,
                        &curlogp, reportMaxcoll, true, true, verbose, drawDiagram);
                if (logpSumPtr != NULL) {
                    *logpSumPtr += curlogp;
                }
                if (!thisresult && drawDiagram) {
                    collisions.clear();
                    collisionidxs.clear();
                    FindCollisionsPrefixesIndices(hashes, collisions, maxColl, nbBits,
                            prevBitsH, collisionidxs, hashidxs, maxPerColl);
                    PrintCollisions(collisions, maxColl, nbBits, prevBitsH, false);
                    prevBitsH = nbBits;
                }
                result &= thisresult;
            }
            if (testLowBits) {
                bool thisresult = ReportCollisions(nbH, collcounts_rev[nbBits - minBits], nbBits,
                        &curlogp, reportMaxcoll, false, true, verbose, drawDiagram);
                if (logpSumPtr != NULL) {
                    *logpSumPtr += curlogp;
                }
                if (!thisresult && drawDiagram) {
                    collisions.clear();
                    collisionidxs.clear();
                    FindCollisionsPrefixesIndices(hashes_rev, collisions, maxColl, nbBits,
                            prevBitsL, collisionidxs, hashidxs_rev, maxPerColl);
                    PrintCollisions(collisions, maxColl, nbBits, prevBitsL, true);
                    prevBitsL = nbBits;
                }
                result &= thisresult;
            }
        }

        // Report a summary of the bit widths in the range [minTBits, maxTBits]
        if (testHighBits) {
            int maxBits;
            bool thisresult = ReportBitsCollisions(nbH, &collcounts_fwd[minTBits - minBits],
                    minTBits, maxTBits, &curlogp, &maxBits, true, verbose, drawDiagram);
            if (logpSumPtr != NULL) {
                *logpSumPtr += curlogp;
            }
            if (!thisresult && drawDiagram) {
                collisions.clear();
                collisionidxs.clear();
                FindCollisionsPrefixesIndices(hashes, collisions, maxColl, maxBits,
                        hashbits + 1, collisionidxs, hashidxs, maxPerColl);
                PrintCollisions(collisions, maxColl, maxBits, maxBits, false);
            }
            result &= thisresult;
        }
        if (testLowBits) {
            int maxBits;
            bool thisresult = ReportBitsCollisions(nbH, &collcounts_rev[minTBits - minBits],
                    minTBits, maxTBits, &curlogp, &maxBits, false, verbose, drawDiagram);
            if (logpSumPtr != NULL) {
                *logpSumPtr += curlogp;
            }
            if (!thisresult && drawDiagram) {
                collisions.clear();
                collisionidxs.clear();
                FindCollisionsPrefixesIndices(hashes_rev, collisions, maxColl, maxBits,
                        hashbits + 1, collisionidxs, hashidxs_rev, maxPerColl);
                PrintCollisions(collisions, maxColl, maxBits, maxBits, true);
            }
            result &= thisresult;
        }
    }

    return result;
}

//----------------------------------------------------------------------------
// Measures how well the hashes are distributed across all hash bins, for
// each possible N-bit slice of the hash values, with N going from 8 to
// MaxDistBits(nbH) (which is 24 or less) inclusive.

template <typename hashtype>
static void TestDistributionBatch( const std::vector<hashtype> & hashes, a_int & ikeybit, int batch_size,
        int maxwidth, int minwidth, int * tests, double * result_scores ) {
    const size_t   nbH       = hashes.size();
    const int      hashbits  = sizeof(hashtype) * 8;
    int            testcount = 0;
    int            startbit;

    std::vector<uint8_t> bins8(1 << maxwidth);
    std::vector<uint32_t> bins32;

    // To calculate the distributions of hash value slices, this loop does
    // random writes to the bins, so time is completely dominated by cache
    // performance. For ballpark numbers, think 2 cycles per hash if bins
    // fit in L1, 4 cycles in L2, and 8 cycles in L3.
    //
    // Since the number of bins is selected so the average occupancy of
    // each bin is in the range 5..10, the initial counts almost always fit
    // into a byte. Thus, there's a huge advantage to using 8-bit bins
    // where possible. The problem is, if the hash is bad, we might
    // overflow a bin.
    //
    // For now, when it happens that any count overflows 8 bits we go
    // straight to 32 bits. We could add a 16-bit bin code path, but it's
    // not clear it'd be worth the complexity.
    while ((startbit = FETCH_ADD(ikeybit, batch_size)) < hashbits) {
        const int stopbit = std::min(startbit + batch_size, hashbits);

        for (int start = startbit; start < stopbit; start++) {
            int    width    = maxwidth;
            size_t bincount = (1 << width);
            bool   bigbins  = false;          // Are we using 32-bit bins?

            memset(&bins8[0], 0, bincount * sizeof(bins8[0]));
            for (size_t j = 0; j < nbH; j++) {
                prefetch(&hashes[j + 4]);
                uint32_t index = hashes[j].window(start, width);

                if (unlikely(++bins8[index] == 0)) {
                    bigbins = true;
                    break;
                }
            }
            if (unlikely(bigbins)) {
                // Primary overflow, during initial counting.
                // XXX Maybe If we got far enough (j large enough), copy counts
                // and continue 8-bit loop?
                // printf("TestDistribution: Overflow %zu into %u: bit %d/%d\n", nbH, bincount, start, hashbits);
                bins32.clear();
                bins32.resize(bincount);
                for (size_t j = 0; j < nbH; j++) {
                    uint32_t index = hashes[j].window(start, width);
                    ++bins32[index];
                }
            }

            // Test the distribution, then fold the bins in half, and
            // repeat until we're down to 256 (== 1 << minwidth) bins.
            double * resultptr = &result_scores[start * (maxwidth - minwidth + 1)];
            while (true) {
                uint64_t sumsq = bigbins ? sumSquares(&bins32[0], bincount) :
                    sumSquares(&bins8[0], bincount);
                *resultptr++ = calcScore(sumsq, bincount, nbH);

                testcount++;
                width--;
                bincount /= 2;

                if (width < minwidth) { break; }

                // To allow the compiler to vectorize these loops
                assume((bincount % 64) == 0);
                if (bigbins) {
                    // Fold 32-bit bins in half
                    for (size_t i = 0; i < bincount; i++) {
                        bins32[i] += bins32[i + bincount];
                    }
                } else {
                    // Fold 8-bit bins in half and detect unsigned overflow. We
                    // can't easily just stop the loop when it happens, because
                    // some number of items have already been folded. I did try
                    // stopping this loop when overflow is detected, undoing
                    // just that addition, and then copying the first i
                    // non-overflowed items from bins8[] into bins32[] followed
                    // by summing the rest into bins32[] as "normal", but that
                    // ended up being slightly slower than this!
                    for (size_t i = 0; i < bincount; i++) {
                        uint8_t b = bins8[i + bincount];
                        uint8_t a = bins8[i] += b;
                        bigbins |= a < b;
                    }
                    if (bigbins) {
                        // Secondary overflow, during folding
                        bins32.resize(bincount);
                        for (size_t i = 0; i < bincount; i++) {
                            // This construction undoes the (possibly
                            // overflowed) addition in the previous loop.
                            uint8_t b = bins8[i + bincount];
                            uint8_t a = bins8[i] - b;
                            bins32[i] = (uint32_t)a + (uint32_t)b;
                        }
                    }
                }
            }
        }
    }

    *tests = testcount;
}

template <typename hashtype>
static bool TestDistribution( std::vector<hashtype> & hashes, int * logpp, bool verbose, bool drawDiagram ) {
    const int      hashbits = hashtype::bitlen;
    const size_t   nbH      = hashes.size();
    int            maxwidth = MaxDistBits(nbH);
    int            minwidth = 8;

    if (maxwidth < minwidth) {
        if (logpp != NULL) {
            *logpp = 0;
        }
        return true;
    }

    if (verbose) {
        printf("Testing distribution   (any  %2i..%2i bits)%s", minwidth, maxwidth, drawDiagram ? "\n[" : " - ");
    }

    std::vector<double> worst_scores(hashbits * (maxwidth - minwidth + 1));
    a_int istartbit( 0 );
    int tests;

    if (g_NCPU == 1) {
        TestDistributionBatch<hashtype>(hashes, istartbit, hashbits,
                maxwidth, minwidth, &tests, &worst_scores[0]);
    } else {
#if defined(HAVE_THREADS)
        std::thread t[g_NCPU];
        int ttests[g_NCPU];
        for (unsigned i = 0; i < g_NCPU; i++) {
            t[i] = std::thread {
                TestDistributionBatch<hashtype>, std::ref(hashes), std::ref(istartbit),
                hashbits/16, maxwidth, minwidth, &ttests[i], &worst_scores[0]
            };
        }
        tests = 0;
        for (unsigned i = 0; i < g_NCPU; i++) {
            t[i].join();
            tests += ttests[i];
        }
#endif
    }

    bool result = ReportDistribution(worst_scores, tests, hashbits, maxwidth, minwidth, logpp, verbose, drawDiagram);

    return result;
}

//-----------------------------------------------------------------------------
// Compute a number of statistical tests on a list of hashes, comparing
// them to a list of i.i.d. random numbers across a large range of bit
// widths. The precise test can vary depending on the bit width being
// tested.
//
// NB: This function is not intended to be used directly; see
// TestHashList() and class TestHashListWrapper in Analyze.h.
template <typename hashtype>
bool TestHashListImpl( std::vector<hashtype> & hashes, int testDeltaNum, int * logpSumPtr, KeyFn keyprint,
        bool drawDiagram, bool testCollision, bool testMaxColl, bool testDist,
        bool testHighBits, bool testLowBits, bool verbose ) {
    uint64_t const nbH    = hashes.size();
    bool           result = true;

    // If testDeltaNum is 1, then compute the difference between each hash
    // and its successor, and test that list of deltas. If it is greater
    // than 1, then do that same thing but *also* compute the difference
    // between each hash and the hash testDeltaNum hashes back and test
    // those deltas also.
    //
    // This must be done before the list of hashes is sorted below inside
    // TestCollisions(). The calls to test the list(s) of deltas come at
    // the bottom of this function.
    //
    // The ASM for these loops contains more mov instructions than seem
    // necessary, and even an extra cmp/je pair for the std::vector length,
    // but no matter how I tweak things to tighten the loop it always ends
    // up slower. Not a huge deal, but this is a hot spot.
    std::vector<hashtype> hashdeltas_1;
    std::vector<hashtype> hashdeltas_N;

    if (testDeltaNum >= 1) {
        hashdeltas_1.reserve(nbH - 1);

        hashtype hprv = hashes[0];
        for (size_t hnb = 1; hnb < nbH; hnb++) {
            hashtype h = hashes[hnb];
            hashdeltas_1.emplace_back(h ^ hprv);
            hprv = h;
        }

        if (testDeltaNum >= 2) {
            hashdeltas_N.reserve(nbH - testDeltaNum);

            for (size_t hnb = testDeltaNum; hnb < nbH; hnb++) {
                hashdeltas_N.emplace_back(hashes[hnb - testDeltaNum] ^ hashes[hnb]);
            }
        }
    }

    //----------

    if (testCollision) {
        result &= TestCollisions(hashes, logpSumPtr, testDist, testMaxColl,
                testHighBits, testLowBits, verbose, drawDiagram);
    }

    //----------

    if (testDist) {
        int curlogp;
        result &= TestDistribution(hashes, &curlogp, verbose, drawDiagram);
        if (logpSumPtr != NULL) {
            *logpSumPtr += curlogp;
        }
    }

    //----------

    if (testDeltaNum >= 1) {
        if (verbose) {
            printf("---Analyzing hash deltas\n");
        }
        result &= TestHashListImpl(hashdeltas_1, -1, logpSumPtr, keyprint, drawDiagram,
                testCollision, testMaxColl, testDist, testHighBits, testLowBits, verbose);

        if (testDeltaNum >= 2) {
            if (verbose) {
                printf("---Analyzing additional hash deltas\n");
            }
            result &= TestHashListImpl(hashdeltas_N, -testDeltaNum, logpSumPtr, keyprint, drawDiagram,
                    testCollision, testMaxColl, testDist, testHighBits, testLowBits, verbose);
        }
    }

    return result;
}

INSTANTIATE(TestHashListImpl, HASHTYPELIST);

#if 0
//----------------------------------------------------------------------------
// Bytepair test - generate 16-bit indices from all possible non-overlapping
// 8-bit sections of the hash value, check distribution on all of them.

// This is a very good test for catching weak intercorrelations between bits -
// much harder to pass than the normal distribution test. However, it doesn't
// really model the normal usage of hash functions in hash table lookup, so
// I'm not sure it's that useful (and hash functions that fail this test but
// pass the normal distribution test still work well in practice)

template <typename hashtype>
double TestDistributionBytepairs( std::vector<hashtype> & hashes, bool drawDiagram ) {
    const int hashbits = hashtype::bitlen;

    const int nbins    = 65536;

    std::vector<uint32_t> bins( nbins, 0 );

    double worst = 0;

    for (int a = 0; a < hashbits; a++) {
        if (drawDiagram) { if ((a % 8 == 0) && (a > 0)) { printf("\n"); } }

        if (drawDiagram) { printf("["); }

        for (int b = 0; b < hashbits; b++) {
            if (drawDiagram) { if ((b % 8 == 0) && (b > 0)) { printf(" "); } }

            bins.clear();
            bins.resize(nbins, 0);

            for (size_t i = 0; i < hashes.size(); i++) {
                uint32_t pa = window(hashes[i], a, 8);
                uint32_t pb = window(hashes[i], b, 8);

                bins[pa | (pb << 8)]++;
            }

            uint64_t sumsq = sumSquares(bins, nbins);
            double s = calcScore(sumsq, nbins, hashes.size());

            if (drawDiagram) { plot(s); }

            worst = std::max(worst, s);
        }

        if (drawDiagram) { printf("]\n"); }
    }

    return worst;
}

#endif /* 0 */
