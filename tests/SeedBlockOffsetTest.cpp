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
 *     Copyright (c) 2019-2020 Yann Collet
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
#include "Hashinfo.h"
#include "TestGlobals.h"
#include "Stats.h" // For chooseUpToK
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "SeedTest.h"

//-----------------------------------------------------------------------------

// Level 3: Generate the keys
template <typename hashtype, size_t blocklen>
static uint8_t * SeedBlockOffsetTest_Impl3( const HashFn hash, uint8_t * hashptr, size_t keylen_min,
        size_t keylen_max, size_t blockoffset, const seed_t seed, uint64_t numblock ) {
    uint8_t buf[keylen_max];

    memset(buf, 0, sizeof(buf));
    memcpy(buf + blockoffset, &numblock, blocklen);

    for (size_t keylen = keylen_min; keylen <= keylen_max; keylen++) {
        hash(buf, keylen, seed, hashptr);
        hashptr += sizeof(hashtype);
    }

    return hashptr;
}

// Level 2: Iterate over the seed and block values
template <typename hashtype, size_t blocklen, bool bigseed>
static void SeedBlockOffsetTest_Impl2( const HashInfo * hinfo, std::vector<hashtype> & hashes, size_t keylen_min,
        size_t keylen_max, size_t blockoffset, size_t seedmaxbits, size_t blockmaxbits ) {
    const HashFn hash    = hinfo->hashFn(g_hashEndian);
    uint8_t *    hashptr = (uint8_t *)&hashes[0];
    uint64_t     numseed, numblock;

    for (size_t seedbits = 1; seedbits <= seedmaxbits; seedbits++) {
        bool seeddone;
        numseed = (UINT64_C(1) << seedbits) - 1;
        do {
            const seed_t seed = hinfo->Seed(numseed);

            for (size_t blockbits = 1; blockbits <= blockmaxbits; blockbits++) {
                bool blockdone;
                numblock = (UINT64_C(1) << blockbits) - 1;
                do {
                    hashptr = SeedBlockOffsetTest_Impl3<hashtype, blocklen>(hash, hashptr,
                            keylen_min, keylen_max, blockoffset, seed, numblock);

                    /* Next lexicographic bit pattern, from "Bit Twiddling Hacks" */
                    uint64_t t = (numblock | (numblock - 1)) + 1;
                    numblock  = t | ((((t & -t) / (numblock & -numblock)) >> 1) - 1);
                    blockdone = (blocklen == 8) ? (numblock == ~0) : ((numblock >> 32) != 0);
                } while (!blockdone);
            }

            /* Next lexicographic bit pattern, from "Bit Twiddling Hacks" */
            uint64_t t = (numseed | (numseed - 1)) + 1;
            numseed  = t | ((((t & -t) / (numseed & -numseed)) >> 1) - 1);
            seeddone = bigseed ? (numseed == ~0) : ((numseed >> 32) != 0);
        } while (!seeddone);
    }
}

// Level 1: print out header, allocate hash vector, generate hashes, test them
template <typename hashtype, size_t blocklen>
static bool SeedBlockOffsetTest_Impl1( const HashInfo * hinfo, size_t keylen_min, size_t keylen_max,
        size_t blockoffset, size_t seedmaxbits, size_t blockmaxbits ) {
    // Compute the number of hashes that will be generated
    size_t testseeds = 0;

    for (size_t seedbits = 1; seedbits <= seedmaxbits; seedbits++) {
        testseeds += chooseK(hinfo->is32BitSeed() ? 32 : 64, seedbits);
    }

    size_t testblocks = 0;
    for (size_t blockbits = 1; blockbits <= blockmaxbits; blockbits++) {
        testblocks += chooseK(blocklen * 8, blockbits);
    }

    size_t testkeys   = keylen_max - keylen_min + 1;

    size_t totaltests = testseeds * testblocks * testkeys;

    // Print out a test header
    printf("Keyset 'SeedBlockOffset' - [%zd..%zd]-byte keys with block at offset %zd - %" PRId64 " hashes\n",
            keylen_min, keylen_max, blockoffset, totaltests);

    if ((totaltests < 10000) || (totaltests > 110000000)) { printf("Skipping\n\n"); return true; }

    // Reserve memory for the hashes
    std::vector<hashtype> hashes( totaltests );

    // Generate the hashes, test them, and record the results
    if (hinfo->is32BitSeed()) {
        SeedBlockOffsetTest_Impl2<hashtype, blocklen, false>(hinfo, hashes, keylen_min,
                keylen_max, blockoffset, seedmaxbits, blockmaxbits);
    } else {
        SeedBlockOffsetTest_Impl2<hashtype, blocklen, true>(hinfo, hashes, keylen_min,
                keylen_max, blockoffset, seedmaxbits, blockmaxbits);
    }

    bool result = TestHashList(hashes).drawDiagram(false);
    printf("\n");

    recordTestResult(result, "SeedBlockOffset", blockoffset);

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool SeedBlockOffsetTest( const HashInfo * hinfo, const bool verbose, const bool extra ) {
    constexpr size_t seedbits  = 2;
    constexpr size_t blockbits = 2;
    constexpr size_t blocklen  = 4;
    const size_t     maxoffset = extra ? 9 : 5;

    printf("[[[ Seed BlockOffset Tests ]]]\n\n");

    printf("Seeds have up to %zd bits set, %zd-byte blocks have up to %zd bits set\n\n",
            seedbits, blocklen, blockbits);

    bool result = true;

    for (size_t blockoffset = 0; blockoffset <= maxoffset; blockoffset++) {
        const size_t minkeylen = blocklen + blockoffset;
        const size_t maxkeylen = 31;
        result &= SeedBlockOffsetTest_Impl1<hashtype, blocklen>(hinfo, minkeylen,
                maxkeylen, blockoffset, seedbits, blockbits);
    }

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(SeedBlockOffsetTest, HASHTYPELIST);
