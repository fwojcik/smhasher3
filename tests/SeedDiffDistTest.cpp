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
#include "Random.h"
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "SeedDiffDistTest.h"

#include <unordered_set>

//-----------------------------------------------------------------------------
// Simpler differential-distribution test - for all 1-bit differentials,
// generate random key pairs and run full distribution/collision tests on the
// hash differentials

template <typename keytype, typename hashtype, bool bigseed, bool ckuniq = (sizeof(keytype) < 6)>
static bool SeedDiffDistTest( const HashInfo * hinfo, bool drawDiagram ) {
    const HashFn hash = hinfo->hashFn(g_hashEndian);
    Rand r( 482813 + sizeof(keytype) );

    int       seedbits = bigseed ? 64 : 32;
    int       keybits  = sizeof(keytype) * 8;
    const int keycount = 512 * 1024 * (ckuniq ? 2 : 3);
    keytype   k;

    std::vector<hashtype> worsthashes;
    int worstlogp    = -1;
    int worstseedbit = -1;
    int fails        =  0;

    std::vector<hashtype> hashes( keycount );
    hashtype h1, h2;

    std::unordered_set<uint64_t> seenkeys;
    uint64_t curkey = 0;

    std::unordered_set<uint64_t> seenseeds;
    uint64_t curseed = 0;

    bool result = true;

    if (!drawDiagram) {
        printf("Testing %3zd-byte keys, %2d-bit seeds, %d reps", sizeof(keytype), seedbits, keycount);
    }

    for (int seedbit = 0; seedbit < seedbits; seedbit++) {
        if (drawDiagram) {
            printf("Testing seed bit %d / %d - %3zd-byte keys - %d keys\n",
                    seedbit, seedbits, sizeof(keytype), keycount);
        }

        for (int i = 0; i < keycount; i++) {
            r.rand_p(&k, sizeof(keytype));

            if (ckuniq) {
                memcpy(&curkey, &k, sizeof(keytype));
                if (seenkeys.count(curkey) > 0) { // not unique
                    i--;
                    continue;
                }
                seenkeys.insert(curkey);
            }

            r.rand_p(&curseed, bigseed ? 8 : 4);
            if (!bigseed) {
                if (seenseeds.count(curseed) > 0) { // not unique
                    i--;
                    continue;
                }
                seenseeds.insert(curseed);
            }

            seed_t hseed1 = hinfo->Seed(curseed, false);
            hash(&k, sizeof(keytype), hseed1, &h1);
            seed_t hseed2 = hinfo->Seed(curseed ^ (UINT64_C(1) << seedbit), false);
            hash(&k, sizeof(keytype), hseed2, &h2);

            addVCodeInput(&k, sizeof(keytype));
            addVCodeInput(curseed);

            hashes[i] = h1 ^ h2;
        }

        int curlogp = 0;
        bool thisresult = TestHashList(hashes).testDistribution(true).verbose(drawDiagram).drawDiagram(drawDiagram).sumLogp(&curlogp);
        if (drawDiagram) {
            printf("\n");
        } else {
            progressdots(seedbit, 0, seedbits - 1, 10);
            // Record worst result, but don't let a pass override a failure
            if ((fails == 0) && !thisresult) {
                worstlogp = -1;
            }
            if (((fails == 0) || !thisresult) && (worstlogp < curlogp)) {
                worstlogp    = curlogp;
                worstseedbit = seedbit;
                worsthashes  = hashes;
            }
            if (!thisresult) {
                fails++;
            }
        }

        addVCodeResult(thisresult);

        result &= thisresult;

        seenkeys.clear();
        seenseeds.clear();
    }

    if (!drawDiagram) {
        printf("%3d failed, worst is seed bit %3d%s\n", fails, worstseedbit, result ? "" : "   !!!!!");
        bool ignored = TestHashList(worsthashes).testDistribution(true);
        printf("\n");
    }

    recordTestResult(result, "SeedDiffDist", sizeof(keytype));

    return result;
}

//----------------------------------------------------------------------------

template <typename hashtype>
bool SeedDiffDistTest( const HashInfo * hinfo, const bool verbose, const bool extra ) {
    bool result = true;

    printf("[[[ Seed 'Differential Distribution' Tests ]]]\n\n");

    if (hinfo->is32BitSeed()) {
        // result &= SeedDiffDistTest<Blob< 24>, hashtype, false>(hinfo, verbose);
        result &= SeedDiffDistTest<Blob<32>, hashtype, false>(hinfo, verbose);
        result &= SeedDiffDistTest<Blob<64>, hashtype, false>(hinfo, verbose);
        if (extra && !hinfo->isSlow()) {
            result &= SeedDiffDistTest<Blob<160>, hashtype, false>(hinfo, verbose);
            result &= SeedDiffDistTest<Blob<256>, hashtype, false>(hinfo, verbose);
        }
    } else {
        // result &= SeedDiffDistTest<Blob< 24>, hashtype,  true>(hinfo, verbose);
        result &= SeedDiffDistTest<Blob<32>, hashtype,  true>(hinfo, verbose);
        result &= SeedDiffDistTest<Blob<64>, hashtype,  true>(hinfo, verbose);
        if (extra && !hinfo->isSlow()) {
            result &= SeedDiffDistTest<Blob<160>, hashtype,  true>(hinfo, verbose);
            result &= SeedDiffDistTest<Blob<256>, hashtype,  true>(hinfo, verbose);
        }
    }
    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(SeedDiffDistTest, HASHTYPELIST);
