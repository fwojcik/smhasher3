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

//-----------------------------------------------------------------------------
// Simpler differential-distribution test - for all 1-bit differentials,
// generate random key pairs and run full distribution/collision tests on the
// hash differentials

template <typename hashtype, bool bigseed>
static bool SeedDiffDistTest( const HashInfo * hinfo, int keybits, bool drawDiagram ) {
    const HashFn hash = hinfo->hashFn(g_hashEndian);

    int       seedbytes = bigseed ? 8 : 4;
    int       seedbits  = seedbytes * 8;
    int       keybytes  = keybits / 8;
    const int keycount  = 512 * 1024 * 3;

    std::vector<hashtype> worsthashes;
    int worstlogp    = -1;
    int worstseedbit = -1;
    int fails        =  0;

    std::vector<hashtype> hashes( keycount );
    std::vector<uint8_t>  keys( keycount * keybytes );
    std::vector<uint8_t>  seeds( keycount * seedbytes );
    hashtype h1, h2;

    Rand r( 482813 + keybytes );

    bool result = true;

    if (!drawDiagram) {
        printf("Testing %3d-byte keys, %2d-bit seeds, %d reps", keybytes, seedbits, keycount);
    }

    for (int seedbit = 0; seedbit < seedbits; seedbit++) {
        if (drawDiagram) {
            printf("Testing seed bit %d / %d - %3d-byte keys - %d keys\n",
                    seedbit, seedbits, keybytes, keycount);
        }

        // Use a new sequence of keys for every seed bit tested
        RandSeq rsK = r.get_seq(SEQ_DIST_1, keybytes);
        rsK.write(&keys[0], 0, keycount);
        addVCodeInput(&keys[0], keycount * keybytes);

        // Use a new sequence of seeds for every seed bit tested also
        RandSeq rsS = r.get_seq(SEQ_DIST_2, seedbytes);
        rsS.write(&seeds[0], 0, keycount);

        const uint8_t * keyptr = &keys[0];
        const uint8_t * seedptr = &seeds[0];
        uint64_t baseseed = 0;
        seed_t curseed;
        for (int i = 0; i < keycount; i++) {
            memcpy(&baseseed, seedptr, seedbytes);

            curseed = hinfo->getFixedSeed((seed_t)baseseed);

            addVCodeInput(curseed);
            seed_t hseed1 = hinfo->Seed(curseed, HashInfo::SEED_FORCED);
            hash(keyptr, keybytes, hseed1, &h1);

            curseed ^= (UINT64_C(1) << seedbit);

            addVCodeInput(curseed);
            seed_t hseed2 = hinfo->Seed(curseed, HashInfo::SEED_FORCED);
            hash(keyptr, keybytes, hseed2, &h2);

            keyptr += keybytes;
            seedptr += seedbytes;

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
    }

    if (!drawDiagram) {
        printf("%3d failed, worst is seed bit %3d%s\n", fails, worstseedbit, result ? "" : "   !!!!!");
        bool ignored = TestHashList(worsthashes).testDistribution(true);
        (void)ignored;
        printf("\n");
    }

    recordTestResult(result, "SeedDiffDist", keybytes);

    return result;
}

//----------------------------------------------------------------------------

template <typename hashtype>
bool SeedDiffDistTest( const HashInfo * hinfo, const bool verbose, const bool extra ) {
    bool result = true;

    printf("[[[ Seed 'Differential Distribution' Tests ]]]\n\n");

    if (hinfo->is32BitSeed()) {
        result &= SeedDiffDistTest<hashtype, false>(hinfo, 24, verbose);
        result &= SeedDiffDistTest<hashtype, false>(hinfo, 32, verbose);
        result &= SeedDiffDistTest<hashtype, false>(hinfo, 64, verbose);
        if (extra && !hinfo->isSlow()) {
            result &= SeedDiffDistTest<hashtype, false>(hinfo, 160, verbose);
            result &= SeedDiffDistTest<hashtype, false>(hinfo, 256, verbose);
        }
    } else {
        result &= SeedDiffDistTest<hashtype,  true>(hinfo, 24, verbose);
        result &= SeedDiffDistTest<hashtype,  true>(hinfo, 32, verbose);
        result &= SeedDiffDistTest<hashtype,  true>(hinfo, 64, verbose);
        if (extra && !hinfo->isSlow()) {
            result &= SeedDiffDistTest<hashtype,  true>(hinfo, 160, verbose);
            result &= SeedDiffDistTest<hashtype,  true>(hinfo, 256, verbose);
        }
    }
    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(SeedDiffDistTest, HASHTYPELIST);
