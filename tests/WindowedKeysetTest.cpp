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
#include "Stats.h" // For EstimateNbCollisions
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "WindowedKeysetTest.h"

#include <math.h>

//-----------------------------------------------------------------------------
// Keyset 'Window' - for all possible N-bit windows of a K-bit key, generate
// all possible keys with bits set in that window

template <typename keytype, typename hashtype>
static bool WindowedKeyImpl( HashFn hash, const seed_t seed, int windowbits, bool verbose, bool extra ) {
    const int keybits  = sizeof(keytype ) * 8;
    const int hashbits = sizeof(hashtype) * 8;
    // calc keycount to expect min. 0.5 collisions: EstimateNbCollisions, except for 64++bit.
    // there limit to 2^25 = 33554432 keys
    int keycount = 1 << windowbits;

    while (EstimateNbCollisions(keycount, hashbits) < 0.5 && windowbits < 25) {
        if ((int)log2(2.0 * keycount) < 0) { // overflow
            break;
        }
        keycount  *= 2;
        windowbits = (int)log2(1.0 * keycount);
        // printf (" enlarge windowbits to %d (%d keys)\n", windowbits, keycount);
        // fflush (NULL);
    }

    std::vector<hashtype> hashes;
    hashes.resize(keycount);

    bool result    = true;
    int  testcount = keybits;

    printf("Keyset 'Window' - %3d-bit key, %3d-bit window - %d tests - %d keys\n",
            keybits, windowbits, testcount, keycount);

    for (int j = 0; j < testcount; j++) {
        int     minbit = j;
        keytype key;

        for (int i = 0; i < keycount; i++) {
            key = i;
            key.lrot(minbit);
            hash(&key, sizeof(keytype), seed, &hashes[i]);
            addVCodeInput(&key, sizeof(keytype));
        }

        printf("Window at bit %3d\n", j);

        // Skip distribution test for these by default - they're too easy
        // to distribute well, and it generates a _lot_ of testing. Also
        // don't test high/low bits, so as to not clutter the screen.
        bool thisresult = TestHashList(hashes).drawDiagram(verbose).testDistribution(extra).
                testHighBits(false).testLowBits(false);

        recordTestResult(thisresult, "Windowed", j);

        addVCodeResult(thisresult);

        result &= thisresult;
    }

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool WindowedKeyTest( const HashInfo * hinfo, const bool verbose, const bool extra ) {
    const HashFn hash   = hinfo->hashFn(g_hashEndian);
    bool         result = true;
    // This value is now adjusted to generate at least 0.5 collisions per window,
    // except for 64++bit where it unrealistic. There use smaller but more keys,
    // to get a higher collision percentage.
    int windowbits         = 20;
    constexpr int hashbits = sizeof(hashtype) * 8;
    constexpr int keybits  = (hashbits >= 64) ? 32 : 72;

    printf("[[[ Keyset 'Window' Tests (deprecated) ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed);

    result &= WindowedKeyImpl<Blob<keybits>, hashtype>(hash, seed, windowbits, verbose, extra);

    printf("\n%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(WindowedKeyTest, HASHTYPELIST);
