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
#include "Stats.h" // For EstimateNbCollisions
#include "Random.h"
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "CyclicKeysetTest.h"

#include <unordered_set>

//-----------------------------------------------------------------------------
// Keyset 'Cyclic' - generate keys that consist solely of N repetitions of M
// bytes.
//
// (This keyset type is designed to make MurmurHash2 fail)

template <typename hashtype, int cycleLen, bool ckuniq = (cycleLen < 6)>
static bool CyclicKeyImpl( HashFn hash, const seed_t seed, int cycleReps, const int keycount, bool drawDiagram ) {
    printf("Keyset 'Cyclic' - %d cycles of %d bytes - %d keys\n", cycleReps, cycleLen, keycount);

    Rand r( 483723 + 4883 * cycleReps + cycleLen );

    std::vector<hashtype> hashes;
    hashes.resize(keycount);

    int keyLen      = cycleLen * cycleReps;

    uint8_t * cycle = new uint8_t[cycleLen];
    uint8_t * key   = new uint8_t[keyLen  ];

    std::unordered_set<uint64_t> seen; // need to be unique, otherwise we report collisions
    uint64_t curcycle = 0;

    //----------

    for (int i = 0; i < keycount; i++) {
        r.rand_p(cycle, cycleLen);
        if (ckuniq) {
            memcpy(&curcycle, cycle, cycleLen);
            if (seen.count(curcycle) > 0) { // not unique
                i--;
                continue;
            }
            seen.insert(curcycle);
        }

        for (int j = 0; j < cycleReps; j++) {
            memcpy(&key[j * cycleLen], cycle, cycleLen);
        }

        hash(key, keyLen, seed, &hashes[i]);
        addVCodeInput(key, keyLen);
    }

    //----------

    bool result = TestHashList(hashes).drawDiagram(drawDiagram).testDistribution(false);
    printf("\n");

    delete [] key;
    delete [] cycle;

    addVCodeResult(result);

    char buf[32];
    snprintf(buf, sizeof(buf), "%d cycles of %d bytes", cycleReps, cycleLen);
    recordTestResult(result, "Cyclic", buf);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool CyclicKeyTest( const HashInfo * hinfo, const bool verbose ) {
    const HashFn hash   = hinfo->hashFn(g_hashEndian);
    bool         result = true;

    printf("[[[ Keyset 'Cyclic' Tests ]]]\n\n");

    const int    reps = hinfo->isVerySlow() ? 100000 : 1000000;
    const seed_t seed = hinfo->Seed(g_seed);

    for (int count = 4; count <= 16; count += 4) {
        result &= CyclicKeyImpl<hashtype, 3>(hash, seed, count, reps, verbose);
        result &= CyclicKeyImpl<hashtype, 4>(hash, seed, count, reps, verbose);
        result &= CyclicKeyImpl<hashtype, 5>(hash, seed, count, reps, verbose);
        result &= CyclicKeyImpl<hashtype, 8>(hash, seed, count, reps, verbose);
    }

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(CyclicKeyTest, HASHTYPELIST);
