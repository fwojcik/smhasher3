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

//-----------------------------------------------------------------------------
// Keyset 'Cyclic' - generate keys that consist solely of N repetitions of M
// bytes.
//
// (This keyset type is designed to make MurmurHash2 fail)

static inline uint32_t f3mix( uint32_t k ) {
    k ^= k >> 16;
    k *= 0x85ebca6b;
    k ^= k >> 13;
    k *= 0xc2b2ae35;
    k ^= k >> 16;

    return k;
}

template <typename hashtype>
static bool CyclicKeyImpl( HashFn hash, const seed_t seed, int cycleLen,
        int cycleReps, const int keycount, bool drawDiagram ) {
    printf("Keyset 'Cyclic' - %d cycles of %d bytes - %d keys\n", cycleReps, cycleLen, keycount);

    Rand r( 483723 );

    std::vector<hashtype> hashes;
    hashes.resize(keycount);

    int keyLen      = cycleLen * cycleReps;

    uint8_t * cycle = new uint8_t[cycleLen + 16];
    uint8_t * key   = new uint8_t[keyLen       ];

    //----------

    for (int i = 0; i < keycount; i++) {
        r.rand_p(cycle, cycleLen);

        *(uint32_t *)cycle = f3mix(i ^ 0x746a94f1);

        for (int j = 0; j < keyLen; j++) {
            key[j] = cycle[j % cycleLen];
        }

        hash(key, keyLen, seed, &hashes[i]);
        addVCodeInput(key, keyLen);
    }

    //----------

    bool result = TestHashList(hashes, drawDiagram);
    printf("\n");

    delete [] key;
    delete [] cycle;

    addVCodeResult(result);

    recordTestResult(result, "Cyclic", cycleLen);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool CyclicKeyTest( const HashInfo * hinfo, const bool verbose ) {
    const HashFn hash   = hinfo->hashFn(g_hashEndian);
    bool         result = true;

#if defined(DEBUG)
    const int reps = 2;
#else
    const int reps = hinfo->isVerySlow() ? 100000 : 1000000;
#endif

    printf("[[[ Keyset 'Cyclic' Tests ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed);

    result &= CyclicKeyImpl<hashtype>(hash, seed, sizeof(hashtype) + 0, 8, reps, verbose);
    result &= CyclicKeyImpl<hashtype>(hash, seed, sizeof(hashtype) + 1, 8, reps, verbose);
    result &= CyclicKeyImpl<hashtype>(hash, seed, sizeof(hashtype) + 2, 8, reps, verbose);
    result &= CyclicKeyImpl<hashtype>(hash, seed, sizeof(hashtype) + 3, 8, reps, verbose);
    result &= CyclicKeyImpl<hashtype>(hash, seed, sizeof(hashtype) + 4, 8, reps, verbose);
    result &= CyclicKeyImpl<hashtype>(hash, seed, sizeof(hashtype) + 8, 8, reps, verbose);

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(CyclicKeyTest, HASHTYPELIST);
