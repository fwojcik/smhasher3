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

#include "SeedBitflipTest.h"

//-----------------------------------------------------------------------------
// Simple bitflip test - for all 1-bit differentials, generate random keys
// and seeds, apply the differential to the seed, and run full
// distribution/collision tests on the hashes and their deltas.

template <typename hashtype, bool bigseed>
static bool SeedBitflipTestImpl( const HashInfo * hinfo, unsigned keybits, flags_t flags ) {
    const HashFn   hash      = hinfo->hashFn(g_hashEndian);
    unsigned       seedbytes = bigseed ? 8 : 4;
    unsigned       seedbits  = seedbytes * 8;
    unsigned       keybytes  = keybits / 8;
    const unsigned keycount  = 512 * 1024 * 3;

    std::vector<hashtype> worsthashes;
    int worstlogp    = -1;
    int worstseedbit = -1;
    int fails        =  0;

    std::vector<hashtype> hashes( keycount * 2 ), hashes_copy;
    std::vector<uint8_t>  keys( keycount * keybytes );
    std::vector<uint8_t>  seeds( keycount * seedbytes );

    Rand r( 18734, keybytes );

    bool result = true;

    if (!REPORT(VERBOSE, flags)) {
        printf("Testing %3d-byte keys, %2d-bit seeds, %d reps", keybytes, seedbits, keycount);
    }

    for (unsigned seedbit = 0; seedbit < seedbits; seedbit++) {
        if (REPORT(VERBOSE, flags)) {
            printf("Testing seed bit %d / %d - %3d-byte keys - %d keys\n", seedbit, seedbits, keybytes, keycount);
        }

        // Use a new sequence of keys for every seed bit tested
        RandSeq rsK = r.get_seq(SEQ_DIST_1, keybytes);
        rsK.write(&keys[0], 0, keycount);
        addVCodeInput(&keys[0], keycount * keybytes);

        // Use a new sequence of seeds for every seed bit tested also. Note
        // that SEQ_DIST_2 is enough to ensure there are no collisions,
        // because only 1 bit _position_ is flipped per set of seeds, and
        // (x ^ N) ^ (y ^ N) == x ^ y, which must have at least 2 set bits.
        RandSeq rsS = r.get_seq(SEQ_DIST_2, seedbytes);
        rsS.write(&seeds[0], 0, keycount);

        const uint8_t * keyptr  = &keys[0];
        const uint8_t * seedptr = &seeds[0];
        seed_t curseed = 0, hseed1, hseed2;
        for (unsigned i = 0; i < keycount; i++) {
            memcpy(&curseed, seedptr, seedbytes);
            curseed = hinfo->getFixedSeed(curseed);

            addVCodeInput(curseed);
            hseed1 = hinfo->Seed(curseed, HashInfo::SEED_FORCED);
            hash(keyptr, keybytes, hseed1, &hashes[2 * i]);

            curseed ^= (UINT64_C(1) << seedbit);

            addVCodeInput(curseed);
            hseed2 = hinfo->Seed(curseed, HashInfo::SEED_FORCED);
            hash(keyptr, keybytes, hseed2, &hashes[2 * i + 1]);

            keyptr  += keybytes;
            seedptr += seedbytes;
        }

        // If VERBOSE reporting isn't enabled, then each test isn't being
        // reported on, and so there might need to be a failure summary at
        // the end of testing. If that's true, then keep a copy of the
        // original list of hashes, since TestHashList() will modify it.
        if (!REPORT(VERBOSE, flags)) {
            hashes_copy = hashes;
        }

        int  curlogp    = 0;
        bool thisresult = TestHashList(hashes).testDistribution(true).
                reportFlags(flags).quiet(!REPORT(VERBOSE, flags)).
                sumLogp(&curlogp).testDeltas(2).dumpFailKeys([&]( hidx_t i ) {
                    ExtBlob k(&keys[(i >> 1) * keybytes], keybytes);
                    hashtype v; seed_t iseed, hseed;

                    memcpy(&iseed, &seeds[(i >> 1) * seedbytes], seedbytes);
                    iseed = hinfo->getFixedSeed(iseed);
                    if (i & 1) { iseed ^= (UINT64_C(1) << seedbit); }
                    hseed = hinfo->Seed(iseed, HashInfo::SEED_FORCED);

                    hash(k, keybytes, hseed, &v);
                    printf("0x%016" PRIx64 "\t", (uint64_t)iseed); k.printbytes(NULL);
                    printf("\t"); v.printhex(NULL);
            });
        if (REPORT(VERBOSE, flags)) {
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
                worsthashes  = hashes_copy;
            }
            if (!thisresult) {
                fails++;
            }
        }

        addVCodeResult(thisresult);

        result &= thisresult;
    }

    if (!REPORT(VERBOSE, flags)) {
        printf("%3d failed, worst is seed bit %3d%s\n", fails, worstseedbit, result ? "" : "   !!!!!");
        bool ignored = TestHashList(worsthashes).testDistribution(true).testDeltas(2);
        unused(ignored);
        printf("\n");
    }

    recordTestResult(result, "SeedBitflip", keybytes);

    return result;
}

//----------------------------------------------------------------------------

template <typename hashtype>
bool SeedBitflipTest( const HashInfo * hinfo, bool extra, flags_t flags ) {
    bool result = true;

    printf("[[[ Seed Bitflip Tests ]]]\n\n");

    if (hinfo->is32BitSeed()) {
        result &= SeedBitflipTestImpl<hashtype, false>(hinfo, 24, flags);
        result &= SeedBitflipTestImpl<hashtype, false>(hinfo, 32, flags);
        result &= SeedBitflipTestImpl<hashtype, false>(hinfo, 64, flags);
        if (extra && !hinfo->isSlow()) {
            result &= SeedBitflipTestImpl<hashtype, false>(hinfo, 160, flags);
            result &= SeedBitflipTestImpl<hashtype, false>(hinfo, 256, flags);
        }
    } else {
        result &= SeedBitflipTestImpl<hashtype,  true>(hinfo, 24, flags);
        result &= SeedBitflipTestImpl<hashtype,  true>(hinfo, 32, flags);
        result &= SeedBitflipTestImpl<hashtype,  true>(hinfo, 64, flags);
        if (extra && !hinfo->isSlow()) {
            result &= SeedBitflipTestImpl<hashtype,  true>(hinfo, 160, flags);
            result &= SeedBitflipTestImpl<hashtype,  true>(hinfo, 256, flags);
        }
    }
    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(SeedBitflipTest, HASHTYPELIST);
