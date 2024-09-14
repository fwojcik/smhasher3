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

#include "BitflipTest.h"

//-----------------------------------------------------------------------------
// Simple bitflip test - for all 1-bit differentials, generate random keys,
// apply the differential, and run full distribution/collision tests on the
// hashes and their deltas.

template <typename hashtype>
static bool BitflipTestImpl( const HashInfo * hinfo, unsigned keybits, const seed_t seed, flags_t flags ) {
    const HashFn   hash     = hinfo->hashFn(g_hashEndian);
    const unsigned keycount = 512 * 1024 * ((hinfo->bits <= 64) ? 3 : 4);
    unsigned       keybytes = keybits / 8;

    std::vector<hashtype> worsthashes;
    int worstlogp   = -1;
    int worstkeybit = -1;
    int fails       =  0;

    std::vector<hashtype> hashes( keycount * 2 ), hashes_copy;
    std::vector<uint8_t>  keys( keycount * keybytes );

    Rand r( 84574, keybytes );

    bool result = true;

    if (!REPORT(VERBOSE, flags)) {
        printf("Testing %3d-byte keys, %d reps", keybytes, keycount);
    }

    for (unsigned keybit = 0; keybit < keybits; keybit++) {
        if (REPORT(VERBOSE, flags)) {
            printf("Testing bit %d / %d - %d keys\n", keybit, keybits, keycount);
        }

        // Use a new sequence of keys for every key bit tested. Note that
        // SEQ_DIST_2 is enough to ensure there are no collisions, because
        // only 1 bit _position_ is flipped per set of keys, and (x ^ bitN)
        // ^ (y ^ bitN) == x ^ y, which must have at least 2 set bits.
        RandSeq rs = r.get_seq(SEQ_DIST_2, keybytes);
        rs.write(&keys[0], 0, keycount);

        for (unsigned i = 0; i < keycount; i++) {
            ExtBlob k( &keys[i * keybytes], keybytes );

            hash(k, keybytes, seed, &hashes[2 * i]);
            addVCodeInput(k, keybytes);

            k.flipbit(keybit);

            hash(k, keybytes, seed, &hashes[2 * i + 1]);
            addVCodeInput(k, keybytes);

            // Restore the bit to its original value, for dumpFailKeys()
            k.flipbit(keybit);
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
                    ExtBlob k(&keys[(i >> 1) * keybytes], keybytes); hashtype v;
                    if (i & 1) { k.flipbit(keybit); }
                    hash(k, keybytes, seed, &v);
                    printf("0x%016" PRIx64 "\t", g_seed); k.printbytes(NULL);
                    printf("\t"); v.printhex(NULL);
                    if (i & 1) { k.flipbit(keybit); }
            });
        if (REPORT(VERBOSE, flags)) {
            printf("\n");
        } else {
            progressdots(keybit, 0, keybits - 1, 20);
            // Record worst result, but don't let a pass override a failure
            if ((fails == 0) && !thisresult) {
                worstlogp = -1;
            }
            if (((fails == 0) || !thisresult) && (worstlogp < curlogp)) {
                worstlogp   = curlogp;
                worstkeybit = keybit;
                worsthashes = hashes_copy;
            }
            if (!thisresult) {
                fails++;
            }
        }

        addVCodeResult(thisresult);

        result &= thisresult;
    }

    if (!REPORT(VERBOSE, flags)) {
        printf("%3d failed, worst is key bit %3d%s\n", fails, worstkeybit, result ? "" : "        !!!!!");
        bool ignored = TestHashList(worsthashes).testDistribution(true).testDeltas(2);
        unused(ignored);
        printf("\n");
    }

    recordTestResult(result, "Bitflip", keybytes);

    return result;
}

//----------------------------------------------------------------------------

template <typename hashtype>
bool BitflipTest( const HashInfo * hinfo, bool extra, flags_t flags ) {
    bool result = true;

    printf("[[[ Keyset 'Bitflip' Tests ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed);

    result &= BitflipTestImpl<hashtype>(hinfo, 24, seed, flags);
    result &= BitflipTestImpl<hashtype>(hinfo, 32, seed, flags);
    result &= BitflipTestImpl<hashtype>(hinfo, 64, seed, flags);
    if (extra && !hinfo->isVerySlow()) {
        result &= BitflipTestImpl<hashtype>(hinfo, 160, seed, flags);
        result &= BitflipTestImpl<hashtype>(hinfo, 256, seed, flags);
    }
    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(BitflipTest, HASHTYPELIST);
