/*
 * SMHasher3
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
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

#define MAXLEN (1024 + 32)

//-----------------------------------------------------------------------------
// Keyset 'SeedSparse' - hash "sphinx of black quartz..." using seeds with few
// bits set

template <typename hashtype, uint32_t maxbits, bool bigseed>
static bool SeedSparseTestImpl( const HashInfo * hinfo, uint32_t keylen, flags_t flags ) {
    assert(maxbits < 16   );
    assert(keylen < MAXLEN);
    const HashFn hash      = hinfo->hashFn(g_hashEndian);
    uint64_t     totalkeys = 1 + chooseUpToK(bigseed ? 64 : 32, maxbits);
    uint64_t     cnt       = 0;

    printf("Keyset 'SeedSparse' - %3d-byte keys - seeds with up to %2d bits set - %" PRId64 " seeds\n",
            keylen, maxbits, totalkeys);

    const char text[64]    = "Sphinx of black quartz, judge my vow";
    const int  textlen     = (int)strlen(text);
    char       key[MAXLEN] = { 0 };
    for (size_t i = 0; i < keylen / textlen; i++) {
        memcpy(&key[i * textlen], text, textlen);
    }
    memcpy(&key[keylen / textlen * textlen], text, keylen % textlen);

    addVCodeInput(key, keylen);
    addVCodeInput(totalkeys);

    //----------

    std::vector<hashtype> hashes( totalkeys );

    if (hinfo->isDoNothing()) {
        std::fill(hashes.begin(), hashes.end(), 0);
    }

    seed_t hseed = hinfo->Seed(0, HashInfo::SEED_FORCED);
    hash(key, keylen, hseed, &hashes[cnt++]);

    for (seed_t i = 1; i <= maxbits; i++) {
        uint64_t iseed = (UINT64_C(1) << i) - 1;

        do {
            hseed = hinfo->Seed(iseed, HashInfo::SEED_FORCED);
            hash(key, keylen, hseed, &hashes[cnt++]);
            iseed = nextlex(iseed, bigseed ? 64 : 32);
        } while (iseed != 0);
    }

    auto keyprint = [&]( hidx_t i ) {
                seed_t   setbits = InverseKChooseUpToK(i, 0, maxbits, bigseed ? 64 : 32);
                seed_t   iseed   = nthlex(i, setbits);
                seed_t   hseed   = hinfo->Seed(iseed, HashInfo::SEED_FORCED);
                hashtype v( 0 );

                printf("0x%016" PRIx64 "\t\"%.*s\"\t", (uint64_t)iseed, keylen, key);
                hash(key, keylen, hseed, &v);
                v.printhex(NULL);
            };

    bool result = TestHashList(hashes).reportFlags(flags).testDeltas(1).dumpFailKeys(keyprint);

    printf("\n");

    recordTestResult(result, "SeedSparse", keylen);

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool SeedSparseTest( const HashInfo * hinfo, flags_t flags ) {
    bool result = true;

    printf("[[[ Keyset 'SeedSparse' Tests ]]]\n\n");

    const std::set<uint32_t> testkeylens = { 2, 3, 6, 15, 18, 31, 52, 80, 200, 1025 };

    if (hinfo->is32BitSeed()) {
        for (const auto testkeylen: testkeylens) {
            result &= SeedSparseTestImpl<hashtype, 7, false>(hinfo, testkeylen, flags);
        }
    } else {
        for (const auto testkeylen: testkeylens) {
            result &= SeedSparseTestImpl<hashtype, 5,  true>(hinfo, testkeylen, flags);
        }
    }

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(SeedSparseTest, HASHTYPELIST);
