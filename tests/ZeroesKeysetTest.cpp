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
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "ZeroesKeysetTest.h"

//-----------------------------------------------------------------------------
// Keyset 'Zeroes' - keys consisting of all zeroes, differing only in length
// We reuse one block of empty bytes, otherwise the RAM cost is enormous.

template <typename hashtype>
static bool ZeroKeyImpl( HashFn hash, const seed_t seed, flags_t flags ) {
    int keycount = 200 * 1024;

    printf("Keyset 'Zeroes' - %d keys\n", keycount);

    uint8_t * nullblock = new uint8_t[keycount];
    memset(nullblock, 0, keycount);

    addVCodeInput(nullblock, keycount);

    //----------
    std::vector<hashtype> hashes;

    hashes.resize(keycount);

    for (int i = 0; i < keycount; i++) {
        hash(nullblock, i, seed, &hashes[i]);
    }

    bool result = TestHashList(hashes).testDeltas(1).reportFlags(flags).dumpFailKeys([&]( hidx_t i ) {
            printf("0x%016" PRIx64 "\t%d copies of 0x00\t", g_seed, i);
            hashtype v; hash(nullblock, i, seed, &v); v.printhex(NULL);
        });
    printf("\n");

    delete [] nullblock;

    recordTestResult(result, "Zeroes", (const char *)NULL);

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool ZeroKeyTest( const HashInfo * hinfo, flags_t flags ) {
    const HashFn hash   = hinfo->hashFn(g_hashEndian);
    bool         result = true;

    printf("[[[ Keyset 'Zeroes' Tests ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed);

    result &= ZeroKeyImpl<hashtype>(hash, seed, flags);

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(ZeroKeyTest, HASHTYPELIST);
