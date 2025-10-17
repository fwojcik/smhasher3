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
#include "Stats.h"
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "SparseKeysetTest.h"

//-----------------------------------------------------------------------------
// Keyset 'Sparse' - generate all possible N-bit keys with up to K bits set

template <typename keytype, typename hashtype>
static void SparseKeygenRecurse( HashFn hash, const seed_t seed, unsigned start, unsigned bitsleft,
        bool inclusive, keytype & k, std::vector<hashtype> & hashes ) {
    hashtype h( 0 );

    for (size_t i = start; i < k.bitlen; i++) {
        k.flipbit(i);

        if (inclusive || (bitsleft == 1)) {
            hash(&k, k.len, seed, &h);
            addVCodeInput(&k, k.len);
            hashes.push_back(h);
        }

        if (bitsleft > 1) {
            SparseKeygenRecurse(hash, seed, i + 1, bitsleft - 1, inclusive, k, hashes);
        }

        k.flipbit(i);
    }
}

//----------
template <int keybits, typename hashtype>
static bool SparseKeyImpl( HashFn hash, const seed_t seed, const unsigned setbits, bool inclusive, flags_t flags ) {
    typedef Blob<keybits> keytype;
    keytype k( 0 );

    const unsigned keybytes  = keybits / 8;
    const unsigned totalkeys = inclusive ? 1 + chooseUpToK(keybits, setbits) : chooseK(keybits, setbits);

    std::vector<hashtype> hashes;
    hashes.reserve(totalkeys);

    printf("Keyset 'Sparse' - %d-byte keys with %s %d bits set - %d keys\n",
            keybytes, inclusive ? "up to" : "exactly", setbits, totalkeys);

    if (inclusive) {
        hashtype h( 0 );
        hash(&k, k.len, seed, &h);
        addVCodeInput(&k, k.len);
        hashes.push_back(h);
    }

    SparseKeygenRecurse(hash, seed, 0, setbits, inclusive, k, hashes);

    // This loop is very close to the loop in PermutationKeysetTest.cpp, so
    // the explanatory comments there also apply here, except that a) there
    // are only two choices for each position, and b) there are a limited
    // number of allowed 1 bits, while counts of block occurrences in
    // Permutation are not limited. That is why this loop uses
    // chooseUpToK() instead of a table, and why it uses the laterbits
    // variable at all.
    auto keyprint = [&]( hidx_t n ) {
                hidx_t   t, pos = 0, maxpos = keybits - 1, laterbits = setbits;
                hashtype v( 0 );

                k = 0;
                while (n > 0) {
                    laterbits--;
                    n--;
                    while (n >= (t = 1 + chooseUpToK(maxpos - pos, laterbits))) {
                        n -= t;
                        pos++;
                    }
                    k.flipbit(pos++);
                }

                printf("0x%016" PRIx64 "\t", g_seed);
                k.printbytes(NULL);
                printf("\t");
                hash(&k, k.len, seed, &v);
                v.printhex(NULL);
            };

    bool result = TestHashList(hashes).reportFlags(flags).testDeltas(1).
            testDistribution(false).dumpFailKeys(keyprint);

    printf("\n");

    char buf[16];
    snprintf(buf, sizeof(buf), "%d/%d", setbits, keybytes);
    recordTestResult(result, "Sparse", buf);

    addVCodeResult(result);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool SparseKeyTest( const HashInfo * hinfo, bool extra, flags_t flags ) {
    const HashFn hash   = hinfo->hashFn(g_hashEndian);
    bool         result = true;

    printf("[[[ Keyset 'Sparse' Tests ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed);

    // Some hashes fail with small numbers of sparse keys, because the rest of the
    // keys will "drown out" the failure modes. These set-bit threshholds were chosen
    // to find these failures. Empirically, this happens above ~2^13.5 (~11586) keys.
    result &= SparseKeyImpl<16, hashtype>(hash, seed, 6, true, flags);
    result &= SparseKeyImpl<24, hashtype>(hash, seed, 4, true, flags);
    result &= SparseKeyImpl<32, hashtype>(hash, seed, 4, true, flags);
    result &= SparseKeyImpl<40, hashtype>(hash, seed, 4, true, flags);
    result &= SparseKeyImpl<48, hashtype>(hash, seed, 3, true, flags);
    result &= SparseKeyImpl<56, hashtype>(hash, seed, 3, true, flags);
    result &= SparseKeyImpl<64, hashtype>(hash, seed, 3, true, flags);
    result &= SparseKeyImpl<72, hashtype>(hash, seed, 3, true, flags);
    result &= SparseKeyImpl<80, hashtype>(hash, seed, 3, true, flags);
    if (extra) {
        result &= SparseKeyImpl<88, hashtype>(hash, seed, 3, true, flags);
    }
    result &= SparseKeyImpl<96, hashtype>(hash, seed, 3, true, flags);
    if (extra) {
        result &= SparseKeyImpl<104, hashtype>(hash, seed, 3, true, flags);
    }
    result &= SparseKeyImpl<112, hashtype>(hash, seed, 3, true, flags);

    // Most hashes which fail this test will fail with larger numbers of sparse keys.
    // These set-bit threshholds were chosen to limit the number of keys to 100,000,000.
    // The longer-running configurations are generally pushed to --extra mode,
    // except 768-bit keys, which seems to be a more-common failure point.
    result &= SparseKeyImpl<16, hashtype>(hash, seed, 10, true, flags);
    result &= SparseKeyImpl<24, hashtype>(hash, seed, 20, true, flags);
    result &= SparseKeyImpl<32, hashtype>(hash, seed,  9, true, flags);
    if (extra) {
        result &= SparseKeyImpl<40, hashtype>(hash, seed, 7, true, flags);
        result &= SparseKeyImpl<48, hashtype>(hash, seed, 7, true, flags);
        result &= SparseKeyImpl<56, hashtype>(hash, seed, 6, true, flags);
        result &= SparseKeyImpl<64, hashtype>(hash, seed, 6, true, flags);
    }

    result &= SparseKeyImpl<72, hashtype>(hash, seed, 5, true, flags);
    if (extra) {
        result &= SparseKeyImpl<96, hashtype>(hash, seed, 5, true, flags);
    }

    result &= SparseKeyImpl<112, hashtype>(hash, seed, 4, true, flags);
    result &= SparseKeyImpl<128, hashtype>(hash, seed, 4, true, flags);
    if (extra) {
        result &= SparseKeyImpl<144, hashtype>(hash, seed, 4, true, flags);
        result &= SparseKeyImpl<192, hashtype>(hash, seed, 4, true, flags);
        result &= SparseKeyImpl<208, hashtype>(hash, seed, 4, true, flags);
    }

    result &= SparseKeyImpl<256, hashtype>(hash, seed, 3, true, flags);
    result &= SparseKeyImpl<384, hashtype>(hash, seed, 3, true, flags);
    result &= SparseKeyImpl<512, hashtype>(hash, seed, 3, true, flags);
    if (1 || extra) {
        result &= SparseKeyImpl<768, hashtype>(hash, seed, 3, true, flags);
    }

    result &= SparseKeyImpl< 1024, hashtype>(hash, seed, 2, true, flags);
    result &= SparseKeyImpl< 2048, hashtype>(hash, seed, 2, true, flags);
    result &= SparseKeyImpl< 4096, hashtype>(hash, seed, 2, true, flags);
    result &= SparseKeyImpl< 8192, hashtype>(hash, seed, 2, true, flags);
    result &= SparseKeyImpl<10240, hashtype>(hash, seed, 2, true, flags);
    if (extra) {
        result &= SparseKeyImpl<12288, hashtype>(hash, seed, 2, true, flags);
        result &= SparseKeyImpl<16384, hashtype>(hash, seed, 2, true, flags);
    }

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(SparseKeyTest, HASHTYPELIST);
