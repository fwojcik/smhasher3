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

#include "PermutationKeysetTest.h"

//-----------------------------------------------------------------------------
// Keyset 'Combination' - all possible combinations of input blocks

template <typename hashtype>
static void CombinationKeygenRecurse( uint8_t * key, int len, int maxlen, const uint8_t * blocks, uint32_t blockcount,
        uint32_t blocksz, HashFn hash, const seed_t seed, std::vector<hashtype> & hashes ) {
    if (len == maxlen) { return; } // end recursion

    for (int i = 0; i < blockcount; i++) {
        memcpy(&key[len * blocksz], &blocks[i * blocksz], blocksz);

        hashtype h;
        hash(key, (len + 1) * blocksz, seed, &h);
        addVCodeInput(key, (len + 1) * blocksz);
        hashes.push_back(h);

        CombinationKeygenRecurse(key, len + 1, maxlen, blocks, blockcount, blocksz, hash, seed, hashes);
    }
}

template <typename hashtype>
static bool CombinationKeyTest( HashFn hash, const seed_t seed, int maxlen, const uint8_t * blocks,
        uint32_t blockcount, uint32_t blocksz, const char * testdesc, bool verbose ) {
    printf("Keyset 'Combination %s' - up to %d blocks from a set of %d - ", testdesc, maxlen, blockcount);

    //----------

    std::vector<hashtype> hashes;

    uint8_t * key = new uint8_t[maxlen * blocksz];

    CombinationKeygenRecurse(key, 0, maxlen, blocks, blockcount, blocksz, hash, seed, hashes);

    delete [] key;

    printf("%d keys\n", (int)hashes.size());

    //----------

    bool result = TestHashList(hashes).drawDiagram(verbose).testDeltas(1);
    printf("\n");

    return result;
}

//-----------------------------------------------------------------------------

const struct {
    const char *                desc;
    const int                   maxlen;
    const uint32_t              nrBlocks;
    const uint32_t              szBlock; // Verify nrBlocks * szBlock == blocks.size()
    const std::vector<uint8_t>  blocks;
} keytests[] = {
    // This one breaks lookup3, surprisingly
    {
        "4-bytes [3 low bits; LE]", 7, 8, 4,
        {
            0, 0, 0, 0,
            1, 0, 0, 0,
            2, 0, 0, 0,
            3, 0, 0, 0,
            4, 0, 0, 0,
            5, 0, 0, 0,
            6, 0, 0, 0,
            7, 0, 0, 0
        }
    },
    {
        "4-bytes [3 low bits; BE]", 7, 8, 4,
        {
            0, 0, 0, 0,
            0, 0, 0, 1,
            0, 0, 0, 2,
            0, 0, 0, 3,
            0, 0, 0, 4,
            0, 0, 0, 5,
            0, 0, 0, 6,
            0, 0, 0, 7
        }
    },
    {
        "4-bytes [3 high bits; LE]", 7, 8, 4,
        {
            0, 0, 0,   0,
            0, 0, 0,  32,
            0, 0, 0,  64,
            0, 0, 0,  96,
            0, 0, 0, 128,
            0, 0, 0, 160,
            0, 0, 0, 192,
            0, 0, 0, 224
        }
    },
    {
        "4-bytes [3 high bits; BE]", 7, 8, 4,
        {
              0, 0, 0, 0,
             32, 0, 0, 0,
             64, 0, 0, 0,
             96, 0, 0, 0,
            128, 0, 0, 0,
            160, 0, 0, 0,
            192, 0, 0, 0,
            224, 0, 0, 0
        }
    },
    {
        "4-bytes [3 high+low bits; LE]", 6, 15, 4,
        {
            0, 0, 0,   0,
            1, 0, 0,   0,
            2, 0, 0,   0,
            3, 0, 0,   0,
            4, 0, 0,   0,
            5, 0, 0,   0,
            6, 0, 0,   0,
            7, 0, 0,   0,
            0, 0, 0,  32,
            0, 0, 0,  64,
            0, 0, 0,  96,
            0, 0, 0, 128,
            0, 0, 0, 160,
            0, 0, 0, 192,
            0, 0, 0, 224
        }
    },
    {
        "4-bytes [3 high+low bits; BE]", 6, 15, 4,
        {
              0, 0, 0, 0,
              0, 0, 0, 1,
              0, 0, 0, 2,
              0, 0, 0, 3,
              0, 0, 0, 4,
              0, 0, 0, 5,
              0, 0, 0, 6,
              0, 0, 0, 7,
             32, 0, 0, 0,
             64, 0, 0, 0,
             96, 0, 0, 0,
            128, 0, 0, 0,
            160, 0, 0, 0,
            192, 0, 0, 0,
            224, 0, 0, 0
        }
    },
    {
        "4-bytes [0, low bit; LE]", 0, 2, 4,
        {
            0, 0, 0, 0,
            1, 0, 0, 0
        }
    },
    {
        "4-bytes [0, low bit; BE]", 0, 2, 4,
        {
            0, 0, 0, 0,
            0, 0, 0, 1
        }
    },
    {
        "4-bytes [0, high bit; LE]", 0, 2, 4,
        {
            0, 0, 0,   0,
            0, 0, 0, 128
        }
    },
    {
        "4-bytes [0, high bit; BE]", 0, 2, 4,
        {
              0, 0, 0, 0,
            128, 0, 0, 0
        }
    },
    {
        "8-bytes [0, low bit; LE]", 0, 2, 8,
        {
            0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0,
        }
    },
    {
        "8-bytes [0, low bit; BE]", 0, 2, 8,
        {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        }
    },
    {
        "8-bytes [0, high bit; LE]", 0, 2, 8,
        {
            0, 0, 0, 0, 0, 0, 0,   0,
            0, 0, 0, 0, 0, 0, 0, 128,
        }
    },
    {
        "8-bytes [0, high bit; BE]", 0, 2, 8,
        {
              0, 0, 0, 0, 0, 0, 0, 0,
            128, 0, 0, 0, 0, 0, 0, 0,
        }
    },
    {
        "16-bytes [0, low bit; LE]", 0, 2, 16,
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        }
    },
    {
        "16-bytes [0, low bit; BE]", 0, 2, 16,
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        }
    },
    {
        "16-bytes [0, high bit; LE]", 0, 2, 16,
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
        }
    },
    {
        "16-bytes [0, high bit; BE]", 0, 2, 16,
        {
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        }
    },
    {
        "32-bytes [0, low bit; LE]", 0, 2, 32,
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        }
    },
    {
        "32-bytes [0, low bit; BE]", 0, 2, 32,
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        }
    },
    {
        "32-bytes [0, high bit; LE]", 0, 2, 32,
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
        }
    },
    {
        "32-bytes [0, high bit; BE]", 0, 2, 32,
        {
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        }
    },
    {
        "64-bytes [0, low bit; LE]", 0, 2, 64,
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        }
    },
    {
        "64-bytes [0, low bit; BE]", 0, 2, 64,
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        }
    },
    {
        "64-bytes [0, high bit; LE]", 0, 2, 64,
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
        }
    },
    {
        "64-bytes [0, high bit; BE]", 0, 2, 64,
        {
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        }
    },
};

template <typename hashtype>
bool PermutedKeyTest( const HashInfo * hinfo, const bool verbose, const bool extra ) {
    const HashFn hash           = hinfo->hashFn(g_hashEndian);
    const int    default_maxlen = 23;
    bool         result         = true;

    printf("[[[ Keyset 'Permutation' Tests ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed);

    for (auto test: keytests) {
        bool curresult = true;
        int  maxlen    = test.maxlen > 0 ? test.maxlen : default_maxlen;

        if (!extra && (test.szBlock >= 16)) { continue; }

        assert(test.blocks.size() == test.nrBlocks * test.szBlock);
        curresult &= CombinationKeyTest<hashtype>(hash, seed, maxlen, &(test.blocks[0]),
                test.nrBlocks, test.szBlock, test.desc, verbose);

        recordTestResult(curresult, "Permutation", test.desc);

        addVCodeResult(curresult);

        result &= curresult;
    }

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(PermutedKeyTest, HASHTYPELIST);
