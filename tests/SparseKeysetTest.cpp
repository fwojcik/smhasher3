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
#include "Types.h"
#include "Bitvec.h"
#include "Stats.h"
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "SparseKeysetTest.h"

//-----------------------------------------------------------------------------
// Keyset 'Sparse' - generate all possible N-bit keys with up to K bits set
static void printSparseKey(const void* buffer, size_t size) {
    const uint8_t * const p = (const uint8_t *)buffer;

    printf("bits:");
    for (size_t s = 0; s < size; s++) {
        for (int b = 0; b < 8; b++) {
            if ((p[s] >> b) & 1) {
                printf(" %2u.%2i,", (unsigned)s, b);
            }
        }
    }
}

template < typename keytype, typename hashtype >
static void SparseKeygenRecurse(HashFn hash, const seed_t seed,
        int start, int bitsleft, bool inclusive,
        keytype & k, std::vector<hashtype> & hashes) {
    const int nbytes = sizeof(keytype);
    const int nbits = nbytes * 8;

    hashtype h;

    for (int i = start; i < nbits; i++) {
        flipbit(k, i);

        if (inclusive || (bitsleft == 1)) {
            hash(&k, sizeof(keytype), seed, &h);
            addVCodeInput(&k, sizeof(keytype));
            hashes.push_back(h);
        }

        if (bitsleft > 1) {
            SparseKeygenRecurse(hash, seed, i+1, bitsleft-1, inclusive, k, hashes);
        }

        flipbit(k, i);
    }
}

//----------
template < int keybits, typename hashtype >
static bool SparseKeyImpl(HashFn hash, const seed_t seed,
        const int setbits, bool inclusive,
        bool testColl, bool testDist, bool drawDiagram) {
  printf("Keyset 'Sparse' - %d-bit keys with %s %d bits set - ",keybits,
         inclusive ? "up to" : "exactly", setbits);

  typedef Blob<keybits> keytype;

  std::vector<hashtype> hashes;

  keytype k;
  memset(&k,0,sizeof(k));

  if (inclusive) {
    hashes.resize(1);
    hash(&k, sizeof(keytype), seed, &hashes[0]);
  }

  SparseKeygenRecurse(hash,seed,0,setbits,inclusive,k,hashes);

  printf("%d keys\n",(int)hashes.size());

  bool result = TestHashList<hashtype>(hashes,drawDiagram,testColl,testDist);
  printf("\n");

  recordTestResult(result, "Sparse", keybits);

  addVCodeResult(result);

  return result;
}

//-----------------------------------------------------------------------------

template < typename hashtype >
bool SparseKeyTest(const HashInfo * hinfo, const bool verbose, const bool extra) {
    const HashFn hash = hinfo->hashFn(g_hashEndian);
    bool result = true;

    printf("[[[ Keyset 'Sparse' Tests ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed);

    result &= SparseKeyImpl<  16,hashtype>(hash,seed,9,true,true,true,verbose);
    result &= SparseKeyImpl<  24,hashtype>(hash,seed,8,true,true,true,verbose);
    result &= SparseKeyImpl<  32,hashtype>(hash,seed,7,true,true,true,verbose);
    result &= SparseKeyImpl<  40,hashtype>(hash,seed,6,true,true,true,verbose);
    result &= SparseKeyImpl<  48,hashtype>(hash,seed,6,true,true,true,verbose);
    result &= SparseKeyImpl<  56,hashtype>(hash,seed,5,true,true,true,verbose);
    result &= SparseKeyImpl<  64,hashtype>(hash,seed,5,true,true,true,verbose);
    result &= SparseKeyImpl<  72,hashtype>(hash,seed,5,true,true,true,verbose);
    result &= SparseKeyImpl<  96,hashtype>(hash,seed,4,true,true,true,verbose);
    if (extra) {
        result &= SparseKeyImpl< 112,hashtype>(hash,seed,4,true,true,true,verbose);
        result &= SparseKeyImpl< 128,hashtype>(hash,seed,4,true,true,true,verbose);
        result &= SparseKeyImpl< 144,hashtype>(hash,seed,4,true,true,true,verbose);
    }
    result &= SparseKeyImpl< 160,hashtype>(hash,seed,4,true,true,true,verbose);
    if (extra) {
        result &= SparseKeyImpl< 192,hashtype>(hash,seed,4,true,true,true,verbose);
    }
    result &= SparseKeyImpl< 256,hashtype>(hash,seed,3,true,true,true,verbose);
    if (extra) {
        result &= SparseKeyImpl< 288,hashtype>(hash,seed,3,true,true,true,verbose);
        result &= SparseKeyImpl< 320,hashtype>(hash,seed,3,true,true,true,verbose);
        result &= SparseKeyImpl< 384,hashtype>(hash,seed,3,true,true,true,verbose);
        result &= SparseKeyImpl< 448,hashtype>(hash,seed,3,true,true,true,verbose);
    } else if (hinfo->bits > 64) {
        goto END_Sparse;
    }
    result &= SparseKeyImpl< 512,hashtype>(hash,seed,3,true,true,true,verbose);
    if (extra) {
        result &= SparseKeyImpl< 640,hashtype>(hash,seed,3,true,true,true,verbose);
        result &= SparseKeyImpl< 768,hashtype>(hash,seed,3,true,true,true,verbose);
        result &= SparseKeyImpl< 896,hashtype>(hash,seed,2,true,true,true,verbose);
    }
    result &= SparseKeyImpl<1024,hashtype>(hash,seed,2,true,true,true,verbose);
    if (extra) {
        result &= SparseKeyImpl<1280,hashtype>(hash,seed,2,true,true,true,verbose);
        result &= SparseKeyImpl<1536,hashtype>(hash,seed,2,true,true,true,verbose);
    }
    result &= SparseKeyImpl<2048,hashtype>(hash,seed,2,true,true,true,verbose);
    if (extra) {
        result &= SparseKeyImpl<3072,hashtype>(hash,seed,2,true,true,true,verbose);
        result &= SparseKeyImpl<4096,hashtype>(hash,seed,2,true,true,true,verbose);
        result &= SparseKeyImpl<6144,hashtype>(hash,seed,2,true,true,true,verbose);
        result &= SparseKeyImpl<8192,hashtype>(hash,seed,2,true,true,true,verbose);
        result &= SparseKeyImpl<9992,hashtype>(hash,seed,2,true,true,true,verbose);
    }

 END_Sparse:
    if(!result) printf("*********FAIL*********\n");
    printf("\n");

    return result;
}

INSTANTIATE(SparseKeyTest, HASHTYPELIST);
