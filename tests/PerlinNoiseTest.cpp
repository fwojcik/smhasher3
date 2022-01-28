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
#include "Types.h"
#include "Stats.h"
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "PerlinNoiseTest.h"

#include <cassert>

//-----------------------------------------------------------------------------
// Keyset 'Perlin Noise' - X,Y coordinates on input & seed

template< typename hashtype >
static bool PerlinNoise (int Xbits, int Ybits, int inputLen, int step,
        const HashInfo * hinfo, bool testColl, bool testDist, bool drawDiagram)
{
  assert(0 < Ybits && Ybits < 31);
  assert(0 < Xbits && Xbits < 31);
  assert(Xbits + Ybits < 31);
  assert(inputLen*8 > Xbits);  // enough space to run the test

  std::vector<hashtype> hashes;
  int const xMax = (1 << Xbits);
  int const yMax = (1 << Ybits);
  const HashFn hash = hinfo->hashFn(g_hashEndian);

#define INPUT_LEN_MAX 256
  assert(inputLen <= INPUT_LEN_MAX);
  char key[INPUT_LEN_MAX] = {0};

  printf("Generating coordinates from %3i-byte keys - %d keys\n", inputLen, xMax * yMax);

  for(uint64_t x = 0; x < xMax; x++) {
      memcpy(key, &x, inputLen);  // Note : only works with Little Endian
      addVCodeInput(key, inputLen);
      addVCodeInput(yMax);
      for (size_t y=0; y < yMax; y++) {
          hashtype h;
          hinfo->Seed(y);
          hash(key, inputLen, y, &h);
          hashes.push_back(h);
      }
  }

  bool result = TestHashList(hashes,drawDiagram,testColl,testDist);

  recordTestResult(result, "PerlinNoise", inputLen);

  addVCodeResult(result);

  return result;
}

//-----------------------------------------------------------------------------

template< typename hashtype >
bool PerlinNoiseTest (const HashInfo * hinfo, const bool verbose, const bool extra) {
    bool result = true;
    bool testCollision = true;
    bool testDistribution = extra;

    printf("[[[ Keyset 'PerlinNoise' Tests ]]]\n\n");

    result &= PerlinNoise<hashtype>(12, 12, 2, 1, hinfo, testCollision, testDistribution, verbose);
    printf("\n");
    if (extra) {
        result &= PerlinNoise<hashtype>(12, 12, 4, 1, hinfo, testCollision, testDistribution, verbose);
        printf("\n");
        result &= PerlinNoise<hashtype>(12, 12, 8, 1, hinfo, testCollision, testDistribution, verbose);
        printf("\n");
    }

    if(!result) printf("*********FAIL*********\n");
    printf("\n");

    return result;
}

INSTANTIATE(PerlinNoiseTest, HASHTYPELIST);
