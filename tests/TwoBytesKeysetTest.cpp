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
#include "Stats.h"   // for chooseK
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "TwoBytesKeysetTest.h"

//-----------------------------------------------------------------------------
// Keyset 'TwoBytes' - generate all keys up to length N with two non-zero bytes

template< typename hashtype >
static void TwoBytesKeygen(int maxlen, HashFn hash, std::vector<hashtype> & hashes) {
  //----------
  // Compute # of keys

  int keycount = 0;

  for(int i = 2; i <= maxlen; i++)
    keycount += (int)chooseK(i,2);

  keycount *= 255*255;

  for(int i = 2; i <= maxlen; i++)
    keycount += i*255;

  printf("Keyset 'TwoBytes' - up-to-%d-byte keys - %d keys\n", maxlen, keycount);

  //----------
  // Add all keys with one non-zero byte

  uint8_t key[256];
  memset(key,0,256);

  for(int keylen = 2; keylen <= maxlen; keylen++)
    for(int byteA = 0; byteA < keylen; byteA++)
      {
        for(int valA = 1; valA <= 255; valA++)
          {
            hashtype h;
            key[byteA] = (uint8_t)valA;
            hash(key,keylen,g_seed,&h);
            addVCodeInput(key, keylen);
            hashes.push_back(h);
          }

        key[byteA] = 0;
      }

  //----------
  // Add all keys with two non-zero bytes

  for(int keylen = 2; keylen <= maxlen; keylen++)
    for(int byteA = 0; byteA < keylen-1; byteA++)
      for(int byteB = byteA+1; byteB < keylen; byteB++)
        {
          for(int valA = 1; valA <= 255; valA++)
            {
              key[byteA] = (uint8_t)valA;

              for(int valB = 1; valB <= 255; valB++)
                {
                    hashtype h;
                    key[byteB] = (uint8_t)valB;
                    hash(key,keylen,g_seed,&h);
                    addVCodeInput(key, keylen);
                    hashes.push_back(h);
                }

              key[byteB] = 0;
            }

          key[byteA] = 0;
        }
}

template < typename hashtype >
static bool TwoBytesTest2 ( HashFn hash, int maxlen, bool drawDiagram )
{
  std::vector<hashtype> hashes;

  TwoBytesKeygen(maxlen,hash,hashes);

  bool result = TestHashList(hashes,drawDiagram);
  printf("\n");

  recordTestResult(result, "TwoBytes", maxlen);

  addVCodeResult(result);

  return result;
}

//-----------------------------------------------------------------------------
template < typename hashtype >
bool TwoBytesKeyTest(const HashInfo * hinfo, const bool verbose, const bool extra) {
    const HashFn hash = hinfo->hashFn(g_hashEndian);
    bool result = true;
    int maxlen;
    if (extra) {
        maxlen = 24;
    } else if (hinfo->isVerySlow()) {
        maxlen = 8;
    } else if (hinfo->bits <= 32) {
        maxlen = 24;
    } else if (hinfo->bits <= 64) {
        maxlen = 20;
    } else {
        maxlen = 12;
    }

    printf("[[[ Keyset 'TwoBytes' Tests ]]]\n\n");

    hinfo->Seed(g_seed);

    for(int len = 4; len <= maxlen; len += 4)
    {
      result &= TwoBytesTest2<hashtype>(hash, len, verbose);
    }

    if(!result) printf("*********FAIL*********\n");
    printf("\n");

    return result;
}

INSTANTIATE(TwoBytesKeyTest, HASHTYPELIST);
