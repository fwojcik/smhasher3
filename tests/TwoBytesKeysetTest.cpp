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
#include "Types.h"
#include "Stats.h"

#include "TwoBytesKeysetTest.h"

//-----------------------------------------------------------------------------
// Keyset 'TwoBytes' - generate all keys up to length N with two non-zero bytes

static void TwoBytesKeygen ( int maxlen, KeyCallback & c )
{
  //----------
  // Compute # of keys

  int keycount = 0;

  for(int i = 2; i <= maxlen; i++)
    keycount += (int)chooseK(i,2);

  keycount *= 255*255;

  for(int i = 2; i <= maxlen; i++)
    keycount += i*255;

  printf("Keyset 'TwoBytes' - up-to-%d-byte keys - %d keys\n", maxlen, keycount);

  c.reserve(keycount);

  //----------
  // Add all keys with one non-zero byte

  uint8_t key[256];
  memset(key,0,256);

  for(int keylen = 2; keylen <= maxlen; keylen++)
    for(int byteA = 0; byteA < keylen; byteA++)
      {
        for(int valA = 1; valA <= 255; valA++)
          {
            key[byteA] = (uint8_t)valA;
            c(key,keylen);
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
                  key[byteB] = (uint8_t)valB;
                  c(key,keylen);
                }

              key[byteB] = 0;
            }

          key[byteA] = 0;
        }
}

template < typename hashtype >
static bool TwoBytesTest2 ( pfHash hash, int maxlen, bool drawDiagram )
{
  std::vector<hashtype> hashes;

  HashCallback<hashtype> c(hash,hashes);

  TwoBytesKeygen(maxlen,c);

  bool result = TestHashList(hashes,drawDiagram);
  printf("\n");

  return result;
}

//-----------------------------------------------------------------------------

template < typename hashtype >
bool TwoBytesKeyTest(HashInfo * info, const bool verbose, const bool extra, const bool hash_is_slow) {
    pfHash hash = info->hash;
    bool result = true;
    int maxlen;
    if (!extra && (info->hashbits > 32)) {
        maxlen = hash_is_slow ? 8 : ((info->hashbits <= 64) ? 20 : 15);
    } else {
        maxlen = 24;
    }

    printf("[[[ Keyset 'TwoBytes' Tests ]]]\n\n");

    Hash_Seed_init (hash, g_seed);

    for(int len = 4; len <= maxlen; len += 4)
    {
      result &= TwoBytesTest2<hashtype>(hash, len, verbose);
    }

    if(!result) printf("*********FAIL*********\n");
    printf("\n");

    return result;
}

template bool TwoBytesKeyTest<uint32_t>(HashInfo * info, const bool verbose, const bool extra, const bool hash_is_slow);
template bool TwoBytesKeyTest<uint64_t>(HashInfo * info, const bool verbose, const bool extra, const bool hash_is_slow);
template bool TwoBytesKeyTest<uint128_t>(HashInfo * info, const bool verbose, const bool extra, const bool hash_is_slow);
template bool TwoBytesKeyTest<Blob<160>>(HashInfo * info, const bool verbose, const bool extra, const bool hash_is_slow);
template bool TwoBytesKeyTest<Blob<224>>(HashInfo * info, const bool verbose, const bool extra, const bool hash_is_slow);
template bool TwoBytesKeyTest<uint256_t>(HashInfo * info, const bool verbose, const bool extra, const bool hash_is_slow);
