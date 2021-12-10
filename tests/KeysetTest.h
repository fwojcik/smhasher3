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
//-----------------------------------------------------------------------------
// Keyset tests generate various sorts of difficult-to-hash keysets and compare
// the distribution and collision frequency of the hash results against an
// ideal random distribution

#pragma once

#include "Types.h"
#include "Stats.h"
#include "Random.h"   // for rand_p

#include <stdint.h>
#include <inttypes.h>
#include <assert.h>

#include <algorithm>  // for std::swap
#include <string>
#if NCPU > 1 // disable with -DNCPU=0 or 1
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#endif

#undef MAX
#define MAX(x,  y)   (((x) > (y)) ? (x) : (y))

static void printKey(const void* key, size_t len)
{
    const unsigned char* const p = (const unsigned char*)key;
    size_t s;
    printf("\n0x");
    for (s=0; s<len; s++) printf("%02X", p[s]);
    printf("\n  ");
    for (s=0; s<len; s+=8) printf("%-16zu", s);
}

//-----------------------------------------------------------------------------
// Keyset 'Prng'


template< typename hashtype >
void Prn_gen (int nbRn, pfHash hash, std::vector<hashtype> & hashes )
{
  assert(nbRn > 0);

  printf("Generating random numbers by hashing previous output - %d keys\n", nbRn);

  hashtype hcopy;
  memset(&hcopy, 0, sizeof(hcopy));

  // a generated random number becomes the input for the next one
  for (int i=0; i< nbRn; i++) {
      hashtype h;
      hash(&hcopy, sizeof(hcopy), g_seed, &h);
      hashes.push_back(h);
      memcpy(&hcopy, &h, sizeof(h));
  }
}


template< typename hashtype >
bool PrngTest ( hashfunc<hashtype> hash,
                bool testColl, bool testDist, bool drawDiagram )
{

  if (sizeof(hashtype) < 8) {
      printf("Skipping PRNG test; it is designed for hashes >= 64-bits\n\n");
      return true;
  }

  //----------

  std::vector<hashtype> hashes;
  Prn_gen(32 << 20, hash, hashes);

  //----------
  bool result = TestHashList(hashes,drawDiagram,testColl,testDist);

  return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Perlin Noise' - X,Y coordinates on input & seed


template< typename hashtype >
void PerlinNoiseTest (int Xbits, int Ybits,
                      int inputLen, int step,
                      pfHash hash, std::vector<hashtype> & hashes )
{
  assert(0 < Ybits && Ybits < 31);
  assert(0 < Xbits && Xbits < 31);
  assert(inputLen*8 > Xbits);  // enough space to run the test

  int const xMax = (1 << Xbits);
  int const yMax = (1 << Ybits);

  assert(Xbits + Ybits < 31);

#define INPUT_LEN_MAX 256
  assert(inputLen <= INPUT_LEN_MAX);
  char key[INPUT_LEN_MAX] = {0};

  printf("Generating coordinates from %3i-byte keys - %d keys\n", inputLen, xMax * yMax);

  for(uint64_t x = 0; x < xMax; x++) {
      memcpy(key, &x, inputLen);  // Note : only works with Little Endian
      for (size_t y=0; y < yMax; y++) {
          hashtype h;
          Hash_Seed_init (hash, y);
          hash(key, inputLen, y, &h);
          hashes.push_back(h);
      }
  }
}


template< typename hashtype >
bool PerlinNoise ( hashfunc<hashtype> hash, int inputLen,
                   bool testColl, bool testDist, bool drawDiagram )
{
  //----------

  std::vector<hashtype> hashes;

  PerlinNoiseTest(12, 12, inputLen, 1, hash, hashes);

  //----------

  bool result = TestHashList(hashes,drawDiagram,testColl,testDist);
  printf("\n");

  return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Window' - for all possible N-bit windows of a K-bit key, generate
// all possible keys with bits set in that window

template < typename keytype, typename hashtype >
bool WindowedKeyTest ( hashfunc<hashtype> hash, int windowbits,
                       bool testCollision, bool testDistribution, bool drawDiagram )
{
  const int keybits = sizeof(keytype) * 8;
  const int hashbits = sizeof(hashtype) * 8;
  // calc keycount to expect min. 0.5 collisions: EstimateNbCollisions, except for 64++bit.
  // there limit to 2^25 = 33554432 keys
  int keycount = 1 << windowbits;
  while (EstimateNbCollisions(keycount, hashbits) < 0.5 && windowbits < 25) {
    if ((int)log2(2.0 * keycount) < 0) // overflow
      break;
    keycount *= 2;
    windowbits = (int)log2(1.0 * keycount);
    //printf (" enlarge windowbits to %d (%d keys)\n", windowbits, keycount);
    //fflush (NULL);
  }

  std::vector<hashtype> hashes;
  hashes.resize(keycount);

  bool result = true;
  int testcount = keybits;

  printf("Keyset 'Window' - %3d-bit key, %3d-bit window - %d tests - %d keys\n",
         keybits,windowbits,testcount,keycount);

  for(int j = 0; j <= testcount; j++)
  {
    int minbit = j;
    keytype key;

    for(int i = 0; i < keycount; i++)
    {
      key = i;
      //key = key << minbit;
      lrot(key,minbit);
      hash(&key,sizeof(keytype),g_seed,&hashes[i]);
    }

    printf("Window at bit %3d\n",j);
    result &= TestHashList(hashes, drawDiagram, testCollision, testDistribution,
                           /* do not test high/low bits (to not clobber the screen) */
                           false, false, true);
    //printf("\n");
  }

  return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Cyclic' - generate keys that consist solely of N repetitions of M
// bytes.

// (This keyset type is designed to make MurmurHash2 fail)

template < typename hashtype >
bool CyclicKeyTest ( pfHash hash, int cycleLen, int cycleReps, const int keycount, bool drawDiagram )
{
  printf("Keyset 'Cyclic' - %d cycles of %d bytes - %d keys\n",cycleReps,cycleLen,keycount);

  Rand r(483723);

  std::vector<hashtype> hashes;
  hashes.resize(keycount);

  int keyLen = cycleLen * cycleReps;

  uint8_t * cycle = new uint8_t[cycleLen + 16];
  uint8_t * key = new uint8_t[keyLen];

  //----------

  for(int i = 0; i < keycount; i++)
  {
    r.rand_p(cycle,cycleLen);

    *(uint32_t*)cycle = f3mix(i ^ 0x746a94f1);

    for(int j = 0; j < keyLen; j++)
    {
      key[j] = cycle[j % cycleLen];
    }

    hash(key,keyLen,g_seed,&hashes[i]);
  }

  //----------

  bool result = TestHashList(hashes,drawDiagram);
  printf("\n");

  delete [] key;
  delete [] cycle;

  return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Text' - generate all keys of the form "prefix"+"core"+"suffix",
// where "core" consists of all possible combinations of the given character
// set of length N.

template < typename hashtype >
bool TextKeyTest ( hashfunc<hashtype> hash, const char * prefix, const char * coreset, const int corelen, const char * suffix, bool drawDiagram )
{
  const int prefixlen = (int)strlen(prefix);
  const int suffixlen = (int)strlen(suffix);
  const int corecount = (int)strlen(coreset);

  const int keybytes = prefixlen + corelen + suffixlen;
  long keycount = (long)pow(double(corecount),double(corelen));
  if (keycount > INT32_MAX / 8)
    keycount = INT32_MAX / 8;

  printf("Keyset 'Text' - keys of form \"%s",prefix);
  for(int i = 0; i < corelen; i++) printf("X");
  printf("%s\" - %ld keys\n",suffix,keycount);

  uint8_t * key = new uint8_t[std::min(keybytes+1, 64)];

  key[keybytes] = 0;

  memcpy(key,prefix,prefixlen);
  memcpy(key+prefixlen+corelen,suffix,suffixlen);

  //----------

  std::vector<hashtype> hashes;
  hashes.resize(keycount);

  for(int i = 0; i < (int)keycount; i++)
  {
    int t = i;

    for(int j = 0; j < corelen; j++)
    {
      key[prefixlen+j] = coreset[t % corecount]; t /= corecount;
    }

    hash(key,keybytes,g_seed,&hashes[i]);
  }

  //----------
  bool result = TestHashList(hashes,drawDiagram);
  printf("\n");

  delete [] key;
  return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Words' - pick random chars from coreset (alnum or password chars)

template < typename hashtype >
bool WordsKeyTest ( hashfunc<hashtype> hash, const long keycount,
                    const int minlen, const int maxlen,
                    const char * coreset,
                    const char* name, bool drawDiagram )
{
  const int corecount = (int)strlen(coreset);
  printf("Keyset 'Words' - %d-%d random chars from %s charset - %d keys\n", minlen, maxlen, name, keycount);
  assert (minlen >= 0);
  assert (maxlen > minlen);

  HashSet<std::string> words; // need to be unique, otherwise we report collisions
  std::vector<hashtype> hashes;
  hashes.resize(keycount);
  Rand r(483723);

  char* key = new char[std::min(maxlen+1, 64)];
  std::string key_str;

  for(long i = 0; i < keycount; i++)
  {
    const int len = minlen + (r.rand_u32() % (maxlen - minlen));
    key[len] = 0;
    for(int j = 0; j < len; j++)
    {
      key[j] = coreset[r.rand_u32() % corecount];
    }
    key_str = key;
    if (words.count(key_str) > 0) { // not unique
      i--;
      continue;
    }
    words.insert(key_str);

    hash(key,len,g_seed,&hashes[i]);

#if 0 && defined DEBUG
    uint64_t h;
    memcpy(&h, &hashes[i], MAX(sizeof(hashtype),8));
    printf("%d %s %lx\n", i, (char*)key, h);
#endif
  }
  delete [] key;

  //----------
  bool result = TestHashList(hashes,drawDiagram);
  printf("\n");

  return result;
}

template < typename hashtype >
bool WordsStringTest ( hashfunc<hashtype> hash, std::vector<std::string> & words,
                       bool drawDiagram )
{
  long wordscount = words.size();
  printf("Keyset 'Words' - dictionary words - %d keys\n", wordscount);

  std::vector<hashtype> hashes;
  hashes.resize(wordscount);
  Rand r(483723);
  HashSet<std::string> wordset; // need to be unique, otherwise we report collisions

  for(int i = 0; i < (int)wordscount; i++)
  {
    if (wordset.count(words[i]) > 0) { // not unique
      i--;
      continue;
    }
    if (0 /*need_minlen64_align16(hash) && words[i].capacity() < 64*/)
      words[i].resize(64);
    wordset.insert(words[i]);
    const int len = words[i].length();
    const char *key = words[i].c_str();
    hash(key, len, g_seed, &hashes[i]);
  }

  //----------
  bool result = TestHashList(hashes,drawDiagram);
  printf("\n");

  return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Seed' - hash "the quick brown fox..." using different seeds

template < typename hashtype >
bool SeedTest ( pfHash hash, int keycount, bool drawDiagram )
{
  printf("Keyset 'Seed' - %d keys\n",keycount);
  assert(keycount < (1<<31));

  const char text[64] = "The quick brown fox jumps over the lazy dog";
  const int len = (int)strlen(text);

  //----------

  std::vector<hashtype> hashes;

  hashes.resize(keycount);

  for(int i = 0; i < keycount; i++)
  {
    Hash_Seed_init (hash, i);
    hash(text,len,i,&hashes[i]);
  }

  bool result = TestHashList(hashes,drawDiagram);
  printf("\n");

  return result;
}
