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
#include "Random.h"
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "HashMapTest.h"

#include <string>
#include <cassert>
#include <math.h>

//-----------------------------------------------------------------------------
// Keyset 'Text' - generate all keys of the form "prefix"+"core"+"suffix",
// where "core" consists of all possible combinations of the given character
// set of length N.

template < typename hashtype >
static bool TextKeyImpl ( pfHash hash, const char * prefix, const char * coreset, const int corelen, const char * suffix, bool drawDiagram )
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
    addVCodeInput(key, keybytes);
  }

  //----------
  bool result = TestHashList(hashes,drawDiagram);
  printf("\n");

  delete [] key;

  addVCodeResult(result);

  return result;
}

//-----------------------------------------------------------------------------
// Keyset 'Words' - pick random chars from coreset (alnum or password chars)

template < typename hashtype >
static bool WordsKeyImpl ( pfHash hash, const long keycount,
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
    addVCodeInput(key, len);

#if 0 && defined DEBUG
    uint64_t h;
    memcpy(&h, &hashes[i], std::max(sizeof(hashtype),8));
    printf("%d %s %lx\n", i, (char*)key, h);
#endif
  }
  delete [] key;

  //----------
  bool result = TestHashList(hashes,drawDiagram);
  printf("\n");

  addVCodeResult(result);

  return result;
}

template < typename hashtype >
static bool WordsStringImpl ( pfHash hash, std::vector<std::string> & words,
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
    addVCodeInput(key, len);
  }

  //----------
  bool result = TestHashList(hashes,drawDiagram);
  printf("\n");

  addVCodeResult(result);

  return result;
}

//-----------------------------------------------------------------------------

template < typename hashtype >
bool TextKeyTest(HashInfo * info, const bool verbose) {
    pfHash hash = info->hash;
    bool result = true;
    const char * alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const char * passwordchars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                                 ".,!?:;-+=()<>/|\"'@#$%&*_^";

    printf("[[[ Keyset 'Text' Tests ]]]\n\n");

    Hash_Seed_init (hash, g_seed);

    result &= TextKeyImpl<hashtype>( hash, "Foo",    alnum, 4, "Bar",    verbose );
    result &= TextKeyImpl<hashtype>( hash, "FooBar", alnum, 4, "",       verbose );
    result &= TextKeyImpl<hashtype>( hash, "",       alnum, 4, "FooBar", verbose );

    // maybe use random-len vector of strings here, from len 6-16
    result &= WordsKeyImpl<hashtype>( hash, 4000000L, 6, 16, alnum, "alnum", verbose );
    result &= WordsKeyImpl<hashtype>( hash, 4000000L, 6, 16, passwordchars, "password", verbose );

    std::vector<std::string> words = HashMapInit(verbose);
    result &= WordsStringImpl<hashtype>( hash, words, verbose );

    if(!result) printf("*********FAIL*********\n");
    printf("\n");

    return result;
}

INSTANTIATE(TextKeyTest, HASHTYPELIST);
