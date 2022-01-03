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
 *     Copyright (c) 2019      Yann Collet
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
#include <cstdio>
#include <vector>
#include <map>
#include <algorithm>
#include <math.h>

#include "Platform.h"
#include "Types.h"
#include "Stats.h"    // for chooseUpToK
#include "Analyze.h"
#include "Random.h"
#include "Instantiate.h"
#include "VCode.h"

#include "DifferentialTest.h"

//-----------------------------------------------------------------------------
// Sort through the differentials, ignoring collisions that only occured once
// (these could be false positives). If we find collisions of 3 or more, the
// differential test fails.

template < class keytype >
static bool ProcessDifferentials ( std::map<keytype, uint32_t> & diffcounts, int reps, bool dumpCollisions )
{
  int totalcount = 0;
  int ignore = 0;

  bool result = true;

  if (diffcounts.size()) {
      for (std::pair<keytype, uint32_t> dc : diffcounts) {
          uint32_t count = dc.second;

          totalcount += count;

          if (count == 1) {
              ignore++;
          } else {
              result = false;

              if(dumpCollisions) {
                  double pct = 100 * (double(count) / double(reps));

                  printbits((unsigned char*)&dc.first, sizeof(keytype));
                  printf(" - %4.2f%%\n", pct );
              }
          }
      }
  }

  printf("%d total collisions, of which %d single collisions were ignored",
         totalcount,ignore);

  addVCodeResult(totalcount);
  addVCodeResult(ignore);

  if(result == false) {
      printf(" !!!!!");
  }

  printf("\n\n");

  return result;
}

//-----------------------------------------------------------------------------
// Check all possible keybits-choose-N differentials for collisions, report
// ones that occur significantly more often than expected.

// Random collisions can happen with probability 1 in 2^32 - if we do more than
// 2^32 tests, we'll probably see some spurious random collisions, so don't report
// them.

template < bool recursemore, typename keytype, typename hashtype >
static void DiffTestRecurse ( pfHash hash, keytype & k1, keytype & k2, hashtype & h1, hashtype & h2, int start, int bitsleft, std::map<keytype, uint32_t> & diffcounts )
{
  const int bits = sizeof(keytype)*8;

  assume(start < bits);
  for(int i = start; i < bits; i++)
  {
    keytype k2_prev = k2;

    flipbit(&k2,sizeof(k2),i);

    bitsleft--;

    hash(&k2,sizeof(k2),g_seed,&h2);
    addVCodeInput(&k2, sizeof(k2));
    addVCodeOutput(&h2, sizeof(h2));

    if(h1 == h2)
    {
        ++diffcounts[k1 ^ k2];
    }

    if(recursemore && likely((i+1) < bits))
    {
      if (bitsleft > 1)
        DiffTestRecurse<true>(hash,k1,k2,h1,h2,i+1,bitsleft,diffcounts);
      else
        DiffTestRecurse<false>(hash,k1,k2,h1,h2,i+1,bitsleft,diffcounts);
    }

    //flipbit(&k2,sizeof(k2),i);
    k2 = k2_prev;
    bitsleft++;
  }
}

//----------

template < typename keytype, typename hashtype >
static bool DiffTestImpl ( pfHash hash, int diffbits, int reps, bool dumpCollisions )
{
  const int keybits = sizeof(keytype) * 8;
  const int hashbits = sizeof(hashtype) * 8;

  double diffcount = chooseUpToK(keybits,diffbits);
  double testcount = (diffcount * double(reps));
  double expected  = testcount / pow(2.0,double(hashbits));

  Rand r(100);

  std::map<keytype, uint32_t> diffcounts;

  keytype k1,k2;
  hashtype h1,h2;
  h1 = h2 = 0;

  printf("Testing %0.f up-to-%d-bit differentials in %d-bit keys -> %d bit hashes.\n",
         diffcount,diffbits,keybits,hashbits);
  printf("%d reps, %0.f total tests, expecting %2.2f random collisions",
         reps,testcount,expected);

  Hash_Seed_init (hash, g_seed);
  for(int i = 0; i < reps; i++)
  {
    if(i % (reps/10) == 0) printf(".");

    r.rand_p(&k1,sizeof(keytype));
    k2 = k1;

    hash(&k1,sizeof(k1),g_seed,(void*)&h1);
    addVCodeInput(&k1, sizeof(k1));
    addVCodeOutput(&h1, sizeof(h1));

    DiffTestRecurse<true,keytype,hashtype>(hash,k1,k2,h1,h2,0,diffbits,diffcounts);
  }
  printf("\n");

  bool result = true;

  result &= ProcessDifferentials(diffcounts,reps,dumpCollisions);

  return result;
}

#if 0
#include "SparseKeysetTest.h" // for SparseKeygenRecurse
//-----------------------------------------------------------------------------
// Differential distribution test - for each N-bit input differential, generate
// a large set of differential key pairs, hash them, and test the output
// differentials using our distribution test code.

// This is a very hard test to pass - even if the hash values are well-distributed,
// the differences between hash values may not be. It's also not entirely relevant
// for testing hash functions, but it's still interesting.

// This test is a _lot_ of work, as it's essentially a full keyset test for
// each of a potentially huge number of input differentials. To speed things
// along, we do only a few distribution tests per keyset instead of the full
// grid.

// #TODO - put diagram drawing back on

template < typename keytype, typename hashtype >
void DiffDistTest ( pfHash hash, const int diffbits, int trials, double & worst, double & avg )
{
  std::vector<keytype>  keys(trials);
  std::vector<hashtype> A(trials),B(trials);

  Hash_Seed_init (hash, g_seed);
  for(int i = 0; i < trials; i++)
  {
    rand_p(&keys[i],sizeof(keytype));

    hash(&keys[i],sizeof(keytype),g_seed,(uint32_t*)&A[i]);
  }

  //----------

  std::vector<keytype> diffs;

  keytype temp(0);

  SparseKeygenRecurse<keytype>(0,diffbits,true,temp,diffs);

  //----------

  worst = 0;
  avg = 0;

  hashtype h2;

  for(size_t j = 0; j < diffs.size(); j++)
  {
    keytype & d = diffs[j];

    for(int i = 0; i < trials; i++)
    {
      keytype k2 = keys[i] ^ d;

      hash(&k2,sizeof(k2),g_seed,&h2);

      B[i] = A[i] ^ h2;
    }

    double dworst,davg;

    TestDistributionFast(B,dworst,davg);

    avg += davg;
    worst = (dworst > worst) ? dworst : worst;
  }

  avg /= double(diffs.size());
}
#endif /* 0 */

//-----------------------------------------------------------------------------
// Simpler differential-distribution test - for all 1-bit differentials,
// generate random key pairs and run full distribution/collision tests on the
// hash differentials

template < typename keytype, typename hashtype >
static bool DiffDistTest2 ( pfHash hash, bool drawDiagram )
{
  Rand r(857374);

  int keybits = sizeof(keytype) * 8;
  const int keycount = 256*256*32;
  keytype k;

  std::vector<hashtype> hashes(keycount);
  hashtype h1,h2;

  bool result = true;

  Hash_Seed_init (hash, g_seed);
  for(int keybit = 0; keybit < keybits; keybit++)
  {
    printf("Testing bit %d - %d keys\n",keybit, keycount);

    for(int i = 0; i < keycount; i++)
    {
      r.rand_p(&k,sizeof(keytype));
      hash(&k,sizeof(keytype),g_seed,&h1);
      addVCodeInput(&k, sizeof(keytype));

      flipbit(&k,sizeof(keytype),keybit);
      hash(&k,sizeof(keytype),g_seed,&h2);
      addVCodeInput(&k, sizeof(keytype));

      hashes[i] = h1 ^ h2;
    }

    result &= TestHashList<hashtype>(hashes,drawDiagram,true,true);
    addVCodeResult(result);

    printf("\n");
  }

  return result;
}

//----------------------------------------------------------------------------

template < typename hashtype >
bool DiffTest(HashInfo * info, const bool verbose, const bool extra, const bool hash_is_slow) {
    pfHash hash = info->hash;
    bool result = true;
    bool dumpCollisions = verbose;
    int reps = (info->quality == SKIP) || (!extra && hash_is_slow) ? 100 : 1000;

    printf("[[[ Diff 'Differential' Tests ]]]\n\n");

    result &= DiffTestImpl< Blob<64>,  hashtype >(hash,5,reps,dumpCollisions);
    result &= DiffTestImpl< Blob<128>, hashtype >(hash,4,reps,dumpCollisions);
    result &= DiffTestImpl< Blob<256>, hashtype >(hash,3,reps,dumpCollisions);

    if(!result) printf("*********FAIL*********\n");
    printf("\n");

    return result;
}

INSTANTIATE(DiffTest, HASHTYPELIST);

template < typename hashtype >
bool DiffDistTest(HashInfo * info, const bool verbose) {
    pfHash hash = info->hash;
    bool result = true;

    printf("[[[ DiffDist 'Differential Distribution' Tests ]]]\n\n");

    result &= DiffDistTest2<uint64_t,hashtype>(hash, verbose);

    if(!result) printf("*********FAIL*********\n");
    printf("\n");

    return result;
}

INSTANTIATE(DiffDistTest, HASHTYPELIST);
