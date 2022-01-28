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
#include "Platform.h"
#include "Types.h"
#include "Stats.h"    // for chooseUpToK
#include "Random.h"
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "DifferentialTest.h"

#include <cstdio>
#include <math.h>

//-----------------------------------------------------------------------------
// Sort through the differentials, ignoring collisions that only
// occured once (these could be false positives). If we find identical
// hash counts of 3 or more (2+ collisions), the differential test fails.

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
static void DiffTestRecurse ( HashFn hash, keytype & k1, keytype & k2, hashtype & h1, hashtype & h2, int start, int bitsleft, std::map<keytype, uint32_t> & diffcounts )
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

//-----------------------------------------------------------------------------

template < typename keytype, typename hashtype >
static bool DiffTestImpl ( HashFn hash, int diffbits, int reps, bool dumpCollisions )
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

  for(int i = 0; i < reps; i++)
  {
    if ((reps >= 10) && (i % (reps/10) == 0)) printf(".");

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

  recordTestResult(result, "Differential", diffbits);

  return result;
}

//----------------------------------------------------------------------------

template < typename hashtype >
bool DiffTest(const HashInfo * hinfo, const bool verbose, const bool extra) {
    const HashFn hash = hinfo->hashFn(g_hashEndian);
    bool dumpCollisions = verbose;
    bool result = true;

    // Do fewer reps with slow or very bad hashes
    bool slowhash = hinfo->bits > 128 || hinfo->isSlow();
    int reps = hinfo->isMock() ? 2 : ((slowhash && !extra) ? 100 : 1000);

    printf("[[[ Diff 'Differential' Tests ]]]\n\n");

    hinfo->Seed(g_seed);

    result &= DiffTestImpl< Blob<64>,  hashtype >(hash,5,reps,dumpCollisions);
    result &= DiffTestImpl< Blob<128>, hashtype >(hash,4,reps,dumpCollisions);
    result &= DiffTestImpl< Blob<256>, hashtype >(hash,3,reps,dumpCollisions);

    if(!result) printf("*********FAIL*********\n");
    printf("\n");

    return result;
}

INSTANTIATE(DiffTest, HASHTYPELIST);
