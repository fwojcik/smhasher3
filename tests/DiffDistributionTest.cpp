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
#include "TestGlobals.h"
#include "Bitvec.h"
#include "Random.h"
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "DiffDistributionTest.h"

//-----------------------------------------------------------------------------
// Simpler differential-distribution test - for all 1-bit differentials,
// generate random key pairs and run full distribution/collision tests on the
// hash differentials

template < typename keytype, typename hashtype >
static bool DiffDistTest2(HashFn hash, const seed_t seed, bool drawDiagram) {
  Rand r(857374);

  int keybits = sizeof(keytype) * 8;
  const int keycount = 256*256*32;
  keytype k;

  std::vector<hashtype> hashes(keycount);
  hashtype h1,h2;

  bool result = true;

  for(int keybit = 0; keybit < keybits; keybit++)
  {
    printf("Testing bit %d - %d keys\n",keybit, keycount);

    for(int i = 0; i < keycount; i++)
    {
      r.rand_p(&k, sizeof(keytype));
      hash(&k, sizeof(keytype), seed, &h1);
      addVCodeInput(&k, sizeof(keytype));

      flipbit(&k, sizeof(keytype), keybit);
      hash(&k, sizeof(keytype), seed, &h2);
      addVCodeInput(&k, sizeof(keytype));

      hashes[i] = h1 ^ h2;
    }

    bool thisresult = TestHashList<hashtype>(hashes,drawDiagram,true,true);
    printf("\n");

    addVCodeResult(thisresult);

    recordTestResult(thisresult, "DiffDist", keybit);

    result &= thisresult;
  }

  return result;
}

//----------------------------------------------------------------------------

template < typename hashtype >
bool DiffDistTest(const HashInfo * hinfo, const bool verbose) {
    const HashFn hash = hinfo->hashFn(g_hashEndian);
    bool result = true;

    printf("[[[ DiffDist 'Differential Distribution' Tests ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed);

    result &= DiffDistTest2<uint64_t,hashtype>(hash, seed, verbose);

    printf("%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(DiffDistTest, HASHTYPELIST);

//-----------------------------------------------------------------------------
// An old implementation; currently unused.

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
void DiffDistTest ( HashFn hash, const int diffbits, int trials, double & worst, double & avg )
{
  std::vector<keytype>  keys(trials);
  std::vector<hashtype> A(trials),B(trials);

  //FIXME seedHash(hash, g_seed);
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
