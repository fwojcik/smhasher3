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
#include "Types.h"
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "PRNGTest.h"

#include <assert.h>

//-----------------------------------------------------------------------------
// Keyset 'Prng'

template< typename hashtype >
static void Prn_gen (int nbRn, pfHash hash, std::vector<hashtype> & hashes )
{
  assert(nbRn > 0);

  printf("Generating random numbers by hashing previous output - %d keys\n", nbRn);

  // Since all inputs were outputs, and outputs get hashed already,
  // just use the test parameters for the input VCode.
  addVCodeInput(nbRn);
  addVCodeInput(sizeof(hashtype));

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

//-----------------------------------------------------------------------------

template < typename hashtype >
bool PRNGTest(HashInfo * info, const bool verbose, const bool extra) {
    pfHash hash = info->hash;
    bool result = true;
    bool testCollision = true;
    bool testDistribution = extra;
    std::vector<hashtype> hashes;

    printf("[[[ Prng Tests ]]]\n\n");

    if (sizeof(hashtype) < 8) {
        printf("Skipping PRNG test; it is designed for hashes >= 64-bits\n\n");
        return result;
    }

    Hash_Seed_init (hash, g_seed);

    Prn_gen(32 << 20, hash, hashes);

    result &= TestHashList(hashes, verbose, testCollision, testDistribution);

    if(!result) printf("\n*********FAIL*********\n");
    printf("\n");

    addVCodeResult(result);

    return result;
}

INSTANTIATE(PRNGTest, HASHTYPELIST);
