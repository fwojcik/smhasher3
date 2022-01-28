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

#include "SeedTest.h"

#include <cassert>

//-----------------------------------------------------------------------------
// Keyset 'Seed' - hash "the quick brown fox..." using different seeds

template < typename hashtype >
static bool SeedTestImpl(const HashInfo * hinfo, int keycount, bool drawDiagram) {
  const HashFn hash = hinfo->hashFn(g_hashEndian);
  printf("Keyset 'Seed' - %d keys\n",keycount);
  assert(keycount < (1<<31));

  const char text[64] = "The quick brown fox jumps over the lazy dog";
  const int len = (int)strlen(text);

  addVCodeInput(text, len);
  addVCodeInput(keycount);

  //----------

  std::vector<hashtype> hashes;

  hashes.resize(keycount);

  for(seed_t i = 0; i < keycount; i++)
  {
    hinfo->Seed(i);
    hash(text,len,i,&hashes[i]);
  }

  bool result = TestHashList(hashes,drawDiagram);
  printf("\n");

  recordTestResult(result, "Seed", (const char *)NULL);

  addVCodeResult(result);

  return result;
}

//-----------------------------------------------------------------------------

template < typename hashtype >
bool SeedTest(const HashInfo * hinfo, const bool verbose) {
    bool result = true;

    printf("[[[ Keyset 'Seed' Tests ]]]\n\n");

    result &= SeedTestImpl<hashtype>( hinfo, 5000000, verbose );

    if(!result) printf("*********FAIL*********\n");
    printf("\n");

    return result;
}

INSTANTIATE(SeedTest, HASHTYPELIST);
