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
 *     Copyright (c) 2015      Paul G
 *     Copyright (c) 2015-2021 Reini Urban
 *     Copyright (c) 2016      Vlad Egorov
 *     Copyright (c) 2020      Paul Khuong
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
#include "Stats.h"
#include "Analyze.h"

#include <math.h>

//----------------------------------------------------------------------------

void plot ( double n )
{
  int ni = (int)floor(n);

  // Less than [0,3) sigma is fine, [3, 12) sigma is notable, 12+ sigma is pretty bad
  if(ni <= 2)
    putchar('.');
  else if (ni <= 11)
    putchar('1' + ni - 3);
  else
    putchar('X');
}

//----------------------------------------------------------------------------

#if 0
// Bytepair test - generate 16-bit indices from all possible non-overlapping
// 8-bit sections of the hash value, check distribution on all of them.

// This is a very good test for catching weak intercorrelations between bits -
// much harder to pass than the normal distribution test. However, it doesn't
// really model the normal usage of hash functions in hash table lookup, so
// I'm not sure it's that useful (and hash functions that fail this test but
// pass the normal distribution test still work well in practice)

template < typename hashtype >
double TestDistributionBytepairs ( std::vector<hashtype> & hashes, bool drawDiagram )
{
  const int nbytes = sizeof(hashtype);
  const int hashbits = nbytes * 8;

  const int nbins = 65536;

  std::vector<unsigned> bins(nbins,0);

  double worst = 0;

  for(int a = 0; a < hashbits; a++)
  {
    if(drawDiagram) if((a % 8 == 0) && (a > 0)) printf("\n");

    if(drawDiagram) printf("[");

    for(int b = 0; b < hashbits; b++)
    {
      if(drawDiagram) if((b % 8 == 0) && (b > 0)) printf(" ");

      bins.clear();
      bins.resize(nbins,0);

      for(size_t i = 0; i < hashes.size(); i++)
      {
        uint32_t pa = window(hashes[i],a,8);
        uint32_t pb = window(hashes[i],b,8);

        bins[pa | (pb << 8)]++;
      }

      double s = calcScore(bins,nbins,hashes.size());

      if(drawDiagram) plot(s);

      if(s > worst)
      {
        worst = s;
      }
    }

    if(drawDiagram) printf("]\n");
  }

  return worst;
}

//-----------------------------------------------------------------------------
// Simplified test - only check 64k distributions, and only on byte boundaries

template < typename hashtype >
void TestDistributionFast ( std::vector<hashtype> & hashes, double & dworst, double & davg )
{
  const int hashbits = sizeof(hashtype) * 8;
  const int nbins = 65536;

  std::vector<unsigned> bins(nbins,0);

  dworst = -1.0e90;
  davg = 0;

  for(int start = 0; start < hashbits; start += 8)
  {
    bins.clear();
    bins.resize(nbins,0);

    for(size_t j = 0; j < hashes.size(); j++)
    {
      uint32_t index = window(hashes[j],start,16);

      bins[index]++;
    }

    double n = calcScore(&bins.front(),nbins,(int)hashes.size());

    davg += n;

    if(n > dworst) dworst = n;
  }

  davg /= double(hashbits/8);
}

//-----------------------------------------------------------------------------
#endif
