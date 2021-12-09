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

//-----------------------------------------------------------------------------

double chooseK ( int n, int k )
{
  if(k > (n - k)) k = n - k;

  double c = 1;

  for(int i = 0; i < k; i++)
  {
    double t = double(n-i) / double(i+1);

    c *= t;
  }

    return c;
}

double chooseUpToK ( int n, int k )
{
  double c = 0;

  for(int i = 1; i <= k; i++)
  {
    c += chooseK(n,i);
  }

  return c;
}

//-----------------------------------------------------------------------------
// Distribution "score"
// TODO - big writeup of what this score means

// Basically, we're computing a constant that says "The test distribution is as
// uniform, RMS-wise, as a random distribution restricted to (1-X)*100 percent of
// the bins. This makes for a nice uniform way to rate a distribution that isn't
// dependent on the number of bins or the number of keys

// (as long as # keys > # bins * 3 or so, otherwise random fluctuations show up
// as distribution weaknesses)

double calcScore ( const int * bins, const int bincount, const int keycount )
{
  double n = bincount;
  double k = keycount;

  // compute rms value

  double r = 0;

  for(int i = 0; i < bincount; i++)
  {
    double b = bins[i];

    r += b*b;
  }

  r = sqrt(r / n);

  // compute fill factor

  double f = (k*k - 1) / (n*r*r - k);

  // rescale to (0,1) with 0 = good, 1 = bad

  return 1 - (f / n);
}


//----------------------------------------------------------------------------

void plot ( double n )
{
  double n2 = n * 1;

  if(n2 < 0) n2 = 0;

  n2 *= 100;

  if(n2 > 64) n2 = 64;

  int n3 = (int)n2;

  if(n3 == 0)
    printf(".");
  else
  {
    char x = '0' + char(n3);

    if(x > '9') x = 'X';

    printf("%c",x);
  }
}

//-----------------------------------------------------------------------------
