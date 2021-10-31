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
// Distribution score
//
// Randomly distributing m balls into n bins is a well-studied
// statistical model, relevant to a wide range of real world
// problems. It is exactly analogous to hashing k keys into n
// bins. The count of balls in a bin approximately follows a Poisson
// distribution, if the number of balls and bins are large enough.
//
// The previous version of this test was intended to compare the total
// set of key counts in each hash bin against a truly random Poisson
// distribution. It computed the Root Mean Square (RMS) of the actual
// key counts, and then computed how many bins would be needed to get
// that same RMS value assuming a random hash, finally comparing the
// two to come up with a single score value. For this score, less than
// 0 meant flatter/more even than random, 0.000 meant exactly random,
// and 1.000 (percent, as it happens) was considered a failure.
//
// This was very clever, but one of the key goals of the test turns
// out not to have been met. The previous comments said: "This makes
// for a nice uniform way to rate a distribution that isn't dependent
// on the number of bins or the number of keys". Unfortunately, it
// turns out that while a score of 0 did hold the desired meaning
// across all bin/key counts, the _variance_ of the score _was_
// dependent on the number of bins. This means that higher bin counts
// typically had higher scores from this test, even if the
// distributions were closer to the random ideal. And since only the
// highest score gets reported on, this also distorted which bit
// widths were reported as having the highest bias.
//
// I tried applying some corrections to the score with the goal of
// keeping this test. Multiplying the score by (keycount/bincount)
// comes close to having it be independent of the test sizes, but not
// close enough. The resulting score is very accurate when the bin
// counts are close to random, but it under-reports failures, and the
// worse the failure the more inaccurate the adjusted score was. A
// further correction to the score, to accurately report failures,
// seems to require bin- and hash-dependent constants for both
// score**2 and score**3 terms at the least.
//
// Rather than go down that complicated route, I changed this test to
// compute Root Mean Square Error (RMSE) across the bin counts. A
// truly random Poisson distribution will have an expected MSE of
// lambda (keycount/bincount), and multiplying the ratio of
// actual/expected by a factor of sqrt(2.0 * bincount) makes the score
// be a standard normal variable (E[score] = 0, Var[score] = 1)
// independent of bincount and keycount.
//
// The way the RMSE is calculated is a little odd. What we want is
// sumN{(Bi - lambda)**2}. But Bi values are integers, and doing all
// that math in a loop is expensive. So that formula gets rearranged:
//
// sumN{(Bi - lambda)**2}
// sumN{(Bi**2 - 2 * Bi * lambda + lambda**2)}
// sumN{(Bi**2)} - 2 * sumN{(Bi * lamba)} + sumN{(lambda**2)}
// sumN{(Bi**2)} - 2 * lambda * sumN{(Bi)} + N * (lambda**2)
// sumN{(Bi**2)} - 2 * lambda * M + N * (lambda**2)
// sumN{(Bi**2)} - 2 * M / N * M + N * M**2 / N**2
// sumN{(Bi**2)} - 2 * M**2 / N + M**2 / N
// sumN{(Bi**2)} - M**2 / N
// sumN{(Bi**2)} - M * lambda
//
// NB: bincount must be a non-zero multiple of 8!
double calcScore ( const unsigned * bins, const int bincount, const int keycount )
{
  const double n = bincount;
  const double k = keycount;
  const double lambda = k/n;

  size_t sumsq = 0;

  assume(bincount >= 8);
  for(int i = 0; i < (bincount>>3)<<3; i++)
    sumsq += (size_t)bins[i] * (size_t)bins[i];

  double sumsqe = (double)sumsq - lambda * k;
  double rmse = sqrt(sumsqe/n);
  double rmse_ratio_m1 = (rmse - sqrt(lambda))/sqrt(lambda); // == rmse/sqrt(lambda) - 1.0
  double score = (rmse_ratio_m1) * sqrt(2.0 * n);

  return score;
}

// Convert the score from calcScore back into (rmse/sqrt(lambda) -
// 1.0), to show the user something like the previous report.
double normalizeScore ( double score, int scorewidth, int tests )
{
    // Never return a result higher than this, as a precise value
    // would be visually cluttered and not really meaningful.
    const double maxresult = 9999.999;

    double result = score / sqrt(2.0 * scorewidth);

    if (result > maxresult)
        return maxresult;

    return result;
}

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

//-----------------------------------------------------------------------------
