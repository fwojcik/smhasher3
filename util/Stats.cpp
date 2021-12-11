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
 *     Copyright (c) 2019-2020 Yann Collet
 *     Copyright (c) 2020      Bradley Austin Davis
 *     Copyright (c) 2020      Paul Khuong
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
#include "Stats.h"

#include <math.h>
#include <cstdio>
#include <algorithm>

//-----------------------------------------------------------------------------

double CalcMean ( std::vector<double> & v )
{
  double mean = 0;

  for(int i = 0; i < (int)v.size(); i++)
  {
    mean += v[i];
  }

  mean /= double(v.size());

  return mean;
}

double CalcMean ( std::vector<double> & v, int a, int b )
{
  double mean = 0;

  for(int i = a; i <= b; i++)
  {
    mean += v[i];
  }

  mean /= (b-a+1);

  return mean;
}

double CalcStdv ( std::vector<double> & v, int a, int b )
{
  double mean = CalcMean(v,a,b);

  double stdv = 0;

  for(int i = a; i <= b; i++)
  {
    double x = v[i] - mean;

    stdv += x*x;
  }

  stdv = sqrt(stdv / (b-a+1));

  return stdv;
}

double CalcStdv ( std::vector<double> & v )
{
  return CalcStdv(v, 0, v.size());
}

// Return true if the largest value in v[0,len) is more than three
// standard deviations from the mean

bool ContainsOutlier ( std::vector<double> & v, size_t len )
{
  double mean = 0;

  for(size_t i = 0; i < len; i++)
  {
    mean += v[i];
  }

  mean /= double(len);

  double stdv = 0;

  for(size_t i = 0; i < len; i++)
  {
    double x = v[i] - mean;
    stdv += x*x;
  }

  stdv = sqrt(stdv / double(len));

  double cutoff = mean + stdv*3;

  return v[len-1] > cutoff;
}

// Do a binary search to find the largest subset of v that does not contain
// outliers.

void FilterOutliers ( std::vector<double> & v )
{
  std::sort(v.begin(),v.end());

  size_t len = 0;

  for(size_t x = 0x40000000; x; x = x >> 1 )
  {
    if((len | x) >= v.size()) continue;

    if(!ContainsOutlier(v,len | x))
    {
      len |= x;
    }
  }

  v.resize(len);
}

#if 0
// Iteratively tighten the set to find a subset that does not contain
// outliers. I'm not positive this works correctly in all cases.

void FilterOutliers2 ( std::vector<double> & v )
{
  std::sort(v.begin(),v.end());

  int a = 0;
  int b = (int)(v.size() - 1);

  for(int i = 0; i < 10; i++)
  {
    //printf("%d %d\n",a,b);

    double mean = CalcMean(v,a,b);
    double stdv = CalcStdv(v,a,b);

    double cutA = mean - stdv*3;
    double cutB = mean + stdv*3;

    while((a < b) && (v[a] < cutA)) a++;
    while((b > a) && (v[b] > cutB)) b--;
  }

  std::vector<double> v2;

  v2.insert(v2.begin(),v.begin()+a,v.begin()+b+1);

  v.swap(v2);
}
#endif

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
// Different ways of estimating collision counts across N numbers,
// each of which is i.i.d. distributed across M bins.
//
// Note: with 32bit 77163 keys will get a 50% probability of one collision.

// Naive multiplication, no accuracy at all
static double ExpectedNBCollisions_Slow ( const double nbH, const double nbBits )
{
  long balls = nbH;
  long double bins = nbBits;
  long double result = 1.0;
  for (long i = 1; i < balls / 2; i++) {
    // take a pair from the front and the end to minimize errors
    result *= ((bins - i) / bins) * ((bins - (nbH - i)) / bins);
  }
  return (double)(nbH * result);
}

// TODO This only works for a low number of collisions
static inline double ExpectedCollisions ( const double balls, const double bins )
{
  return balls - (bins * (1 - pow((bins - 1)/bins, balls)));
}

// Still too inaccurate: https://preshing.com/20110504/hash-collision-probabilities/
static double EstimateNbCollisions_Taylor(const double nbH, const double nbBits)
{
  const long double k = nbH;
  const long double b = nbBits;
  return (double)(k * (1.0 - expl(-0.5 * k * (k - 1.0) / b)));
}

// demerphq: (double(count) * double(count-1)) / pow(2.0,double(sizeof(hashtype) * 8 + 1));
// the very same as our calc. pow 2 vs exp2. Just the high cutoff is missing here.
static double EstimateNbCollisions_Demerphq(const double nbH, const double nbBits)
{
  return (nbH * (nbH - 1)) / pow(2.0, nbBits + 1);
}

// The previous best calculation, highly prone to inaccuracies with low results (1.0 - 10.0)
// TODO: return also the error.
static double EstimateNbCollisions_previmpl(const double nbH, const double nbBits)
{
  double exp = exp2(nbBits); // 2 ^ bits
  double result = (nbH * (nbH-1)) / (2.0 * exp);
  if (result > nbH)
    result = nbH;
  // improved floating point accuracy
  if (result <= exp || nbBits > 32)
    return result;
  return result - exp;
}

static double EstimateNbCollisions_fwojcik(const double nbH, const int nbBits)
{
    // If the probability that there are 1 or more collisions (p(C >=
    // 1)) is not much higher than the probability of exactly 1
    // collision (p(C == 1)), then the classically-good approximation
    // of the probability of any collisions is also a good estimate
    // for the expected number of collisions.
    //
    // If there are 2**n buckets and 2**(n-r) hashes, then the ratio
    // of p(C >= 1)/p(C == 1) is about 1/(1-2**(n-2r-1)). This uses
    // the new estimator if that ratio is > 1 + 2**-8. That cutoff
    // minimizes the error around the values we care about.
    if (nbBits - 2.0*log2(nbH) >= 8 - 1) {
        return nbH * (nbH - 1) * exp2(-nbBits-1);
    }

    // The probability that any given hash bucket is empty after nbH
    // insertions is:
    //    pE     = ((2**nbBits - 1)/(2**nbBits))**nbH
    // so we compute:
    //    ln(pE) = nbH * ln((2**nbBits - 1)/(2**nbBits))
    //           = nbH * ln(1 - 1/2**(nbBits))
    //           = nbH * ln(1 - 2**(-nbBits))
    //           = nbH * ln(1 + -(2**(-nbBits)))
    // This means the probability that any given hash bucket is
    // occupied after nbH insertions is:
    //     pF = 1 - pE
    //     pF = 1 - exp(ln(pE)
    //     pF = -(exp(ln(pE) - 1)
    //     pF = -expm1(ln(pE))
    // And the expected number of collisions is:
    //     C = m - n + n * pE
    //     C = m - n * (1 - pE)
    //     C = n * (m/n - 1 + pE)
    //     C = n * (m/n - (1 - pE))
    //     C = n * (m/n - pF)
    //     C = n * (m/n - (-expm1(ln(pE))))
    //     C = n * (m/n + expm1(ln(pE)))
    // Since the format of floats/doubles is k*2**n, multiplying by
    // exp2(x) doesn't lose any precision, and this formulation keeps
    // m/n and pF at the same general orders of magnitude, so it tends
    // to have very good precision. At low hash occupancy, pF is too
    // close to m/n for this formula to work well.
    double logpE = (double)nbH  * log1p(-exp2(-nbBits));
    double result = exp2(nbBits) * (exp2(-nbBits) * (double)nbH + expm1(logpE));

    return result;
}

double EstimateNbCollisions(const unsigned long nbH, const int nbBits)
{
  return EstimateNbCollisions_fwojcik((const double)nbH, (const double)nbBits);
}

double EstimateNbCollisionsCand(const unsigned long nbH, const int nbBits, const int estimator)
{
    switch(estimator) {
    case 0: return EstimateNbCollisions_fwojcik((const double)nbH, (const double)nbBits);
    case 1: return EstimateNbCollisions_previmpl((const double)nbH, (const double)nbBits);
    case 2: return EstimateNbCollisions_Demerphq((const double)nbH, (const double)nbBits);
    //case 3: return EstimateNbCollisions_Taylor((const double)nbH, (const double)nbBits);
    //case 4: return ExpectedCollisions((const double)nbH, (const double)nbBits);
    //case 5: return ExpectedNBCollisions_Slow((const double)nbH, (const double)nbBits);
    default: { printf("Invalid estimator requested\n"); exit(1); }
    }
    return NAN;
}

//-----------------------------------------------------------------------------

/*
 * Compute the lowest number of hash bits (n) such that there are
 * fewer than (2**n)*log(2**n) hashes, for a given hash count.
 *
 * This may validly return a value exceeding the number of hash bits
 * that exist for the hash being tested!
 */
int GetNLogNBound ( unsigned nbH )
{
  int nbHBits;
  for (nbHBits = 1; nbHBits <= 255; nbHBits++)
    if (nbH < (log(2.0) * nbHBits * exp2(nbHBits)))
      break;
  return nbHBits - 1;
}

/*
 * What SMHasher3 frequently reports on is the worst result across some
 * number of tests. If we compute the CDF/p-value of each test and
 * consider only those, then the tests become statistically identical,
 * since CDFs are continuous ~Uniform(0,1). Assuming sufficient
 * independence also, the CDF of the maximum of N values is equal to
 * the CDF of a single value raised to the Nth power, so we can just
 * raise the p-value itself to the power of the number of tests.
 *
 * The p-values in SMHasher3 are usually stored in variables as 1.0-p,
 * so that p-values very close to 1 (which are in the vicinity of
 * failing results) can be kept as accurate as possible in the face of
 * floating-point representation realities. This means we can't just
 * use pow(), but this alternate formulation does the same thing for
 * values in 1-p space.
 */
double ScalePValue ( double p_value, unsigned testcount )
{
  return -expm1(log1p(-p_value) * testcount);
}

/*
 * This is exactly the same as ScalePValue, but for 2**N tests.
 */
double ScalePValue2N ( double p_value, unsigned testbits )
{
  return -expm1(log1p(-p_value) * exp2(testbits));
}

/*
 * SMHasher3 reports p-values by displaying how many powers of 2 the
 * improbability is. This is the nicest way of summarizing the p-value
 * I've found. And since the really, truly most important result of
 * these tests is "does a hash pass or fail", and perhaps how close to
 * the line it is, the precise p-value is generally better left
 * unprinted.
 *
 * This is not a percentage or a ratio, and there is no standard unit
 * of log probability that I can find, so I've semi-arbitrarily chosen
 * the caret (^) to display these values, as that can indicate
 * exponentiation, and the p-value is no less than 1/(2**logp_value).
 */
int GetLog2PValue ( double p_value )
{
    return (log2(p_value) <= -99.0) ? 99 : -ceil(log2(p_value));
}

/*
 * Given a mean and standard deviation, return (1.0 - p) for the given
 * random normal variable.
 */
double GetNormalPValue(const double mu, const double sd, const double variable)
{
    double stdvar = (variable - mu) / sd;
    double p_value = erfc(stdvar/sqrt(2.0))/2.0;

    return p_value;
}

/*
 * A helper function for the Peizer and Pratt approximation below.
 */
static double GFunc_PeizerPratt(const double x) {
    if (x < 0.0)
        return NAN;
    if (x == 0.0)
        return 1.0;
    if (x == 1.0)
        return 0.0;
    if (x > 1.0)
        return -GFunc_PeizerPratt(1.0/x);
    return (1.0 - x*x + 2*x*log(x))/((1.0 - x)*(1.0 - x));
}

/*
 * Assume that m balls are i.i.d. randomly across n bins, with m >=
 * n*log(n). Then, the number of balls in any given bin tends to have
 * about log(n) balls and follows a binomial distribution. That is, if
 * Xi is the number of balls in bin i, then Xi ~ Bin(m, 1/n).
 *
 * But we aren't reporting on Xi, we are reporting on Xm = max{i=1..n;
 * Xi}. All the Xi are from identical distributions, and are actually
 * sufficiently independent in the random case that we can use the
 * usual {CDF(Xm)} = {CDF(Xi)}**n.
 *
 * The best non-iterative approximation to the Binomial distribution
 * CDF that I've found is the Peizer and Pratt transformation into a
 * standard normal distribution. We use that to find a p-value for Xi.
 * NB: "best" here is akin to "closest to p-values obtained through
 * simulation for Xm in the extreme tails", and not "least error
 * compared to actual overall binomial distribution values".
 *
 * Thanks to the paper:
 *   "APPROXIMATIONS TO THE BINOMIAL", by MYRTLE ANNA BRUCE
 *   https://core.ac.uk/download/pdf/33362622.pdf
 */
double EstimatedBinomialPValue(const unsigned long nbH, const int nbBits, const int maxColl)
{
    const double s = maxColl + 1;
    const double n = nbH;
    const double t = nbH - maxColl;
    const double p = exp2(-nbBits);
    const double q = 1.0 - p;

    const double d1 = s + 1.0/6.0 - p * (n + 1.0/3.0);
    const double d2 = d1 + 0.02 * (q/(s+0.5) - p/(t+0.5) + (q-0.5)/(n+1));

    const double num = 1.0 + q*GFunc_PeizerPratt(s/(n*p)) + p*GFunc_PeizerPratt(t/(n*q));
    const double denom = (n + 1.0/6.0) * p * q;
    const double z2 = d2 * sqrt(num/denom);

    // (1.0 - p) for one hash bin
    double p_value = GetNormalPValue(0.0, 1.0, z2);
    //fprintf(stderr, "Pr(Xi > %ld; %d, %d) ~= 1.0 - N(%f)\n", nbH, nbBits, maxColl, z2);

    // (1.0 - p) across all 2**nbBits hash bins
    double pm_value = ScalePValue2N(p_value, nbBits);
    //fprintf(stderr,"Pr(Xm > %ld; %d, %d) ~= 1.0-((1.0-%e)**(2**n)) == %.12f\n", nbH, nbBits, maxColl, p_value, pm_value, pm_value);

    return pm_value;
}

/*
 * For estimating the maximum value, we could get the normal value
 * with p=0.5 and back-convert, but the C standard library doesn't
 * have an inverse erf(), and I don't want to add an external
 * dependency just for this.
 *
 * This function computes an estimate of an upper bound on the number
 * of balls in the most-occupied bin. This set of formulas comes from:
 *
 * '"Balls into Bins" - A Simple and Tight Analysis', by
 *   Martin Raab and Angelika Steger
 *   http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.399.3974
 *
 * The adjustments for calculating the value that corresponds to the
 * 50th-percentile for a given nbBits were computed via linear
 * regression from Monte Carlo experiments by fwojcik [N ~= 80,000,000].
 */
double EstimateMaxCollisions(const unsigned long nbH, const int nbBits)
{
    double alpha = -expm1(-0.128775055 * nbBits - 0.759110989);
    double m     = (double)nbH - 16;
    double n     = exp2(nbBits);
    double logn  = nbBits * log(2);

    return (m/n) + alpha * sqrt(2.0 * (m/n) * logn);
}

/*
 * While computing p-values for Poisson distributions is generally
 * straightforward, it is also iterative and can require special care
 * due to floating-point considerations, especially in the long tail
 * of the distribution. Instead, this computes an upper bound on the
 * p-value using a single calculation. This is taken from:
 *
 * "Sharp Bounds on Tail Probabilities for Poisson Random Variables", by
 *   Peter Harremoës
 *   https://helda.helsinki.fi/bitstream/handle/10138/229679/witmse_proc_17.pdf
 *
 * Similar to other places in SMHasher3, this returns 1.0-p, so the
 * closer to 0 the worse the result. This also doesn't bother
 * computing real p-values for lower-than-expected collision counts,
 * since that is never a failure condition.
 */
double BoundedPoissonPValue(const double expected, const uint64_t collisions)
{
    if (collisions < expected)
        return 1.0;
    double x = (double)collisions - 0.5;
    double g_over_root2 = sqrt(x * log(x / expected) + expected - x);
    double p_lbound = erfc(g_over_root2)/2.0;
    return p_lbound;
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
