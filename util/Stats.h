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
#pragma once

#include "Types.h"

#ifdef DEBUG
#include "Bitvec.h"
#endif

#include <math.h>
#include <vector>
#include <map>
#include <limits>
#include <climits>
#include <algorithm>   // for std::sort
#include <string.h>    // for memset
#include <stdio.h>     // for printf
#include <assert.h>

// If score exceeds this improbability of happening, note a failing result
const double FAILURE_PBOUND = exp2(-15); // 2**-15 == 1/32768 =~ 0.00305%
// If score exceeds this improbability of happening, note a warning
const double WARNING_PBOUND = exp2(-12); // 2**-12 == 1/4096 =~ 0.0244%, 8x as much as failure
// If these bounds seem overly generous, remember that SMHasher3 uses
// about 1000 tests, so a 1/1000 chance event will hit once per run on
// average, even with a perfect-quality hash function.

double CalcMean ( std::vector<double> & v );
double CalcMean ( std::vector<double> & v, int a, int b );
double CalcStdv ( std::vector<double> & v );
double CalcStdv ( std::vector<double> & v, int a, int b );
bool ContainsOutlier ( std::vector<double> & v, size_t len );
void FilterOutliers ( std::vector<double> & v );

double calcScore ( const unsigned * bins, const int bincount, const int ballcount );
double normalizeScore ( double score, int scorewidth, int tests );

void plot ( double n );

double chooseK ( int b, int k );
double chooseUpToK ( int n, int k );

//-----------------------------------------------------------------------------

inline uint32_t f3mix ( uint32_t k )
{
  k ^= k >> 16;
  k *= 0x85ebca6b;
  k ^= k >> 13;
  k *= 0xc2b2ae35;
  k ^= k >> 16;

  return k;
}

//-----------------------------------------------------------------------------
// Sort the hash list, count the total number of collisions and return
// the first N collisions for further processing

template< typename hashtype >
unsigned int FindCollisions ( std::vector<hashtype> & hashes,
                              HashSet<hashtype> & collisions,
                              int maxCollisions = 1000,
                              bool drawDiagram = false)
{
  unsigned int collcount = 0;
  blobsort(hashes.begin(),hashes.end());

  for(size_t hnb = 1; hnb < hashes.size(); hnb++)
    {
      if(hashes[hnb] == hashes[hnb-1])
        {
          collcount++;
          if(collcount < maxCollisions)
            {
#ifdef DEBUG
              printf ("\n%zu: ", hnb);
              printHash(&hashes[hnb], sizeof(hashtype));
#endif
              if (drawDiagram)
                collisions.insert(hashes[hnb]);
            }
        }
    }

#ifdef DEBUG
    if (collcount)
      printf ("\n");
#endif
  return collcount;

#if 0
  // sort indices instead
  std::vector< std::pair<hashtype, size_t>> pairs;
  pairs.resize (hashes.size());
  for(size_t i = 0; i < hashes.size(); i++)
    {
      pairs[i] = std::make_pair(hashes[i], i);
    }
  std::sort(pairs.begin(),pairs.end());
  for(size_t hnb = 1; hnb < pairs.size(); hnb++)
    {
      hashtype h1 = pairs[hnb].first;
      hashtype prev = pairs[hnb-1].first;
      if(h1 == prev)
        {
          collcount++;
          if((int)collisions.size() < maxCollisions)
            {
#ifdef DEBUG
              printf ("\n%zu <=> %zu: ", pairs[hnb-1].second, pairs[hnb].second);
              printHash(&h1, sizeof(hashtype));
#endif
              collisions.insert(h1);
            }
        }
    }
#endif
}

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

static double EstimateNbCollisions(const unsigned long nbH, const int nbBits)
{
  return EstimateNbCollisions_fwojcik((const double)nbH, (const double)nbBits);
}

#define COLLISION_ESTIMATORS 3
static double EstimateNbCollisionsCand(const unsigned long nbH, const int nbBits, const int estimator )
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
static int GetNLogNBound ( unsigned nbH )
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
static double ScalePValue ( double p_value, unsigned testcount )
{
  return -expm1(log1p(-p_value) * testcount);
}

/*
 * This is exactly the same as ScalePValue, but for 2**N tests.
 */
static double ScalePValue2N ( double p_value, unsigned testbits )
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
static int GetLog2PValue ( double p_value )
{
    return (log2(p_value) <= -99.0) ? 99 : -ceil(log2(p_value));
}

/*
 * Given a mean and standard deviation, return (1.0 - p) for the given
 * random normal variable.
 */
static double GetNormalPValue(const double mu, const double sd, const double variable)
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
static double EstimatedBinomialPValue(const unsigned long nbH, const int nbBits, const int maxColl)
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
static double EstimateMaxCollisions(const unsigned long nbH, const int nbBits)
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
static double BoundedPoissonPValue(const double expected, const uint64_t collisions)
{
    if (collisions < expected)
        return 1.0;
    double x = (double)collisions - 0.5;
    double g_over_root2 = sqrt(x * log(x / expected) + expected - x);
    double p_lbound = erfc(g_over_root2)/2.0;
    return p_lbound;
}

//-----------------------------------------------------------------------------

static bool ReportCollisions( size_t const nbH, int collcount, unsigned hashsize, bool maxcoll, bool highbits, bool header, bool verbose, bool drawDiagram )
{
  bool largehash = hashsize > (8 * sizeof(uint32_t));

  // The expected number depends on what collision statistic is being
  // reported on; "worst of N buckets" is very different than "sum
  // over N buckets".
  //
  // Also determine an upper-bound on the unlikelihood of the observed
  // collision count.
  double expected, p_value;
  if (maxcoll)
  {
    expected = EstimateMaxCollisions(nbH, hashsize);
    p_value = EstimatedBinomialPValue(nbH, hashsize, collcount);
  }
  else
  {
    expected = EstimateNbCollisions(nbH, hashsize);
    p_value = BoundedPoissonPValue(expected, collcount);
  }
  int logp_value = GetLog2PValue(p_value);

  // Since p-values are now used to determine pass/warning/failure
  // status, ratios are now solely for humans reading the results.
  //
  // If there were no collisions and none were expected, for a
  // suitably fuzzy value of "none", then a ratio of 1.00 ("test
  // exactly met expectations") is most sensible.
  //
  // If there were no collisions and there was a decent chance of
  // seeing one, then a ratio of 0.00 ("test saw 0% of expected
  // collisions") seems best.
  //
  // If there were any collisions, and the odds of seeing one were
  // quite low (arbitrarily chosen to be 0.01), then a ratio isn't
  // really meaningful, so we use +inf.
  //
  // A collision count matching the rounded expectation value is
  // treated as "exactly expected". For small hash sizes, if the
  // expected count has more than 0.1 after the decimal place and the
  // actual collision count is the next integer above the expected
  // one, then that case is also treated as "exactly expected".
  //
  // In all other cases, the true ratio is computed, but the value
  // will be bounded to not clutter the output in failure cases.
  double ratio;
  if (collcount == 0)
      ratio = (expected < 0.1) ? 1.00 : 0.00;
  else if (expected < 0.01)
      ratio = INFINITY;
  else if (collcount == (int)round(expected))
      ratio = 1.00;
  else if (!largehash && (collcount == (int)round(expected+0.4)))
      ratio = 1.00;
  else {
      ratio = double(collcount) / expected;
      if (ratio > 9999.99)
          ratio = INFINITY;
  }

  bool warning = false, failure = false;
  if (p_value <  FAILURE_PBOUND)
      failure = true;
  else if (p_value < WARNING_PBOUND)
      warning = true;
  else if (isnan(ratio))
      warning = true;

  if (verbose)
  {
    if (header)
      printf("Testing %s collisions (%s %3i-bit)", maxcoll ? "max" : "all",
        highbits ? "high" : "low ", hashsize);

    // 7 integer digits would match the 9.1 float specifier
    // (9 characters - 1 decimal point - 1 digit after the decimal),
    // but some hashes greatly exceed expected collision counts.
    if (finite(ratio))
      printf(" - Expected %9.1f, actual %9i  (%.3fx) ", expected, collcount, ratio);
    else
      printf(" - Expected %9.1f, actual %9i  (------) ", expected, collcount);

    // Since ratios and p-value summaries are most important to humans,
    // and deltas and exact p-values add visual noise and variable line
    // widths and possibly field counts, they are now only printed out
    // in --verbose mode.
    if (drawDiagram)
      printf("(%+i) (p<%8.6f) (^%2d)",  collcount - (int)round(expected), p_value, logp_value);
    else
      printf("(^%2d)", logp_value);

    if (failure)
      printf(" !!!!!\n");
    else if (warning)
      printf(" !\n");
    else
      printf("\n");
  }

  return !failure;
}

// If threshHBits is 0, then this tallies the total number of
// collisions across all given hashes for each bit window in the range
// of [minHBits, maxHBits], considering only the high bits.
//
// If threshHBits is not 0, then this tallies the total number of
// collisions across all the given hashes for each bit window in the
// range (threshHBits, maxHBits], and the peak/maximum number of
// collisions for each bit window in the range [minHBits,
// threshHBits], considering only the high bits in each case.
//
// This is possible to do in a single pass over all the hashes by
// counting the number of bits which match the next-lower hash value,
// since a collision for N bits is also a collision for N-k bits.
//
// This requires the vector of hashes to be sorted.
template< typename hashtype >
void CountRangedNbCollisions ( std::vector<hashtype> & hashes, size_t const nbH, int minHBits, int maxHBits, int threshHBits, int * collcounts)
{
  const int origBits = sizeof(hashtype) * 8;
  assert(minHBits >= 1);
  assert(minHBits <= maxHBits);
  assert(origBits >= maxHBits);
  assert((threshHBits == 0) || (threshHBits >= minHBits));
  assert((threshHBits == 0) || (threshHBits <= maxHBits));

  const int collbins = maxHBits - minHBits + 1;
  const int maxcollbins = (threshHBits == 0) ? 0 : threshHBits - minHBits + 1;
  int prevcoll[maxcollbins] = { 0 };
  int maxcoll[maxcollbins] = { 0 };

  memset(collcounts, 0, sizeof(collcounts[0])*collbins);
  for (size_t hnb = 1; hnb < nbH; hnb++)
  {
    hashtype hdiff = hashes[hnb-1] ^ hashes[hnb];
    int hzb = highzerobits(hdiff);
    if (hzb > maxHBits)
      hzb = maxHBits;
    if (hzb >= minHBits)
      collcounts[hzb - minHBits]++;
    // If we don't care about maximum collision counts, or if this
    // hash is a collision for *all* bit widths where we do care about
    // maximums, then this is all that need be done for this hash.
    if (hzb >= threshHBits)
      continue;
    // If we do care about maximum collision counts, then any window
    // sizes which are strictly larger than hzb have just encountered
    // a non-collision. For each of those window sizes, see how many
    // collisions there have been since the last non-collision, and
    // record it if that's the new peak.
    if (hzb < minHBits - 1)
      hzb = minHBits - 1;
    // coll is the total number of collisions so far, for the window
    // width corresponding to index i
    int coll = 0;
    for (int i = collbins - 1; i >= maxcollbins; i--)
      coll += collcounts[i];
    for (int i = maxcollbins - 1; i > hzb - minHBits; i--)
    {
      coll += collcounts[i];
      // See if this is the new peak for this window width
      maxcoll[i] = std::max(maxcoll[i], coll - prevcoll[i]);
      // Record the total number of collisions seen so far at this
      // non-collision, so that when the next non-collision happens we
      // can compute how many collisions there have been since this one.
      prevcoll[i] = coll;
    }
  }

  for (int i = collbins - 2; i >= 0; i--)
    collcounts[i] += collcounts[i + 1];
  for (int i = maxcollbins - 1; i >= 0; i--)
    collcounts[i] = std::max(maxcoll[i], collcounts[i] - prevcoll[i]);
}

static int FindMinBits_TargetCollisionShare(int nbHashes, double share)
{
    int nb;
    for (nb=2; nb<64; nb++) {
        double const maxColls = (double)(1ULL << nb) * share;
        double const nbColls = EstimateNbCollisions(nbHashes, nb);
        if (nbColls < maxColls) return nb;
    }
    assert(0);
    return nb;
}

static int FindMaxBits_TargetCollisionNb(int nbHashes, int minCollisions, int maxbits)
{
    int nb;
    for (nb=maxbits; nb>2; nb--) {
        double const nbColls = EstimateNbCollisions(nbHashes, nb);
        if (nbColls > minCollisions) return nb;
    }
    //assert(0);
    return nb;
}

static bool ReportBitsCollisions ( size_t nbH, int * collcounts, int minBits, int maxBits, bool highbits, bool drawDiagram )
{
  if (maxBits <= 1 || minBits > maxBits) return true;

  int spacelen = 78;
  spacelen -= printf("Testing all collisions (%s %2i..%2i bits) - ",
          highbits ? "high" : "low ", minBits, maxBits);

  double maxCollDev = 0.0;
  int maxCollDevBits = 0;
  int maxCollDevNb = 0;
  double maxCollDevExp = 1.0;
  double maxPValue = INFINITY;

  for (int b = minBits; b <= maxBits; b++) {
      int    const nbColls = collcounts[b - minBits];
      double const expected = EstimateNbCollisions(nbH, b);
      assert(expected > 0.0);
      double const dev = (double)nbColls / expected;
      double const p_value = BoundedPoissonPValue(expected, nbColls);
      //printf("%d bits, %d/%f, p %f\n", b, nbColls, expected, p_value);
      if (p_value < maxPValue) {
          maxPValue = p_value;
          maxCollDev = dev;
          maxCollDevBits = b;
          maxCollDevNb = nbColls;
          maxCollDevExp = expected;
      }
  }

  const char * spaces = "                ";
  int i_maxCollDevExp = (int)round(maxCollDevExp);
  spacelen -= printf("Worst is %2i bits: %i/%i ", maxCollDevBits, maxCollDevNb, i_maxCollDevExp);
  if (spacelen < 0)
      spacelen = 0;
  else if (spacelen > strlen(spaces))
      spacelen = strlen(spaces);

  if (maxCollDev > 9999.99)
      maxCollDev = INFINITY;

  if (finite(maxCollDev))
    printf("%.*s(%.3fx) ", spacelen, spaces, maxCollDev);
  else
    printf("%.*s(------) ", spacelen, spaces);

  double p_value = ScalePValue(maxPValue, maxBits - minBits + 1);
  int logp_value = GetLog2PValue(p_value);

  if (drawDiagram)
    printf("(%+i) (p<%8.6f) (^%2d)", maxCollDevNb - i_maxCollDevExp, p_value, logp_value);
  else
    printf("(^%2d)", logp_value);

  if (p_value < FAILURE_PBOUND)
  {
    printf(" !!!!!\n");
    return false;
  }
  else if (p_value < WARNING_PBOUND)
    printf(" !\n");
  else
    printf("\n");
  return true;
}

//-----------------------------------------------------------------------------

template < typename hashtype >
int PrintCollisions ( HashSet<hashtype> & collisions )
{
  printf("\nCollisions:\n");
  for (typename HashSet<hashtype>::iterator it = collisions.begin();
       it != collisions.end(); ++it)
  {
    const hashtype &hash = *it;
    printhex(&hash, sizeof(hashtype));
    printf("\n");
  }
  return 0;
}

//----------------------------------------------------------------------------
// Measure the distribution "score" for each possible N-bit span, with
// N going from 8 to 20 inclusive.

static int MaxDistBits ( const size_t nbH )
{
  int maxwidth = 20;
  // We need at least 5 keys per bin to reliably test distribution biases
  // down to 1%, so don't bother to test sparser distributions than that
  while(double(nbH) / double(1 << maxwidth) < 5.0)
    --maxwidth;
  return maxwidth;
}

template< typename hashtype >
bool TestDistribution ( std::vector<hashtype> & hashes, bool drawDiagram )
{
  const int hashbits = sizeof(hashtype) * 8;
  const uint32_t nbH = hashes.size();
  int maxwidth = MaxDistBits(nbH);
  int minwidth = 8;

  if (maxwidth < minwidth) return true;

  printf("Testing distribution - %s", drawDiagram ? "\n[" : "");

  std::vector<unsigned> bins;
  bins.resize(1 << maxwidth);

  double worstN = 0; // Only report on biases above 0
  int worstStart = -1;
  int worstWidth = -1;
  int tests = 0;

  for(int start = 0; start < hashbits; start++)
  {
    int width = maxwidth;
    int bincount = (1 << width);

    memset(&bins[0],0,sizeof(int)*bincount);

    for(size_t j = 0; j < nbH; j++)
    {
      uint32_t index = window(hashes[j],start,width);

      bins[index]++;
    }

    // Test the distribution, then fold the bins in half,
    // repeat until we're down to 256 bins

    while(bincount >= 256)
    {
      double n = calcScore(&bins[0],bincount,nbH);

      tests++;

      if(drawDiagram) plot(n);

      if(n > worstN)
      {
        worstN = n;
        worstStart = start;
        worstWidth = width;
      }

      width--;
      bincount /= 2;

      if(width < minwidth) break;

      // To allow the compiler to parallelize this loop
      assume((bincount % 8) == 0);

      for(int i = 0; i < bincount; i++)
      {
        bins[i] += bins[i+bincount];
      }
    }

    if(drawDiagram) printf("]\n%s", ((start + 1) == hashbits) ? "" : "[");
  }

  double p_value = ScalePValue(GetNormalPValue(0, 1, worstN), tests);
  int logp_value = GetLog2PValue(p_value);
  double mult = normalizeScore(worstN, worstWidth, tests);

  if (worstStart == -1)
      printf("Worst bias is                              - %.3fx             ",
              mult, logp_value);
  else
      printf("Worst bias is the %2d-bit window at bit %3d - %.3fx             ",
              worstWidth, worstStart, mult, logp_value);

  if (drawDiagram)
    printf("(%f) (p<%8.6f) (^%2d)", worstN, p_value, logp_value);
  else
    printf("(^%2d)", logp_value);

  if (p_value < FAILURE_PBOUND)
  {
    printf(" !!!!!\n");
    return false;
  }
  else if (p_value < WARNING_PBOUND)
    printf(" !\n");
  else
    printf("\n");
  return true;
}

//----------------------------------------------------------------------------

static int FindNbBitsForCollisionTarget(int targetNbCollisions, int nbHashes)
{
    int nb;
    double const target = (double)targetNbCollisions;
    for (nb=2; nb<64; nb++) {
        double nbColls = EstimateNbCollisions(nbHashes, nb);
        if (nbColls < target) break;
    }

    if ((EstimateNbCollisions(nbHashes, nb)) > targetNbCollisions/5)
        return nb;

    return nb-1;
}

static void ComputeCollBitBounds ( std::vector<int> & nbBitsvec, int origBits, int nbH, int & minBits, int & maxBits, int & threshBits )
{
  const int nlognBits = GetNLogNBound(nbH);

  minBits = origBits + 1;
  maxBits = 0;
  threshBits = 0;

  for(const int nbBits: nbBitsvec)
  {
    // If the nbBits value is too large for this hashtype, do nothing.
    if (nbBits >= origBits)
      continue;
    // If many hashes are being tested (compared to the hash width),
    // then the expected number of collisions will approach the number
    // of keys (indeed, it will converge to every hash bucket being
    // full, leaving nbH - 2**nbBits collisions). In those cases, it is
    // not very useful to count all collisions, so at some point of high
    // expected collisions, it is better to instead count the number of
    // keys in the fullest bucket. The cutoff here is if there are
    // (n*log(n)) hashes, where n is the number of hash buckets. This
    // cutoff is an inflection point where the "balls-into-bins"
    // statistics really start changing. ReportCollisions() will
    // estimate the correct key count for that differently, as it is a
    // different statistic.
    if (nbBits < nlognBits)
      threshBits = std::max(threshBits, nbBits);
    // Record the highest and lowest valid bit widths to test
    maxBits = std::max(maxBits, nbBits);
    minBits = std::min(minBits, nbBits);
  }
}

template < typename hashtype >
bool TestHashList ( std::vector<hashtype> & hashes, bool drawDiagram,
                    bool testCollision = true, bool testDist = true,
                    bool testHighBits = true, bool testLowBits = true,
                    bool verbose = true )
{
  bool result = true;

  if (testCollision)
  {
    unsigned const hashbits = sizeof(hashtype) * 8;
    if (verbose)
      printf("Testing all collisions (     %3i-bit)", hashbits);

    size_t const nbH = hashes.size();
    int collcount = 0;
    HashSet<hashtype> collisions;
    collcount = FindCollisions(hashes, collisions, 1000, drawDiagram);

    /*
     * Do all other compute-intensive stuff (as requested) before
     * displaying any results from FindCollisions, to be a little bit
     * more human-friendly.
     */

    std::vector<int> nbBitsvec = { 224, 160, 128, 64, 32, 12, 8, };
    /*
     * cyan: The 12- and -8-bit tests are too small : tables are necessarily saturated.
     * It would be better to count the nb of collisions per Cell, and
     * compared the distribution of values against a random source.
     * But that would be a different test.
     *
     * rurban: No, these tests are for non-prime hash tables, using only
     *     the lower 5-10 bits
     *
     * fwojcik: Collision counting did not previously reflect
     * rurban's comment, as the code counted the sum of collisions
     * across _all_ buckets. So if there are many more hashes than
     * 2**nbBits, and the hash is even _slightly_ not broken, then
     * every n-bit truncated hash value will appear at least once, in
     * which case the "actual" value reported would always be
     * (hashes.size() - 2**nbBits). Checking the results in doc/
     * confirms this. cyan's comment was correct.
     *
     * Collision counting has now been modified to report on the
     * single bucket with the most collisions when fuller hash tables
     * are being tested, and ReportCollisions() computes an
     * appropriate "expected" statistic.
     */

    /*
     * Compute the number of bits for a collision count of
     * approximately 100.
     */
    if (testHighBits || testLowBits)
    {
      int const hundredCollBits = FindMaxBits_TargetCollisionNb(nbH, 100, hashbits);
      if (EstimateNbCollisions(nbH, hundredCollBits) >= 100)
        nbBitsvec.push_back(hundredCollBits);
      std::sort(nbBitsvec.rbegin(), nbBitsvec.rend());
      std::unique(nbBitsvec.rbegin(), nbBitsvec.rend());
    }

    /*
     * Each bit width value in nbBitsvec is explicitly reported on. If
     * any of those values are less than the n*log(n) bound, then the
     * bin with the most collisions will be reported on, otherwise the
     * total sum of collisions across all bins will be reported on.
     *
     * But there are many more bit widths that a) are probably used in
     * the real world, and b) we can now cheaply analyze and report
     * on. Any bit width above the n*log(n) bound that has a
     * reasonable number of expected collisions is worth analyzing, so
     * that range of widths is computed here.
     *
     * This is slightly complicated by the fact that
     * TestDistribution() may also get invoked, which does an
     * RMSE-based comparison to the expected distribution over some
     * range of bit width values. If that will be invoked, then
     * there's no point in doubly-reporting on collision counts for
     * those bit widths, so they get excluded here.
     */
    std::vector<int> testBitsvec;
    int const nlognBits = GetNLogNBound(nbH);
    int const minTBits = testDist ? std::max(MaxDistBits(nbH)+1, nlognBits) : nlognBits;
    int const maxTBits = FindMaxBits_TargetCollisionNb(nbH, 10, hashbits - 1);

    if (testHighBits || testLowBits)
      for (int i = minTBits; i <= maxTBits; i++)
        testBitsvec.push_back(i);

    /*
     * Given the range of hash sizes we care about, compute all
     * collision counts for them, for high- and low-bits as requested.
     */
    std::vector<hashtype> revhashes;
    std::vector<int> collcounts_fwd;
    std::vector<int> collcounts_rev;
    int minBits, maxBits, threshBits;

    if (testHighBits || testLowBits)
    {
      std::vector<int> combinedBitsvec;
      combinedBitsvec.insert(combinedBitsvec.begin(), nbBitsvec.begin(),   nbBitsvec.end());
      combinedBitsvec.insert(combinedBitsvec.begin(), testBitsvec.begin(), testBitsvec.end());
      std::sort(combinedBitsvec.rbegin(), combinedBitsvec.rend());
      std::unique(combinedBitsvec.rbegin(), combinedBitsvec.rend());
      ComputeCollBitBounds(combinedBitsvec, hashbits, nbH, minBits, maxBits, threshBits);
    }

    if (testHighBits && (maxBits > 0))
    {
      collcounts_fwd.reserve(maxBits - minBits + 1);
      CountRangedNbCollisions(hashes, nbH, minBits, maxBits, threshBits, &collcounts_fwd[0]);
    }

    if (testLowBits && (maxBits > 0))
    {
      // reverse: bitwise flip the hashes. lowest bits first
      revhashes.reserve(hashes.size());
      for(const auto hashval: hashes)
      {
        hashtype rev = hashval;
        reversebits(rev);
        revhashes.push_back(rev);
      }
      blobsort(revhashes.begin(), revhashes.end());

      collcounts_rev.reserve(maxBits - minBits + 1);
      CountRangedNbCollisions(revhashes, nbH, minBits, maxBits, threshBits, &collcounts_rev[0]);
    }

    // Report on complete collisions, now that the heavy lifting is complete
    result &= ReportCollisions(nbH, collcount, hashbits, false, false, false, verbose, drawDiagram);
    if(!result && drawDiagram)
    {
      PrintCollisions(collisions);
      //printf("Mapping collisions\n");
      //CollisionMap<uint128_t,ByteVec> cmap;
      //CollisionCallback<uint128_t> c2(hash,collisions,cmap);
      ////TwoBytesKeygen(20,c2);
      //printf("Dumping collisions\n");
      //DumpCollisionMap(cmap);
    }

    if (testHighBits || testLowBits)
      for(const int nbBits: nbBitsvec)
      {
        if ((nbBits < minBits) || (nbBits > maxBits))
          continue;
        bool maxcoll = (nbBits <= threshBits) ? true : false;
        if (testHighBits)
          result &= ReportCollisions(nbH, collcounts_fwd[nbBits - minBits], nbBits,
              maxcoll, true, true, true, drawDiagram);
        if (testLowBits)
          result &= ReportCollisions(nbH, collcounts_rev[nbBits - minBits], nbBits,
              maxcoll, false, true, true, drawDiagram);
      }

    if (testHighBits)
      result &= ReportBitsCollisions(nbH, &collcounts_fwd[minTBits - minBits], minTBits, maxTBits, true, drawDiagram);
    if (testLowBits)
      result &= ReportBitsCollisions(nbH, &collcounts_rev[minTBits - minBits], minTBits, maxTBits, false, drawDiagram);
  }

  //----------

  if(testDist)
    result &= TestDistribution(hashes,drawDiagram);

  return result;
}

//-----------------------------------------------------------------------------
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
