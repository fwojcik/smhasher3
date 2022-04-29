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
#include "TestGlobals.h"
#include "Blobsort.h"
#include "Stats.h"
#include "Instantiate.h"
#include "VCode.h"

#include <set>
#include <cassert>
#include <cstring>    // for memset
#include <math.h>

#include "Analyze.h"

//-----------------------------------------------------------------------------
// If score exceeds this improbability of happening, note a failing result
static const double FAILURE_PBOUND = exp2(-15); // 2**-15 == 1/32768 =~ 0.00305%
// If score exceeds this improbability of happening, note a warning
static const double WARNING_PBOUND = exp2(-12); // 2**-12 == 1/4096 =~ 0.0244%, 8x as much as failure
// If these bounds seem overly generous, remember that SMHasher3 uses
// about 1000 tests, so a 1/1000 chance event will hit once per run on
// average, even with a perfect-quality hash function.

//-----------------------------------------------------------------------------
// Report on the fact that, in each of the specified number of trials,
// a fair coin was "flipped" coinflips times, and the worst bias
// (number of excess "heads" or "tails") over all those trials was the
// specified worstbiascnt.

bool ReportBias(const int worstbiascnt, const int coinflips, const int trials, const bool drawDiagram )
{
  double ratio = (double)worstbiascnt / (double)coinflips;
  double p1value = 2 * exp(-(double)worstbiascnt * ratio); // two-tailed Chernoff Bound
  double p_value = ScalePValue(p1value, trials);
  int logp_value = GetLog2PValue(p_value);
  bool result = true;

  recordLog2PValue(logp_value);
  if (drawDiagram)
    printf(" worst bias is %f%% (%6d) (p<%8.6e) (^%2d)", ratio*200.0, worstbiascnt, p_value, logp_value);
  else
    printf(" worst bias is %f%% (^%2d)", ratio*200.0, logp_value);

  if (p_value < FAILURE_PBOUND)
  {
    printf(" !!!!!\n");
    result = false;
  }
  else if (p_value < WARNING_PBOUND)
    printf(" !\n");
  else
    printf("\n");

  return result;
}

//-----------------------------------------------------------------------------

static bool ReportCollisions(uint64_t const nbH, int collcount, unsigned hashsize, bool maxcoll, bool highbits, bool header, bool verbose, bool drawDiagram )
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
      if (ratio >= 999.95)
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

    // 8 integer digits would match the 10.1 float specifier
    // (10 characters - 1 decimal point - 1 digit after the decimal),
    // but some hashes greatly exceed expected collision counts.
    if (!finite(ratio))
        printf(" - Expected %10.1f, actual %10i  (------) ", expected, collcount);
    else if (ratio < 9.0)
        printf(" - Expected %10.1f, actual %10i  (%5.3fx) ", expected, collcount, ratio);
    else
        printf(" - Expected %10.1f, actual %10i  (%#.4gx) ", expected, collcount, ratio);

    // Since ratios and p-value summaries are most important to humans,
    // and deltas and exact p-values add visual noise and variable line
    // widths and possibly field counts, they are now only printed out
    // in --verbose mode.
    recordLog2PValue(logp_value);
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

//----------------------------------------------------------------------------

static void plot ( double n )
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
// Sort the hash list, count the total number of collisions and return
// the first N collisions for further processing
template< typename hashtype >
unsigned int FindCollisions(std::vector<hashtype> & hashes,
                            std::set<hashtype> & collisions,
                            int maxCollisions,
                            bool drawDiagram) {
    unsigned int collcount = 0;
    blobsort(hashes.begin(),hashes.end());

    const size_t sz = hashes.size();
    for (size_t hnb = 1; hnb < sz; hnb++) {
        if(hashes[hnb] == hashes[hnb-1]) {
            collcount++;
            if(collcount < maxCollisions) {
#if 0
                printf ("  %zu: ", hnb);
                hashes[hnb].printhex("");
#endif
                if (drawDiagram) {
                    collisions.insert(hashes[hnb]);
                }
            }
        }
    }

#if 0 && defined(DEBUG)
    if (collcount)
        printf ("\n");
#endif

    return collcount;
}

INSTANTIATE(FindCollisions, HASHTYPELIST);

template < typename hashtype >
void PrintCollisions(std::set<hashtype> & collisions) {
    printf("\nCollisions:\n");

    for (auto it = collisions.begin(); it != collisions.end(); ++it) {
        const hashtype &hash = *it;
        hash.printhex("  ");
    }
    printf("\n");
}

INSTANTIATE(PrintCollisions, HASHTYPELIST);

//-----------------------------------------------------------------------------
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
static void CountRangedNbCollisions ( std::vector<hashtype> & hashes, uint64_t const nbH, int minHBits, int maxHBits, int threshHBits, int * collcounts)
{
  const int origBits = sizeof(hashtype) * 8;
  assert(minHBits >= 1);
  assert(minHBits <= maxHBits);
  assert(origBits >= maxHBits);
  assert((threshHBits == 0) || (threshHBits >= minHBits));
  assert((threshHBits == 0) || (threshHBits <= maxHBits));

  const int collbins = maxHBits - minHBits + 1;
  const int maxcollbins = (threshHBits == 0) ? 0 : threshHBits - minHBits + 1;
  int prevcoll[maxcollbins + 1];
  int maxcoll[maxcollbins + 1];

  memset(collcounts, 0, sizeof(collcounts[0])*collbins);
  memset(prevcoll, 0, sizeof(prevcoll[0])*maxcollbins);
  memset(maxcoll, 0, sizeof(maxcoll[0])*maxcollbins);

  for (uint64_t hnb = 1; hnb < nbH; hnb++) {
    hashtype hdiff = hashes[hnb-1] ^ hashes[hnb];
    int hzb = hdiff.highzerobits();
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

//-----------------------------------------------------------------------------
//

static bool ReportBitsCollisions (uint64_t nbH, int * collcounts, int minBits, int maxBits, bool highbits, bool drawDiagram )
{
  if (maxBits <= 1 || minBits > maxBits) return true;

  int spacelen = 80;
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

  if (maxCollDev >= 999.95)
      maxCollDev = INFINITY;

  if (!finite(maxCollDev))
      printf("%.*s(------) ", spacelen, spaces);
  else if (maxCollDev < 9.0)
      printf("%.*s(%5.3fx) ", spacelen, spaces, maxCollDev);
  else
      printf("%.*s(%#.4gx) ", spacelen, spaces, maxCollDev);


  double p_value = ScalePValue(maxPValue, maxBits - minBits + 1);
  int logp_value = GetLog2PValue(p_value);

  recordLog2PValue(logp_value);
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

//----------------------------------------------------------------------------
// Measure the distribution "score" for each possible N-bit span, with
// N going from 8 to 20 inclusive.

static int MaxDistBits ( const uint64_t nbH )
{
  // If there aren't 5 keys per bin over 8 bins, then don't bother
  // testing distribution at all.
  if (nbH < (5 * 8))
    return 0;
  int maxwidth = 20;
  // We need at least 5 keys per bin to reliably test distribution biases
  // down to 1%, so don't bother to test sparser distributions than that
  while(double(nbH) / double(1 << maxwidth) < 5.0)
    --maxwidth;
  return maxwidth;
}

template< typename hashtype >
static bool TestDistribution ( std::vector<hashtype> & hashes, bool drawDiagram )
{
  const int hashbits = sizeof(hashtype) * 8;
  const uint64_t nbH = hashes.size();
  int maxwidth = MaxDistBits(nbH);
  int minwidth = 8;

  if (maxwidth < minwidth) return true;

  printf("Testing distribution   (any  %2i..%2i bits)%s", minwidth, maxwidth, drawDiagram ? "\n[" : " - ");

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

    for(uint64_t j = 0; j < nbH; j++)
    {
      uint32_t index = hashes[j].window(start,width);

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

  addVCodeResult((uint32_t)worstN);
  addVCodeResult(worstWidth);
  addVCodeResult(worstStart);

  double p_value = ScalePValue(GetNormalPValue(0, 1, worstN), tests);
  int logp_value = GetLog2PValue(p_value);
  double mult = normalizeScore(worstN, worstWidth, tests);

  if (worstStart == -1)
      printf("No positive bias detected            %5.3fx  ", 0.0);
  else if (mult < 9.0)
      printf("Worst bias is %2d bits at bit %3d:    %5.3fx  ",
              worstWidth, worstStart, mult);
  else
      printf("Worst bias is %2d bits at bit %3d:    %#.4gx  ",
              worstWidth, worstStart, mult);

  recordLog2PValue(logp_value);
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

//-----------------------------------------------------------------------------
// Compute a number of statistical tests on a list of hashes,
// comparing them to a list of i.i.d. random numbers across the full
// origBits range.

static void ComputeCollBitBounds ( std::vector<int> & nbBitsvec, int origBits, uint64_t nbH, int & minBits, int & maxBits, int & threshBits )
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

static int FindMinBits_TargetCollisionShare(uint64_t nbHashes, double share)
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

static int FindMaxBits_TargetCollisionNb(uint64_t nbHashes, int minCollisions, int maxbits)
{
    int nb;
    for (nb=maxbits; nb>2; nb--) {
        double const nbColls = EstimateNbCollisions(nbHashes, nb);
        if (nbColls > minCollisions) return nb;
    }
    //assert(0);
    return nb;
}

template < typename hashtype >
bool TestHashList ( std::vector<hashtype> & hashes, bool drawDiagram,
                    bool testCollision, bool testDist ,
                    bool testHighBits, bool testLowBits ,
                    bool verbose )
{
  bool result = true;

  if (testCollision)
  {
    unsigned const hashbits = sizeof(hashtype) * 8;
    uint64_t const nbH = hashes.size();
    if (verbose)
      printf("Testing all collisions (     %3i-bit)", hashbits);

    addVCodeOutput(&hashes[0], sizeof(hashtype) * nbH);

    std::set<hashtype> collisions;
    int collcount = FindCollisions(hashes, collisions, 1000, drawDiagram);

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
      nbBitsvec.erase(std::unique(nbBitsvec.begin(), nbBitsvec.end()), nbBitsvec.end());
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
      combinedBitsvec.reserve(200); // Workaround for GCC bug 100366
      combinedBitsvec.insert(combinedBitsvec.begin(), nbBitsvec.begin(),   nbBitsvec.end());
      combinedBitsvec.insert(combinedBitsvec.begin(), testBitsvec.begin(), testBitsvec.end());
      std::sort(combinedBitsvec.rbegin(), combinedBitsvec.rend());
      combinedBitsvec.erase(std::unique(combinedBitsvec.begin(), combinedBitsvec.end()), combinedBitsvec.end());
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
        rev.reversebits();
        revhashes.push_back(rev);
      }
      blobsort(revhashes.begin(), revhashes.end());

      collcounts_rev.reserve(maxBits - minBits + 1);
      CountRangedNbCollisions(revhashes, nbH, minBits, maxBits, threshBits, &collcounts_rev[0]);
    }

    addVCodeResult(collcount);
    if (testHighBits && (collcounts_fwd.size() != 0)) {
        addVCodeResult(&collcounts_fwd[0], sizeof(collcounts_fwd[0]) *
                collcounts_fwd.size());
    }
    if (testLowBits && (collcounts_rev.size() != 0)) {
        addVCodeResult(&collcounts_rev[0], sizeof(collcounts_rev[0]) *
                collcounts_rev.size());
    }

    // Report on complete collisions, now that the heavy lifting is complete
    result &= ReportCollisions(nbH, collcount, hashbits, false, false, false, verbose, drawDiagram);
    if(!result && drawDiagram)
    {
      PrintCollisions(collisions);
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

INSTANTIATE(TestHashList, HASHTYPELIST);

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

      for(uint64_t i = 0; i < hashes.size(); i++)
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

    for(uint64_t j = 0; j < hashes.size(); j++)
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
