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
 *     Copyright (c) 2014-2021 Reini Urban
 *     Copyright (c) 2015      Ivan Kruglov
 *     Copyright (c) 2015      Paul G
 *     Copyright (c) 2016      Jason Schulz
 *     Copyright (c) 2016-2018 Leonid Yuriev
 *     Copyright (c) 2016      Sokolov Yura aka funny_falcon
 *     Copyright (c) 2016      Vlad Egorov
 *     Copyright (c) 2018      Jody Bruchon
 *     Copyright (c) 2019      Niko Rebenich
 *     Copyright (c) 2019-2020 Yann Collet
 *     Copyright (c) 2019-2021 data-man
 *     Copyright (c) 2019      王一 WangYi
 *     Copyright (c) 2020      Cris Stringfellow
 *     Copyright (c) 2020      HashTang
 *     Copyright (c) 2020      Jim Apple
 *     Copyright (c) 2020      Thomas Dybdahl Ahle
 *     Copyright (c) 2020      Tom Kaitchuck
 *     Copyright (c) 2021      Logan oos Even
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
#include "Instantiate.h"
#include "VCode.h"

#include "PopcountTest.h"

#include <cassert>

//-----------------------------------------------------------------------------
// Moment Chi-Square test, measuring the probability of the
// lowest 32 bits set over the whole key space. Not where the bits are, but how many.
// See e.g. https://www.statlect.com/fundamentals-of-probability/moment-generating-function

typedef long double moments[8];

// Copy the results into g_NCPU ranges of 2^32
static void PopcountThread(const HashInfo * hinfo, const int inputSize,
                        const unsigned start, const unsigned end, const unsigned step,
                        moments &b)
{
  const HashFn hash = hinfo->hashFn(g_hashEndian);
  seed_t seed = g_seed;
  long double const n = (end-(start+1)) / step;
  uint64_t previous = 0;
  long double b0h = b[0], b0l = b[1], db0h = b[2], db0l = b[3];
  long double b1h = b[4], b1l = b[5], db1h = b[6], db1l = b[7];
#define INPUT_SIZE_MAX 256
  assert(inputSize <= INPUT_SIZE_MAX);
  char key[INPUT_SIZE_MAX] = {0};
#define HASH_SIZE_MAX 64
  char hbuff[HASH_SIZE_MAX] = {0};
  const int hbits = std::min(hinfo->bits, 64U); // limited due to popcount8

  assert(sizeof(unsigned) <= inputSize);
  assert(start < end);
  //assert(step > 0);

  hinfo->FixupSeed(seed);
  hinfo->Seed(seed, 1);

  uint64_t i = start - step;
  memcpy(key, &i, sizeof(i));
  hash(key, inputSize, seed, hbuff);
  memcpy(&previous, hbuff, 8);

  for (uint64_t i=start; i<=end; i+=step) {
    memcpy(key, &i, sizeof(i));
    hash(key, inputSize, seed, hbuff);

    uint64_t h; memcpy(&h, hbuff, 8);
    // popcount8 assumed to work on 64-bit
    // note : ideally, one should rather popcount the whole hash
    {
      uint64_t const bits1 = popcount8(h);
      uint64_t const bits0 = hbits - bits1;
      uint64_t const b1_exp5 = bits1 * bits1 * bits1 * bits1 * bits1;
      uint64_t const b0_exp5 = bits0 * bits0 * bits0 * bits0 * bits0;
      b1h += b1_exp5; b1l += b1_exp5 * b1_exp5;
      b0h += b0_exp5; b0l += b0_exp5 * b0_exp5;
    }
    // derivative
    {
      uint64_t const bits1 = popcount8(previous^h);
      uint64_t const bits0 = hbits - bits1;
      uint64_t const b1_exp5 = bits1 * bits1 * bits1 * bits1 * bits1;
      uint64_t const b0_exp5 = bits0 * bits0 * bits0 * bits0 * bits0;
      db1h += b1_exp5; db1l += b1_exp5 * b1_exp5;
      db0h += b0_exp5; db0l += b0_exp5 * b0_exp5;
    }
    previous = h;
  }

  b[0] = b0h;
  b[1] = b0l;
  b[2] = db0h;
  b[3] = db0l;
  b[4] = b1h;
  b[5] = b1l;
  b[6] = db1h;
  b[7] = db1l;
}

static double PopcountResults ( long double srefh, long double srefl,
        long double b1h, long double b1l,
        long double b0h, long double b0l )
{
  double worse;
  {
      double chi2 = (b1h-srefh) * (b1h-srefh) / (b1l+srefl);
      printf("From counting 1s : %9.2Lf, %9.2Lf  -  moment chisq %10.4f\n",
              b1h, b1l, chi2);
      worse = chi2;
  }
  {
      double chi2 = (b0h-srefh) * (b0h-srefh) / (b0l+srefl);
      printf("From counting 0s : %9.2Lf, %9.2Lf  -  moment chisq %10.4f\n",
              b0h, b0l, chi2);
      worse = std::max(worse, chi2);
  }
  return worse;
}

static bool PopcountTestImpl(const HashInfo * hinfo, int inputSize, int step) {
  const HashFn hash = hinfo->hashFn(g_hashEndian);
  const unsigned mx = 0xffffffff;
  const long double n = 0x100000000UL / step;
  const int hbits = std::min(hinfo->bits, 64U); // limited due to popcount8

  assert(hbits <= HASH_SIZE_MAX*8);
  assert(inputSize >= 4);

  printf("Generating hashes from a linear sequence of %i-bit numbers "
         "with a step size of %d ... \n", inputSize*8, step);

  /* Notes on the ranking system.
   * Ideally, this test should report and sum all popcount values
   * and compare the resulting distribution to an ideal distribution.
   *
   * What happens here is quite simplified :
   * the test gives "points" for each popcount, and sum them all.
   * The metric (using N^5) is heavily influenced by the largest outliers.
   * For example, a 64-bit hash should have a popcount close to 32.
   * But a popcount==40 will tilt the metric upward
   * more than popcount==24 will tilt the metric downward.
   * In reality, both situations should be ranked similarly.
   *
   * To compensate, we measure both popcount1 and popcount0,
   * and compare to some pre-calculated "optimal" sums for the hash size.
   *
   * Another limitation of this test is that it only popcounts the first 64-bit.
   * For large hashes, bits beyond this limit are ignored.
   *
   * Derivative hash testing:
   * In this scenario, 2 consecutive hashes are xored,
   * and the outcome of this xor operation is then popcount controlled.
   * Obviously, the _order_ in which the hash values are generated becomes critical.
   *
   * This scenario comes from the prng world,
   * where derivative of the generated suite of random numbers is analyzed
   * to ensure the suite is truly "random".
   *
   * However, in almost all prng, the seed of next random number is the previous random number.
   *
   * This scenario is quite different: it introduces a fixed distance between 2 consecutive "seeds".
   * This is especially detrimental to algorithms relying on linear operations, such as multiplications.
   *
   * This scenario is relevant if the hash is used as a prng and generates values from a linearly increasing counter as a seed.
   * It is not relevant for scenarios employing the hash as a prng
   * with the more classical method of using the previous random number as a seed for the next one.
   * This scenario has no relevance for classical usages of hash algorithms,
   * such as hash tables, bloom filters and such, were only the raw values are ever used.
   */

  long double srefh, srefl;
  switch (hbits/8) {
      case 8:
          srefh = 38918200.;
          if (step == 2)
            srefl = 273633.333333;
          else if (step == 6)
            srefl = 820900.0;
          else
            abort();
          break;
      case 4:
          srefh = 1391290.;
          if (step == 2)
            srefl = 686.6666667;
          else if (step == 6)
            srefl = 2060.0;
          else
            abort();
          break;
      default:
          printf("hash size not covered \n");
          abort();
  }

  moments b[g_NCPU];
  memset(b, 0, sizeof(b));

  // Because of threading, the actual inputs can't be hashed into the
  // main thread's state, so just hash the parameters of the input data.
  addVCodeInput(0);          // start
  addVCodeInput(0xffffffff); // end
  addVCodeInput(step);       // step
  addVCodeInput(inputSize);  // size

  if (g_NCPU == 1) {
      PopcountThread(hinfo, inputSize, 0, 0xffffffff, step, std::ref(b[0]));
  } else {
#ifdef HAVE_THREADS
      // split into g_NCPU threads
      std::thread t[g_NCPU];
      printf("%d threads starting... ", g_NCPU);

      const uint64_t len = 0x100000000UL / (step * g_NCPU);
      for (int i=0; i < g_NCPU; i++) {
          const uint32_t start = i * len * step;
          const uint32_t end = (i < (g_NCPU - 1)) ? start + (len * step - 1) : 0xffffffff;
          //printf("thread[%d]: %d, 0x%x - 0x%x %d\n", i, inputSize, start, end, step);
          t[i] = std::thread {PopcountThread, hinfo, inputSize, start, end, step, std::ref(b[i])};
      }

      std::this_thread::sleep_for(std::chrono::seconds(1));

      for (int i=0; i < g_NCPU; i++) {
          t[i].join();
      }

      printf(" done\n");

      //printf("[%d]: %Lf, %Lf, %Lf, %Lf, %Lf, %Lf, %Lf, %Lf\n", 0,
      //       b[0][0], b[0][1], b[0][2], b[0][3], b[0][4], b[0][5], b[0][6], b[0][7]);
      for (int i=1; i < g_NCPU; i++) {
          //printf("[%d]: %Lf, %Lf, %Lf, %Lf, %Lf, %Lf, %Lf, %Lf\n", i,
          //       b[i][0], b[i][1], b[i][2], b[i][3], b[i][4], b[i][5], b[i][6], b[i][7]);
          for (int j=0; j < 8; j++)
              b[0][j] += b[i][j];
      }
#endif
  }

  long double b0h = b[0][0], b0l = b[0][1], db0h = b[0][2], db0l = b[0][3];
  long double b1h = b[0][4], b1l = b[0][5], db1h = b[0][6], db1l = b[0][7];

  b1h  /= n;  b1l = (b1l/n  - b1h*b1h) / n;
  db1h /= n; db1l = (db1l/n - db1h*db1h) / n;
  b0h  /= n;  b0l = (b0l/n  - b0h*b0h) / n;
  db0h /= n; db0l = (db0l/n - db0h*db0h) / n;

  double worstL, worstD;

  printf("Ideal results    : %9.2Lf, %9.2Lf\n", srefh, srefl);

  printf("\nResults from literal hashes :\n");
  worstL = PopcountResults(srefh, srefl, b1h, b1l, b0h, b0l);

  printf("\nResults from derivative hashes (XOR of 2 consecutive values) :\n");
  worstD = PopcountResults(srefh, srefl, db1h, db1l, db0h, db0l);

  // note : previous threshold : 3.84145882069413
  double worstchisq = std::max(worstL, worstD);
  int const rank = (worstchisq < 500.) + (worstchisq < 50.) + (worstchisq < 5.);
  assert(0 <= rank && rank <= 3);

  const char* rankstr[4] = { "FAIL !!!!", "pass", "Good !", "Great !!" };
  printf("\n  %s \n\n", rankstr[rank]);

  // Similar threading problems for the outputs, so just hash in the
  // summary data.
  addVCodeOutput(&b[0][0], 8 * sizeof(b[0][0]));
  addVCodeResult((uint32_t)(worstchisq * 1000.0));

  return (rank > 0);
}

//-----------------------------------------------------------------------------

template < typename hashtype >
bool PopcountTest(const HashInfo * hinfo, const bool extra) {
    const int step = ((hinfo->isVerySlow() || hinfo->bits > 128) && extra) ? 6 : 2;
    bool result = true;

    printf("[[[ Popcount Tests ]]]\n\n");

    result &= PopcountTestImpl(hinfo, 4, step);
    if (extra) {
        result &= PopcountTestImpl(hinfo, 8, step);
        result &= PopcountTestImpl(hinfo, 16, step);
    }

    if(!result) printf("\n*********FAIL*********\n");
    printf("\n");

    return result;
}

INSTANTIATE(PopcountTest, HASHTYPELIST);
