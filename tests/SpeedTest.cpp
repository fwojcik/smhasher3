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
#include "Platform.h"
#include "Types.h"
#include "Timing.h"
#include "Stats.h"
#include "Random.h"

#include "SpeedTest.h"

#include <algorithm> // for sort, min
#include <string>
#include <functional>
#include <cassert>

//-----------------------------------------------------------------------------
// This is functionally a speed test, and so will not inform VCodes,
// since that would affect results too much.

//-----------------------------------------------------------------------------
// We view our timing values as a series of random variables V that has been
// contaminated with occasional outliers due to cache misses, thread
// preemption, etcetera. To filter out the outliers, we search for the largest
// subset of V such that all its values are within three standard deviations
// of the mean.

//-----------------------------------------------------------------------------
// We really want the rdtsc() calls to bracket the function call as tightly
// as possible, but that's hard to do portably. We'll try and get as close as
// possible by marking the function as NEVER_INLINE (to keep the optimizer from
// moving it) and marking the timing variables as "volatile register".

NEVER_INLINE static int64_t timehash(HashFn hash, const seed_t seed,
        const void * const key, int len) {
  volatile int64_t begin, end;
  uint32_t temp[16];

  begin = timer_start();

  hash(key,len,seed,temp);

  end = timer_end();

  return end - begin;
}

//-----------------------------------------------------------------------------
// Specialized procedure for small lengths. Serialize invocations of the hash
// function. Make sure they would not be computed in parallel on an out-of-order CPU.

NEVER_INLINE static int64_t timehash_small(HashFn hash, const seed_t seed,
        uint8_t * const key, int len) {
  const int NUM_TRIALS = 200;
  volatile unsigned long long int begin, end;
  uint32_t hash_temp[16] = {0};

  begin = timer_start();

  for(int i = 0; i < NUM_TRIALS; i++) {
      hash(key, len, seed, hash_temp);
      // XXX Add more dependency between invocations of hash-function
      // to prevent parallel evaluation of them. However this way the
      // invocations still would not be fully serialized. Another
      // option is to use lfence instruction (load-from-memory
      // serialization instruction) or mfence (load-from-memory AND
      // store-to-memory serialization instruction):
      //   __asm volatile ("lfence");
      // It's hard to say which one is the most realistic and sensible
      // approach.

      // XXX Can't do this particular thing anymore, since hashes
      // might have expensive seeding, and we don't want to/can't call
      // hInfo->Seed() every speedtest loop!
      //seed += hash_temp[0];

      // This seems to be good enough, maybe?
      key[0] = (i & 0xFF) ^ hash_temp[0];
  }

  end = timer_end();

  return (int64_t)((end - begin) / (double)NUM_TRIALS);
}

//-----------------------------------------------------------------------------

static double SpeedTest(HashFn hash, seed_t seed, const int trials,
        const int blocksize, const int align,
        const int varysize, const int varyalign) {
  Rand r(seed);
  uint8_t *buf = new uint8_t[blocksize + 512]; // assumes (align + varyalign) <= 257
  uintptr_t t1 = reinterpret_cast<uintptr_t>(buf);

  t1 = (t1 + 255) & UINT64_C(0xFFFFFFFFFFFFFF00);
  t1 += align;

  uint8_t * block = reinterpret_cast<uint8_t*>(t1);

  std::vector<int> sizes;
  if (varysize > 0)
  {
      sizes.reserve(trials);
      for(int i = 0; i < trials; i++)
          sizes.push_back(blocksize - varysize + (i % (varysize + 1)));
      for(int i = trials - 1; i > 0; i--)
          std::swap(sizes[i], sizes[r.rand_range(i + 1)]);
  }

  std::vector<int> alignments;
  if (varyalign > 0)
  {
      alignments.reserve(trials);
      for(int i = 0; i < trials; i++)
          alignments.push_back((i + 1) % (varyalign + 1));
      for(int i = trials - 1; i > 0; i--)
          std::swap(alignments[i], alignments[r.rand_range(i + 1)]);
  }

  //----------w

  std::vector<double> times;
  times.reserve(trials);

  int testsize = blocksize;
  for(int itrial = 0; itrial < trials; itrial++)
  {
    if (varysize > 0)
        testsize = sizes[itrial];
    if (varyalign > 0)
        block = reinterpret_cast<uint8_t*>(t1 + alignments[itrial]);

    r.rand_p(block,testsize);

    double t;
    if (testsize < 100) {
        t = (double)timehash_small(hash,seed,block,testsize);
    } else {
        t = (double)timehash(hash,seed,block,testsize);
    }

    if(t > 0) times.push_back(t);
  }

  //----------

  std::sort(times.begin(),times.end());

  FilterOutliers(times);

  delete [] buf;

  return CalcMean(times);
}

//-----------------------------------------------------------------------------
// 256k blocks seem to give the best results.

static void BulkSpeedTest ( HashFn hash, seed_t seed, bool vary_align, bool vary_size )
{
  const int trials = 2999;
  const int blocksize = 256 * 1024;
  const int maxvary = vary_size ? 127 : 0;

  if (vary_size)
      printf("Bulk speed test - [%d, %d]-byte keys\n",blocksize - maxvary, blocksize);
  else
      printf("Bulk speed test - %d-byte keys\n",blocksize);
  double sumbpc = 0.0;

  volatile double warmup_cycles = SpeedTest(hash,seed,trials,blocksize,0,0,0);

  for(int align = 7; align >= 0; align--)
  {
    double cycles = SpeedTest(hash,seed,trials,blocksize,align,maxvary,0);

    double bestbpc = ((double)blocksize - ((double)maxvary / 2)) / cycles;

    double bestbps = (bestbpc * 3000000000.0 / 1048576.0);
    printf("Alignment  %2d - %6.3f bytes/cycle - %7.2f MiB/sec @ 3 ghz\n",align,bestbpc,bestbps);
    sumbpc += bestbpc;
  }
  if (vary_align)
  {
    double cycles = SpeedTest(hash,seed,trials,blocksize,0,maxvary,7);

    double bestbpc = ((double)blocksize - ((double)maxvary / 2)) / cycles;

    double bestbps = (bestbpc * 3000000000.0 / 1048576.0);
    printf("Alignment rnd - %6.3f bytes/cycle - %7.2f MiB/sec @ 3 ghz\n",bestbpc,bestbps);
    // Deliberately not counted in the Average stat, so the two can be directly compared
  }

  sumbpc = sumbpc / 8.0;
  printf("Average       - %6.3f bytes/cycle - %7.2f MiB/sec @ 3 ghz\n",sumbpc,(sumbpc * 3000000000.0 / 1048576.0));
  fflush(NULL);
}

//-----------------------------------------------------------------------------

static double TinySpeedTest ( HashFn hash, int maxkeysize, seed_t seed, bool verbose, bool include_vary )
{
  const int trials = 99999;
  double sum = 0.0;

  printf("Small key speed test - [1, %2d]-byte keys\n",maxkeysize);

  for(int i = 1; i <= maxkeysize; i++)
  {
    volatile int j = i;
    double cycles = SpeedTest(hash,seed,trials,j,0,0,0);
    if(verbose) printf("  %2d-byte keys - %8.2f cycles/hash\n",j,cycles);
    sum += cycles;
  }
  if (include_vary) {
    double cycles = SpeedTest(hash,seed,trials,maxkeysize,0,maxkeysize-1,0);
    if(verbose) printf(" rnd-byte keys - %8.2f cycles/hash\n",maxkeysize,cycles);
    // Deliberately not counted in the Average stat, so the two can be directly compared
  }

  sum = sum / (double)maxkeysize;
  printf("Average        - %8.2f cycles/hash\n",sum);

  return sum;
}

//-----------------------------------------------------------------------------
bool SpeedTest(const HashInfo * hinfo) {
    const HashFn hash = hinfo->hashFn(g_hashEndian);
    bool result = true;
    Rand r(633692);

    printf("[[[ Speed Tests ]]]\n\n");

    const seed_t seed = hinfo->Seed(g_seed ^ r.rand_u64());

    BulkSpeedTest(hash, seed, true, false);
    printf("\n");

    BulkSpeedTest(hash, seed, true, true);
    printf("\n");

    TinySpeedTest(hash, 31, seed, true, true);
    printf("\n");

    return result;
}
