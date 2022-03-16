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
 *     Copyright (c) 2020      Yann Collet
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
#include "Random.h"
#include "Analyze.h"
#include "Instantiate.h"
#include "VCode.h"

#include "AvalancheTest.h"

#include <cstdio>
#include <cassert>
#include <math.h>

#if defined(NEW_HAVE_AVX2) || defined(NEW_HAVE_SSE_4_1)
#include <immintrin.h>
#endif

#if defined(HAVE_THREADS)
#include <atomic>
typedef std::atomic<int> a_int;
#else
typedef int a_int;
#endif

//-----------------------------------------------------------------------------

static void PrintAvalancheDiagram ( int x, int y, int reps, double scale, uint32_t * bins )
{
  const char * symbols = ".123456789X";

  for(int i = 0; i < y; i++)
  {
    printf("[");
    for(int j = 0; j < x; j++)
    {
      int k = (y - i) -1;

      uint32_t bin = bins[k + (j*y)];

      double b = double(bin) / double(reps);
      b = fabs(b*2 - 1);

      b *= scale;

      int s = (int)floor(b*10);

      if(s > 10) s = 10;
      if(s < 0) s = 0;

      printf("%c",symbols[s]);
    }

    printf("]\n");
    fflush(NULL);
  }
}

//----------------------------------------------------------------------------

static int maxBias ( uint32_t * counts, int buckets, int reps )
{
  int expected = reps / 2;
  int worst = 0;

  for(int i = 0; i < buckets; i++)
  {
    int c = abs((int)counts[i] - expected);
    if(worst < c)
      worst = c;
  }

  return worst;
}

//-----------------------------------------------------------------------------
// Flipping a single bit of a key should cause an "avalanche" of changes in
// the hash function's output. Ideally, each output bits should flip 50% of
// the time - if the probability of an output bit flipping is not 50%, that bit
// is "biased". Too much bias means that patterns applied to the input will
// cause "echoes" of the patterns in the output, which in turn can cause the
// hash function to fail to create an even, random distribution of hash values.

template < typename hashtype >
static void calcBiasRange ( const HashFn hash, std::vector<uint32_t> &bins,
                     const int keybytes, const uint8_t * keys,
                     a_int & irepp, const int reps, const bool verbose )
{
  const int keybits = keybytes * 8;
  const int hashbytes = sizeof(hashtype);
#if defined(NEW_HAVE_AVX2)
  const __m256i ONE  = _mm256_set1_epi32(1);
  const __m256i MASK = _mm256_setr_epi32(
                                         1 << 0,
                                         1 << 1,
                                         1 << 2,
                                         1 << 3,
                                         1 << 4,
                                         1 << 5,
                                         1 << 6,
                                         1 << 7);
#elif defined(NEW_HAVE_SSE_4_1)
  const __m128i ONE  = _mm_set1_epi32(1);
  const __m128i MASK = _mm_setr_epi32(
                                         1 << 0,
                                         1 << 1,
                                         1 << 2,
                                         1 << 3);
#endif

  uint8_t K[keybytes];
  hashtype A,B;
  int irep;

  while ((irep = irepp++) < reps)
  {
    if(verbose) {
      if(irep % (reps/10) == 0) printf(".");
    }

    memcpy(K,&keys[keybytes * irep],keybytes);
    hash(K,keybytes,g_seed,&A);

    uint32_t * cursor = &bins[0];

    for(int iBit = 0; iBit < keybits; iBit++)
    {
      flipbit(K,keybytes,iBit);
      hash(K,keybytes,g_seed,&B);
      flipbit(K,keybytes,iBit);

      B ^= A;

#if defined(NEW_HAVE_AVX2)
      for(int oWord = 0; oWord < (hashbytes/4); oWord++) {
          // Get the next 32-bit chunk of the hash difference
          uint32_t word;
          memcpy(&word, ((const uint8_t *)&B) + 4*oWord, 4);

          // Expand it out into 4 sets of 8 32-bit integer words, with
          // each integer being zero or one.
          __m256i base  = _mm256_set1_epi32(word);
          __m256i incr1 =_mm256_min_epu32(_mm256_and_si256(base, MASK), ONE);
          base = _mm256_srli_epi32(base, 8);
          __m256i incr2 =_mm256_min_epu32(_mm256_and_si256(base, MASK), ONE);
          base = _mm256_srli_epi32(base, 8);
          __m256i incr3 =_mm256_min_epu32(_mm256_and_si256(base, MASK), ONE);
          base = _mm256_srli_epi32(base, 8);
          __m256i incr4 =_mm256_min_epu32(_mm256_and_si256(base, MASK), ONE);

          // Add these into the counts in bins[]
          __m256i cnt1  = _mm256_loadu_si256((const __m256i *)cursor);
          cnt1 = _mm256_add_epi32(cnt1, incr1);
          _mm256_storeu_si256((__m256i *)cursor, cnt1);
          cursor += 8;
          __m256i cnt2  = _mm256_loadu_si256((const __m256i *)cursor);
          cnt2 = _mm256_add_epi32(cnt2, incr2);
          _mm256_storeu_si256((__m256i *)cursor, cnt2);
          cursor += 8;
          __m256i cnt3  = _mm256_loadu_si256((const __m256i *)cursor);
          cnt3 = _mm256_add_epi32(cnt3, incr3);
          _mm256_storeu_si256((__m256i *)cursor, cnt3);
          cursor += 8;
          __m256i cnt4  = _mm256_loadu_si256((const __m256i *)cursor);
          cnt4 = _mm256_add_epi32(cnt4, incr4);
          _mm256_storeu_si256((__m256i *)cursor, cnt4);
          cursor += 8;
      }
#elif defined(NEW_HAVE_SSE_4_1)
      for(int oWord = 0; oWord < (hashbytes/4); oWord++) {
          // Get the next 32-bit chunk of the hash difference
          uint32_t word;
          memcpy(&word, ((const uint8_t *)&B) + 4*oWord, 4);

          // Expand it out into 8 sets of 4 32-bit integer words, with
          // each integer being zero or one, and add them into the
          // counts in bins[].
          __m128i base = _mm_set1_epi32(word);
          for (int i = 0; i < 8; i++) {
              __m128i incr = _mm_min_epu32(_mm_and_si128(base, MASK), ONE);
              __m128i cnt  = _mm_loadu_si128((const __m128i *)cursor);
              cnt = _mm_add_epi32(cnt, incr);
              _mm_storeu_si128((__m128i *)cursor, cnt);
              base = _mm_srli_epi32(base, 4);
              cursor += 4;
          }
      }
#else
      for(int oByte = 0; oByte < hashbytes; oByte++) {
          uint32_t byte = getbyte(B, oByte);
          for(int oBit = 0; oBit < 8; oBit++) {
              (*cursor++) += byte & 1;
              byte >>= 1;
          }
      }
#endif
    }
  }
}

//-----------------------------------------------------------------------------

template < typename hashtype >
static bool AvalancheImpl ( HashFn hash, const int keybits, const int reps, bool drawDiagram, bool drawdots )
{
  Rand r(48273);

  assert((keybits & 7)==0);

  const int keybytes = keybits / 8;

  const int hashbytes = sizeof(hashtype);
  const int hashbits = hashbytes * 8;

  const int arraysize = keybits * hashbits;

  printf("Testing %4d-bit keys -> %3d-bit hashes, %6d reps",
         keybits, hashbits, reps);
  //----------
  std::vector<uint8_t> keys(reps * keybytes);
  for (int i = 0; i < reps; i++)
    r.rand_p(&keys[i*keybytes],keybytes);
  addVCodeInput(&keys[0], reps * keybytes);

  a_int irep(0);

  std::vector<std::vector<uint32_t> > bins(g_NCPU);
  for (unsigned i = 0; i < g_NCPU; i++) {
      bins[i].resize(arraysize);
  }

  if (g_NCPU == 1) {
      calcBiasRange<hashtype>(hash,bins[0],keybytes,&keys[0],irep,reps,drawdots);
  } else {
#ifdef HAVE_THREADS
      std::thread t[g_NCPU];
      for (int i=0; i < g_NCPU; i++) {
          t[i] = std::thread {calcBiasRange<hashtype>,hash,std::ref(bins[i]),keybytes,&keys[0],std::ref(irep),reps,drawdots};
      }
      for (int i=0; i < g_NCPU; i++) {
          t[i].join();
      }
      for (int i=1; i < g_NCPU; i++)
          for (int b=0; b < arraysize; b++)
              bins[0][b] += bins[i][b];
#endif
  }

  //----------

  int bias = maxBias(&bins[0][0], arraysize, reps);
  bool result = true;

  // Due to threading and memory complications, add the summed
  // avalanche results instead of the hash values. Not ideal, but the
  // "real" way is just too expensive.
  addVCodeOutput(&bins[0][0], arraysize * sizeof(bins[0][0]));
  addVCodeResult(bias);

  result &= ReportBias(bias, reps, arraysize, drawDiagram);

  recordTestResult(result, "Avalanche", keybits);

  return result;
}

//-----------------------------------------------------------------------------

template < typename hashtype >
bool AvalancheTest(const HashInfo * hinfo, const bool verbose, const bool extra) {
    const HashFn hash = hinfo->hashFn(g_hashEndian);
    bool result = true;
    bool drawdots = true; //.......... progress dots

    printf("[[[ Avalanche Tests ]]]\n\n");

    hinfo->Seed(g_seed, 2);

    std::vector<int> testBitsvec =
        { 24, 32, 40, 48, 56, 64, 72, 80, 96, 112, 128, 160 };
    testBitsvec.reserve(50); // Workaround for GCC bug 100366
    if (hinfo->bits <= 64) {
        testBitsvec.insert(testBitsvec.end(), { 512, 1024 });
    }
    if (extra) {
        testBitsvec.insert(testBitsvec.end(), { 192, 224, 256, 320, 384, 448, 512, 640,
                                                768, 896, 1024, 1280, 1536 });
    }
    std::sort(testBitsvec.begin(), testBitsvec.end());
    testBitsvec.erase(std::unique(testBitsvec.begin(), testBitsvec.end()), testBitsvec.end());

    for (int testBits : testBitsvec) {
        result &= AvalancheImpl<hashtype> (hash,testBits,300000,verbose,drawdots);
    }

    if(!result) printf("*********FAIL*********\n");
    printf("\n");

    return result;
}

INSTANTIATE(AvalancheTest, HASHTYPELIST);
