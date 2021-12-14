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
#include "Analyze.h"
#include "Instantiate.h"

#include "BadSeedsTest.h"

#include <inttypes.h>
#ifdef HAVE_THREADS
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#endif

//-----------------------------------------------------------------------------
// Find bad seeds, and test against the known secrets/bad seeds.

// A more thourough test for a known secret. vary keys and key len
template< typename hashtype >
static bool TestSecret ( const HashInfo* info, const uint64_t secret ) {
  bool result = true;
  static hashtype zero;
  pfHash hash = info->hash;
  uint8_t key[128];
  HashSet<hashtype> collisions_dummy;
  // Currently *only* seeds going through Hash_Seed_init() can be
  // wider than 32 bits!!
  if (!Hash_Seed_init (hash, secret) && (secret > UINT64_C(0xffffffff)))
      return true;
  printf("0x%" PRIx64 "  ", secret);
  for (int len : std::vector<int> {1,2,4,8,12,16,32,64,128}) {
    std::vector<hashtype> hashes;
    for (int c : std::vector<int> {0,32,'0',127,128,255}) {
      hashtype h;
      memset(&key, c, len);
      hash(key, len, secret, &h);
      if (h == 0 && c == 0) {
        printf("Confirmed broken seed 0x%" PRIx64 " => 0 with key[%d] of all %d bytes => hash 0\n",
               secret, len, c);
        hashes.push_back(h);
        result = false;
      }
      else
        hashes.push_back(h);
    }
    if (FindCollisions(hashes, collisions_dummy, 0, false) > 0) {
      printf("Confirmed bad seed 0x%" PRIx64 " for len %d ", secret, len);
#if !defined __clang__ && !defined _MSC_VER
      printf("=> hashes: ");
      for (hashtype x : hashes) printf ("%lx ", x);
#endif
      printf ("\n");
      TestHashList(hashes, true, true, false, false, false, true);
      result = false;
    }
  }
  return result;
}

#ifdef HAVE_THREADS
// For keeping track of progress printouts across threads
static std::atomic<unsigned> secret_progress;
static std::mutex print_mutex;
#else
static unsigned secret_progress;
#endif

// Process part of a 2^32 range, split into g_NCPU threads
template< typename hashtype >
static void TestSecretRangeThread ( const HashInfo* info, const uint64_t hi,
                             const uint32_t start, const uint32_t endlow,
                             bool &result, bool &newresult )
{
  size_t last = hi | endlow;
  const char * progress_fmt =
      (last <= UINT64_C(0xffffffff)) ?
      "%8" PRIx64 "%c"  : "%16" PRIx64 "%c";
  const uint64_t progress_nl_every =
      (last <= UINT64_C(0xffffffff)) ? 8 : 4;
#ifdef HAVE_INT64
  const std::vector<uint64_t> secrets = info->secrets;
#else
  const std::vector<size_t> secrets = info->secrets;
#endif
  pfHash hash = info->hash;
  std::vector<hashtype> hashes;
  HashSet<hashtype> collisions_dummy;
  int fails = 0;
  hashes.resize(4);
  result = true;
  {
#ifdef HAVE_THREADS
    std::lock_guard<std::mutex> lock(print_mutex);
#endif
    printf("Testing [0x%016" PRIx64 ", 0x%016" PRIx64 "] ... \n", hi | start, last);
  }
  for (size_t seed = hi | start; seed < last; seed++) {
    static hashtype zero;
    /*
     * Print out progress using *one* printf() statement (for thread
     * friendliness). Add newlines periodically to make output
     * friendlier to humans, keeping track of printf()s across all
     * threads.
     */
    if ((seed & UINT64_C(0x1ffffff)) == UINT64_C(0x1ffffff)) {
#ifdef HAVE_THREADS
      std::lock_guard<std::mutex> lock(print_mutex);
#endif
      unsigned count = ++secret_progress;
      const char spacer = ((count % progress_nl_every) == 0) ? '\n' : ' ';
      printf (progress_fmt, seed, spacer);
    }
    hashes.clear();
    Hash_Seed_init (hash, seed, 1);
    for (int x : std::vector<int> {0,32,127,255}) {
      hashtype h;
      uint8_t key[64]; // for crc32_pclmul, otherwie we would need only 16 byte
      memset(&key, x, sizeof(key));
      hash(key, 16, seed, &h);
      hashes.push_back(h);
      if (h == 0 && x == 0) {
        bool known_seed = (std::find(secrets.begin(), secrets.end(), seed) != secrets.end());
        {
#ifdef HAVE_THREADS
          std::lock_guard<std::mutex> lock(print_mutex);
#endif
          if (known_seed)
            printf("\nVerified broken seed 0x%" PRIx64 " => 0 with key[16] of all %d bytes\n", seed, x);
          else
            printf("\nNew broken seed 0x%" PRIx64 " => 0 with key[16] of all %d bytes\n", seed, x);
        }
        fails++;
        result = false;
        if (!known_seed)
          newresult = true;
      }
    }
    if (FindCollisions(hashes, collisions_dummy, 0, false) > 0) {
#ifdef HAVE_THREADS
      std::lock_guard<std::mutex> lock(print_mutex);
#endif
      bool known_seed = (std::find(secrets.begin(), secrets.end(), seed) != secrets.end());
      if (known_seed)
        printf("\nVerified bad seed 0x%" PRIx64 "\n", seed);
      else
        printf("\nNew bad seed 0x%" PRIx64 "\n", seed);
      fails++;
      if (!known_seed && (fails < 32)) // don't print too many lines
        TestHashList(hashes, true, true, false, false, false, true);
      result = false;
      if (!known_seed)
        newresult = true;
    }
    if (fails > 300) {
      fprintf(stderr, "Too many bad seeds, aborting\n");
      exit(1);
    }
  }

  return;
}

// Test the full 2^32 range [hi + 0, hi + 0xffffffff], the hi part
// If no new bad seed is found, then newresult must be left unchanged.
template< typename hashtype >
static bool TestSecret32 ( const HashInfo* info, const uint64_t hi, bool &newresult ) {
  bool result = true;
  secret_progress = 0;

  if (g_NCPU == 1) {
      TestSecretRangeThread<hashtype>(info, hi, 0x0, 0xffffffff, result, newresult);
      printf("\n");
  } else {
#ifdef HAVE_THREADS
      // split into g_NCPU threads
      std::thread t[g_NCPU];
      const uint64_t len = 0x100000000UL / g_NCPU;
      // Can't make VLAs in C++, so have to use vectors, but can't
      // pass a ref of a bool in a vector to a thread... :-<
      bool * results    = new bool[g_NCPU]();
      bool * newresults = new bool[g_NCPU]();

      printf("%d threads starting...\n", g_NCPU);
      for (int i=0; i < g_NCPU; i++) {
          const uint32_t start = i * len;
          const uint32_t end = (i < (g_NCPU - 1)) ? start + (len - 1) : 0xffffffff;
          t[i] = std::thread {TestSecretRangeThread<hashtype>, info, hi, start, end,
                              std::ref(results[i]), std::ref(newresults[i])};
      }

      std::this_thread::sleep_for(std::chrono::seconds(1));

      for (int i=0; i < g_NCPU; i++) {
          t[i].join();
      }

      printf("All %d threads ended\n", g_NCPU);

      for (int i=0; i < g_NCPU; i++) {
          result &= results[i];
          newresult |= newresults[i];
      }

      delete [] results;
      delete [] newresults;
#endif
  }

  return result;
}

template< typename hashtype >
static bool BadSeedsImpl ( HashInfo* info, bool testAll ) {
  bool result = true;
  bool newresult = false;
  bool have_lower = false;
#ifdef HAVE_INT64
  const std::vector<uint64_t> secrets = info->secrets;
#else
  const std::vector<size_t> secrets = info->secrets;
#endif
#if !defined __arm__ && !defined __aarch64__
  printf("Testing %lu internal secrets:\n", (unsigned long)secrets.size());
#endif
  for (auto secret : secrets) {
    result &= TestSecret<hashtype>(info, secret);
    if (sizeof(hashtype) == 8 && secret <= 0xffffffff) { // check the upper hi mask also
      uint64_t s = secret << 32;
      have_lower = true;
      result &= TestSecret<hashtype>(info, s);
    }
  }
  if (!secrets.size())
    result &= TestSecret<hashtype>(info, 0x0);
  if (getenv("SEED")) {
    const char *s = getenv("SEED");
    size_t seed = strtol(s, NULL, 0);
    printf("\nTesting SEED=0x%" PRIx64 " ", seed);
    //if (*s && s[1] && *s == '0' && s[1] == 'x')
    //  seed = strtol(&s[2], NULL, 16);
    if (seed || secrets.size())
      result &= TestSecret<hashtype>(info, seed);
  }
  if (result)
    printf("PASS\n");
  if (testAll == false ||
          ((info->quality == SKIP) &&
                  (strncmp(info->name, "aes", 3) != 0)))
    return result;

  // many days with >= 64 bit hashes
  printf("Testing the first 0xffffffff seeds ...\n");
  result &= TestSecret32<hashtype>(info, UINT64_C(0x0), newresult);
#ifdef HAVE_INT64
  // Currently *only* seeds going through Hash_Seed_init() can be
  // wider than 32 bits!!
  if (Hash_Seed_init(info->hash, 0)) {
    if (sizeof(hashtype) > 4) { // and the upper half 32bit range
      if (have_lower) {
        for (auto secret : secrets) {
          if (secret <= 0xffffffff) {
            uint64_t s = secret;
            s = s << 32;
            printf("Suspect the 0x%" PRIx64 " seeds ...\n", s);
            result &= TestSecret32<hashtype>(info, s, newresult);
          }
        }
      }
    }
    printf("And the last 0xffffffff00000000 seeds ...\n");
    result &= TestSecret32<hashtype>(info, UINT64_C(0xffffffff00000000), newresult);
  }
#endif
  if (result)
    printf("PASS\n");
  else {
    printf("FAIL\n");
    if (newresult)
      printf("Consider adding any new bad seeds to this hash's list of secrets in main.cpp\n");
  }

  return result;
}

//-----------------------------------------------------------------------------

template < typename hashtype >
bool BadSeedsTest(HashInfo * info, const bool find_new_seeds) {
    pfHash hash = info->hash;
    bool result = true;

    printf("[[[ BadSeeds Tests ]]]\n\n");

    Hash_Seed_init (hash, 0);

    result &= BadSeedsImpl<hashtype>( info, find_new_seeds );

    if(!result) printf("\n*********FAIL*********\n");
    printf("\n");

    return result;
}

INSTANTIATE(BadSeedsTest, HASHTYPELIST);
