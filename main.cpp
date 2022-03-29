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
#define _MAIN_CPP
#include "Platform.h"
#include "Types.h"
#include "Timing.h"
#include "Stats.h"
#include "LegacyHashes.h"
#include "Hashlib.h"
#include "Analyze.h"
#include "VCode.h"

#include "SanityTest.h"
#include "SparseKeysetTest.h"
#include "ZeroesKeysetTest.h"
#include "WindowedKeysetTest.h"
#include "CyclicKeysetTest.h"
#include "TwoBytesKeysetTest.h"
#include "TextKeysetTest.h"
#include "PermutationKeysetTest.h"
#include "SpeedTest.h"
#include "PerlinNoiseTest.h"
#include "PopcountTest.h"
#include "PRNGTest.h"
#include "AvalancheTest.h"
#include "BitIndependenceTest.h" // aka BIC
#include "DifferentialTest.h"
#include "DiffDistributionTest.h"
#include "HashMapTest.h"
#include "SeedTest.h"
#include "BadSeedsTest.h"

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>

//-----------------------------------------------------------------------------
// Globally-visible configuration
#ifdef HAVE_THREADS
unsigned g_NCPU        = 4;
#else
const unsigned g_NCPU  = 1;
#endif

HashInfo::endianness g_hashEndian = HashInfo::ENDIAN_DEFAULT;

//--------
// Overall log2-p-value statistics and test pass/fail counts
uint32_t g_log2pValueCounts[COUNT_MAX_PVALUE+2];
uint32_t g_testPass, g_testFail;
std::vector< std::pair<const char *, char *> > g_testFailures;

//-----------------------------------------------------------------------------
// Locally-visible configuration
static bool g_drawDiagram = false;

// excessive torture tests: Sparse, Avalanche, DiffDist, scan all seeds
static bool g_testExtra   = false;

static bool g_testAll;
static bool g_testVerifyAll;
static bool g_testSanity;
static bool g_testSpeed;
static bool g_testHashmap;
static bool g_testAvalanche;
static bool g_testSparse;
static bool g_testPermutation;
static bool g_testWindow;
static bool g_testCyclic;
static bool g_testTwoBytes;
static bool g_testText;
static bool g_testZeroes;
static bool g_testSeed;
static bool g_testPerlinNoise;
static bool g_testDiff;
static bool g_testDiffDist;
static bool g_testPopcount;
static bool g_testPrng;
static bool g_testBIC;
static bool g_testBadSeeds;

struct TestOpts {
  bool         &var;
  bool         defaultvalue;  // What "All" sets the test to
  bool         testspeedonly; // If true, then disabling test doesn't affect "All" testing
  const char*  name;
};
static TestOpts g_testopts[] =
{
  { g_testVerifyAll,    false,     false,    "VerifyAll" }, // Overrides all others
  { g_testAll,           true,     false,    "All" },
  { g_testSanity,        true,     false,    "Sanity" },
  { g_testSpeed,         true,      true,    "Speed" },
  { g_testHashmap,       true,      true,    "Hashmap" },
  { g_testAvalanche,     true,     false,    "Avalanche" },
  { g_testSparse,        true,     false,    "Sparse" },
  { g_testPermutation,   true,     false,    "Permutation" },
  { g_testWindow,        true,     false,    "Window" },
  { g_testCyclic,        true,     false,    "Cyclic" },
  { g_testTwoBytes,      true,     false,    "TwoBytes" },
  { g_testText,          true,     false,    "Text" },
  { g_testZeroes,        true,     false,    "Zeroes" },
  { g_testSeed,          true,     false,    "Seed" },
  { g_testPerlinNoise,   true,     false,    "PerlinNoise" },
  { g_testDiff,          true,     false,    "Diff" },
  { g_testDiffDist,      true,     false,    "DiffDist" },
  { g_testPopcount,      true,     false,    "Popcount" },
  { g_testPrng,          true,     false,    "Prng" },
  { g_testBIC,          false,     false,    "BIC" },
  { g_testBadSeeds,     false,     false,    "BadSeeds" },
};

static void set_default_tests(bool enable) {
    for (size_t i = 0; i < sizeof(g_testopts) / sizeof(TestOpts); i++) {
        if (enable) {
            g_testopts[i].var = g_testopts[i].defaultvalue;
        } else if (g_testopts[i].defaultvalue) {
            g_testopts[i].var = false;
        }
    }
}

static void parse_tests(const char * str, bool enable_tests) {
    while (*str != '\0') {
        size_t len;
        const char *p = strchr(str, ',');
        if (p == NULL) {
            len = strlen(str);
        } else {
            len = p - str;
        }

        bool found = false;
        for (size_t i = 0; i < sizeof(g_testopts) / sizeof(TestOpts); i++) {
            const char * testname = g_testopts[i].name;
            // Allow the user to specify test names by case-agnostic
            // unique prefix.
            if (strncasecmp(str, testname, len) == 0) {
                if (found) {
                    printf("Ambiguous test name: --%stest=%*s\n",
                            enable_tests ? "" : "no", len, str);
                    goto error;
                }
                found = true;
                //printf("%sabling test %s\n", enable_tests ? "en" : "dis", testname);
                g_testopts[i].var = enable_tests;
                // If "All" tests are being enabled or disabled, then
                // adjust the individual test variables as
                // instructed. Otherwise, if a material "All" test
                // (not just a speed-testing test) is being
                // specifically disabled, then don't consider "All"
                // tests as being run.
                if (&g_testopts[i].var == &g_testAll) {
                    set_default_tests(enable_tests);
                } else if (!enable_tests                 &&
                        g_testopts[i].defaultvalue       &&
                        !g_testopts[i].testspeedonly) {
                    g_testAll = false;
                }
                if (testname[len] == '\0') {
                    //printf("Exact match\n");
                    break;
                }
            }
        }
        if (!found) {
            printf("Invalid option: --test=%*s\n", len, str);
            goto error;
        }
        if (p == NULL) {
            break;
        }
        str += len + 1;
    }

    return;

 error:
    printf("Valid tests: --test=%s", g_testopts[0].name);
    for(size_t i = 1; i < sizeof(g_testopts) / sizeof(TestOpts); i++) {
        printf(",%s", g_testopts[i].name);
    }
    printf(" \n");
    exit(1);
}

static void usage(void);
static HashInfo::endianness parse_endian(const char * str) {
    if (!strcmp(str, "native"))     { return HashInfo::ENDIAN_NATIVE; }
    if (!strcmp(str, "nonnative"))  { return HashInfo::ENDIAN_BYTESWAPPED; }
    if (!strcmp(str, "default"))    { return HashInfo::ENDIAN_DEFAULT; }
    if (!strcmp(str, "nondefault")) { return HashInfo::ENDIAN_NONDEFAULT; }
    if (!strcmp(str, "big"))        { return HashInfo::ENDIAN_BIG; }
    if (!strcmp(str, "little"))     { return HashInfo::ENDIAN_LITTLE; }
    printf("Unknown endian option: %s\n", str);
    usage();
    exit(1);
}

//-----------------------------------------------------------------------------
// Self-test - verify that all installed hashes work correctly.

static void HashSelfTestAll(bool verbose) {
  const size_t numhashes = numLegacyHashes();
  bool pass = true;

  pass &= verifyAllHashes(verbose);

  for (size_t i = 0; i < numhashes; i++) {
    LegacyHashInfo * linfo = numLegacyHash(i);
    HashInfo * hinfo = convertLegacyHash(linfo);
    pass &= (hinfo->Init() && hinfo->Verify(HashInfo::ENDIAN_NATIVE, verbose));
    delete hinfo;
  }

  if (!pass) {
    printf("Self-test FAILED!\n");
    if (!verbose) {
      verifyAllHashes(true);
      for (size_t i = 0; i < numhashes; i++) {
        LegacyHashInfo * linfo = numLegacyHash(i);
        HashInfo * hinfo = convertLegacyHash(linfo);
        pass &= hinfo->Verify(HashInfo::ENDIAN_NATIVE, true);
        delete hinfo;
      }
    }
    exit(1);
  }
}

//-----------------------------------------------------------------------------
void print_pvaluecounts(void) {
  printf("Log2(p-value) summary:");
  for (uint32_t lo = 0; lo <= (COUNT_MAX_PVALUE+1); lo += 10) {
    printf("\n\t %2d%c", lo, (lo == (COUNT_MAX_PVALUE+1)) ? '+' : ' ');
    for (uint32_t i = 1; i < 10; i++) {
      printf("  %2d%c", lo+i, ((lo+i) == (COUNT_MAX_PVALUE+1)) ? '+' : ' ');
    }
    printf("\n\t----");
    for (uint32_t i = 1; i < 10; i++) {
      printf(" ----");
    }
    printf("\n\t%4d", g_log2pValueCounts[lo+0]);
    for (uint32_t i = 1; i < 10; i++) {
      printf(" %4d", g_log2pValueCounts[lo+i]);
    }
    printf("\n");
  }
  printf("\n");
}

//-----------------------------------------------------------------------------

template < typename hashtype >
static bool test ( const HashInfo * hInfo )
{
  const int hashbits = sizeof(hashtype) * 8;
  bool result = true;

  if (g_testAll) {
    printf("-------------------------------------------------------------------------------\n");
  }

  if (!hInfo->Init()) {
      printf("Hash initialization failed! Cannot continue.\n");
      exit(1);
  }

  //-----------------------------------------------------------------------------
  // Most legacy hashes don't use Hash_Seed_init(), so they only get
  // their seed through hash(), which has a uint32_t seed parameter,
  // so there's no way of getting big seeds to them at all.
  if ((g_seed >= (1ULL << (8 * sizeof(uint32_t)))) &&
          hInfo->isLegacy() && !hInfo->Seed(g_seed)) {
      printf("Specified global seed 0x%016" PRIx64 ""
              " is larger than the legacy hash harness can accept\n", g_seed);
      exit(1);
  }

  //-----------------------------------------------------------------------------
  // Sanity tests

  FILE * outfile;
  if (g_testAll || g_testSpeed || g_testHashmap)
    outfile = stdout;
  else
    outfile = stderr;
  fprintf(outfile, "--- Testing %s \"%s\" %s", hInfo->name, hInfo->desc, hInfo->isMock() ? "MOCK" : "");
  if (g_seed != 0)
    fprintf(outfile, " seed 0x%016" PRIx64 "\n\n", g_seed);
  else
    fprintf(outfile, "\n\n");

  if(g_testSanity)
  {
    printf("[[[ Sanity Tests ]]]\n\n");

    result &=  VerifyTest(hInfo);
    result &= (SanityTest(hInfo)          || hInfo->isMock());
    result &= (AppendedZeroesTest(hInfo)  || hInfo->isMock());
    result &= (PrependedZeroesTest(hInfo) || hInfo->isMock());
    printf("\n");
  }

  //-----------------------------------------------------------------------------
  // Speed tests

  if(g_testSpeed)
  {
      SpeedTest(hInfo);
  }

  if(g_testHashmap)
  {
      result &= HashMapTest(hInfo, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Avalanche tests

  if(g_testAvalanche)
  {
      result &= AvalancheTest<hashtype>(hInfo, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Sparse' - keys with all bits 0 except a few

  if(g_testSparse)
  {
      result &= SparseKeyTest<hashtype>(hInfo, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Permutation' - all possible combinations of a set of blocks

  if(g_testPermutation)
  {
      result &= PermutedKeyTest<hashtype>(hInfo, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Window'

  if(g_testWindow)
  {
      result &= WindowedKeyTest<hashtype>(hInfo, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Cyclic' - keys of the form "abcdabcdabcd..."

  if (g_testCyclic)
  {
      result &= CyclicKeyTest<hashtype>(hInfo, g_drawDiagram);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'TwoBytes' - all keys up to N bytes containing two non-zero bytes
  // With --extra this generates some huge keysets,
  // 128-bit tests will take ~1.3 gigs of RAM.

  if(g_testTwoBytes)
  {
      result &= TwoBytesKeyTest<hashtype>(hInfo, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Text'

  if(g_testText)
  {
      result &= TextKeyTest<hashtype>(hInfo, g_drawDiagram);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Zeroes'

  if(g_testZeroes)
  {
      result &= ZeroKeyTest<hashtype>(hInfo, g_drawDiagram);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Seed'

  if(g_testSeed)
  {
      result &= SeedTest<hashtype>(hInfo, g_drawDiagram);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'PerlinNoise'

  if(g_testPerlinNoise)
  {
      result &= PerlinNoiseTest<hashtype>(hInfo, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Differential tests

  if(g_testDiff)
  {
      result &= DiffTest<hashtype>(hInfo, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Differential-distribution tests

  if (g_testDiffDist)
  {
      result &= DiffDistTest<hashtype>(hInfo, g_drawDiagram);
  }

  //-----------------------------------------------------------------------------
  // Measuring the distribution of the population count of the
  // lowest 32 bits set over the whole key space.

  if (g_testPopcount)
  {
      result &= PopcountTest<hashtype>(hInfo, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Test the hash function as a PRNG by repeatedly feeding its output
  // back into the hash to get the next random number.

  if (g_testPrng)
  {
      result &= PRNGTest<hashtype>(hInfo, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Bit Independence Criteria. Interesting, but doesn't tell us much about
  // collision or distribution. For >=128bit hashes, do this only with --extra

  if (g_testAll && g_testExtra && hInfo->bits >= 128) {
      g_testBIC = true;
  }
  if(g_testBIC)
  {
    result &= BicTest<hashtype>(hInfo, g_drawDiagram);
  }

  //-----------------------------------------------------------------------------
  // Test for known or unknown seed values which give bad/suspect hash values.

  if (g_testBadSeeds)
  {
      result &= BadSeedsTest<hashtype>(hInfo, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // If All material tests were done, show a final summary of testing
  if (g_testAll) {
      printf("-------------------------------------------------------------------------------\n");
      print_pvaluecounts();
      printf("-------------------------------------------------------------------------------\n");
      printf("Overall result: %s            (%d/%d passed)\n", result ? "pass" : "FAIL",
              g_testPass, g_testPass+g_testFail);
      if (!result) {
          const char * prev = "";
          printf("Failures");
          for (auto x: g_testFailures) {
              if (strcmp(prev, x.first) != 0) {
                  printf("%c\n    %-20s: [%s", (strlen(prev) == 0) ? ':' : ']',
                          x.first, x.second ? x.second : "");
                  prev = x.first;
              } else {
                  printf(", %s", x.second);
              }
              free(x.second);
          }
          printf("]\n\n");
      } else {
          printf("\n");
      }
      printf("-------------------------------------------------------------------------------\n");
  }

  return result;
}

//-----------------------------------------------------------------------------

static bool testHash(const char * name) {
  LegacyHashInfo * lhInfo = NULL;
  const HashInfo * hInfo;

  if ((hInfo = findHash(name)) == NULL) {
      if((lhInfo = findLegacyHash(name)) == NULL) {
          printf("Invalid hash '%s' specified\n", name);
          return false;
      }
      // This technically leaks, but all the legacy stuff will be gone
      // soon enough.
      hInfo = convertLegacyHash(lhInfo);
  }

  // If you extend these statements by adding a new bitcount/type, you
  // need to adjust HASHTYPELIST in util/Instantiate.h also.
  if(hInfo->bits == 32)
      return test<uint32_t>( hInfo );
  if(hInfo->bits == 64)
      return test<uint64_t>( hInfo );
  if(hInfo->bits == 128)
      return test<Blob<128>>( hInfo );
  if(hInfo->bits == 160)
      return test<Blob<160>>( hInfo );
  if(hInfo->bits == 224)
      return test<Blob<224>>( hInfo );
  if(hInfo->bits == 256)
      return test<Blob<256>>( hInfo );

  printf("Invalid hash bit width %d for hash '%s'",
          hInfo->bits, hInfo->name);

  return false;
}

//-----------------------------------------------------------------------------

static void usage( void )
{
    printf("Usage: SMHasher3 [--[no]test=<testname>[,...]] [--extra] [--seed=<globalseed>]\n"
           "                 [--endian=default|nondefault|native|nonnative|big|little]\n"
           "                 [--verbose] [--vcode] [--ncpu=N] [<hashname>]\n"
           "\n"
           "       SMHasher3 [--list]|[--listnames]|[--tests]\n"
           );
}

int main ( int argc, const char ** argv )
{
  setbuf(stdout, NULL); // Unbuffer stdout always
  setbuf(stderr, NULL); // Unbuffer stderr always

  if (!isLE() && !isBE()) {
    printf("Runtime endian detection failed! Cannot continue\n");
    exit(1);
  }

  set_default_tests(true);

#if defined(__x86_64__) || defined(_M_X64) || defined(_X86_64_)
  const char * defaulthash = "xxh3";
#else
  const char * defaulthash = "wyhash-32";
#endif
  const char * hashToTest = defaulthash;

  if (argc < 2) {
    printf("No test hash given on command line, testing %s.\n", hashToTest);
    usage();
  }

  for (int argnb = 1; argnb < argc; argnb++) {
    const char* const arg = argv[argnb];
    if (strncmp(arg,"--", 2) == 0) {
      // This is a command
      if (strcmp(arg,"--help") == 0) {
        usage();
        exit(0);
      }
      if (strcmp(arg,"--list") == 0) {
        listHashes(false);
        const size_t numhashes = numLegacyHashes();
        for(size_t i = 0; i < numhashes; i++) {
          LegacyHashInfo * h = numLegacyHash(i);
          printf("%-16s\t\"%s\" %s\n", h->name, h->desc, h->quality == SKIP ? "MOCK" : "");
        }
        exit(0);
      }
      if (strcmp(arg,"--listnames") == 0) {
        listHashes(true);
        const size_t numhashes = numLegacyHashes();
        for(size_t i = 0; i < numhashes; i++) {
          LegacyHashInfo * h = numLegacyHash(i);
          printf("%s\n", h->name);
        }
        exit(0);
      }
      if (strcmp(arg,"--tests") == 0) {
        printf("Valid tests:\n");
        for(size_t i = 0; i < sizeof(g_testopts) / sizeof(TestOpts); i++) {
          printf("  %s\n", g_testopts[i].name);
        }
        exit(0);
      }
      if (strcmp(arg,"--verbose") == 0) {
        g_drawDiagram = true;
        continue;
      }
      if (strcmp(arg,"--extra") == 0) {
        g_testExtra = true;
        continue;
      }
      // VCodes allow easy comparison of test results and hash inputs
      // and outputs across SMHasher3 runs, hashes (of the same width),
      // and systems.
      if (strcmp(arg,"--vcode") == 0) {
        g_doVCode = 1;
        VCODE_INIT();
        continue;
      }
      if (strncmp(arg,"--endian=", 9) == 0) {
        g_hashEndian = parse_endian(&arg[9]);
        continue;
      }
      if (strncmp(arg,"--seed=", 7) == 0) {
        errno = 0;
        char * endptr;
        uint64_t seed = strtol(&arg[7], &endptr, 0);
        if ((errno != 0) || (arg[7] == '\0') || (*endptr != '\0')) {
            printf("Error parsing global seed value \"%s\"\n", &arg[7]);
            exit(1);
        }
        g_seed = seed;
        continue;
      }
      if (strncmp(arg,"--ncpu=", 7) == 0) {
#ifdef HAVE_THREADS
        errno = 0;
        char * endptr;
        long int Ncpu = strtol(&arg[7], &endptr, 0);
        if ((errno != 0) || (arg[7] == '\0') || (*endptr != '\0') || (Ncpu < 1)) {
            printf("Error parsing cpu number \"%s\"\n", &arg[7]);
            exit(1);
        }
        if (Ncpu > 32) {
            printf("WARNING: limiting to 32 threads\n");
            Ncpu = 32;
        }
        g_NCPU = Ncpu;
        continue;
#else
        printf("WARNING: compiled without threads; ignoring --ncpu\n");
        continue;
#endif
      }
      if (strncmp(arg,"--test=", 6) == 0) {
          // If a list of tests is given, only test those
          g_testAll = false;
          set_default_tests(false);
          parse_tests(&arg[7], true);
          continue;
      }
      if (strncmp(arg,"--notest=", 8) == 0) {
          parse_tests(&arg[9], false);
          continue;
      }
      if (strcmp(arg,"--EstimateNbCollisions") == 0) {
        ReportCollisionEstimates();
        exit(0);
      }
      // invalid command
      printf("Invalid command \n");
      usage();
      exit(1);
    }
    // Not a command ? => interpreted as hash name
    hashToTest = arg;
  }

  // Code runs on the 3rd CPU by default? only for speed tests
  //SetAffinity((1 << 2));
  //SelfTest();

  size_t timeBegin = monotonic_clock();

  if (g_testVerifyAll) {
      printf("[[[ VerifyAll Tests ]]]\n\n");
      HashSelfTestAll(g_drawDiagram);
      printf("PASS\n\n");
  } else {
      testHash(hashToTest);
  }

  size_t timeEnd = monotonic_clock();

  uint32_t vcode = VCODE_FINALIZE();

  FILE * outfile = g_testAll ? stdout : stderr;
  fprintf(outfile,
          "Input vcode 0x%08x, Output vcode 0x%08x, Result vcode 0x%08x\n",
          g_inputVCode, g_outputVCode, g_resultVCode);
  fprintf(outfile,
          "Verification value is 0x%08x - Testing took %f seconds\n\n",
          vcode, double(timeEnd-timeBegin)/double(NSEC_PER_SEC));

  return 0;
}
