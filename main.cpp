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
#include "Stats.h"
#include "LegacyHashes.h"
#include "HashSanityTest.h"
#include "VCode.h"

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
#include "DifferentialTest.h"
#include "HashMapTest.h"
#include "SeedTest.h"
#include "BadSeedsTest.h"

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>

//-----------------------------------------------------------------------------
// Configuration.

bool g_drawDiagram     = false;
bool g_testAll         = true;
bool g_testExtra       = false; // excessive torture tests: Sparse, Avalanche, DiffDist, scan all seeds
bool g_testVerifyAll   = false;

bool g_testSanity      = false;
bool g_testSpeed       = false;
bool g_testHashmap     = false;
bool g_testAvalanche   = false;
bool g_testSparse      = false;
bool g_testPermutation = false;
bool g_testWindow      = false;
bool g_testCyclic      = false;
bool g_testTwoBytes    = false;
bool g_testText        = false;
bool g_testZeroes      = false;
bool g_testSeed        = false;
bool g_testPerlinNoise = false;
bool g_testDiff        = false;
bool g_testDiffDist    = false;
bool g_testPopcount    = false;
bool g_testPrng        = false;
bool g_testBIC         = false;
bool g_testBadSeeds    = false;

#ifdef HAVE_THREADS
unsigned g_NCPU        = 4;
#else
const unsigned g_NCPU  = 1;
#endif

struct TestOpts {
  bool         &var;
  const char*  name;
};
TestOpts g_testopts[] =
{
  { g_testAll,          "All" },
  { g_testVerifyAll,    "VerifyAll" },
  { g_testSanity,       "Sanity" },
  { g_testSpeed,        "Speed" },
  { g_testHashmap,      "Hashmap" },
  { g_testAvalanche,    "Avalanche" },
  { g_testSparse,       "Sparse" },
  { g_testPermutation,  "Permutation" },
  { g_testWindow,       "Window" },
  { g_testCyclic,       "Cyclic" },
  { g_testTwoBytes,     "TwoBytes" },
  { g_testText,	        "Text" },
  { g_testZeroes,       "Zeroes" },
  { g_testSeed,	        "Seed" },
  { g_testPerlinNoise,	"PerlinNoise" },
  { g_testDiff,         "Diff" },
  { g_testDiffDist,     "DiffDist" },
  { g_testBIC, 	        "BIC" },
  { g_testPopcount,     "Popcount" },
  { g_testPrng,         "Prng" },
  { g_testBadSeeds,     "BadSeeds" },
};

//-----------------------------------------------------------------------------

uint32_t g_doVCode = 0;
uint32_t g_inputVCode = 1;
uint32_t g_outputVCode = 1;
uint32_t g_resultVCode = 1;
HashInfo * g_hashUnderTest = NULL;

void VCodeWrappedHash ( const void * key, int len, uint32_t seed, void * out )
{
  g_hashUnderTest->hash(key, len, seed, out);

  // Note that the seed also counts towards the input VCode, but that
  // was already added via Hash_Seed_init(), and so is not done here.
  addVCodeInput(key, len);
  addVCodeOutput(out, g_hashUnderTest->hashbits/8);
}

//-----------------------------------------------------------------------------

const char* quality_str[3] = { "SKIP", "POOR", "GOOD" };

template < typename hashtype >
bool test ( hashfunc<hashtype> hash, HashInfo* info )
{
  const int hashbits = sizeof(hashtype) * 8;
  bool result = true;

  if (g_testAll) {
    printf("-------------------------------------------------------------------------------\n");
  }

  // eventual initializers
  Hash_init (info);

  // Most hashes don't use Hash_Seed_init(), so they only get their
  // seed through hash(), which has a uint32_t seed parameter, so
  // there's no way of getting big seeds to them at all.
  //
  // XXX - This general problem will need to be addressed at
  // some point!! For now, just limit global seeds to 32 bits.
  if (g_seed > (1ULL << (8 * sizeof(uint32_t)))) {
      if (!Hash_Seed_init(hash, g_seed)) {
          printf("Specified global seed 0x%016" PRIx64 ""
                  " is larger than the hash harness can accept\n", g_seed);
          exit(1);
      }
  }

  //-----------------------------------------------------------------------------
  // Sanity tests

  if(g_testVerifyAll)
  {
    printf("[[[ VerifyAll Tests ]]]\n\n"); fflush(NULL);
    HashSelfTestAll(g_drawDiagram);
    printf("PASS\n\n");
  }

  FILE * outfile;
  if (g_testAll || g_testSpeed || g_testHashmap)
    outfile = stdout;
  else
    outfile = stderr;
  fprintf(outfile, "--- Testing %s \"%s\" %s", info->name, info->desc, quality_str[info->quality]);
  if (g_seed != 0)
    fprintf(outfile, " seed 0x%016" PRIx64 "\n\n", g_seed);
  else
    fprintf(outfile, "\n\n");

  if(g_testSanity || g_testAll)
  {
    printf("[[[ Sanity Tests ]]]\n\n");

    result &= VerificationTest(info,true);
    Hash_Seed_init (hash, 0);
    result &= (SanityTest(hash,hashbits)          || (info->quality == SKIP));
    result &= (AppendedZeroesTest(hash,hashbits)  || (info->quality == SKIP));
    result &= (PrependedZeroesTest(hash,hashbits) || (info->quality == SKIP));
    printf("\n");
  }

  //-----------------------------------------------------------------------------
  // Speed tests

  if(g_testSpeed || g_testAll)
  {
      SpeedTest(info);
  }

  // known slow hashes (typically > 500 cycle/hash)
  const struct { pfHash h; } slowhashes[] = {
     { md5_32                   },
     { md5_64                   },
     { md5_128                  },
     { sha1_32                  },
     { sha1_64                  },
     { sha1_160                 },
     { sha2_224                 },
     { sha2_224_64              },
     { sha2_256                 },
     { sha2_256_64              },
     { rmd128                   },
     { rmd160                   },
     { rmd256                   },
     { blake2s128_test          },
     { blake2s160_test          },
     { blake2s224_test          },
     { blake2s256_test          },
     { blake2s256_64            },
     { blake2b160_test          },
     { blake2b224_test          },
     { blake2b256_test          },
     { blake2b256_64            },
     { sha3_256                 },
     { sha3_256_64              },
     { tifuhash_64              },
     { floppsyhash_64           },
     { beamsplitter_64          },
    };
  bool hash_is_slow = false;
  for (int i=0; i<sizeof(slowhashes)/sizeof(slowhashes[0]); i++) {
      if (slowhashes[i].h == hash) {
          hash_is_slow = true;
          break;
      }
  }

  if(g_testHashmap || g_testAll)
  {
      result &= HashMapTest(info, g_drawDiagram, g_testExtra, hash_is_slow);
  }

  //-----------------------------------------------------------------------------
  // Avalanche tests

  if(g_testAvalanche || g_testAll)
  {
      result &= AvalancheTest<hashtype>(info, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Sparse' - keys with all bits 0 except a few

  if(g_testSparse || g_testAll)
  {
      result &= SparseKeyTest<hashtype>(info, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Permutation' - all possible combinations of a set of blocks

  if(g_testPermutation || g_testAll)
  {
      result &= PermutedKeyTest<hashtype>(info, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Window'

  if(g_testWindow || g_testAll)
  {
      result &= WindowedKeyTest<hashtype>(info, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Cyclic' - keys of the form "abcdabcdabcd..."

  if (g_testCyclic || g_testAll)
  {
      result &= CyclicKeyTest<hashtype>(info, g_drawDiagram, hash_is_slow);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'TwoBytes' - all keys up to N bytes containing two non-zero bytes
  // With --extra this generates some huge keysets,
  // 128-bit tests will take ~1.3 gigs of RAM.

  if(g_testTwoBytes || g_testAll)
  {
      result &= TwoBytesKeyTest<hashtype>(info, g_drawDiagram, g_testExtra, hash_is_slow);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Text'

  if(g_testText || g_testAll)
  {
      result &= TextKeyTest<hashtype>(info, g_drawDiagram);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Zeroes'

  if(g_testZeroes || g_testAll)
  {
      result &= ZeroKeyTest<hashtype>(info, g_drawDiagram);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'Seed'

  if(g_testSeed || g_testAll)
  {
      result &= SeedTest<hashtype>(info, g_drawDiagram);
  }

  //-----------------------------------------------------------------------------
  // Keyset 'PerlinNoise'

  if(g_testPerlinNoise || g_testAll)
  {
      result &= PerlinNoiseTest<hashtype>(info, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Differential tests
  // less reps with slow or very bad hashes

  if(g_testDiff || g_testAll)
  {
      bool slow =
          hash_is_slow                        ||
          info->hashbits > 128                ||
          hash == o1hash_test                 ||
          hash == halftime_hash_style64_test  ||
          hash == halftime_hash_style128_test ||
          hash == halftime_hash_style256_test ||
          hash == halftime_hash_style512_test;
      result &= DiffTest<hashtype>(info, g_drawDiagram, g_testExtra, slow);
  }

  //-----------------------------------------------------------------------------
  // Differential-distribution tests

  if (g_testDiffDist || g_testAll)
  {
      result &= DiffDistTest<hashtype>(info, g_drawDiagram);
  }

  //-----------------------------------------------------------------------------
  // Measuring the distribution of the population count of the
  // lowest 32 bits set over the whole key space.

  if (g_testPopcount || g_testAll)
  {
      result &= PopcountTest<hashtype>(info, g_testExtra, hash_is_slow);
  }

  //-----------------------------------------------------------------------------
  // Test the hash function as a PRNG by repeatedly feeding its output
  // back into the hash to get the next random number.

  if (g_testPrng || g_testAll)
  {
      result &= PRNGTest<hashtype>(info, g_drawDiagram, g_testExtra);
  }

  //-----------------------------------------------------------------------------
  // Bit Independence Criteria. Interesting, but doesn't tell us much about
  // collision or distribution. For >=128bit hashes, do this only with --extra

  if(g_testBIC || (g_testAll && info->hashbits >= 128 && g_testExtra))
  {
    result &= BicTest<hashtype>(info, g_drawDiagram, hash_is_slow);
  }

  //-----------------------------------------------------------------------------
  // Test for known or unknown seed values which give bad/suspect hash values.

  if (g_testBadSeeds || g_testAll)
  {
      result &= BadSeedsTest<hashtype>(info, g_testExtra);
  }

  if (g_testAll) {
      printf("-------------------------------------------------------------------------------\n");
      printf("Overall result: %s\n", result ? "pass" : "FAIL");
  }

  return result;
}

//-----------------------------------------------------------------------------

bool testHash ( const char * name )
{
  HashInfo * pInfo = findHash(name);

  if(pInfo == NULL) {
    printf("Invalid hash '%s' specified\n", name);
    return false;
  }

  g_hashUnderTest = pInfo;

  if(pInfo->hashbits == 32)
      return test<uint32_t>( pInfo->hash, pInfo );
  if(pInfo->hashbits == 64)
      return test<uint64_t>( pInfo->hash, pInfo );
  if(pInfo->hashbits == 128)
      return test<uint128_t>( pInfo->hash, pInfo );
  if(pInfo->hashbits == 160)
      return test<Blob<160>>( pInfo->hash, pInfo );
  if(pInfo->hashbits == 224)
      return test<Blob<224>>( pInfo->hash, pInfo );
  if(pInfo->hashbits == 256)
      return test<uint256_t>( pInfo->hash, pInfo );

  printf("Invalid hash bit width %d for hash '%s'",
          pInfo->hashbits, pInfo->name);
  return false;
}

//-----------------------------------------------------------------------------

void usage( void )
{
    printf("Usage: SMHasher3 [--list][--listnames][--tests] [--verbose][--extra]\n"
           "       [--ncpu=N] [--vcode] [--test=Speed,...] [--seed=globalseed] hash\n");
}

int main ( int argc, const char ** argv )
{
  setbuf(stdout, NULL); // Unbuffer stdout always
  setbuf(stderr, NULL); // Unbuffer stderr always

#if defined(__x86_64__) || defined(_M_X64) || defined(_X86_64_)
  const char * defaulthash = "xxh3";
#else
  const char * defaulthash = "wyhash";
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
        const size_t numhashes = numHashes();
        for(size_t i = 0; i < numhashes; i++) {
          HashInfo * h = numHash(i);
          printf("%-16s\t\"%s\" %s\n", h->name, h->desc, quality_str[h->quality]);
        }
        exit(0);
      }
      if (strcmp(arg,"--listnames") == 0) {
        const size_t numhashes = numHashes();
        for(size_t i = 0; i < numhashes; i++) {
          HashInfo * h = numHash(i);
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
      if (strcmp(arg,"--vcode") == 0) {
        g_doVCode = 1;
        VCODE_INIT();
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
      if (strcmp(arg,"--EstimateNbCollisions") == 0) {
        ReportCollisionEstimates();
        exit(0);
      }
      /* default: --test=All. comma seperated list of options */
      if (strncmp(arg,"--test=", 6) == 0) {
        char *opt = (char *)&arg[7];
        char *rest = opt;
        char *p;
        bool found = false;
        bool need_opt_free = false;
        g_testAll = false;
        do {
          if ((p = strchr(rest, ','))) {
            opt = strndup(rest, p-rest);
            need_opt_free = true;
            rest = p+1;
          } else {
            need_opt_free = false;
            opt = rest;
          }
          for (size_t i = 0; i < sizeof(g_testopts) / sizeof(TestOpts); i++) {
            if (strcmp(opt, g_testopts[i].name) == 0) {
              g_testopts[i].var = true; found = true; break;
            }
          }
          if (!found) {
            printf("Invalid option: --test=%s\n", opt);
            printf("Valid tests: --test=%s", g_testopts[0].name);
            for(size_t i = 1; i < sizeof(g_testopts) / sizeof(TestOpts); i++) {
              printf(",%s", g_testopts[i].name);
            }
            printf(" \n");
            if (need_opt_free)
              free(opt);
            exit(1);
          }
          if (need_opt_free)
            free(opt);
        } while (p);
        continue;
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

  clock_t timeBegin = clock();

  testHash(hashToTest);

  clock_t timeEnd = clock();

  printf("\n");

  if (g_doVCode) {
      VCODE_FINALIZE();
  }

  FILE * outfile = g_testAll ? stdout : stderr;
  fprintf(outfile,
          "Input vcode 0x%08x, Output vcode 0x%08x, Result vcode 0x%08x\n",
          g_inputVCode, g_outputVCode, g_resultVCode);
  fprintf(outfile,
          "Verification value is 0x%08x - Testing took %f seconds\n",
          g_verify, double(timeEnd-timeBegin)/double(CLOCKS_PER_SEC));

  return 0;
}
