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
#include "Timing.h"
#include "Hashlib.h"
#include "TestGlobals.h"
#include "Random.h"
#include "Blobsort.h"
#include "Analyze.h"
#include "Stats.h"
#include "VCode.h"
#include "AES.h"
#include "version.h"

#include "SanityTest.h"
#include "SparseKeysetTest.h"
#include "ZeroesKeysetTest.h"
#include "CyclicKeysetTest.h"
#include "TwoBytesKeysetTest.h"
#include "TextKeysetTest.h"
#include "PermutationKeysetTest.h"
#include "SpeedTest.h"
#include "PerlinNoiseTest.h"
#include "AvalancheTest.h"
#include "BitflipTest.h"
#include "BitIndependenceTest.h" // aka BIC
#include "HashMapTest.h"
#include "SeedTest.h"
#include "SeedZeroesTest.h"
#include "SeedSparseTest.h"
#include "SeedBitflipTest.h"
#include "SeedBlockLenTest.h"
#include "SeedBlockOffsetTest.h"
#include "SeedAvalancheTest.h"
#include "SeedBitIndependenceTest.h"
#include "BadSeedsTest.h"

#include <cstdio>
#include <cstdint>
#include <cinttypes>
#include <ctime>
#include <cerrno>
#include <clocale>

//-----------------------------------------------------------------------------
// Locally-visible configuration
static bool g_forceSummary   = false;
static bool g_exitOnFailure  = false;
static bool g_exitCodeResult = false;
static bool g_dumpAllVCodes  = false;

// Setting to test more thoroughly.
//
// Default settings find most hash problems. For testing a new hash,
// consider testing without --extra until that passes completely, and then
// move to testing with --extra.
static bool g_testExtra = false;

static bool g_testAll;
static bool g_testVerifyAll;
static bool g_testSanityAll;
static bool g_testSpeedAll;
static bool g_testSanity;
static bool g_testSpeed;
static bool g_testSpeedSmall;
static bool g_testSpeedBulk;
static bool g_testHashmap;
static bool g_testAvalanche;
static bool g_testSparse;
static bool g_testPermutation;
static bool g_testCyclic;
static bool g_testTwoBytes;
static bool g_testText;
static bool g_testZeroes;
static bool g_testSeed;
static bool g_testSeedZeroes;
static bool g_testSeedSparse;
static bool g_testSeedBlockLen;
static bool g_testSeedBlockOffset;
static bool g_testSeedBitflip;
static bool g_testSeedAvalanche;
static bool g_testSeedBIC;
static bool g_testPerlinNoise;
static bool g_testBitflip;
static bool g_testBIC;
static bool g_testBadSeeds;

struct TestOpts {
    bool &       var;
    bool         defaultvalue;  // What "All" sets the test to
    bool         testspeedonly; // If true, then disabling test doesn't affect "All" testing
    const char * name;
};
// These first 3 override all other selections
static TestOpts g_testopts[] = {
    { g_testVerifyAll,       false,     false,    "VerifyAll" },
    { g_testSanityAll,       false,     false,    "SanityAll" },
    { g_testSpeedAll,        false,     false,    "SpeedAll" },
    { g_testAll,              true,     false,    "All" },
    { g_testSanity,           true,     false,    "Sanity" },
    { g_testSpeed,            true,      true,    "Speed" },
    { g_testSpeedSmall,       true,      true,    "SpeedSmall" },
    { g_testSpeedBulk,        true,      true,    "SpeedBulk" },
    { g_testHashmap,          true,      true,    "Hashmap" },
    { g_testAvalanche,        true,     false,    "Avalanche" },
    { g_testSparse,           true,     false,    "Sparse" },
    { g_testPermutation,      true,     false,    "Permutation" },
    { g_testCyclic,           true,     false,    "Cyclic" },
    { g_testTwoBytes,         true,     false,    "TwoBytes" },
    { g_testText,             true,     false,    "Text" },
    { g_testZeroes,           true,     false,    "Zeroes" },
    { g_testSeed,             true,     false,    "Seed" },
    { g_testSeedZeroes,       true,     false,    "SeedZeroes" },
    { g_testSeedSparse,       true,     false,    "SeedSparse" },
    { g_testSeedBlockLen,     true,     false,    "SeedBlockLen" },
    { g_testSeedBlockOffset,  true,     false,    "SeedBlockOffset" },
    { g_testSeedBitflip,      true,     false,    "SeedBitflip" },
    { g_testSeedAvalanche,    true,     false,    "SeedAvalanche" },
    { g_testSeedBIC,          true,     false,    "SeedBIC" },
    { g_testPerlinNoise,      true,     false,    "PerlinNoise" },
    { g_testBitflip,          true,     false,    "Bitflip" },
    { g_testBIC,              true,     false,    "BIC" },
    { g_testBadSeeds,        false,     false,    "BadSeeds" },
};

static void set_default_tests( bool enable ) {
    for (size_t i = 0; i < sizeof(g_testopts) / sizeof(TestOpts); i++) {
        if (enable) {
            g_testopts[i].var = g_testopts[i].defaultvalue;
        } else if (g_testopts[i].defaultvalue) {
            g_testopts[i].var = false;
        }
    }
}

static void parse_tests( const char * str, bool enable_tests ) {
    while (*str != '\0') {
        size_t       len;
        const char * p = strchr(str, ',');
        if (p == NULL) {
            len = strlen(str);
        } else {
            len = p - str;
        }

        struct TestOpts * found = NULL;
        bool foundmultiple      = false;
        for (size_t i = 0; i < sizeof(g_testopts) / sizeof(TestOpts); i++) {
            const char * testname = g_testopts[i].name;
            // Allow the user to specify test names by case-agnostic
            // unique prefix.
            if (strncasecmp(str, testname, len) == 0) {
                if (found != NULL) {
                    foundmultiple = true;
                }
                found = &g_testopts[i];
                if (testname[len] == '\0') {
                    // Exact match found, don't bother looking further, and
                    // don't error out.
                    foundmultiple = false;
                    break;
                }
            }
        }
        if (foundmultiple) {
            printf("Ambiguous test name: --%stest=%*s\n", enable_tests ? "" : "no", (int)len, str);
            goto error;
        }
        if (found == NULL) {
            printf("Invalid option: --%stest=%*s\n", enable_tests ? "" : "no", (int)len, str);
            goto error;
        }

        // printf("%sabling test %s\n", enable_tests ? "en" : "dis", testname);
        found->var = enable_tests;

        // If "Speed" tests are being enabled or disabled, then adjust the
        // two sub-tests to match. If "All" tests are being enabled or
        // disabled, then adjust the individual test variables to
        // match. Otherwise, if a material "All" test (not just a
        // speed-testing test) is being specifically disabled, then don't
        // consider "All" tests as being run.
        if (&found->var == &g_testSpeed) {
            g_testSpeedSmall = g_testSpeedBulk = enable_tests;
        } else if (&found->var == &g_testAll) {
            set_default_tests(enable_tests);
        } else if (!enable_tests && found->defaultvalue && !found->testspeedonly) {
            g_testAll = false;
        }

        if (p == NULL) {
            break;
        }
        str += len + 1;
    }

    // Make g_testSpeed reflect the request to run any speed sub-test
    g_testSpeed = g_testSpeedSmall | g_testSpeedBulk;

    return;

  error:
    printf("Valid tests: --test=%s", g_testopts[0].name);
    for (size_t i = 1; i < sizeof(g_testopts) / sizeof(TestOpts); i++) {
        printf(",%s", g_testopts[i].name);
    }
    printf(" \n");
    exit(1);
}

static void usage( void );

static HashInfo::endianness parse_endian( const char * str ) {
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
// Show intermediate-stage VCodes, to help narrow down test differences
// across runs and platforms
static void DumpVCodes( void ) {
    uint32_t vcode = VCODE_FINALIZE();
    printf("Input 0x%08x, Output 0x%08x, Result 0x%08x, Overall 0x%08x\n\n",
            g_inputVCode, g_outputVCode, g_resultVCode, vcode);
}

//-----------------------------------------------------------------------------
// Self-tests - verify that hashes work correctly

static void HashSelfTestAll( flags_t flags ) {
    bool verbose = REPORT(VERBOSE, flags);
    bool pass = true;

    printf("[[[ VerifyAll Tests ]]]\n\n");

    pass &= verifyAllHashes(verbose);

    if (!pass) {
        printf("Self-test FAILED!\n");
        if (!verbose) {
            verifyAllHashes(true);
        }
        exit(1);
    }

    printf("PASS\n\n");
}

static bool HashSelfTest( const HashInfo * hinfo ) {
    bool result = verifyHash(hinfo, g_hashEndian, true, false);

    recordTestResult(result, "Sanity", "Implementation verification");

    return result;
}

static void HashSanityTestAll( flags_t flags ) {
    const uint64_t mask_flags = FLAG_HASH_MOCK | FLAG_HASH_CRYPTOGRAPHIC;
    uint64_t       prev_flags = FLAG_HASH_MOCK;
    std::vector<const HashInfo *> allHashes = findAllHashes();

    printf("[[[ SanityAll Tests ]]]\n\n");

    SanityTestHeader(flags);
    for (const HashInfo * h: allHashes) {
        if ((h->hash_flags & mask_flags) != prev_flags) {
            printf("\n");
            prev_flags = h->hash_flags & mask_flags;
        }
        if (!h->Init()) {
            printf("%s : hash initialization failed!", h->name);
            continue;
        }
        SanityTest(h, flags, true);
    }
    printf("\n");
}

//-----------------------------------------------------------------------------
// Quickly speed test all hashes

static void HashSpeedTestAll( flags_t flags ) {
    const uint64_t   mask_flags    = FLAG_HASH_MOCK | FLAG_HASH_CRYPTOGRAPHIC;
    uint64_t         prev_flags    = FLAG_HASH_MOCK;
    const HashInfo * overhead_hash = findHash("donothing-32");
    std::vector<const HashInfo *> allHashes = findAllHashes();

    printf("[[[ Short Speed Tests ]]]\n\n");

    SpeedTestInit(overhead_hash, flags);
    ShortSpeedTestHeader(flags);

    for (const HashInfo * h: allHashes) {
        if ((h->hash_flags & mask_flags) != prev_flags) {
            printf("\n");
            prev_flags = h->hash_flags & mask_flags;
        }
        if (!h->Init()) {
            printf("%s : hash initialization failed!", h->name);
            continue;
        }
        ShortSpeedTest(h, flags);
    }
    printf("\n");
}

//-----------------------------------------------------------------------------

static void print_pvaluecounts( void ) {
    printf("-log2(p-value) summary:\n");
    const uint32_t per_line = (COUNT_MAX_PVALUE + 2) / 2;
    for (uint32_t lo = 0; lo <= (COUNT_MAX_PVALUE + 1); lo += per_line) {
        printf("\n         %2d%c ", lo, (lo == (COUNT_MAX_PVALUE + 1)) ? '+' : ' ');
        for (uint32_t i = 1; i < per_line; i++) {
            printf("  %2d%c ", lo + i, ((lo + i) == (COUNT_MAX_PVALUE + 1)) ? '+' : ' ');
        }
        printf("\n        -----");
        for (uint32_t i = 1; i < per_line; i++) {
            printf(" -----");
        }
        printf("\n        %5d", g_log2pValueCounts[lo + 0]);
        for (uint32_t i = 1; i < per_line; i++) {
            printf(" %5d", g_log2pValueCounts[lo + i]);
        }
        printf("\n");
    }
    printf("\n");
}

//-----------------------------------------------------------------------------

template <typename hashtype>
static bool test( const HashInfo * hInfo, const flags_t flags ) {
    bool result  = true;
    bool summary = g_forceSummary;

    if (g_testAll) {
        printf("-------------------------------------------------------------------------------\n");
    }

    if (!hInfo->Init()) {
        printf("Hash initialization failed! Cannot continue.\n");
        exit(1);
    }

    //-----------------------------------------------------------------------------
    // Some hashes only take 32-bits of seed data, so there's no way of
    // getting big seeds to them at all.
    if ((g_seed >= (1ULL << 32)) && hInfo->is32BitSeed()) {
        printf("WARNING: Specified global seed 0x%016" PRIx64 "\n"
                " is larger than the specified hash can accept\n", g_seed);
    }

    //-----------------------------------------------------------------------------
    // Sanity tests

    FILE * outfile;
    if (g_testAll || g_testSpeed || g_testHashmap) {
        outfile = stdout;
    } else {
        outfile = stderr;
    }
    if ((hInfo->impl != NULL) && (hInfo->impl[0] != '\0')) {
        fprintf(outfile, "--- Testing %s \"%s\" [%s]%s", hInfo->name, hInfo->desc,
                hInfo->impl, hInfo->isMock() ? " MOCK" : hInfo->isCrypto() ? " CRYPTO" : "");
    } else {
        fprintf(outfile, "--- Testing %s \"%s\"%s", hInfo->name, hInfo->desc,
                hInfo->isMock() ? " MOCK" : hInfo->isCrypto() ? " CRYPTO" : "");
    }
    if (g_seed != 0) {
        fprintf(outfile, " seed 0x%016" PRIx64 "\n\n", g_seed);
    } else {
        fprintf(outfile, "\n\n");
    }

    if (g_testSanity) {
        printf("[[[ Sanity Tests ]]]\n\n");

        result &= HashSelfTest(hInfo);
        result &= (SanityTest(hInfo, flags) || hInfo->isMock());
        printf("\n");
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Speed tests

    if (g_testSpeed) {
        const HashInfo * overhead_hash = findHash("donothing-32");
        SpeedTestInit(overhead_hash, flags);
        SpeedTest(hInfo, flags, g_testSpeedSmall, g_testSpeedBulk);
    }

    if (g_testHashmap) {
        result &= HashMapTest(hInfo, g_testExtra, flags);
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Avalanche tests

    if (g_testAvalanche) {
        result &= AvalancheTest<hashtype>(hInfo, g_testExtra, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Bit Independence Criteria

    if (g_testBIC) {
        result &= BicTest<hashtype>(hInfo, g_testExtra, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'Zeroes'

    if (g_testZeroes) {
        result &= ZeroKeyTest<hashtype>(hInfo, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'Cyclic' - keys of the form "abcdabcdabcd..."

    if (g_testCyclic) {
        result &= CyclicKeyTest<hashtype>(hInfo, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'Sparse' - keys with all bits 0 except a few

    if (g_testSparse) {
        result &= SparseKeyTest<hashtype>(hInfo, g_testExtra, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'Permutation' - all possible combinations of a set of blocks

    if (g_testPermutation) {
        result &= PermutedKeyTest<hashtype>(hInfo, g_testExtra, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'Text'

    if (g_testText) {
        result &= TextKeyTest<hashtype>(hInfo, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'TwoBytes' - all keys up to N bytes containing two non-zero bytes

    if (g_testTwoBytes) {
        result &= TwoBytesKeyTest<hashtype>(hInfo, g_testExtra, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'PerlinNoise'

    if (g_testPerlinNoise) {
        result &= PerlinNoiseTest<hashtype>(hInfo, g_testExtra, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'Bitflip'

    if (g_testBitflip) {
        result &= BitflipTest<hashtype>(hInfo, g_testExtra, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'SeedZeroes'

    if (g_testSeedZeroes) {
        result &= SeedZeroKeyTest<hashtype>(hInfo, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'SeedSparse'

    if (g_testSeedSparse) {
        result &= SeedSparseTest<hashtype>(hInfo, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'SeedBlockLen'

    if (g_testSeedBlockLen) {
        result &= SeedBlockLenTest<hashtype>(hInfo, g_testExtra, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'SeedBlockOffset'

    if (g_testSeedBlockOffset) {
        result &= SeedBlockOffsetTest<hashtype>(hInfo, g_testExtra, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'Seed'

    if (g_testSeed) {
        result &= SeedTest<hashtype>(hInfo, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'SeedAvalanche'

    if (g_testSeedAvalanche) {
        result &= SeedAvalancheTest<hashtype>(hInfo, g_testExtra, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'SeedBIC'

    if (g_testSeedBIC) {
        result &= SeedBicTest<hashtype>(hInfo, g_testExtra, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Keyset 'SeedBitflip'

    if (g_testSeedBitflip) {
        result &= SeedBitflipTest<hashtype>(hInfo, g_testExtra, flags);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // Test for known or unknown seed values which give bad/suspect hash values

    if (g_testBadSeeds) {
        result &= BadSeedsTest<hashtype>(hInfo, g_testExtra);
        if (g_dumpAllVCodes) { DumpVCodes(); }
        if (!result && g_exitOnFailure) { goto out; }
    }

    //-----------------------------------------------------------------------------
    // If All material tests were done, show a final summary of testing
    summary |= g_testAll;

 out:
    if (summary) {
        printf("----------------------------------------------------------------------------------------------\n");
        print_pvaluecounts();
        printf("----------------------------------------------------------------------------------------------\n");
        if ((hInfo->impl != NULL) && (hInfo->impl[0] != '\0')) {
            printf("Summary for: %s [%s]%s\n", hInfo->name, hInfo->impl, hInfo->isMock() ? " MOCK" : "");
        } else {
            printf("Summary for: %s%s\n", hInfo->name, hInfo->isMock() ? " MOCK" : "");
        }
        printf("Overall result: %s            ( %d / %d passed)\n", result ? "pass" : "FAIL",
                g_testPass, g_testPass + g_testFail);
        if (!result) {
            const char * prev = "";
            printf("Failures");
            for (auto x: g_testFailures) {
                if (strcmp(prev, x.first) != 0) {
                    printf("%c\n    %-20s: [%s", (strlen(prev) == 0) ? ':' : ']', x.first, x.second ? x.second : "");
                    prev = x.first;
                } else {
                    printf(", %s", x.second);
                }
            }
            printf("]\n");
        }
        printf("\n----------------------------------------------------------------------------------------------\n");
    }
    for (auto x: g_testFailures) {
        free(x.second);
    }

    return result;
}

//-----------------------------------------------------------------------------

static bool testHash( const char * name, const flags_t flags ) {
    const HashInfo * hInfo;

    if ((hInfo = findHash(name)) == NULL) {
        printf("Invalid hash '%s' specified\n", name);
        return false;
    }

    // If you extend these statements by adding a new bitcount/type, you
    // need to adjust HASHTYPELIST in util/Instantiate.h also.
    if (hInfo->bits == 32) {
        return test<Blob<32>>(hInfo, flags);
    }
    if (hInfo->bits == 64) {
        return test<Blob<64>>(hInfo, flags);
    }
    if (hInfo->bits == 128) {
        return test<Blob<128>>(hInfo, flags);
    }
    if (hInfo->bits == 160) {
        return test<Blob<160>>(hInfo, flags);
    }
    if (hInfo->bits == 224) {
        return test<Blob<224>>(hInfo, flags);
    }
    if (hInfo->bits == 256) {
        return test<Blob<256>>(hInfo, flags);
    }

    printf("Invalid hash bit width %d for hash '%s'", hInfo->bits, hInfo->name);

    return false;
}

//-----------------------------------------------------------------------------

static void usage( void ) {
    printf("Usage: SMHasher3 [--[no]test=<testname>[,...]] [--extra] [--verbose] [--ncpu=N]\n"
           "                 [--seed=<hash_default_seed>] [--randseed=<RNG_base_seed>]\n"
           "                 [--endian=default|nondefault|native|nonnative|big|little]\n"
           "                 [--[no]exit-on-failure] [--[no]exit-code-on-failure]\n"
           "                 [--vcode[-all]] [--[no]time-tests]\n"
           "                 [<hashname>]\n"
           "\n"
           "       SMHasher3 [--list]|[--listnames]|[--tests]|[--version]\n"
           "\n"
           "  Hashnames can be supplied using any case letters.\n");
}

int main( int argc, const char ** argv ) {
    setbuf(stdout, NULL); // Unbuffer stdout always
    setbuf(stderr, NULL); // Unbuffer stderr always
    std::setlocale(LC_COLLATE, "C");
    std::setlocale(LC_CTYPE, "C");

    if (!isLE() && !isBE()) {
        printf("Runtime endian detection failed! Cannot continue\n");
        exit(1);
    }

    cycle_timer_init();

#if 0 && defined(DEBUG)
    BlobsortTest();
    RandTest(1);
#endif

    set_default_tests(true);

#if defined(HAVE_32BIT_PLATFORM)
    const char * defaulthash = "wyhash-32";
#else
    const char * defaulthash = "xxh3-64";
#endif
    const char * hashToTest  = defaulthash;

    if (argc < 2) {
        printf("No test hash given on command line, testing %s.\n", hashToTest);
        usage();
    }

    flags_t flags = FLAG_REPORT_PROGRESS;
    for (int argnb = 1; argnb < argc; argnb++) {
        const char * const arg = argv[argnb];
        if (strncmp(arg, "--", 2) == 0) {
            // This is a command
            if (strcmp(arg, "--help") == 0) {
                usage();
                exit(0);
            }
            if (strcmp(arg, "--list") == 0) {
                listHashes(false);
                exit(0);
            }
            if (strcmp(arg, "--listnames") == 0) {
                listHashes(true);
                exit(0);
            }
            if (strcmp(arg, "--tests") == 0) {
                printf("Valid tests:\n");
                for (size_t i = 0; i < sizeof(g_testopts) / sizeof(TestOpts); i++) {
                    printf("  %s\n", g_testopts[i].name);
                }
                exit(0);
            }
            if (strcmp(arg, "--version") == 0) {
                printf("SMHasher3 %s\n", VERSION);
                exit(0);
            }
            if (strcmp(arg, "--verbose") == 0) {
                flags |= FLAG_REPORT_VERBOSE;
                flags |= FLAG_REPORT_MORESTATS;
                flags |= FLAG_REPORT_DIAGRAMS;
                continue;
            }
            if (strcmp(arg, "--force-summary") == 0) {
                g_forceSummary = true;
                continue;
            }
            // VCodes allow easy comparison of test results and hash inputs
            // and outputs across SMHasher3 runs, hashes (of the same width),
            // and systems.
            if (strcmp(arg, "--vcode") == 0) {
                g_doVCode = 1;
                VCODE_INIT();
                continue;
            }
            if (strcmp(arg, "--vcode-all") == 0) {
                g_doVCode = 1;
                VCODE_INIT();
                g_dumpAllVCodes = true;
                continue;
            }
            if (strcmp(arg, "--exit-on-failure") == 0) {
                g_exitOnFailure = true;
                continue;
            }
            if (strcmp(arg, "--noexit-on-failure") == 0) {
                g_exitOnFailure = false;
                continue;
            }
            if (strcmp(arg, "--exit-code-on-failure") == 0) {
                g_exitCodeResult = true;
                continue;
            }
            if (strcmp(arg, "--noexit-code-on-failure") == 0) {
                g_exitCodeResult = false;
                continue;
            }
            if (strcmp(arg, "--time-tests") == 0) {
                g_showTestTimes = true;
                continue;
            }
            if (strcmp(arg, "--notime-tests") == 0) {
                g_showTestTimes = false;
                continue;
            }
            if (strcmp(arg, "--extra") == 0) {
                g_testExtra = true;
                continue;
            }
            if (strncmp(arg, "--endian=", 9) == 0) {
                g_hashEndian = parse_endian(&arg[9]);
                continue;
            }
            if (strncmp(arg, "--seed=", 7) == 0) {
                errno = 0;
                char *   endptr;
                uint64_t seed = strtol(&arg[7], &endptr, 0);
                if ((errno != 0) || (arg[7] == '\0') || (*endptr != '\0')) {
                    printf("Error parsing global seed value \"%s\"\n", &arg[7]);
                    exit(1);
                }
                g_seed = seed;
                continue;
            }
            if (strncmp(arg, "--randseed=", 11) == 0) {
                errno = 0;
                char *   endptr;
                uint64_t seed = strtol(&arg[11], &endptr, 0);
                if ((errno != 0) || (arg[11] == '\0') || (*endptr != '\0')) {
                    printf("Error parsing RNG seed value \"%s\"\n", &arg[11]);
                    exit(1);
                }
                Rand::GLOBAL_SEED = seed;
                continue;
            }
            if (strncmp(arg, "--ncpu=", 7) == 0) {
#if defined(HAVE_THREADS)
                errno = 0;
                char *   endptr;
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
            if (strncmp(arg, "--test=", 6) == 0) {
                // If a list of tests is given, only test those
                g_testAll = false;
                set_default_tests(false);
                parse_tests(&arg[7], true);
                continue;
            }
            if (strncmp(arg, "--notest=", 8) == 0) {
                parse_tests(&arg[9], false);
                continue;
            }
            if (strcmp(arg, "--EstimateNbCollisions") == 0) {
                ReportCollisionEstimates();
                exit(0);
            }
            if (strcmp(arg, "--InternalTests") == 0) {
                TestAESWrappers();
                BlobsortTest();
                RandTest(5);
                exit(0);
            }
            if (strcmp(arg, "--SortBench") == 0) {
                BlobsortBenchmark();
                exit(0);
            }
            if (strcmp(arg, "--RandBench") == 0) {
                RandTest(1);
                RandBenchmark();
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

    bool   result    = true;
    size_t timeBegin = g_prevtime = monotonic_clock();

    if (g_testVerifyAll) {
        HashSelfTestAll(flags);
    } else if (g_testSanityAll) {
        HashSanityTestAll(flags);
    } else if (g_testSpeedAll) {
        HashSpeedTestAll(flags);
    } else {
        result = testHash(hashToTest, flags);
    }

    size_t timeEnd = monotonic_clock();

    uint32_t vcode = VCODE_FINALIZE();

    FILE * outfile = g_testAll ? stdout : stderr;

    if (g_doVCode) {
        fprintf(outfile, "Input vcode 0x%08x, Output vcode 0x%08x, Result vcode 0x%08x\n",
                g_inputVCode, g_outputVCode, g_resultVCode);
    }

    fprintf(outfile, "Verification value is 0x%08x - Testing took %f seconds\n\n",
            vcode, (double)(timeEnd - timeBegin) / (double)NSEC_PER_SEC);

    return (!result && g_exitCodeResult) ? 99 : 0;
}
