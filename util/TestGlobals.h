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
 */

//-----------------------------------------------------------------------------
// Basic infrastructure that basically all tests use
#include <map>
#include <set>
#include <vector>
#include <functional>
#include <cassert>
#include "Blob.h"

// A type for indexing into lists of hashes. Using 32-bits saves time and
// memory but limits tests to 2^32 hashes. This should be fine.
typedef uint32_t hidx_t;

// A type for a function that displays the given key and seed.
typedef std::function<void (hidx_t)> KeyFn;

//-----------------------------------------------------------------------------
// Global variables from main.cpp

// To be able to sample different statistics sets from the same hash,
// a seed can be supplied which will be used in each test where a seed
// is not explicitly part of that test.
extern seed_t g_seed;

// What each test suite prints upon failure
extern const char * g_failstr;

// A string with 128 spaces, used for aligning text outputs
extern const char * g_manyspaces;

// By rights, the HAVE_HASHINFO #define shouldn't exist, but C++11
// doesn't allow forward declaration of class enums (enum classes,
// yes, but not class enums) for no good reason, and we definitely
// don't want to force files which use TestGlobals.h to include
// Hashinfo.h. So this is the least-bad solution. :-{
#if defined(HAVE_HASHINFO)
// The user can select which endian-ness of the hash implementation to test
extern HashInfo::endianness g_hashEndian;
#endif

//-----------------------------------------------------------------------------
// Verbosity flags

typedef uint32_t flags_t;

#define REPORT(flagname, var) (!!(var & FLAG_REPORT_ ## flagname))

#define FLAG_REPORT_QUIET        (1 << 0)
#define FLAG_REPORT_VERBOSE      (1 << 1)
#define FLAG_REPORT_DIAGRAMS     (1 << 2)
#define FLAG_REPORT_MORESTATS    (1 << 3)
#define FLAG_REPORT_PROGRESS     (1 << 4)

//-----------------------------------------------------------------------------
// Recording test results for final summary printout

#define COUNT_MAX_PVALUE 24
extern uint32_t g_log2pValueCounts[COUNT_MAX_PVALUE + 2];

static inline void recordLog2PValue( uint32_t log_pvalue ) {
    if (log_pvalue <= COUNT_MAX_PVALUE) {
        g_log2pValueCounts[log_pvalue]++;
    } else {
        g_log2pValueCounts[COUNT_MAX_PVALUE + 1]++;
    }
}

extern uint32_t g_testPass, g_testFail;
extern std::vector<std::pair<const char *, char *>> g_testFailures;
extern uint64_t g_prevtime;
extern bool     g_showTestTimes;

static inline void recordTestResult( bool pass, const char * suitename, const char * testname ) {
    if (testname != NULL) {
        // Skip any leading spaces in the testname
        testname += strspn(testname, " ");
    }

    if (g_showTestTimes) {
        uint64_t curtime = monotonic_clock();
        if (testname != NULL) {
            printf("Elapsed: %f seconds\t[%s\t%s]\n\n", (double)(curtime - g_prevtime) / (double)NSEC_PER_SEC,
                    suitename, testname);
        } else {
            printf("Elapsed: %f seconds\t[%s]\n\n", (double)(curtime - g_prevtime) / (double)NSEC_PER_SEC, suitename);
        }
        g_prevtime = curtime;
    }

    if (pass) {
        g_testPass++;
    } else {
        g_testFail++;

        char * ntestname = NULL;
        if (testname != NULL) {
            ntestname = strdup(testname);
            if (!ntestname) {
                printf("OOM\n");
                exit(1);
            }
        }
        g_testFailures.push_back(std::pair<const char *, char *>(suitename, ntestname));
    }
}

static inline void recordTestResult( bool pass, const char * suitename, uint64_t testnum ) {
    const uint64_t maxlen = sizeof("18446744073709551615"); // UINT64_MAX
    char           testname[maxlen];

    snprintf(testname, maxlen, "%" PRIu64, testnum);
    recordTestResult(pass, suitename, testname);
}

//----------------------------------------------------------------------------
// Helper for printing out the right number of progress dots

static void progressdots( int cur, int min, int max, int totaldots ) {
    // cur goes from [min, max]. When cur is max, totaldots should
    // have been printed. Print out enough dots, assuming either we
    // were called for cur-1, or that we are being called for the
    // first time with cur==min.
    assert(totaldots > 0);
    assert(min < max    );
    assert(cur >= min   );
    assert(cur <= max   );

    int count = 0;
    int span  = max - min + 1;
    if (span > totaldots) {
        // Possibly zero dots per call.
        // Always print out one dot the first time through.
        // Treat the range as one smaller, to spread out that first
        // dot's "stolen time slice".
        if (cur == min) {
            count = 1;
        } else {
            totaldots--;
            min++;
            span--;
        }
    }
    if (count == 0) {
        int expect = (cur - min + 1) * totaldots / span;
        int sofar  = (cur - min    ) * totaldots / span;
        count = expect - sofar;
    }

    for (int i = 0; i < count; i++) {
        printf(".");
    }
}

//----------------------------------------------------------------------------
// Helper for iterating through all possible ways of arranging N bits in an
// integer. This is basically the formula for computing the next
// lexicographic bit pattern, from "Bit Twiddling Hacks".

static inline uint64_t nextlex( const uint64_t in, const size_t bits ) {
    uint64_t tmp = (in | (in - 1)) + 1;
    uint64_t out = tmp | ((((tmp & -tmp) / (in & -in)) >> 1) - 1);

    assert(bits <= 64);
    if (bits == 64) {
        return (out == ~UINT64_C(0)) ? 0 : out;
    }
    return ((out >> bits) != 0) ? 0 : out;
}
