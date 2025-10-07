/*
 * SMHasher3
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (C) 2023       jason
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
 *     Copyright (c) 2019-2020 Reini Urban
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
#include "Hashinfo.h"
#include "TestGlobals.h"
#include "Stats.h" // For FilterOutliers, CalcMean, CalcStdv
#include "Random.h"
#include "Wordlist.h"

#include "HashMapTest.h"

#include <string>
#include <unordered_map>
#undef prefetch
#include <parallel_hashmap/phmap.h>

//-----------------------------------------------------------------------------
// This is functionally a speed test, and so will not inform VCodes,
// since that would affect results too much.

//-----------------------------------------------------------------------------
using namespace std;

typedef std::unordered_map<std::string, int,
        std::function<size_t (const std::string & key)>> std_hashmap;
typedef phmap::flat_hash_map<std::string, int,
        std::function<size_t (const std::string & key)>> fast_hashmap;

//-----------------------------------------------------------------------------

static double HashMapSpeedTest( const HashInfo * hinfo, std::vector<std::string> words,
        const int trials, const flags_t flags ) {
    Rand r( 358512 );

    unused(flags);

    const HashFn hash = hinfo->hashFn(g_hashEndian);
    const seed_t seed = hinfo->Seed(g_seed ^ r.rand_u64());

    std_hashmap hashmap( words.size(), [=]( const std::string & key ) {
            // 256 needed for hasshe2, but only size_t used
            static char out[256] = { 0 };
            hash(key.c_str(), key.length(), seed, &out);
            return *(size_t *)out;
        } );
    fast_hashmap phashmap( words.size(), [=]( const std::string & key ) {
            // 256 for hasshe2, but stripped to 64/32
            static char out[256] = { 0 };
            hash(key.c_str(), key.length(), seed, &out);
            return *(size_t *)out;
        } );

    std::vector<std::string>::iterator it;
    std::vector<double> times;
    double t1;

    printf("std::unordered_map\n"      );
    printf("Init std HashMapTest:     ");

    times.reserve(trials);
    if (0 /*need_minlen64_align16(pfhash)*/) {
        for (it = words.begin(); it != words.end(); it++) {
            // requires min len 64, and 16byte key alignment
            (*it).resize(64);
        }
    }
    {
        // hash inserts plus 1% deletes
        volatile int64_t begin, end;
        int i = 0;
        begin = cycle_timer_start();
        for (it = words.begin(); it != words.end(); it++, i++) {
            std::string line = *it;
            hashmap[line] = 1;
            if (i % 100 == 0) {
                hashmap.erase(line);
            }
        }
        end = cycle_timer_end();
        t1  = (double)(end - begin) / (double)words.size();
    }

    printf("%0.3f cycles/op (%zu inserts, 1%% deletions)\n", t1, words.size());
    printf("Running std HashMapTest:  ");

    for (int itrial = 0; itrial < trials; itrial++) { // hash query
        volatile int64_t begin, end;
        int    i = 0, found = 0;
        double t;
        begin = cycle_timer_start();
        for (it = words.begin(); it != words.end(); it++, i++) {
            std::string line = *it;
            if (hashmap[line]) {
                found++;
            }
        }
        end = cycle_timer_end();
        t   = (double)(end - begin) / (double)words.size();
        if ((found > 0) && (t > 0)) { times.push_back(t); }
    }
    hashmap.clear();

    FilterOutliers(times);
    double mean = CalcMean(times);
    double stdv = CalcStdv(times);
    printf("%0.3f cycles/op", mean);
    printf(" (%0.1f stdv)\n", stdv);

    times.clear();

    printf("\ngreg7mdp/parallel-hashmap\n");
    printf("Init fast HashMapTest:    "   );

    times.reserve(trials);
    { // hash inserts and 1% deletes
        volatile int64_t begin, end;
        int i = 0;
        begin = cycle_timer_start();
        for (it = words.begin(); it != words.end(); it++, i++) {
            std::string line = *it;
            phashmap[line] = 1;
            if (i % 100 == 0) {
                phashmap.erase(line);
            }
        }
        end = cycle_timer_end();
        t1  = (double)(end - begin) / (double)words.size();
    }

    printf("%0.3f cycles/op (%zu inserts, 1%% deletions)\n", t1, words.size());
    printf("Running fast HashMapTest: ");

    for (int itrial = 0; itrial < trials; itrial++) { // hash query
        volatile int64_t begin, end;
        int    i = 0, found = 0;
        double t;
        begin = cycle_timer_start();
        for (it = words.begin(); it != words.end(); it++, i++) {
            std::string line = *it;
            if (phashmap[line]) {
                found++;
            }
        }
        end = cycle_timer_end();
        t   = (double)(end - begin) / (double)words.size();
        if ((found > 0) && (t > 0)) { times.push_back(t); }
    }
    phashmap.clear();

    FilterOutliers(times);
    double mean1 = CalcMean(times);
    double stdv1 = CalcStdv(times);
    printf("%0.3f cycles/op (%0.1f stdv)", mean1, stdv1);

    return mean;
}

//-----------------------------------------------------------------------------

static bool HashMapImpl( const HashInfo * hinfo, std::vector<std::string> words,
        const int trials, const flags_t flags ) {
    try {
        HashMapSpeedTest(hinfo, words, trials, flags);
    } catch (...) {
        printf(" aborted !!!!\n");
    }
    return true;
}

//-----------------------------------------------------------------------------

bool HashMapTest( const HashInfo * hinfo, bool extra, flags_t flags ) {
    const int trials = (hinfo->isVerySlow() || !extra) ? 5 : 50;
    bool      result = true;

    printf("[[[ 'Hashmap' Speed Tests ]]]\n\n");

    if (hinfo->isMock()) {
        printf("Skipping Hashmap test; it is designed for true hashes\n\n");
        return result;
    }

    if (hinfo->isVerySlow()) {
        printf("Skipping Hashmap test for very slow hashes\n\n");
        return result;
    }

    std::vector<std::string> words = GetWordlist(CASE_ALL, REPORT(VERBOSE, flags));
    if (!words.size()) {
        printf("WARNING: Hashmap initialization failed! Skipping Hashmap test.\n");
        return result;
    }

    result &= HashMapImpl(hinfo, words, trials, flags);

    printf("\n%s\n", result ? "" : g_failstr);

    return result;
}
