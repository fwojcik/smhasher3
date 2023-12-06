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
#include "Hashinfo.h"
#include "TestGlobals.h"
#include "Random.h"
#include "Reporting.h"
#include "Histogram.h"
#include "Instantiate.h"
#include "VCode.h"

#include "BitIndependenceTest.h"

#include <math.h>

#if defined(HAVE_THREADS)
  #include <atomic>
  #define FETCH_ADD(v, n) v.fetch_add(n)
typedef std::atomic<int> a_int;
#else
  #define FETCH_ADD(v, n) ((v += n) - n)
typedef int a_int;
#endif

//-----------------------------------------------------------------------------
// Seed BIC test
//
// See BitIndependenceTest.cpp for many comments on how the
// math/recordkeeping here works.

template <typename hashtype>
static void SeedBicTestBatch( const HashInfo * hinfo, std::vector<uint32_t> & popcount0,
        std::vector<uint32_t> & andcount0, size_t keybytes, const uint8_t * keys,
        size_t seedbytes, const uint8_t * seeds, a_int & irepp, size_t reps) {
    const HashFn hash         = hinfo->hashFn(g_hashEndian);
    const size_t seedbits     = hinfo->is32BitSeed() ? 32 : 64;
    const size_t hashbits     = hashtype::bitlen;
    const size_t hashbitpairs = hashbits / 2 * hashbits;

    hashtype h1, h2;
    size_t   irep;
    size_t   iseed;
    uint64_t baseseed = 0;

    while ((irep = irepp++) < reps) {
        progressdots(irep, 0, reps - 1, 12);

        const uint8_t * key = &keys[keybytes * irep];

        memcpy(&baseseed, &seeds[seedbytes * irep], seedbytes);
        iseed = hinfo->getFixedSeed((seed_t)baseseed);

        seed_t hseed = hinfo->Seed(iseed, HashInfo::SEED_FORCED, 1);
        hash(key, keybytes, hseed, &h1);

        uint32_t * pop_cursor = &popcount0[0];

        for (size_t seedbit = 0; seedbit < seedbits; seedbit++) {
            // The andcount array needs 1 element as a buffer due to how
            // HistogramHashBits accesses memory prior to the cursor.
            uint32_t * and_cursor = &andcount0[seedbit * hashbitpairs + 1];

            hseed = hinfo->Seed(iseed ^ UINT64_C(1) << seedbit, HashInfo::SEED_FORCED, 1);
            hash(key, keybytes, hseed, &h2);

            h2 = h1 ^ h2;

            // First count how often each output bit changes
            pop_cursor = HistogramHashBits(h2, pop_cursor);

            // Then count how often each pair of output bits changed together
            for (size_t out1 = 0; out1 < hashbits - 1; out1++) {
                if (h2.getbit(out1) == 0) {
                    and_cursor += hashbits - 1 - out1;
                    continue;
                }
                and_cursor = HistogramHashBits(h2, and_cursor, out1 + 1);
            }
        }
    }
}

template <typename hashtype>
static bool SeedBicTestImpl( const HashInfo * hinfo, const size_t keybytes, const size_t reps, const flags_t flags ) {
    const size_t seedbits     = hinfo->is32BitSeed() ? 32 : 64;
    const size_t seedbytes    = seedbits / 8;
    const size_t hashbits     = hashtype::bitlen;
    const size_t hashbitpairs = hashbits / 2 * hashbits;

    printf("Testing %4zd-byte keys, %7zd reps", keybytes, reps);

    Rand r( {209036, keybytes} );

    RandSeq rsK = r.get_seq(SEQ_DIST_1, keybytes);

    std::vector<uint8_t> keys( reps * keybytes );
    rsK.write(&keys[0], 0, reps);
    addVCodeInput(&keys[0], reps * keybytes);

    enum RandSeqType seqtype = reps > r.seq_maxelem(SEQ_DIST_3, seedbytes) ? SEQ_DIST_2 : SEQ_DIST_3;
    RandSeq rsS = r.get_seq(seqtype, seedbytes);

    std::vector<uint8_t> seeds( reps * seedbytes );
    rsS.write(&seeds[0], 0, reps);
    addVCodeInput(&seeds[0], reps * seedbytes);

    a_int irep( 0 );

    std::vector<std::vector<uint32_t>> popcounts( g_NCPU );
    std::vector<std::vector<uint32_t>> andcounts( g_NCPU );
    for (unsigned i = 0; i < g_NCPU; i++) {
        // The andcount array needs 1 element as a buffer due to how
        // HistogramHashBits accesses memory prior to the cursor.
        popcounts[i].resize(seedbits * hashbits);
        andcounts[i].resize(seedbits * hashbitpairs + 1);
    }

    if (g_NCPU == 1) {
        SeedBicTestBatch<hashtype>(hinfo, popcounts[0], andcounts[0],
                keybytes, &keys[0], seedbytes, &seeds[0], irep, reps);
    } else {
#if defined(HAVE_THREADS)
        std::vector<std::thread> t(g_NCPU);
        for (unsigned i = 0; i < g_NCPU; i++) {
            t[i] = std::thread {
                SeedBicTestBatch<hashtype>, hinfo, std::ref(popcounts[i]), std::ref(andcounts[i]),
                keybytes, &keys[0], seedbytes, &seeds[0], std::ref(irep), reps
            };
        }
        for (unsigned i = 0; i < g_NCPU; i++) {
            t[i].join();
        }
        for (unsigned i = 1; i < g_NCPU; i++) {
            for (size_t b = 0; b < seedbits * hashbits; b++) {
                popcounts[0][b] += popcounts[i][b];
            }
            for (size_t b = 1; b < seedbits * hashbitpairs + 1; b++) {
                andcounts[0][b] += andcounts[i][b];
            }
        }
#endif
    }

    //----------

    bool result = true;

    result &= ReportChiSqIndep(&popcounts[0][0], &andcounts[0][1], seedbits, hashbits, reps, flags);

    recordTestResult(result, "SeedBIC", keybytes);

    return result;
}

//-----------------------------------------------------------------------------

template <typename hashtype>
bool SeedBicTest( const HashInfo * hinfo, bool extra, flags_t flags ) {
    size_t reps   = (hinfo->bits > 128 || hinfo->isVerySlow()) ? 100000 : 600000;
    bool   result = true;

    printf("[[[ Seed 'Bit Independence Criteria' Tests ]]]\n\n");

    // std::set<size_t> keylens = { 3, 4, 5, 6, 7, 8, 32, 128, 1024 };
    // std::set<size_t> keylens = { 3, 4, 6, 7, 8, 11, 15, 28, 52, 256, 1024 };
    std::set<size_t> keylens = { 3, 8, 11, 15 };
    if (extra && !hinfo->isSlow()) {
        keylens.insert({ 4, 6, 28, 52, 1024 });
    }
    for (const auto keylen: keylens) {
        if (keylen <= 16) {
            result &= SeedBicTestImpl<hashtype>(hinfo, keylen, reps * 2, flags);
        } else {
            result &= SeedBicTestImpl<hashtype>(hinfo, keylen, reps, flags);
        }
    }

    printf("\n%s\n", result ? "" : g_failstr);

    return result;
}

INSTANTIATE(SeedBicTest, HASHTYPELIST);
