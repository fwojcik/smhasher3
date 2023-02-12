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
#include "Platform.h"
#include "Timing.h"
#include "Blob.h"
#include "Blobsort.h"
#include "Instantiate.h"
#include "Random.h"

#include <vector>
#include <type_traits>

//-----------------------------------------------------------------------------
// Blob sorting routine unit tests

static const uint32_t SORT_TESTS = 20;
static const char * teststr[SORT_TESTS] = {
    "Consecutive numbers, sorted",
    "Consecutive numbers, almost sorted",
    "Consecutive numbers, scrambled",
    "Consecutive numbers, reverse sorted",
    "Random numbers, sorted",
    "Random numbers, almost sorted",
    "Random numbers, scrambled",
    "Random numbers, reverse sorted",
    "Random numbers, many duplicates",
    "Random numbers, many duplicates, scrambled",
    "Random number,  all duplicates",
    "Random numbers, all zero in LSB",
    "Random numbers, all zero in MSB",
    "Random numbers, all zero in LSB+1",
    "Random numbers, all zero in MSB+1",
    "Random numbers, each byte has some missing values",
    "All zeroes",
    "All ones",
    "All set bits",
    "All 0xAAAA.... and 0x5555.... values",
};

template <typename blobtype, uint32_t TEST_SIZE>
static void blobfill( std::vector<blobtype> & blobs, int testnum, int iternum ) {
    if (testnum >= SORT_TESTS) { return; }

    Rand r( testnum + 0xb840a149 * (iternum + 1) );

    switch (testnum) {
    case  0: // Consecutive numbers, sorted
    case  1: // Consecutive numbers, sorted almost
    case  2: // Consecutive numbers, scrambled
    {
        for (uint32_t n = 0; n < TEST_SIZE; n++) {
            blobs[n] = n;
        }
        break;
    }
    case  3: // Consecutive numbers, sorted backwards
    {
        for (uint32_t n = 0; n < TEST_SIZE; n++) {
            blobs[n] = TEST_SIZE - 1 - n;
        }
        break;
    }
    case  4: // Random numbers, sorted
    case  5: // Random numbers, sorted almost
    case  6: // Random numbers, scrambled
    case  7: // Random numbers, sorted backwards
    case 11: // All zero bytes in LSB position
    case 12: // All zero bytes in MSB position
    case 13: // All zero bytes in LSB+1 position
    case 14: // All zero bytes in MSB-1 position
    case 15: // Random numbers, except each position has some missing bytes
    {
        r.rand_p(&blobs[0], sizeof(blobtype) * TEST_SIZE);
        break;
    }
    case  8: // Many duplicates
    case  9: // Many duplicates, scrambled
    {
        uint32_t x = 0;
        do {
            r.rand_p(&blobs[x], sizeof(blobtype));
            uint32_t count = 1 + r.rand_range(TEST_SIZE - 1 - x);
            for (uint32_t i = 1; i < count; i++) {
                blobs[x + i] = blobs[x];
            }
            x += count;
        } while (x < TEST_SIZE);
        break;
    }
    case 10: // All duplicates
    {
        r.rand_p(&blobs[0], sizeof(blobtype));
        for (uint32_t i = 1; i < TEST_SIZE; i++) {
            blobs[i] = blobs[0];
        }
        break;
    }
    case 16: // All zeroes
    {
        memset(&blobs[0], 0, TEST_SIZE * sizeof(blobtype));
        break;
    }
    case 17: // All ones
    {
        for (uint32_t i = 0; i < TEST_SIZE; i++) {
            blobs[i] = 1;
        }
        break;
    }
    case 18: // All Fs
    {
        memset(&blobs[0], 0xFF, TEST_SIZE * sizeof(blobtype));
        break;
    }
    case 19: // All 0xAAA and 0x555
    {
        uint32_t i = 0;
        do {
            uint64_t rndnum = r.rand_u64();
            for (int j = 0; j < 64; j++) {
                if (rndnum & 1) {
                    memset(&blobs[i], 0xAA, sizeof(blobtype));
                } else {
                    memset(&blobs[i], 0x55, sizeof(blobtype));
                }
                i++;
                rndnum >>= 1;
                if (i == TEST_SIZE) { break; }
            }
        } while (i < TEST_SIZE);
        break;
    }
    default: unreachable(); break;
    }

    switch (testnum) {
    // Sorted backwards
    case  7:
    {
        std::sort(blobs.rbegin(), blobs.rend());
        break;
    }
    // Sorted
    case  4:
    case  5:
    {
        std::sort(blobs.begin(), blobs.end());
        if (testnum == 4) { break; }
    }
    // 5 is fallthrough to...
    // "Almost sorted" == mix up a few entries
    case  1:
    {
        for (uint32_t n = 0; n < TEST_SIZE / 1000; n++) {
            std::swap(blobs[r.rand_range(TEST_SIZE)], blobs[r.rand_range(TEST_SIZE)]);
        }
        break;
    }
    // "Scrambled" == shuffle all the entries
    case  2:
    case  9:
    {
        for (uint32_t n = TEST_SIZE - 1; n > 0; n--) {
            std::swap(blobs[n], blobs[r.rand_range(n + 1)]);
        }
        break;
    }
    // Zero out bytes in some position
    case 11:
    case 12:
    case 13:
    case 14:
    {
        uint32_t offset = (testnum == 11) ? 0 :
                                            ((testnum == 12) ? (sizeof(blobtype) - 1) :
                                                               ((testnum == 13) ? 1 : (sizeof(blobtype) - 2)));
        for (uint32_t n = 0; n < TEST_SIZE; n++) {
            blobs[n][offset] = 0;
        }
        break;
    }
    // Exclude a byte value from each position
    case 15:
    {
        uint8_t excludes[sizeof(blobtype)];
        r.rand_p(excludes, sizeof(excludes));
        for (uint32_t n = 0; n < TEST_SIZE; n++) {
            for (uint32_t i = 0; i < sizeof(blobtype); i++) {
                if (blobs[n][i] == excludes[i]) {
                    blobs[n][i] = ~excludes[i];
                }
            }
        }
        break;
    }
    default: break;
    }
}

template <typename blobtype>
static bool blobverify( std::vector<blobtype> & blobs ) {
    bool passed     = true;

    const size_t sz = blobs.size();

    for (size_t nb = 1; nb < sz; nb++) {
        if (!((blobs[nb - 1] < blobs[nb]) ||
                (blobs[nb - 1] == blobs[nb]))) {
            passed = false;
        }
        if (blobs[nb] < blobs[nb - 1]) {
            passed = false;
        }
    }

    return passed;
}

template <uint32_t TEST_SIZE, uint32_t TEST_ITER, typename blobtype>
bool test_blobsort_type( void ) {
    bool passed = true;
    std::vector<blobtype> blobs( TEST_SIZE );
    size_t timetotal = 0;
    size_t timesum;
    std::vector<int> testnums;

    if (TEST_ITER > 1) {
        testnums = { 4, 6, 8, 9, 10, 15, 16, 19 };
    } else {
        for (int i = 0; i < SORT_TESTS; i++) {
            testnums.push_back(i);
        }
    }

    for (int i: testnums) {
        timesum = 0;
        for (int j = 0; j < TEST_ITER; j++) {
            blobfill<blobtype, TEST_SIZE>(blobs, i, j);
            size_t timeBegin = monotonic_clock();
            blobsort(blobs.begin(), blobs.end());
            size_t timeEnd   = monotonic_clock();
            timesum += timeEnd - timeBegin;
            passed  &= blobverify(blobs);
        }
        if (TEST_ITER > 1) {
            timetotal += timesum;
            printf("%3lu bits, test %2d [%-50s]\t\t %5.2f s\n", sizeof(blobtype) * 8,
                    i, teststr[i], (double)timesum / (double)NSEC_PER_SEC);
        }
        // printf("After test %d: %s\n", i, passed ? "ok" : "no");
    }
    if (TEST_ITER > 1) {
        printf("%3lu bits, %-60s\t\t%6.2f s\n\n", sizeof(blobtype) * 8, "SUM TOTAL",
                (double)timetotal / (double)NSEC_PER_SEC);
    }

    return passed;
}

//-----------------------------------------------------------------------------
// Instantiator for test_blobsort_type()
//
// All this does is create a std::vector<> full of function pointers to the various
// instantiations of test_blobsort_type<>. Then SortBenchmark() can just iterate over
// those function pointers, calling each one in turn.

typedef bool (* SortTestFn)( void );

template <uint32_t TEST_SIZE, uint32_t TEST_ITER, typename... T>
std::vector<SortTestFn> PACKEXPANDER() {
    return { &test_blobsort_type<TEST_SIZE, TEST_ITER, T>... };
}

auto SortTestFns  = PACKEXPANDER<  100000,  1, HASHTYPELIST>();
auto SortBenchFns = PACKEXPANDER<10000000, 10, HASHTYPELIST>();

void BlobsortTest( void ) {
    bool result = true;

    for (SortTestFn testFn: SortTestFns) {
        result &= testFn();
    }
    if (!result) {
        printf("Blobsort self-test failed! Cannot continue\n");
        exit(1);
    }
    printf("Blobsort self-test passed.\n");
    return;
}

void BlobsortBenchmark( void ) {
    bool result = true;

    for (SortTestFn testFn: SortBenchFns) {
        result &= testFn();
    }
    if (!result) {
        printf("Blobsort self-test failed! Cannot continue\n");
        exit(1);
    }
    return;
}
