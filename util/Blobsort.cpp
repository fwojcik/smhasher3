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
#include "Blob.h"
#include "Blobsort.h"
#include "Instantiate.h"
#include "Random.h"

#include <vector>
#include <type_traits>

//-----------------------------------------------------------------------------
// Blob sorting routine unit tests

static const uint32_t SORT_TESTS = 19;
static const uint32_t TEST_SIZE  = 100000;

template <typename blobtype>
static void blobfill( std::vector<blobtype> & blobs, int testnum ) {
    if (testnum >= SORT_TESTS) { return; }

    Rand r( testnum + 0xb840a149 );

    switch (testnum) {
    case  0: // Consecutive numbers
    case  1: // Consecutive numbers, sorted almost
    case  2: // Consecutive numbers, scrambled
    {
        for (uint32_t n = 0; n < TEST_SIZE; n++) {
            blobs[n] = n;
        }
        break;
    }
    case  3: // Consecutive numbers, backwards
    {
        for (uint32_t n = 0; n < TEST_SIZE; n++) {
            blobs[n] = TEST_SIZE - 1 - n;
        }
        break;
    }
    case  4: // Random numbers
    case  5: // Random numbers, sorted
    case  6: // Random numbers, sorted almost
    case  7: // Random numbers, sorted backwards
    case 10: // All zero bytes in LSB position
    case 11: // All zero bytes in MSB position
    case 12: // All zero bytes in LSB+1 position
    case 13: // All zero bytes in MSB-1 position
    case 14: // Random numbers, except each position has some missing bytes
    {
        for (uint32_t n = 0; n < TEST_SIZE; n++) {
            r.rand_p(&blobs[n], sizeof(blobtype));
        }
        break;
    }
    case  8: // Many duplicates
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
    case  9: // All duplicates
    {
        r.rand_p(&blobs[0], sizeof(blobtype));
        for (uint32_t i = 1; i < TEST_SIZE; i++) {
            blobs[i] = blobs[0];
        }
        break;
    }
    case 15: // All zeroes
    {
        memset(&blobs[0], 0, TEST_SIZE * sizeof(blobtype));
        break;
    }
    case 16: // All ones
    {
        for (uint32_t i = 0; i < TEST_SIZE; i++) {
            blobs[i] = 1;
        }
        break;
    }
    case 17: // All Fs
    {
        memset(&blobs[0], 0xFF, TEST_SIZE * sizeof(blobtype));
        break;
    }
    case 18: // All 0xAAA and 0x555
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
    case  5:
    case  6:
    {
        std::sort(blobs.begin(), blobs.end());
        if (testnum == 5) { break; }
    }
    // 6 is fallthrough to...
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
    {
        for (uint32_t n = TEST_SIZE - 1; n > 0; n--) {
            std::swap(blobs[n], blobs[r.rand_range(n + 1)]);
        }
        break;
    }
    // Zero out bytes in some position
    case 10:
    case 11:
    case 12:
    case 13:
    {
        uint32_t offset = (testnum == 10) ? 0 :
                                            ((testnum == 11) ? (sizeof(blobtype) - 1) :
                                                               ((testnum == 12) ? 1 : (sizeof(blobtype) - 2)));
        for (uint32_t n = 0; n < TEST_SIZE; n++) {
            blobs[n][offset] = 0;
        }
        break;
    }
    // Exclude a byte value from each position
    case 14:
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

template <typename blobtype>
static bool test_blobsort_type( void ) {
    bool passed = true;
    std::vector<blobtype> blobs( TEST_SIZE );

    for (int i = 0; i < SORT_TESTS; i++) {
        blobfill(blobs, i);
        blobsort(blobs.begin(), blobs.end());
        passed &= blobverify(blobs);
        // printf("After test %d: %s\n", i, passed ? "ok" : "no");
    }

    return passed;
}

//-----------------------------------------------------------------------------
// Instantiator for test_blobsort_type()
//
// All this does is call test_blobsort_type() for every type in
// HASHTYPELIST, then ANDs together all the boolean results.
//
// This is less magic than it looks. "int" is used as a sentinel to
// mark the end of the list of types. The second template function
// basically pops off the first type in the variadic pack, evaluates
// it, and "passes the rest on". It is disabled if the first type is
// an integral type. That only happens when "int" is the last type in
// the list, which means the first template function gets called,
// which ignores that type and just passes its input through.

template <typename T>
static bool AND( bool in ) {
    return in;
}

template <typename T, typename... More>
typename std::enable_if<!std::is_integral<T>::value, bool>::type
static AND( bool in ) {
    return test_blobsort_type<T>() && AND<More...>(in);
}

// If the global variable isn't referenced anywhere, then this
// constructor code isn't run, as the linker will exclude this whole
// file. Adding a printout of blobsort_test_result somewhere will
// cause it to run during startup, which takes a few seconds.
// So this is only referenced in DEBUG mode.
extern bool blobsort_test_result;
bool        blobsort_test_result = AND<HASHTYPELIST, int>(true);
