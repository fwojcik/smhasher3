/*
 * Unit tests for SMHasher3's Mathmult routines
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
#include "Hashlib.h"

#include "Mathmult.h"

using namespace MathMult;

template <typename T>
static void fail( const char * test, int idx, const T * expected, std::initializer_list<T> actual ) {
    if (idx >= 0) {
        printf("Test %s #%d failed!\n\tGot     :", test, idx);
    } else {
        printf("Test %s failed!\n\tGot     :", test);
    }
    int count = 0;
    // The casts are needed in the printf()s so that clang doesn't complain about the
    // if() branches that aren't taken. If we had C++17's constexpr if then this
    // wouldn't be needed.
    for (auto val: actual) {
        if (sizeof(T) == 4) {
            printf(" %08x", (uint32_t)val);
        } else {
            printf(" %016" PRIx64, (uint64_t)val);
        }
        count++;
    }
    printf("\n\tExpected:");
    for (int i = 0; i < count; i++) {
        if (sizeof(T) == 4) {
            printf(" %08x", (uint32_t)expected[i]);
        } else {
            printf(" %016" PRIx64, (uint64_t)expected[i]);
        }
    }
    printf("\n\n");
}

static bool test_32( void ) {
    bool passed = true;
    const uint32_t tests[14][4] = {
        {        0x1,        0x1,        0x0,        0x1 },
        { 0xBC517F07,        0x0,        0x0,        0x0 },
        { 0xEBFB0D45, 0x9BD56D74, 0x8FA5BDCF, 0xA3D16444 },
        { 0x7FFFFFFF,        0x1,        0x0, 0x7FFFFFFF },
        { 0x7FFFFFFF,        0x2,        0x0, 0xFFFFFFFE },
        { 0x7FFFFFFF,        0x3,        0x1, 0x7FFFFFFD },
        { 0x7FFFFFFF,        0x4,        0x1, 0xFFFFFFFC },
        { 0xFFFFFFFF,        0x1,        0x0, 0xFFFFFFFF },
        { 0xFFFFFFFF,        0x2,        0x1, 0xFFFFFFFE },
        { 0xFFFFFFFF,        0x3,        0x2, 0xFFFFFFFD },
        { 0xFFFFFFFF,        0x4,        0x3, 0xFFFFFFFC },
        { 0xFFFFFFFF,        0x8,        0x7, 0xFFFFFFF8 },
        { 0xFFFFFFFF, 0x11111111, 0x11111110, 0xEEEEEEEF },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE,        0x1 },
    };
    const uint32_t testsum[3] = { 0x33058587, 0x416D9DEB, 0x2580A632 };

    uint32_t sum1_lo, sum1_mi, sum1_hi, sum2_lo, sum2_mi, sum2_hi;
    uint32_t r1_lo, r1_hi, r2_lo, r2_hi;
    uint64_t r1_64, r2_64;

    sum1_lo = sum1_mi = sum1_hi = sum2_lo = sum2_mi = sum2_hi = 0;

    for (int i = 0; i < 14; i++) {
        mult32_64(r1_lo, r1_hi      , tests[i][0], tests[i][1]);
        mult32_64(r1_64, tests[i][0], tests[i][1]);
        mult32_64(r2_lo, r2_hi      , tests[i][1], tests[i][0]);
        mult32_64(r2_64, tests[i][1], tests[i][0]);
        if ((r1_hi != tests[i][2]) || (r1_lo != tests[i][3])) {
            fail("mult32_64, r1, rhi:rlo", i, &tests[i][2], { r1_hi, r1_lo });
            passed = false;
        }
        if (((r1_64 >> 32) != tests[i][2]) || (((uint32_t)r1_64) != tests[i][3])) {
            fail("mult32_64, r1, r64", i, &tests[i][2], { (uint32_t)(r1_64 >> 32), (uint32_t)r1_64 });
            passed = false;
        }
        if ((r2_hi != tests[i][2]) || (r2_lo != tests[i][3])) {
            fail("mult32_64, r2, rhi:rlo", i, &tests[i][2], { r2_hi, r2_lo });
            passed = false;
        }
        if (((r2_64 >> 32) != tests[i][2]) || (((uint32_t)r2_64) != tests[i][3])) {
            fail("mult32_64, r2, r64", i, &tests[i][2], { (uint32_t)(r2_64 >> 32), (uint32_t)r2_64 });
            passed = false;
        }
        add96(sum1_lo, sum1_mi, sum1_hi, tests[i][3], tests[i][2], 0x38ADE957);
        add96(sum1_lo, sum1_mi, sum1_hi, tests[i][3], tests[i][2], 0x38ADE957);
        fma32_96(sum2_lo, sum2_mi, sum2_hi, tests[i][0], tests[i][1]); sum2_hi += 0x38ADE957;
        fma32_96(sum2_lo, sum2_mi, sum2_hi, tests[i][1], tests[i][0]); sum2_hi += 0x38ADE957;
    }

    if ((sum1_hi != testsum[0]) || (sum1_mi != testsum[1]) || (sum1_lo != testsum[2])) {
        fail("add96", -1, &testsum[0], { sum1_hi, sum1_mi, sum1_lo });
        passed = false;
    }
    if ((sum2_hi != testsum[0]) || (sum2_mi != testsum[1]) || (sum2_lo != testsum[2])) {
        fail("fma32_96", -1, &testsum[0], { sum2_hi, sum2_mi, sum2_lo });
        passed = false;
    }

    return passed;
}

static bool test_64( void ) {
    bool passed = true;

    const uint64_t tests[16][6] = {
        {
            0x1,                         0x1,
            0x0,                         0x1,
            0x0,                         0x1
        },
        {
            UINT64_C(0x2F9AC342168A6741), 0x0,
            0x0, 0x0,
            0x0,                         0x0
        },
        // No cross-lane carry
        {
            UINT64_C(0x418FD883CEB217D8), UINT64_C(0x7213F60E1222CE60),
            UINT64_C(0x1D372B1B98652CD8), UINT64_C(0xC1E418E52CA8C100),
            UINT64_C(0x1D372B1B98652CD8), UINT64_C(0xC1E418E52CA8C100)
        },
        // 1 cross-lane carry
        {
            UINT64_C(0x477B3604218D2514), UINT64_C(0xA6019680FBEACF3B),
            UINT64_C(0x2E5A5688195E73C4), UINT64_C(0x1E1F1A735CCAB79C),
            UINT64_C(0x2E5A5688195E73C3), UINT64_C(0x1E1F1A735CCAB79C)
        },
        // 2 cross-lane carries
        {
            UINT64_C(0xA7E5AD86B74C236C), UINT64_C(0x1522F8FF937041C7),
            UINT64_C(0x0DDCC70B3782740B), UINT64_C(0x0249EA7D546DF4F4),
            UINT64_C(0x0DDCC70B37827409), UINT64_C(0x0249EA7D546DF4F4)
        },
        {
            UINT64_C(0x7FFFFFFFFFFFFFFF), UINT64_C(               0x1),
            UINT64_C(               0x0), UINT64_C(0x7FFFFFFFFFFFFFFF),
            UINT64_C(               0x0), UINT64_C(0x7FFFFFFFFFFFFFFF)
        },
        {
            UINT64_C(0x7FFFFFFFFFFFFFFF), UINT64_C(               0x2),
            UINT64_C(               0x0), UINT64_C(0xFFFFFFFFFFFFFFFE),
            UINT64_C(               0x0), UINT64_C(0xFFFFFFFFFFFFFFFE)
        },
        {
            UINT64_C(0x7FFFFFFFFFFFFFFF), UINT64_C(               0x3),
            UINT64_C(               0x1), UINT64_C(0x7FFFFFFFFFFFFFFD),
            UINT64_C(               0x1), UINT64_C(0x7FFFFFFFFFFFFFFD)
        },
        {
            UINT64_C(0x7FFFFFFFFFFFFFFF), UINT64_C(               0x4),
            UINT64_C(               0x1), UINT64_C(0xFFFFFFFFFFFFFFFC),
            UINT64_C(               0x1), UINT64_C(0xFFFFFFFFFFFFFFFC)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(               0x1),
            UINT64_C(               0x0), UINT64_C(0xFFFFFFFFFFFFFFFF),
            UINT64_C(               0x0), UINT64_C(0xFFFFFFFFFFFFFFFF)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(               0x2),
            UINT64_C(               0x1), UINT64_C(0xFFFFFFFFFFFFFFFE),
            UINT64_C(               0x1), UINT64_C(0xFFFFFFFFFFFFFFFE)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(               0x3),
            UINT64_C(               0x2), UINT64_C(0xFFFFFFFFFFFFFFFD),
            UINT64_C(               0x2), UINT64_C(0xFFFFFFFFFFFFFFFD)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(               0x4),
            UINT64_C(               0x3), UINT64_C(0xFFFFFFFFFFFFFFFC),
            UINT64_C(               0x3), UINT64_C(0xFFFFFFFFFFFFFFFC)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(               0x8),
            UINT64_C(               0x7), UINT64_C(0xFFFFFFFFFFFFFFF8),
            UINT64_C(               0x7), UINT64_C(0xFFFFFFFFFFFFFFF8)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0x1111111111111111),
            UINT64_C(0x1111111111111110), UINT64_C(0xEEEEEEEEEEEEEEEF),
            UINT64_C(0x111111111111110F), UINT64_C(0xEEEEEEEEEEEEEEEF)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFF),
            UINT64_C(0xFFFFFFFFFFFFFFFE), UINT64_C(               0x1),
            UINT64_C(0xFFFFFFFFFFFFFFFD), UINT64_C(               0x1)
        },
    };
    const uint64_t testsum[3] = {
        UINT64_C(0x92791E340E9CF671),
        UINT64_C(0xD4FEB37FF4AE4B9B),
        UINT64_C(0xA278198999A0B8CA)
    };

    uint64_t sum1_lo, sum1_mi, sum1_hi, sum2_lo, sum2_mi, sum2_hi;
    uint64_t sum3_lo, sum3_mi, sum3_hi;
    uint64_t r1_lo, r1_hi, r2_lo, r2_hi;

    sum1_lo = sum1_mi = sum1_hi = sum2_lo = sum2_mi = sum2_hi = 0;
    sum3_lo = sum3_mi = sum3_hi = 0;

    for (int i = 0; i < 16; i++) {
        mult64_128_nocarry(r1_lo, r1_hi, tests[i][0], tests[i][1]);
        mult64_128_nocarry(r2_lo, r2_hi, tests[i][1], tests[i][0]);
        if ((r1_hi != tests[i][4]) || (r1_lo != tests[i][5])) {
            fail("mult64_128_nocarry, r1, rhi:rlo", i, &tests[i][4], { r1_hi, r1_lo });
            passed = false;
        }
        if ((r2_hi != tests[i][4]) || (r2_lo != tests[i][5])) {
            fail("mult64_128_nocarry, r2, rhi:rlo", i, &tests[i][4], { r2_hi, r2_lo });
            passed = false;
        }

        mult64_128(r1_lo, r1_hi, tests[i][0], tests[i][1]);
        mult64_128(r2_lo, r2_hi, tests[i][1], tests[i][0]);
        if ((r1_hi != tests[i][2]) || (r1_lo != tests[i][3])) {
            fail("mult64_128, r1, rhi:rlo", i, &tests[i][0], { r1_hi, r1_lo });
            passed = false;
        }
        if ((r2_hi != tests[i][2]) || (r2_lo != tests[i][3])) {
            fail("mult64_128, r2, rhi:rlo", i, &tests[i][0], { r2_hi, r2_lo });
            passed = false;
        }

        add128(sum1_lo, sum1_mi, tests[i][3], tests[i][2]);
        add192(sum1_lo, sum1_mi, sum1_hi, tests[i][3], tests[i][2], UINT64_C(0x192791e340e9cf67));
        fma64_128(sum2_lo, sum2_mi, tests[i][0], tests[i][1]);
        fma64_128(sum3_lo, sum3_mi, tests[i][1], tests[i][0]);
        fma64_192(sum2_lo, sum2_mi, sum2_hi, tests[i][0], tests[i][1]);
        fma64_192(sum3_lo, sum3_mi, sum3_hi, tests[i][1], tests[i][0]);
        sum2_hi += UINT64_C(0x192791e340e9cf67);
        sum3_hi += UINT64_C(0x192791e340e9cf67);
    }

    if ((sum1_hi != testsum[0]) || (sum1_mi != testsum[1]) || (sum1_lo != testsum[2])) {
        fail("add128/add192", -1, &testsum[0], { sum1_hi, sum1_mi, sum1_lo });
        passed = false;
    }
    if ((sum2_hi != testsum[0]) || (sum2_mi != testsum[1]) || (sum2_lo != testsum[2])) {
        fail("fma64_128/fma64_192", 1, &testsum[0], { sum2_hi, sum2_mi, sum2_lo });
        passed = false;
    }
    if ((sum3_hi != testsum[0]) || (sum3_mi != testsum[1]) || (sum3_lo != testsum[2])) {
        fail("fma64_128/fma64_192", 2, &testsum[0], { sum3_hi, sum3_mi, sum3_lo });
        passed = false;
    }

    return passed;
}

static bool test_128( void ) {
    bool passed = true;

    const uint64_t tests[16][6] = {
        {
            0x0,                         0x1,
            0x0,                         0x1,
            0x0,                         0x1
        },
        {
            UINT64_C(0xAF756DACBD453D68), UINT64_C(0xE5915DA08FF8BFD9),
            0x0,                         0x0,
            0x0,                         0x0
        },
        {
            UINT64_C(0xAF756DACBD453D68), UINT64_C(0xE5915DA08FF8BFD9),
            UINT64_C(0x2C297F5B51B1274F), UINT64_C(0x2A51DC0FB3F6EA0A),
            UINT64_C(0xB9E5265202949E5E), UINT64_C(0x96526CC31499D87A)
        },
        {
            UINT64_C(0x7FFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFF),
            UINT64_C(               0x0), UINT64_C(               0x1),
            UINT64_C(0x7FFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFF)
        },
        {
            UINT64_C(0x7FFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFF),
            UINT64_C(               0x0), UINT64_C(               0x2),
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFE)
        },
        {
            UINT64_C(0x7FFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFF),
            UINT64_C(               0x0), UINT64_C(               0x3),
            UINT64_C(0x7FFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFD)
        },
        {
            UINT64_C(0x7FFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFF),
            UINT64_C(               0x0), UINT64_C(               0x4),
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFC)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(               0x1),
            UINT64_C(               0x0), UINT64_C(               0x1),
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(               0x1)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFE), UINT64_C(               0x1),
            UINT64_C(               0x0), UINT64_C(               0x2),
            UINT64_C(0xFFFFFFFFFFFFFFFC), UINT64_C(               0x2)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFF),
            UINT64_C(               0x0), UINT64_C(               0x3),
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFD)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFF),
            UINT64_C(               0x0), UINT64_C(               0x4),
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFC)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFF),
            UINT64_C(               0x0), UINT64_C(               0x8),
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFF8)
        },
        {
            UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0x1111111111111111),
            UINT64_C(0x1111111111111110), UINT64_C(0xEEEEEEEEEEEEEEEE),
            UINT64_C(0x1FDB97530ECA8642), UINT64_C(0xDF0123456789ABCE)
        },
        {
            UINT64_C(0xAAAAAAAAAAAAAAAA), UINT64_C(0xFFFFFFFFFFFFFFFF),
            UINT64_C(0xFFFFFFFFFFFFFFFE), UINT64_C(               0x1),
            UINT64_C(0xAAAAAAAAAAAAAAAC), UINT64_C(0xFFFFFFFFFFFFFFFF)
        },
        {
            UINT64_C(0xAAAAAAAAAAAAAAAA), UINT64_C(0x5555555555555555),
            UINT64_C(0xFFFFFFFFFFFFFFFE), UINT64_C(               0x1),
            UINT64_C(               0x0), UINT64_C(0x5555555555555555)
        },
        {
            UINT64_C(0xAAAAAAAAAAAAAAAA), UINT64_C(0x5555555555555555),
            UINT64_C(0xFFFFFFFFFFFFFFFE), UINT64_C(               0x0),
            UINT64_C(0x5555555555555556), UINT64_C(               0x0)
        },
    };

    uint64_t r1_lo, r1_hi, r2_lo, r2_hi;

    for (int i = 0; i < 16; i++) {
        mult128_128(r1_lo, r1_hi, tests[i][1], tests[i][0], tests[i][3], tests[i][2]);
        mult128_128(r2_lo, r2_hi, tests[i][3], tests[i][2], tests[i][1], tests[i][0]);
        if ((r1_hi != tests[i][4]) || (r1_lo != tests[i][5])) {
            fail("mult128_128, r1, rhi:rlo", i, &tests[i][4], { r1_hi, r1_lo });
            passed = false;
        }
        if ((r2_hi != tests[i][4]) || (r2_lo != tests[i][5])) {
            fail("mult128_128, r2, rhi:rlo", i, &tests[i][4], { r2_hi, r2_lo });
            passed = false;
        }
    }

    return passed;
}

int Mathmult_selftest( void ) {
    bool passed = true;

    passed &= test_32();
    passed &= test_64();
    passed &= test_128();

    if (!passed) {
        exit(1);
    }

    return 42;
}
