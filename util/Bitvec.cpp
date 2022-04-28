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
 *     Copyright (c) 2019-2020 Yann Collet
 *     Copyright (c) 2020      Reini Urban
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
#include "TestGlobals.h"
#include "Bitvec.h"

void printhex(const void * blob, size_t len, const char * prefix) {
    const uint8_t * bytes = (const uint8_t *)blob;
    const size_t buflen = 4 + 2 * len + ((len + 3) / 4);
    char buf[buflen];
    char * p;

    buf[0]          = '[';
    buf[1]          = ' ';
    // Space preceding the closing ']' gets added by the loop below
    buf[buflen - 2] = ']';
    buf[buflen - 1] = '\0';

    // Print using MSB-first notation
    p = &buf[2];
    for (size_t i = len; i != 0; i--) {
        uint8_t vh = (bytes[i - 1] >> 4);
        uint8_t vl = (bytes[i - 1] & 15);
        *p++ = vh + ((vh <= 9) ? '0' : 'W'); // 'W' + 10 == 'a'
        *p++ = vl + ((vl <= 9) ? '0' : 'W');
        if ((i & 3) == 1) {
            *p++ = ' ';
        }
    }

    printf("%s%s\n", prefix, buf);
}
