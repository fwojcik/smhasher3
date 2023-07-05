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

#include <vector>
#include <string>
#include <algorithm>

#include "Wordlist.h"
#include "words/array.h"

std::vector<std::string> GetWordlist( bool addSingleCap, bool verbose ) {
    std::vector<std::string> wordvec;
    std::string line;
    unsigned    sum  = 0;

    const char * ptr = words_array + 1; // Skip over initial newline
    const char * eof = ptr + strlen(ptr);

    while (ptr != eof) {
        const char * end = (const char *)memchr(ptr, '\n', eof - ptr);
        std::string  str( ptr, end - ptr );
        wordvec.push_back(str);
        if (addSingleCap) {
            std::transform(str.begin(), str.begin() + 1, str.begin(), ::toupper);
            wordvec.push_back(str);
        }
        std::transform(str.begin(), str.end(), str.begin(), ::toupper);
        wordvec.push_back(str);
        sum += end - ptr;
        ptr  = end + 1;
    }

    if (verbose) {
        unsigned cnt = (double)wordvec.size() / (addSingleCap ? 3.0 : 2.0);
        printf("Read %d words from internal list, ", cnt);
        printf("avg len: %0.3f\n\n", (double)(sum) / (double)(cnt));
    }

    return wordvec;
}
