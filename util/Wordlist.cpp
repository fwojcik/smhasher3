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
#include <unordered_set>

#include "Wordlist.h"
#include "words/array.h"

std::vector<std::string> GetWordlist( wordlist_case_t cases, bool verbose ) {
    std::vector<std::string>        wordvec;
    std::unordered_set<std::string> wordset; // words need to be unique, otherwise we report collisions
    unsigned sum = 0, skip_dup = 0, skip_char = 0;

    for (const char * cstr: words_array) {
        std::string str = cstr;
        if (str.find_first_not_of("abcdefghijklmnopqrstuvwxyz") != std::string::npos) {
            skip_char++;
            continue;
        } else if (wordset.count(str) > 0) {
            skip_dup++;
            continue;
        }
        wordvec.push_back(str);
        if ((cases == CASE_LOWER_SINGLE) || (cases == CASE_ALL)) {
            std::transform(str.begin(), str.begin() + 1, str.begin(), ::toupper);
            wordvec.push_back(str);
        }
        if ((cases == CASE_LOWER_UPPER) || (cases == CASE_ALL)) {
            std::transform(str.begin(), str.end(), str.begin(), ::toupper);
            wordvec.push_back(str);
        }
        sum += str.size();
    }

    if ((skip_dup > 0) || (skip_char > 0)) {
        fprintf(stderr, "WARNING: skipped %d bad internal words (%d dupes, %d from invalid chars)\n",
                skip_dup + skip_char, skip_dup, skip_char);
    }

    if (verbose) {
        unsigned cnt = (double)wordvec.size() /
                ((cases == CASE_ALL) ? 3.0 : (cases == CASE_LOWER) ? 1.0 : 2.0);
        printf("Read %d words from internal list, ", cnt);
        printf("avg len: %0.3f\n\n", (double)(sum) / (double)(cnt));
    }

    return wordvec;
}
