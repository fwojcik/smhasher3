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

#include <string>

// The list of words in all lower-case are always returned. In addition,
// the list may include the same words in all upper-case and/or the same
// words with only their first letter in upper-case, as specified.
typedef enum {
    CASE_LOWER        = 0,
    CASE_LOWER_UPPER  = 1,
    CASE_LOWER_SINGLE = 2,
    CASE_ALL          = 3
} wordlist_case_t;

std::vector<std::string> GetWordlist( wordlist_case_t cases, bool verbose );
