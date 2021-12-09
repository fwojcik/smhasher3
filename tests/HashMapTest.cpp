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
#include "HashMapTest.h"
#include "SpeedTest.h"
#include "Random.h"

#include <string>
#include <unordered_map>
#include <functional>
#include <iostream>
#include <fstream>

using namespace std;

//-----------------------------------------------------------------------------
// This should be a realistic I-Cache test, when our hash is used inlined
// in a hash table. There the size matters more than the bulk speed.

std::vector<std::string> HashMapInit(bool verbose) {
  std::vector<std::string> words;
  std::string line;
  std::string filename = "/usr/share/dict/words";
  int lines = 0, sum = 0;
  std::ifstream wordfile(filename.c_str());
  if (!wordfile.is_open()) {
#ifdef __aarch64__ /* should be __ANDROID_API__, but not yet */
    filename = "dict.words";
    std::ifstream wordfile1(filename.c_str());
    if (wordfile1.is_open()) {
      wordfile = move(wordfile1);
      goto ok_file;
    }
#endif
    std::cout << "Unable to open words dict file " << filename << "\n";
    return words;
  }
 ok_file:
  while (getline(wordfile, line)) {
    int len = line.length();
    lines++;
    sum += len;
    words.push_back(line);
  }
  wordfile.close();
  if (verbose) {
    printf ("Read %d words from '%s'\n", lines, filename.c_str());
    printf ("Avg len: %0.3f\n", (sum+0.0)/lines);
  }
  return words;
}

bool HashMapTest ( pfHash pfhash, 
                   const int hashbits, std::vector<std::string> words,
                   const uint32_t seed, const int trials, bool verbose )
{
  double mean = 0.0;
  try {
    mean = HashMapSpeedTest( pfhash, hashbits, words, seed, trials, verbose);
  }
  catch (...) {
    printf(" aborted !!!!\n");
  }
  // if faster than ~sha1
  if (mean > 5. && mean < 1500.)
    printf(" ....... PASS\n");
  else
    printf(" ....... FAIL\n");
  return true;
}
