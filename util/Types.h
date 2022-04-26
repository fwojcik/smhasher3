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
 *     Copyright (c) 2019-2021 Reini Urban
 *     Copyright (c) 2019-2020 Yann Collet
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
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <algorithm>

#include "Hashinfo.h"

#ifdef HAVE_INT128
typedef unsigned __int128 uint128_t;
typedef          __int128 int128_t;
#endif

//-----------------------------------------------------------------------------
template< typename hashtype >
struct HashSet : public std::set<hashtype>
{
};

//-----------------------------------------------------------------------------
// To be able to sample different statistics sets from the same hash,
// a seed can be supplied which will be used in each test where a seed
// is not explicitly part of that test.
extern seed_t g_seed;

//-----------------------------------------------------------------------------
// The user can select which endian-ness of the hash implementation to test
extern HashInfo::endianness g_hashEndian;

//-----------------------------------------------------------------------------
extern const char * g_failstr;

//-----------------------------------------------------------------------------
template < int _bits >
class Blob {

public:
  Blob() {
    memset(bytes, 0, sizeof(bytes));
  }

  Blob(uint64_t x) {
    x = COND_BSWAP(x, isBE());
    set(&x, sizeof(x));
  }

  uint8_t & operator [] (int i) {
    return bytes[i];
  }

  const uint8_t & operator [](int i) const {
    return bytes[i];
  }

  Blob & operator = (const Blob & k) {
    memcpy(bytes, k.bytes, sizeof(bytes));
    return *this;
  }

  //----------
  // boolean operations

  bool operator < (const Blob & k) const {
    for(int i = sizeof(bytes) -1; i >= 0; i--) {
      if(bytes[i] < k.bytes[i]) return true;
      if(bytes[i] > k.bytes[i]) return false;
    }
    return false;
  }

  bool operator == ( const Blob & k ) const {
    int r = memcmp(&bytes[0], &k.bytes[0], sizeof(bytes));
    return (r == 0) ? true : false;
  }

  bool operator != ( const Blob & k ) const {
    return !(*this == k);
  }

  //----------
  // bitwise operations

  Blob operator ^ (const Blob & k) const {
    Blob t;

    for(size_t i = 0; i < sizeof(bytes); i++) {
      t.bytes[i] = bytes[i] ^ k.bytes[i];
    }

    return t;
  }

  Blob & operator ^= (const Blob & k) {
    for(size_t i = 0; i < sizeof(bytes); i++) {
      bytes[i] ^= k.bytes[i];
    }
    return *this;
  }

  //----------

private:
  uint8_t bytes[(_bits+7)/8];

  void set(const void * blob, size_t len) {
    len = std::min(len, sizeof(bytes));
    memcpy(bytes, blob, len);
    memset(&bytes[len], 0, sizeof(bytes) - len);
  }
};

//-----------------------------------------------------------------------------
