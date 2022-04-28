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
#include <algorithm>

//-----------------------------------------------------------------------------

void printhex(const void * blob, size_t len, const char * prefix = "");

//----------

static inline void flipbit ( void * block, int len, uint32_t bit )
{
  uint8_t * b = (uint8_t*)block;

  int byte = bit >> 3;
  bit = bit & 0x7;

  if(byte < len) b[byte] ^= (1 << bit);
}

template< typename T >
inline void flipbit ( T & blob, uint32_t bit )
{
  flipbit(&blob,sizeof(T),bit);
}

//-----------------------------------------------------------------------------
extern const uint32_t hzb[256];

template < int _bits >
class Blob {

public:
  Blob() {
    memset(bytes, 0, sizeof(bytes));
  }

  Blob(const void * p, size_t len) {
    len = std::min(len, sizeof(bytes));
    memcpy(bytes, p, len);
    memset(&bytes[len], 0, sizeof(bytes) - len);
  }

  Blob(uint64_t x) :
      Blob((x = COND_BSWAP(x, isBE()), &x), sizeof(x)) {};

  uint8_t & operator [] (int i) {
    //assert(i < sizeof(bytes));
    return bytes[i];
  }

  const uint8_t & operator [](int i) const {
    //assert(i < sizeof(bytes));
    return bytes[i];
  }

  Blob & operator = (const Blob & k) {
    memcpy(bytes, k.bytes, sizeof(bytes));
    return *this;
  }

  void printhex(const char * prefix = "") const {
      constexpr size_t buflen = 4 + 2 * sizeof(bytes) + ((sizeof(bytes) + 3) / 4);
      char buf[buflen];
      char * p;

      buf[0]          = '[';
      buf[1]          = ' ';
      // Space preceding the closing ']' gets added by the loop below
      buf[buflen - 2] = ']';
      buf[buflen - 1] = '\0';

      // Print using MSB-first notation
      p = &buf[2];
      for (size_t i = sizeof(bytes); i != 0; i--) {
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

  void printbits(const char * prefix = "") const {
      constexpr size_t buflen = 4 + 9 * sizeof(bytes);
      char buf[buflen];
      char * p;

      buf[0]          = '[';
      buf[1]          = ' ';
      // Space preceding the closing ']' gets added by the loop below
      buf[buflen - 2] = ']';
      buf[buflen - 1] = '\0';

      // Print using MSB-first notation
      p = &buf[2];
      for (size_t i = sizeof(bytes); i != 0; i--) {
          uint8_t v = bytes[i - 1];
          for (int j = 7; j >= 0; j--) {
              *p++ = (v & (1 << j)) ? '1' : '0';
          }
          *p++ = ' ';
      }

      printf("%s%s\n", prefix, buf);
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

  FORCE_INLINE uint8_t getbit(size_t bit) const {
      size_t byte = bit >> 3;
      bit &= 7;
      if (byte > sizeof(bytes)) return 0;
      return (bytes[byte] >> bit) & 1;
  }

  FORCE_INLINE uint32_t highzerobits(void) const {
      const size_t len = sizeof(bytes);
      uint32_t zb = 0;
      for(size_t i = len - 1; i >= 0; i--) {
          zb += hzb[bytes[i]];
          if (bytes[i] != 0) {
              break;
          }
      }
      return zb;
  }

  // Bit-windowing function.
  // Select some N-bit subset of the Blob, where N <= 24.
  FORCE_INLINE uint32_t window(size_t start, size_t count) const {
      assume(count <= 24);
      const size_t bitlen = 8 * sizeof(bytes);
      const uint32_t mask = (1 << count) - 1;
      uint32_t v;

      if (start <= (bitlen - 25)) {
          memcpy(&v, &bytes[start >> 3], 4);
          v = COND_BSWAP(v, isBE());
          v >>= (start & 7);
      } else {
          memcpy(&v, &bytes[sizeof(bytes) - 4], 4);
          v = COND_BSWAP(v, isBE());
          v >>= 32 + start - bitlen;
          if ((start + count) > bitlen) {
              uint32_t v2;
              memcpy(&v2, bytes, 4);
              v2 = COND_BSWAP(v2, isBE());
              v2 <<= bitlen - start;
              v |= v2;
          }
      }
      return v & mask;
  }

  // 0xf00f1001 => 0x8008f00f
  FORCE_INLINE void reversebits(void) {
      const size_t len = sizeof(bytes);
      uint8_t tmp[len];

      for (size_t i = 0; i < len; i++)
          tmp[len - i - 1] = byterev(bytes[i]);
      memcpy(bytes, tmp, len);
  }

  void lrot(size_t c) {
      const size_t byteoffset = c >> 3;
      const size_t bitoffset  = c & 7;
      const size_t len = sizeof(bytes);
      uint8_t tmp[len];

      for (size_t i = 0; i < len; i++) {
          tmp[(i + byteoffset) % len] = bytes[i];
      }
      if (bitoffset == 0) {
          memcpy(bytes, tmp, len);
      } else {
          for (size_t i = 0; i < len; i++) {
              uint8_t a = tmp[i];
              uint8_t b = (i == 0) ? tmp[len - 1] : tmp[i - 1];
              bytes[i] = (a << bitoffset) | (b >> (8 - bitoffset));
          }
      }
  }
  //----------

private:
  uint8_t bytes[(_bits+7)/8];

  // from the "Bit Twiddling Hacks" webpage
  static FORCE_INLINE uint8_t byterev(uint8_t b) {
      return ((b * UINT64_C(0x0802) & UINT64_C(0x22110)) |
              (b * UINT64_C(0x8020) & UINT64_C(0x88440)))  * UINT64_C(0x10101) >> 16;
  }

};

// from the "Bit Twiddling Hacks" webpage
template<> FORCE_INLINE void Blob<32>::reversebits(void) {
    uint32_t v = GET_U32<false>(bytes, 0);
    // swap odd and even bits
    v = ((v >> 1) & 0x55555555) | ((v & 0x55555555) <<  1);
    // swap consecutive pairs
    v = ((v >> 2) & 0x33333333) | ((v & 0x33333333) <<  2);
    // swap nibbles ...
    v = ((v >> 4) & 0x0F0F0F0F) | ((v & 0x0F0F0F0F) <<  4);
    // swap bytes
    v = ((v >> 8) & 0x00FF00FF) | ((v & 0x00FF00FF) <<  8);
    // swap 2-byte long pairs
    v = ( v >> 16             ) | ( v               << 16);
    PUT_U32<false>(v, bytes, 0);
}

template<> FORCE_INLINE void Blob<64>::reversebits(void) {
    uint64_t v = GET_U64<false>(bytes, 0);
    // swap odd and even bits
    v = ((v >> 1)  & UINT64_C(0x5555555555555555)) | ((v & UINT64_C(0x5555555555555555)) <<  1);
    // swap consecutive pairs
    v = ((v >> 2)  & UINT64_C(0x3333333333333333)) | ((v & UINT64_C(0x3333333333333333)) <<  2);
    // swap nibbles ...
    v = ((v >> 4)  & UINT64_C(0x0F0F0F0F0F0F0F0F)) | ((v & UINT64_C(0x0F0F0F0F0F0F0F0F)) <<  4);
    // swap bytes
    v = ((v >> 8)  & UINT64_C(0x00FF00FF00FF00FF)) | ((v & UINT64_C(0x00FF00FF00FF00FF)) <<  8);
    // swap 2-byte long pairs
    v = ((v >> 16) & UINT64_C(0x0000FFFF0000FFFF)) | ((v & UINT64_C(0x0000FFFF0000FFFF)) << 16);
    // swap 4-byte long pairs
    v = ( v >> 32                      ) | ( v                       << 32);
    PUT_U64<false>(v, bytes, 0);
}

//-----------------------------------------------------------------------------
// Blob sorting routines
static const uint32_t    RADIX_BITS   = 8;
static const uint32_t    RADIX_SIZE   = (uint32_t)1 << RADIX_BITS;
static const uint32_t    RADIX_MASK   = RADIX_SIZE - 1;

template< typename T >
static void radixsort( T * begin, T * end )
{
  const uint32_t RADIX_LEVELS = sizeof(T);
  const size_t count = end - begin;

  size_t freqs [RADIX_LEVELS][RADIX_SIZE] = {};
  T * ptr = begin;
  // Record byte frequencies in each position over all items except
  // the last one.
  do {
    for (uint32_t pass = 0; pass < RADIX_LEVELS; pass++) {
      uint8_t value = (*ptr)[pass];
      ++freqs[pass][value];
    }
  } while (++ptr < (end - 1));
  // Process the last item separately, so that we can record which
  // passes (if any) would do no reordering of items, and which can
  // therefore be skipped entirely.
  uint32_t trivial_passes = 0;
  for (uint32_t pass = 0; pass < RADIX_LEVELS; pass++) {
    uint8_t value = (*ptr)[pass];
    if (++freqs[pass][value] == count)
      trivial_passes |= 1UL << pass;
  }

  std::unique_ptr<T[]> queue_area(new T[count]);
  T * from = begin;
  T * to   = queue_area.get();

  for (uint32_t pass = 0; pass < RADIX_LEVELS; pass++) {
    // If this pass would do nothing, just skip it.
    if (trivial_passes & (1UL << pass))
      continue;

    // Array of pointers to the current position in each queue,
    // pre-arranged based on the known final sizes of each queue. This
    // way all the entries end up contiguous with no gaps.
    T * queue_ptrs[RADIX_SIZE];
    T * next = to;
    for (size_t i = 0; i < RADIX_SIZE; i++) {
      queue_ptrs[i] = next;
      next += freqs[pass][i];
    }

    // Copy each element into its queue based on the current byte.
    for (size_t i = 0; i < count; i++) {
      uint8_t index = from[i][pass];
      *queue_ptrs[index]++ = from[i];
      __builtin_prefetch(queue_ptrs[index] + 1);
    }

    std::swap(from, to);
  }

  // Because the swap always happens in the above loop, the "from"
  // area has the sorted payload. If that's not the original array,
  // then do a final copy.
  if (from != begin)
    std::copy(from, from + count, begin);
}

//-----------------------------------------------------------------------------
static const uint32_t    SORT_CUTOFF  = 60;

#if 0
#define expectp(x, p)  __builtin_expect_with_probability(!!(x), 1, (p))
#else
#define expectp(x, p) (x)
#endif

// This is an in-place MSB radix sort that recursively sorts each
// block, sometimes known as an "American Flag Sort". Testing shows
// that performance increases by devolving to std::sort once we get
// down to small block sizes. Both 40 and 60 items are best on my
// system, but there could be a better value for the general case.
template< typename T >
static void flagsort( T * begin, T * end, int idx )
{
  const uint32_t DIGITS = sizeof(T);
  const size_t count = end - begin;
  assume(idx >= 0);
  assume(idx < DIGITS);

  // Each pass must compute its own frequency table, because the
  // counts depend on all previous bytes, since each pass operates on
  // a successively smaller subset of the total list to sort.
  size_t freqs[RADIX_SIZE] = {};
  T * ptr = begin;
  do {
    ++freqs[(*ptr)[idx]];
  } while (++ptr < (end - 1));
  // As in radix sort, if this pass would do no rearrangement, then
  // there's no need to iterate over every item. Since this case is
  // only likely to hit in degenerate cases (e.g. donothing64), just
  // devolve into radixsort since that performs better on lists of
  // many similar values.
  if (++freqs[(*ptr)[idx]] == count) {
      // If there are no more passes, then we're just done.
      if (idx == 0) {
          return;
      }
      return radixsort(begin, end);
  }

  T * block_ptrs[RADIX_SIZE];
  ptr = begin;
  for (size_t i = 0; i < RADIX_SIZE; i++) {
    block_ptrs[i] = ptr;
    ptr += freqs[i];
  }

  // Move all values into their correct block, maintaining a stable
  // sort ordering inside each block.
  ptr     = begin;
  T * nxt = begin + freqs[0];
  uint8_t curblock = 0;
  while (curblock < (RADIX_SIZE - 1)) {
    if (expectp(ptr >= nxt, 0.0944)) {
      curblock++;
      nxt += freqs[curblock];
      continue;
    }
    uint8_t value = (*ptr)[idx];
    if (expectp(value == curblock, 0.501155)) {
      ptr++;
      continue;
    }
    //assert(block_ptrs[value] < end);
    std::swap(*ptr, *block_ptrs[value]++); // MAYBE do this better manually?
  }

  if (idx == 0)
    return;

  // Sort each block by the next less-significant byte, or by
  // std::sort if there are only a few entries in the block.
  ptr = begin;
  for (int i = 0; i < RADIX_SIZE; i++) {
    if (expectp(freqs[i] > SORT_CUTOFF, 0.00390611))
      flagsort(ptr, ptr + freqs[i], idx - 1);
    else if (expectp(freqs[i] > 1, 0.3847))
      std::sort(ptr, ptr + freqs[i]);
    ptr += freqs[i];
  }
}

//-----------------------------------------------------------------------------
// For 32-bit values, radix sorting is a clear win on my system, and
// flag sorting wins for all other item sizes. I'm not 100% sure why
// that is, so some effort into finding the right cutoff might be
// appropriate. This approach handily beats just using std::sort, at
// least on my system (526 seconds vs 1430).
template< class Iter >
void blobsort ( Iter iter_begin, Iter iter_end )
{
  typedef typename std::iterator_traits<Iter>::value_type T;
  // Nothing to sort if there are 0 or 1 items
  if ((iter_end - iter_begin) < 2)
    return;
  else if ((iter_end - iter_begin) <= SORT_CUTOFF)
    return std::sort(iter_begin, iter_end);

  T * begin = &(*iter_begin);
  T * end   = &(*iter_end);
  if (sizeof(T) > 4)
    flagsort(begin, end, sizeof(T) - 1);
  else
    radixsort(begin, end);
}

//-----------------------------------------------------------------------------
