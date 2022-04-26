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
 *     Copyright (c) 2019      Yann Collet
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

//-----------------------------------------------------------------------------

void     printHash   ( const void * key, size_t len );
void     printbits   ( const void * blob, int len );
void     printhex    ( const void * blob, int len );

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
// Bit-windowing functions - select some N-bit subset of the input blob

template<uint32_t bitlen>
inline uint32_t window ( const void * blob, int start, int count )
{
  assume(count <= 24);
  const uint32_t mask = (1 << count) - 1;
  const uint8_t * b = (const uint8_t *)blob;
  uint32_t v;

  if (bitlen == 8)
      v = (b[0] | (b[0] << 8)) >> start;
  else if (bitlen == 16)
      v = (b[0] | (b[1] << 8) | (b[0] << 16) | (b[1] << 24)) >> start;
  else if (bitlen == 24) {
      uint8_t t[6];
      memcpy(&t[0], b, 3);
      memcpy(&t[3], b, 3);
      memcpy(&v, t + (start >> 3), 4);
      v >>= (start & 7);
  } else if (start <= (bitlen - 25)) {
      memcpy(&v, b + (start >> 3), 4);
      v >>= (start & 7);
  } else {
      memcpy(&v, b + (bitlen / 8) - 4, 4);
      v >>= 32 + start - bitlen;
      if ((start + count) > bitlen) {
          uint32_t v2;
          memcpy(&v2, b, 4);
          v2 <<= bitlen - start;
          v |= v2;
      }
  }
  return v & mask;
}

template < typename T >
inline uint32_t window ( const T & blob, int start, int count )
{
  return window<8*sizeof(T)>(&blob,start,count);
}

//-----------------------------------------------------------------------------
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
