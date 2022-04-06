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
void     printhex32  ( const void * blob, int len );
void     printbytes  ( const void * blob, int len );
void     printbytes2 ( const void * blob, int len );

uint32_t parity      ( uint32_t v );

uint32_t getbit_wrap ( const void * blob, int len, uint32_t bit );

void     setbit      ( void * blob, int len, uint32_t bit );
void     setbit      ( void * blob, int len, uint32_t bit, uint32_t val );

void     clearbit    ( void * blob, int len, uint32_t bit );

int      countbits   ( uint32_t v );
int      countbits   ( std::vector<uint32_t> & v );

int      countbits   ( const void * blob, int len );

extern const uint32_t hzb[256];

//----------

static inline uint32_t getbyte ( const void * block, int len, uint32_t byte )
{
  uint8_t * b = (uint8_t*)block;

  if(byte >= len) return 0;

  return b[byte];
}

template< typename T >
inline uint32_t getbyte ( T & blob, uint32_t byte )
{
  return getbyte(&blob,sizeof(T),byte);
}

template<>
inline uint32_t getbyte ( uint32_t & blob, uint32_t byte ) { return (blob >> (byte * 8)) & 255; }
template<>
inline uint32_t getbyte ( uint64_t & blob, uint32_t byte ) { return (blob >> (byte * 8)) & 255; }

//----------

static inline uint32_t getbit ( const void * block, int len, uint32_t bit )
{
  uint8_t * b = (uint8_t*)block;

  int byte = bit >> 3;
  bit = bit & 0x7;

  if(byte >= len) return 0;

  return (b[byte] >> bit) & 1;
}

template< typename T >
inline uint32_t getbit ( T & blob, uint32_t bit )
{
  return getbit(&blob,sizeof(T),bit);
}

template<>
inline uint32_t getbit ( uint32_t & blob, uint32_t bit ) { return (blob >> (bit & 31)) & 1; }
template<>
inline uint32_t getbit ( uint64_t & blob, uint32_t bit ) { return (blob >> (bit & 63)) & 1; }

//----------

template< typename T >
inline void setbit ( T & blob, uint32_t bit )
{
  return setbit(&blob,sizeof(T),bit);
}

template<>
inline void setbit ( uint32_t & blob, uint32_t bit ) { blob |= uint32_t(1) << (bit & 31); }
template<>
inline void setbit ( uint64_t & blob, uint32_t bit ) { blob |= uint64_t(1) << (bit & 63); }

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

template<>
inline void flipbit ( uint32_t & blob, uint32_t bit ) { bit &= 31; blob ^= (uint32_t(1) << bit); }
template<>
inline void flipbit ( uint64_t & blob, uint32_t bit ) { bit &= 63; blob ^= (uint64_t(1) << bit); }

//----------

// from the "Bit Twiddling Hacks" webpage
static inline uint8_t byterev(uint8_t b)
{
  return ((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16;
}

// 0xf00f1001 => 0x8008f00f
static inline void reversebits ( void * blob, int len )
{
  uint8_t * b = (uint8_t*)blob;
  uint8_t tmp[len];

  for (size_t i = 0; i < len; i++)
    tmp[len - i - 1] = byterev(b[i]);
  memcpy(blob, tmp, len);
}

// from the "Bit Twiddling Hacks" webpage
static inline void reverse32 ( uint32_t & v )
{
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
}

// from the "Bit Twiddling Hacks" webpage
static inline void reverse64 ( uint64_t & v )
{
  // swap odd and even bits
  v = ((v >> 1)  & 0x5555555555555555) | ((v & 0x5555555555555555) <<  1);
  // swap consecutive pairs
  v = ((v >> 2)  & 0x3333333333333333) | ((v & 0x3333333333333333) <<  2);
  // swap nibbles ...
  v = ((v >> 4)  & 0x0F0F0F0F0F0F0F0F) | ((v & 0x0F0F0F0F0F0F0F0F) <<  4);
  // swap bytes
  v = ((v >> 8)  & 0x00FF00FF00FF00FF) | ((v & 0x00FF00FF00FF00FF) <<  8);
  // swap 2-byte long pairs
  v = ((v >> 16) & 0x0000FFFF0000FFFF) | ((v & 0x0000FFFF0000FFFF) << 16);
  // swap 4-byte long pairs
  v = ( v >> 32                      ) | ( v                       << 32);
}

template< typename T >
inline void reversebits ( T & blob )
{
  reversebits(&blob,sizeof(T));
}

template<>
inline void reversebits ( uint32_t & blob ) { reverse32(blob); }
template<>
inline void reversebits ( uint64_t & blob ) { reverse64(blob); }

//----------

static inline uint32_t highzerobits ( void * block, size_t len )
{
  uint8_t * b = (uint8_t*)block;
  uint32_t zb = 0;
  for(int i = len - 1; i >= 0; i--)
  {
    zb += hzb[b[i]];
    if (b[i] != 0)
      break;
  }
  return zb;
}

template< typename T >
inline uint32_t highzerobits ( T & blob )
{
  return highzerobits(&blob,sizeof(T));
}

template<>
inline uint32_t highzerobits ( uint32_t & blob ) { return blob == 0 ? 32 : clz4(blob); }
template<>
inline uint32_t highzerobits ( uint64_t & blob ) { return blob == 0 ? 64 : clz8(blob); }

//-----------------------------------------------------------------------------
// Left and right shift of blobs. The shift(N) versions work on chunks of N
// bits at a time (faster)

void lshift1  ( void * blob, int len, int c );
void lshift8  ( void * blob, int len, int c );
void lshift32 ( void * blob, int len, int c );

void rshift1  ( void * blob, int len, int c );
void rshift8  ( void * blob, int len, int c );
void rshift32 ( void * blob, int len, int c );

inline void lshift ( void * blob, int len, int c )
{
  if((len & 3) == 0)
  {
    lshift32(blob, len, c);
  }
  else
  {
    lshift8(blob, len, c);
  }
}

inline void rshift ( void * blob, int len, int c )
{
  if((len & 3) == 0)
  {
    rshift32(blob, len, c);
  }
  else
  {
    rshift8(blob, len, c);
  }
}

template < typename T >
inline void lshift ( T & blob, int c )
{
  if((sizeof(T) & 3) == 0)
  {
    lshift32(&blob,sizeof(T),c);
  }
  else
  {
    lshift8(&blob,sizeof(T),c);
  }
}

template < typename T >
inline void rshift ( T & blob, int c )
{
  if((sizeof(T) & 3) == 0)
  {
    lshift32(&blob,sizeof(T),c);
  }
  else
  {
    lshift8(&blob,sizeof(T),c);
  }
}

template<> inline void lshift ( uint32_t & blob, int c ) { blob <<= c; }
template<> inline void lshift ( uint64_t & blob, int c ) { blob <<= c; }
template<> inline void rshift ( uint32_t & blob, int c ) { blob >>= c; }
template<> inline void rshift ( uint64_t & blob, int c ) { blob >>= c; }

//-----------------------------------------------------------------------------
// Left and right rotate of blobs. The rot(N) versions work on chunks of N
// bits at a time (faster)

void lrot1    ( void * blob, int len, int c );
void lrot8    ( void * blob, int len, int c );
void lrot32   ( void * blob, int len, int c );

void rrot1    ( void * blob, int len, int c );
void rrot8    ( void * blob, int len, int c );
void rrot32   ( void * blob, int len, int c );

inline void lrot ( void * blob, int len, int c )
{
  if((len & 3) == 0)
  {
    return lrot32(blob,len,c);
  }
  else
  {
    return lrot8(blob,len,c);
  }
}

inline void rrot ( void * blob, int len, int c )
{
  if((len & 3) == 0)
  {
    return rrot32(blob,len,c);
  }
  else
  {
    return rrot8(blob,len,c);
  }
}

template < typename T >
inline void lrot ( T & blob, int c )
{
  if(sizeof(T) == 4)
  {
    return lrot((uint32_t &)blob, c);
  }
  else if(sizeof(T) == 8)
  {
    return lrot((uint64_t &)blob, c);
  }
  else if((sizeof(T) & 3) == 0)
  {
    return lrot32(&blob,sizeof(T),c);
  }
  else
  {
    return lrot8(&blob,sizeof(T),c);
  }
}

template < typename T >
inline void rrot ( T & blob, int c )
{
  if((sizeof(T) & 3) == 0)
  {
    return rrot32(&blob,sizeof(T),c);
  }
  else
  {
    return rrot8(&blob,sizeof(T),c);
  }
}

template<> inline void lrot ( uint32_t & blob, int c ) {
    if (c > 0) { blob = ROTL32(blob,c&31); }
}
template<> inline void lrot ( uint64_t & blob, int c ) {
    if (c > 0) { blob = ROTL64(blob,c&63); }
}
template<> inline void rrot ( uint32_t & blob, int c ) {
    if (c > 0) { blob = ROTR32(blob,c&31); }
}
template<> inline void rrot ( uint64_t & blob, int c ) {
    if (c > 0) { blob = ROTR64(blob,c&63); }
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

template<>
inline uint32_t window ( const uint32_t & blob, int start, int count )
{
  if ((start + count) == 32)
    return (blob >> start);
  return ((start == 0) ? blob : ROTR32(blob,start)) & ((1<<count)-1);
}

template<>
inline uint32_t window ( const uint64_t & blob, int start, int count )
{
  if ((start + count) == 64)
    return (uint32_t)(blob >> start);
  return (uint32_t)((start == 0) ? blob : ROTR64(blob,start)) & ((1<<count)-1);
}

//-----------------------------------------------------------------------------
static const size_t    RADIX_BITS   = 8;
static const size_t    RADIX_SIZE   = (size_t)1 << RADIX_BITS;
static const size_t    RADIX_MASK   = RADIX_SIZE - 1;

template< typename T >
static void radixsort( T * begin, T * end )
{
  const size_t RADIX_LEVELS = sizeof(T);
  const size_t count = end - begin;

  size_t freqs [RADIX_LEVELS][RADIX_SIZE] = {};
  T * ptr = begin;
  // Record byte frequencies in each position over all items except
  // the last one.
  do {
    for (size_t pass = 0; pass < RADIX_LEVELS; pass++) {
      uint32_t value = getbyte(*ptr, pass);
      ++freqs[pass][value];
    }
  } while (++ptr < (end - 1));
  // Process the last item separately, so that we can record which
  // passes (if any) would do no reordering of items, and which can
  // therefore be skipped entirely.
  size_t trivial_passes = 0;
  for (size_t pass = 0; pass < RADIX_LEVELS; pass++) {
    uint32_t value = getbyte(*ptr, pass);
    if (++freqs[pass][value] == count)
      trivial_passes |= 1UL << pass;
  }

  std::unique_ptr<T[]> queue_area(new T[count]);
  T * from = begin;
  T * to   = queue_area.get();

  for (size_t pass = 0; pass < RADIX_LEVELS; pass++) {
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
      uint32_t index = getbyte(from[i], pass);
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
static const size_t    SORT_CUTOFF  = 60;

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
  const size_t DIGITS = sizeof(T);
  const size_t count = end - begin;
  assume(idx >= 0);
  assume(idx < DIGITS);

  // Each pass must compute its own frequency table, because the
  // counts depend on all previous bytes, since each pass operates on
  // a successively smaller subset of the total list to sort.
  size_t freqs[RADIX_SIZE] = {};
  T * ptr = begin;
  do {
    ++freqs[getbyte(*ptr, idx)];
  } while (++ptr < (end - 1));
  // As in radix sort, if this pass would do no rearrangement, then
  // there's no need to iterate over every item. Since this case is
  // only likely to hit in degenerate cases (e.g. donothing64), just
  // devolve into radixsort since that performs better on lists of
  // many similar values.
  if (++freqs[getbyte(*ptr, idx)] == count) {
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
  unsigned curblock = 0;
  while (curblock < (RADIX_SIZE - 1)) {
    if (expectp(ptr >= nxt, 0.0944)) {
      curblock++;
      nxt += freqs[curblock];
      continue;
    }
    uint32_t value = getbyte(*ptr, idx);
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
