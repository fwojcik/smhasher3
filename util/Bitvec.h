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
#pragma once

#include "Platform.h"

#include <vector>
#include <cstring>

//-----------------------------------------------------------------------------

void     printbits   ( const void * blob, int len );
void     printhex  ( const void * blob, int len );
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

template<> inline uint32_t getbyte ( uint32_t & blob, uint32_t byte ) { return (blob >> (byte * 8)) & 255; }
template<> inline uint32_t getbyte ( uint64_t & blob, uint32_t byte ) { return (blob >> (byte * 8)) & 255; }

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
  return getbit(&blob,sizeof(blob),bit);
}

template<> inline uint32_t getbit ( uint32_t & blob, uint32_t bit ) { return (blob >> (bit & 31)) & 1; }
template<> inline uint32_t getbit ( uint64_t & blob, uint32_t bit ) { return (blob >> (bit & 63)) & 1; }

//----------

template< typename T >
inline void setbit ( T & blob, uint32_t bit )
{
  return setbit(&blob,sizeof(blob),bit);
}

template<> inline void setbit ( uint32_t & blob, uint32_t bit ) { blob |= uint32_t(1) << (bit & 31); }
template<> inline void setbit ( uint64_t & blob, uint32_t bit ) { blob |= uint64_t(1) << (bit & 63); }

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
  flipbit(&blob,sizeof(blob),bit);
}

template<> inline void flipbit ( uint32_t & blob, uint32_t bit ) { bit &= 31; blob ^= (uint32_t(1) << bit); }
template<> inline void flipbit ( uint64_t & blob, uint32_t bit ) { bit &= 63; blob ^= (uint64_t(1) << bit); }

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
  reversebits(&blob,sizeof(blob));
}

template<> inline void reversebits ( uint32_t & blob ) { reverse32(blob); }
template<> inline void reversebits ( uint64_t & blob ) { reverse64(blob); }

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
  if((sizeof(T) & 3) == 0)
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

template<> inline void lrot ( uint32_t & blob, int c ) { blob = ROTL32(blob,c); }
template<> inline void lrot ( uint64_t & blob, int c ) { blob = ROTL64(blob,c); }
template<> inline void rrot ( uint32_t & blob, int c ) { blob = ROTR32(blob,c); }
template<> inline void rrot ( uint64_t & blob, int c ) { blob = ROTR64(blob,c); }

//-----------------------------------------------------------------------------
// Bit-windowing functions - select some N-bit subset of the input blob

uint32_t window1  ( void * blob, int len, int start, int count );
uint32_t window8  ( void * blob, int len, int start, int count );
uint32_t window32 ( void * blob, int len, int start, int count );

inline uint32_t window ( void * blob, int len, int start, int count )
{
  if(len & 3)
  {
    return window8(blob,len,start,count);
  }
  else
  {
    return window32(blob,len,start,count);
  }
}

template < typename T >
inline uint32_t window ( T & blob, int start, int count )
{
  if((sizeof(T) & 3) == 0)
  {
    return window32(&blob,sizeof(T),start,count);
  }
  else
  {
    return window8(&blob,sizeof(T),start,count);
  }
}

template<>
inline uint32_t window ( uint32_t & blob, int start, int count )
{
  return ROTR32(blob,start) & ((1<<count)-1);
}

template<>
inline uint32_t window ( uint64_t & blob, int start, int count )
{
  return (uint32_t)ROTR64(blob,start) & ((1<<count)-1);
}

//-----------------------------------------------------------------------------
