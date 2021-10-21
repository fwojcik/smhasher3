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
 *     Copyright (c) 2020-2021 Reini Urban
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

#include "Types.h"

//-----------------------------------------------------------------------------
// Xorshift RNG based on code by George Marsaglia
// http://en.wikipedia.org/wiki/Xorshift

struct Rand
{
  uint32_t x;
  uint32_t y;
  uint32_t z;
  uint32_t w;

  Rand()
  {
    reseed(uint32_t(0));
  }

  Rand( uint32_t seed )
  {
    reseed(seed);
  }

  void reseed ( uint32_t seed )
  {
    x = 0x498b3bc5 ^ seed;
    y = 0;
    z = 0;
    w = 0;

    for(int i = 0; i < 10; i++) mix();
  }

  void reseed ( uint64_t seed )
  {
    x = 0x498b3bc5 ^ (uint32_t)(seed >>  0);
    y = 0x5a05089a ^ (uint32_t)(seed >> 32);
    z = 0;
    w = 0;

    for(int i = 0; i < 10; i++) mix();
  }

  //-----------------------------------------------------------------------------

  void mix ( void )
  {
    uint32_t t = x ^ (x << 11);
    x = y; y = z; z = w;
    w = w ^ (w >> 19) ^ t ^ (t >> 8); 
  }

  uint32_t rand_u32 ( void )
  {
    mix();

    return x;
  }

  uint64_t rand_u64 ( void ) 
  {
    mix();

    uint64_t a = x;
    uint64_t b = y;

    return (a << 32) | b;
  }

#ifdef __SIZEOF_INT128__
  __uint128_t rand_u128 ( void ) 
  {
    __uint128_t a = rand_u64();
    return (a << 64) | rand_u64();
  }
#endif

  void rand_p ( void * blob, int bytes )
  {
    uint32_t * blocks;
    int i;

#ifdef HAVE_ALIGNED_ACCESS_REQUIRED
    // avoid ubsan, misaligned writes
    if ((i = (uintptr_t)blob % 4)) {
      uint8_t *pre = reinterpret_cast<uint8_t*>(blob);
      uint32_t u = rand_u32();
      switch (i) {
      case 1:
        *pre++ = u & 0xff; u >>= 8;
      case 2:
        *pre++ = u & 0xff; u >>= 8;
      case 3:
        *pre++ = u & 0xff;
      default:
        break;
      }
      blocks = reinterpret_cast<uint32_t*>(pre);
    }
    else
#endif
      blocks = reinterpret_cast<uint32_t*>(blob);

    while(bytes >= 4)
    {
      *blocks = rand_u32();
      blocks++;
      bytes -= 4;
    }

    uint8_t * tail = reinterpret_cast<uint8_t*>(blocks);
    for (i = 0; i < bytes; i++)
    {
      tail[i] = (uint8_t)rand_u32();
    }
  }
};

//-----------------------------------------------------------------------------

extern Rand g_rand1;

inline uint32_t rand_u32 ( void ) { return g_rand1.rand_u32(); }
inline uint64_t rand_u64 ( void ) { return g_rand1.rand_u64(); }
#ifdef __SIZEOF_INT128__
inline __uint128_t rand_u128 ( void ) { return g_rand1.rand_u128(); }
#endif

inline void rand_p ( void * blob, int bytes )
{
  uint32_t * blocks;
  int i;
  // avoid ubsan, misaligned writes
  if ((i = (uintptr_t)blob % 4)) {
    uint8_t *pre = reinterpret_cast<uint8_t*>(blob);
    uint32_t u = rand_u32();
    switch (i) {
    case 1:
      *pre++ = u & 0xff; u >>= 8;
    case 2:
      *pre++ = u & 0xff; u >>= 8;
    case 3:
      *pre++ = u & 0xff;
    default:
      break;
    }
    blocks = reinterpret_cast<uint32_t*>(pre);
  }
  else
    blocks = reinterpret_cast<uint32_t*>(blob);

  while(bytes >= 4)
  {
    *blocks++ = rand_u32();
    bytes -= 4;
  }

  uint8_t * tail = (uint8_t*)blocks;
  for (i = 0; i < bytes; i++)
  {
    tail[i] = (uint8_t)rand_u32();
  }
}

//-----------------------------------------------------------------------------