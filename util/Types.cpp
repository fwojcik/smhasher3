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
#include "Random.h"

#include <stdio.h>

uint32_t MurmurOAAT ( const char * blob, int len, uint32_t seed );

//-----------------------------------------------------------------------------

#if defined(_MSC_VER)
#pragma optimize( "", off )
#endif

void blackhole ( uint32_t )
{
}

uint32_t whitehole ( void )
{
  return 0;
}

#if defined(_MSC_VER)
#pragma optimize( "", on ) 
#endif

uint64_t g_seed = 0;

//-----------------------------------------------------------------------------
// unused
bool isprime ( uint32_t x )
{
  uint32_t p[] = 
  {
    2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,
    103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,
    199,211,223,227,229,233,239,241,251
  };

  for(size_t i=0; i < sizeof(p)/sizeof(uint32_t); i++)
  { 
    if((x % p[i]) == 0)
    {
      return false;
    }
  } 

  for(int i = 257; i < 65536; i += 2) 
  { 
    if((x % i) == 0)
    {
      return false;
    }
  }

  return true;
}

// unused. useful to create a 32bit hash mixer
void GenerateMixingConstants ( void )
{
  Rand r(8350147);

  int count = 0;

  int trials = 0;
  int bitfail = 0;
  int popfail = 0;
  int matchfail = 0;
  int primefail = 0;

  //for(uint32_t x = 1; x; x++)
  while(count < 100)
  {
    //if(x % 100000000 == 0) printf(".");

    trials++;
    uint32_t b = r.rand_u32();
    //uint32_t b = x;

    //----------
    // must have between 14 and 18 set bits

    if(popcount4(b) < 16) { b = 0; popfail++; }
    if(popcount4(b) > 16) { b = 0; popfail++; }

    if(b == 0) continue;

    //----------
    // must have 3-5 bits set per 8-bit window

    for(int i = 0; i < 32; i++)
    {
      uint32_t c = ROTL32(b,i) & 0xFF;

      if(popcount4(c) < 3) { b = 0; bitfail++; break; }
      if(popcount4(c) > 5) { b = 0; bitfail++; break; }
    }

    if(b == 0) continue;

    //----------
    // all 8-bit windows must be different

    uint8_t match[256];

    memset(match,0,256);

    for(int i = 0; i < 32; i++)
    {
      uint32_t c = ROTL32(b,i) & 0xFF;
      
      if(match[c]) { b = 0; matchfail++; break; }

      match[c] = 1;
    }

    if(b == 0) continue;

    //----------
    // must be prime

    if(!isprime(b))
    {
      b = 0;
      primefail++;
    }

    if(b == 0) continue;

    //----------

    if(b)
    {
      printf("0x%08x : 0x%08x\n",b,~b);
      count++;
    }
  }

  printf("%d %d %d %d %d %d\n",trials,popfail,bitfail,matchfail,primefail,count);
}

//-----------------------------------------------------------------------------
