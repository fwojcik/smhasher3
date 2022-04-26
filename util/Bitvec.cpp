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
 *     Copyright (c) 2019-2020 Yann Collet
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
#include "Platform.h"
#include "Types.h"
#include "Bitvec.h"

#include <cassert>

//----------------------------------------------------------------------------

static void printKey(const void* key, size_t len)
{
    const unsigned char* const p = (const unsigned char*)key;
    size_t s;
    printf("\n0x");
    for (s=0; s<len; s++) printf("%02X", p[s]);
    printf("\n  ");
    for (s=0; s<len; s+=8) printf("%-16zu", s);
}

void printHash(const void* key, size_t len)
{
    const unsigned char* const p = (const unsigned char*)key;
    assert(len < 2048);
    for (int i=(int)len-1; i >= 0 ; i--) printf("%02x", p[i]);
    printf("  ");
}

void printbits ( const void * blob, int len )
{
  const uint8_t * data = (const uint8_t *)blob;

  printf("[");
  for(int i = 0; i < len; i++)
  {
    unsigned char byte = data[i];

    int hi = (byte >> 4);
    int lo = (byte & 0xF);

    if(hi) printf("%01x",hi);
    else   printf(".");

    if(lo) printf("%01x",lo);
    else   printf(".");

    if(i != len-1) printf(" ");
  }
  printf("]");
}

void printbits2 ( const uint8_t * k, int nbytes )
{
  printf("[");

  for(int i = nbytes-1; i >= 0; i--)
  {
    uint8_t b = k[i];

    for(int j = 7; j >= 0; j--)
    {
      uint8_t c = (b & (1 << j)) ? '#' : ' ';

      putc(c,stdout);
    }
  }
  printf("]");
}

void printhex ( const void * blob, int len )
{
  assert((len & 3) == 0);
  uint8_t * d = (uint8_t*)blob;
  for(int i = 0; i < len; i++)
  {
    printf("%02x",d[i]);
  }
}

void printhex32 ( const void * blob, int len )
{
  assert((len & 3) == 0);

  uint32_t * d = (uint32_t*)blob;

  printf("{ ");

  for(int i = 0; i < len/4; i++)
  {
    printf("0x%08x, ",d[i]);
  }

  printf("}");
}

void printbytes ( const void * blob, int len )
{
  uint8_t * d = (uint8_t*)blob;

  printf("{ ");

  for(int i = 0; i < len; i++)
  {
    printf("0x%02x, ",d[i]);
  }

  printf(" };");
}

void printbytes2 ( const void * blob, int len )
{
  uint8_t * d = (uint8_t*)blob;

  for(int i = 0; i < len; i++)
  {
    printf("%02x ",d[i]);
  }
}
