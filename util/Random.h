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
// Xorshift RNG based on code by George Marsaglia
// http://en.wikipedia.org/wiki/Xorshift

class Rand {
  private:
    uint32_t  x;
    uint32_t  y;
    uint32_t  z;
    uint32_t  w;

  public:
    Rand() {
        reseed(uint32_t(0));
    }

    Rand( uint32_t seed ) {
        reseed(seed);
    }

    void reseed( uint32_t seed ) {
        x = 0x498b3bc5 ^ seed;
        y = 0;
        z = 0;
        w = 0;

        for (int i = 0; i < 10; i++) { mix(); }
    }

    void reseed( uint64_t seed ) {
        x = 0x498b3bc5 ^ (uint32_t)(seed >>  0);
        y = 0x5a05089a ^ (uint32_t)(seed >> 32);
        z = 0;
        w = 0;

        for (int i = 0; i < 10; i++) { mix(); }
    }

    //-----------------------------------------------------------------------------

    void mix( void ) {
        uint32_t t = x ^ (x << 11);

        x = y; y = z; z = w;
        w = w ^ (w >> 19) ^ t ^ (t >> 8);
    }

    uint32_t rand_u32( void ) {
        mix();

        return x;
    }

    uint64_t rand_u64( void ) {
        mix();

        uint64_t a = x;
        uint64_t b = y;

        return (a << 32) | b;
    }

#if defined(HAVE_INT128)

    uint128_t rand_u128( void ) {
        uint128_t a = rand_u64();

        return (a << 64) | rand_u64();
    }

#endif

    // Returns a value in the range [0, max)
    uint32_t rand_range( uint32_t max ) {
        uint64_t r = rand_u32();

        return (r * max) >> 32;
    }

    void rand_p( void * blob, uint64_t bytes ) {
        uint8_t * blocks = reinterpret_cast<uint8_t *>(blob);
        size_t    i;

        while (bytes >= 4) {
            uint32_t r = COND_BSWAP(rand_u32(), isBE());
            memcpy(blocks, &r, 4);
            blocks += 4;
            bytes  -= 4;
        }
        if (bytes > 0) {
            uint32_t r = COND_BSWAP(rand_u32(), isBE());
            memcpy(blocks, &r, bytes);
        }
    }
}; // class Rand

//-----------------------------------------------------------------------------
