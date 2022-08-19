/*
 * SHA-1 hash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2014-2021 Reini Urban
 * Copyright (c) 2016-2018 Leo Yuriev
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Based on:
 *     SHA-1 in C
 *     By Steve Reid <steve@edmweb.com>
 *     100% Public Domain
 *
 *     SHA-Instrinsics
 *     Written and place in public domain by Jeffrey Walton
 *     Based on code from Intel, and by Sean Gulley for the miTLS project.
 *     Based on code from ARM, and by Johannes Schneiders,
 *     Skip Hovsmith and Barry O'Rourke for the mbedTLS project.
 */

/* Hash a single 512-bit block. This is the core of the algorithm. */
template <bool bswap>
static void SHA1_Transform( uint32_t state[5], const uint8_t buffer[64] ) {
    uint32_t a, b, c, d, e;
    uint32_t l[16];

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#define blk0(i) (l[i] = GET_U32<bswap>(buffer, 4 * (i)))
#define blk(i)  (l[i & 15] = ROTL32(l[(i + 13) & 15]  ^ \
                                    l[(i +  8) & 15]  ^ \
                                    l[(i +  2) & 15]  ^ \
                                    l[ i       & 15]    \
                                    , 1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i)                                      \
  z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + ROTL32(v, 5); \
  w = ROTL32(w, 30);
#define R1(v, w, x, y, z, i)                                     \
  z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + ROTL32(v, 5); \
  w = ROTL32(w, 30);
#define R2(v, w, x, y, z, i)                             \
  z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + ROTL32(v, 5); \
  w = ROTL32(w, 30);
#define R3(v, w, x, y, z, i)                                           \
  z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + ROTL32(v, 5); \
  w = ROTL32(w, 30);
#define R4(v, w, x, y, z, i)                             \
  z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + ROTL32(v, 5); \
  w = ROTL32(w, 30);

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a, b, c, d, e,  0);
    R0(e, a, b, c, d,  1);
    R0(d, e, a, b, c,  2);
    R0(c, d, e, a, b,  3);
    R0(b, c, d, e, a,  4);
    R0(a, b, c, d, e,  5);
    R0(e, a, b, c, d,  6);
    R0(d, e, a, b, c,  7);
    R0(c, d, e, a, b,  8);
    R0(b, c, d, e, a,  9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);

    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);

    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);

    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);

    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);

    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}
