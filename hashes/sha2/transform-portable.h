/*
 * SHA-2 hash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2019-2021 Reini Urban
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
 *     SHA-Instrinsics
 *     Written and place in public domain by Jeffrey Walton
 *     Based on code from Intel, and by Sean Gulley for the miTLS project.
 *     Based on code from ARM, and by Johannes Schneiders,
 *     Skip Hovsmith and Barry O'Rourke for the mbedTLS project.
 */

static const uint32_t K256[] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

#define ROTATE(x, y)  (((x) >> (y)) | ((x) << (32 - (y))))
#define Sigma0(x)    (ROTATE((x),  2) ^ ROTATE((x), 13) ^ ROTATE((x), 22))
#define Sigma1(x)    (ROTATE((x),  6) ^ ROTATE((x), 11) ^ ROTATE((x), 25))
#define sigma0(x)    (ROTATE((x),  7) ^ ROTATE((x), 18) ^ ((x) >> 3))
#define sigma1(x)    (ROTATE((x), 17) ^ ROTATE((x), 19) ^ ((x) >> 10))

#define Ch(x, y, z)    (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x, y, z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

template <bool bswap>
static void SHA256_Transform( uint32_t state[8], const uint8_t buffer[64] ) {
    uint32_t a, b, c, d, e, f, g, h, s0, s1, T1, T2;
    uint32_t X[16], i;

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (i = 0; i < 16; i++) {
        X[i] = GET_U32<bswap>(buffer, i * 4);

        T1   = h;
        T1  += Sigma1(e);
        T1  += Ch(e, f, g);
        T1  += K256[i];
        T1  += X[i];

        T2   = Sigma0(a);
        T2  += Maj(a, b, c);

        h    = g;
        g    = f;
        f    = e;
        e    = d + T1;
        d    = c;
        c    = b;
        b    = a;
        a    = T1 + T2;
    }

    for (; i < 64; i++) {
        s0  = X[(i +  1) & 0x0f];
        s0  = sigma0(s0);
        s1  = X[(i + 14) & 0x0f];
        s1  = sigma1(s1);

        T1  = X[i & 0xf] += s0 + s1 + X[(i + 9) & 0xf];
        T1 += h + Sigma1(e) + Ch(e, f, g) + K256[i];
        T2  = Sigma0(a) + Maj(a, b, c);
        h   = g;
        g   = f;
        f   = e;
        e   = d + T1;
        d   = c;
        c   = b;
        b   = a;
        a   = T1 + T2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}
