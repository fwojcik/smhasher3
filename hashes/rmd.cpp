/*
 * RIPEMD hash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
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
 * based on:
 *     The RIPEMD source by Antoon Bosselaers, ESAT-COSIC
 *     LibTomCrypt API Tom St Denis
 */
#include "Platform.h"
#include "Hashlib.h"

typedef struct {
    uint64_t  length;
    uint8_t   buf[64];
    uint32_t  curlen, state[8];
} rmd_ctx;

/* the five basic functions */
#define F(x, y, z)        ((x) ^ (y) ^ (z))
#define G(x, y, z)        (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z)        (((x) | ~(y)) ^ (z))
#define I(x, y, z)        (((x) & (z)) | ((y) & ~(z)))
#define J(x, y, z)        ((x) ^ ((y) | ~(z)))

#define OP4(f, a, b, c, d, x, s, k)    \
  (a) += f((b), (c), (d)) + (x) + (k); \
  (a) = ROTL32((a), (s));

#define OP5(f, a, b, c, d, e, x, s, k) \
  (a) += f((b), (c), (d)) + (x) + (k); \
  (a) = ROTL32((a), (s)) + (e);        \
  (c) = ROTL32((c), 10);

template <uint32_t hashwidth, bool bswap>
static void rmd_compress( rmd_ctx * ctx, const uint8_t * buf ) {
    uint32_t aa, bb, cc, dd, ee, aaa, bbb, ccc, ddd, eee, X[16];
    int      i;
    const uint32_t k0 = 0;
    const uint32_t k1 = 0x50a28be6;
    const uint32_t k2 = 0x5a827999;
    const uint32_t k3 = 0x5c4dd124;
    const uint32_t k4 = 0x6ed9eba1;
    const uint32_t k5 = 0x6d703ef3;
    const uint32_t k6 = 0x8f1bbcdc;
    const uint32_t k7 = 0;
    const uint32_t k8 = 0xa953fd4e;
    const uint32_t k9 = 0x7a6d76e9;

    /* load words X */
    for (i = 0; i < 16; i++) {
        X[i] = GET_U32<bswap>(buf, (4 * i));
    }

    /* load state */
    aa = aaa = ctx->state[0];
    bb = bbb = ctx->state[1];
    cc = ccc = ctx->state[2];
    dd = ddd = ctx->state[3];
    if (hashwidth == 160) {
        ee = eee = ctx->state[4];
    } else if (hashwidth == 256) {
        aaa = ctx->state[4];
        bbb = ctx->state[5];
        ccc = ctx->state[6];
        ddd = ctx->state[7];
    }

    /* round 1 */
    if (hashwidth == 160) {
        OP5(F, aa , bb , cc , dd , ee , X[0] , 11, k0);
        OP5(F, ee , aa , bb , cc , dd , X[1] , 14, k0);
        OP5(F, dd , ee , aa , bb , cc , X[2] , 15, k0);
        OP5(F, cc , dd , ee , aa , bb , X[3] , 12, k0);
        OP5(F, bb , cc , dd , ee , aa , X[4] ,  5, k0);
        OP5(F, aa , bb , cc , dd , ee , X[5] ,  8, k0);
        OP5(F, ee , aa , bb , cc , dd , X[6] ,  7, k0);
        OP5(F, dd , ee , aa , bb , cc , X[7] ,  9, k0);
        OP5(F, cc , dd , ee , aa , bb , X[8] , 11, k0);
        OP5(F, bb , cc , dd , ee , aa , X[9] , 13, k0);
        OP5(F, aa , bb , cc , dd , ee , X[10], 14, k0);
        OP5(F, ee , aa , bb , cc , dd , X[11], 15, k0);
        OP5(F, dd , ee , aa , bb , cc , X[12],  6, k0);
        OP5(F, cc , dd , ee , aa , bb , X[13],  7, k0);
        OP5(F, bb , cc , dd , ee , aa , X[14],  9, k0);
        OP5(F, aa , bb , cc , dd , ee , X[15],  8, k0);

        OP5(J, aaa, bbb, ccc, ddd, eee, X[5] ,  8, k1);
        OP5(J, eee, aaa, bbb, ccc, ddd, X[14],  9, k1);
        OP5(J, ddd, eee, aaa, bbb, ccc, X[7] ,  9, k1);
        OP5(J, ccc, ddd, eee, aaa, bbb, X[0] , 11, k1);
        OP5(J, bbb, ccc, ddd, eee, aaa, X[9] , 13, k1);
        OP5(J, aaa, bbb, ccc, ddd, eee, X[2] , 15, k1);
        OP5(J, eee, aaa, bbb, ccc, ddd, X[11], 15, k1);
        OP5(J, ddd, eee, aaa, bbb, ccc, X[4] ,  5, k1);
        OP5(J, ccc, ddd, eee, aaa, bbb, X[13],  7, k1);
        OP5(J, bbb, ccc, ddd, eee, aaa, X[6] ,  7, k1);
        OP5(J, aaa, bbb, ccc, ddd, eee, X[15],  8, k1);
        OP5(J, eee, aaa, bbb, ccc, ddd, X[8] , 11, k1);
        OP5(J, ddd, eee, aaa, bbb, ccc, X[1] , 14, k1);
        OP5(J, ccc, ddd, eee, aaa, bbb, X[10], 14, k1);
        OP5(J, bbb, ccc, ddd, eee, aaa, X[3] , 12, k1);
        OP5(J, aaa, bbb, ccc, ddd, eee, X[12],  6, k1);
    } else {
        OP4(F, aa , bb , cc , dd , X[0] , 11, k0);
        OP4(F, dd , aa , bb , cc , X[1] , 14, k0);
        OP4(F, cc , dd , aa , bb , X[2] , 15, k0);
        OP4(F, bb , cc , dd , aa , X[3] , 12, k0);
        OP4(F, aa , bb , cc , dd , X[4] ,  5, k0);
        OP4(F, dd , aa , bb , cc , X[5] ,  8, k0);
        OP4(F, cc , dd , aa , bb , X[6] ,  7, k0);
        OP4(F, bb , cc , dd , aa , X[7] ,  9, k0);
        OP4(F, aa , bb , cc , dd , X[8] , 11, k0);
        OP4(F, dd , aa , bb , cc , X[9] , 13, k0);
        OP4(F, cc , dd , aa , bb , X[10], 14, k0);
        OP4(F, bb , cc , dd , aa , X[11], 15, k0);
        OP4(F, aa , bb , cc , dd , X[12],  6, k0);
        OP4(F, dd , aa , bb , cc , X[13],  7, k0);
        OP4(F, cc , dd , aa , bb , X[14],  9, k0);
        OP4(F, bb , cc , dd , aa , X[15],  8, k0);

        OP4(I, aaa, bbb, ccc, ddd, X[5] ,  8, k1);
        OP4(I, ddd, aaa, bbb, ccc, X[14],  9, k1);
        OP4(I, ccc, ddd, aaa, bbb, X[7] ,  9, k1);
        OP4(I, bbb, ccc, ddd, aaa, X[0] , 11, k1);
        OP4(I, aaa, bbb, ccc, ddd, X[9] , 13, k1);
        OP4(I, ddd, aaa, bbb, ccc, X[2] , 15, k1);
        OP4(I, ccc, ddd, aaa, bbb, X[11], 15, k1);
        OP4(I, bbb, ccc, ddd, aaa, X[4] ,  5, k1);
        OP4(I, aaa, bbb, ccc, ddd, X[13],  7, k1);
        OP4(I, ddd, aaa, bbb, ccc, X[6] ,  7, k1);
        OP4(I, ccc, ddd, aaa, bbb, X[15],  8, k1);
        OP4(I, bbb, ccc, ddd, aaa, X[8] , 11, k1);
        OP4(I, aaa, bbb, ccc, ddd, X[1] , 14, k1);
        OP4(I, ddd, aaa, bbb, ccc, X[10], 14, k1);
        OP4(I, ccc, ddd, aaa, bbb, X[3] , 12, k1);
        OP4(I, bbb, ccc, ddd, aaa, X[12],  6, k1);

        if (hashwidth == 256) {
            uint64_t tmp = aa; aa = aaa; aaa = tmp;
        }
    }

    /* round 2 */
    if (hashwidth == 160) {
        OP5(G, ee , aa , bb , cc , dd , X[7] ,  7, k2);
        OP5(G, dd , ee , aa , bb , cc , X[4] ,  6, k2);
        OP5(G, cc , dd , ee , aa , bb , X[13],  8, k2);
        OP5(G, bb , cc , dd , ee , aa , X[1] , 13, k2);
        OP5(G, aa , bb , cc , dd , ee , X[10], 11, k2);
        OP5(G, ee , aa , bb , cc , dd , X[6] ,  9, k2);
        OP5(G, dd , ee , aa , bb , cc , X[15],  7, k2);
        OP5(G, cc , dd , ee , aa , bb , X[3] , 15, k2);
        OP5(G, bb , cc , dd , ee , aa , X[12],  7, k2);
        OP5(G, aa , bb , cc , dd , ee , X[0] , 12, k2);
        OP5(G, ee , aa , bb , cc , dd , X[9] , 15, k2);
        OP5(G, dd , ee , aa , bb , cc , X[5] ,  9, k2);
        OP5(G, cc , dd , ee , aa , bb , X[2] , 11, k2);
        OP5(G, bb , cc , dd , ee , aa , X[14],  7, k2);
        OP5(G, aa , bb , cc , dd , ee , X[11], 13, k2);
        OP5(G, ee , aa , bb , cc , dd , X[8] , 12, k2);

        OP5(I, eee, aaa, bbb, ccc, ddd, X[6] ,  9, k3);
        OP5(I, ddd, eee, aaa, bbb, ccc, X[11], 13, k3);
        OP5(I, ccc, ddd, eee, aaa, bbb, X[3] , 15, k3);
        OP5(I, bbb, ccc, ddd, eee, aaa, X[7] ,  7, k3);
        OP5(I, aaa, bbb, ccc, ddd, eee, X[0] , 12, k3);
        OP5(I, eee, aaa, bbb, ccc, ddd, X[13],  8, k3);
        OP5(I, ddd, eee, aaa, bbb, ccc, X[5] ,  9, k3);
        OP5(I, ccc, ddd, eee, aaa, bbb, X[10], 11, k3);
        OP5(I, bbb, ccc, ddd, eee, aaa, X[14],  7, k3);
        OP5(I, aaa, bbb, ccc, ddd, eee, X[15],  7, k3);
        OP5(I, eee, aaa, bbb, ccc, ddd, X[8] , 12, k3);
        OP5(I, ddd, eee, aaa, bbb, ccc, X[12],  7, k3);
        OP5(I, ccc, ddd, eee, aaa, bbb, X[4] ,  6, k3);
        OP5(I, bbb, ccc, ddd, eee, aaa, X[9] , 15, k3);
        OP5(I, aaa, bbb, ccc, ddd, eee, X[1] , 13, k3);
        OP5(I, eee, aaa, bbb, ccc, ddd, X[2] , 11, k3);
    } else {
        OP4(G, aa , bb , cc , dd , X[7] ,  7, k2);
        OP4(G, dd , aa , bb , cc , X[4] ,  6, k2);
        OP4(G, cc , dd , aa , bb , X[13],  8, k2);
        OP4(G, bb , cc , dd , aa , X[1] , 13, k2);
        OP4(G, aa , bb , cc , dd , X[10], 11, k2);
        OP4(G, dd , aa , bb , cc , X[6] ,  9, k2);
        OP4(G, cc , dd , aa , bb , X[15],  7, k2);
        OP4(G, bb , cc , dd , aa , X[3] , 15, k2);
        OP4(G, aa , bb , cc , dd , X[12],  7, k2);
        OP4(G, dd , aa , bb , cc , X[0] , 12, k2);
        OP4(G, cc , dd , aa , bb , X[9] , 15, k2);
        OP4(G, bb , cc , dd , aa , X[5] ,  9, k2);
        OP4(G, aa , bb , cc , dd , X[2] , 11, k2);
        OP4(G, dd , aa , bb , cc , X[14],  7, k2);
        OP4(G, cc , dd , aa , bb , X[11], 13, k2);
        OP4(G, bb , cc , dd , aa , X[8] , 12, k2);

        OP4(H, aaa, bbb, ccc, ddd, X[6] ,  9, k3);
        OP4(H, ddd, aaa, bbb, ccc, X[11], 13, k3);
        OP4(H, ccc, ddd, aaa, bbb, X[3] , 15, k3);
        OP4(H, bbb, ccc, ddd, aaa, X[7] ,  7, k3);
        OP4(H, aaa, bbb, ccc, ddd, X[0] , 12, k3);
        OP4(H, ddd, aaa, bbb, ccc, X[13],  8, k3);
        OP4(H, ccc, ddd, aaa, bbb, X[5] ,  9, k3);
        OP4(H, bbb, ccc, ddd, aaa, X[10], 11, k3);
        OP4(H, aaa, bbb, ccc, ddd, X[14],  7, k3);
        OP4(H, ddd, aaa, bbb, ccc, X[15],  7, k3);
        OP4(H, ccc, ddd, aaa, bbb, X[8] , 12, k3);
        OP4(H, bbb, ccc, ddd, aaa, X[12],  7, k3);
        OP4(H, aaa, bbb, ccc, ddd, X[4] ,  6, k3);
        OP4(H, ddd, aaa, bbb, ccc, X[9] , 15, k3);
        OP4(H, ccc, ddd, aaa, bbb, X[1] , 13, k3);
        OP4(H, bbb, ccc, ddd, aaa, X[2] , 11, k3);

        if (hashwidth == 256) {
            uint64_t tmp = bb; bb = bbb; bbb = tmp;
        }
    }

    /* round 3 */
    if (hashwidth == 160) {
        OP5(H, dd , ee , aa , bb , cc , X[3] , 11, k4);
        OP5(H, cc , dd , ee , aa , bb , X[10], 13, k4);
        OP5(H, bb , cc , dd , ee , aa , X[14],  6, k4);
        OP5(H, aa , bb , cc , dd , ee , X[4] ,  7, k4);
        OP5(H, ee , aa , bb , cc , dd , X[9] , 14, k4);
        OP5(H, dd , ee , aa , bb , cc , X[15],  9, k4);
        OP5(H, cc , dd , ee , aa , bb , X[8] , 13, k4);
        OP5(H, bb , cc , dd , ee , aa , X[1] , 15, k4);
        OP5(H, aa , bb , cc , dd , ee , X[2] , 14, k4);
        OP5(H, ee , aa , bb , cc , dd , X[7] ,  8, k4);
        OP5(H, dd , ee , aa , bb , cc , X[0] , 13, k4);
        OP5(H, cc , dd , ee , aa , bb , X[6] ,  6, k4);
        OP5(H, bb , cc , dd , ee , aa , X[13],  5, k4);
        OP5(H, aa , bb , cc , dd , ee , X[11], 12, k4);
        OP5(H, ee , aa , bb , cc , dd , X[5] ,  7, k4);
        OP5(H, dd , ee , aa , bb , cc , X[12],  5, k4);

        OP5(H, ddd, eee, aaa, bbb, ccc, X[15],  9, k5);
        OP5(H, ccc, ddd, eee, aaa, bbb, X[5] ,  7, k5);
        OP5(H, bbb, ccc, ddd, eee, aaa, X[1] , 15, k5);
        OP5(H, aaa, bbb, ccc, ddd, eee, X[3] , 11, k5);
        OP5(H, eee, aaa, bbb, ccc, ddd, X[7] ,  8, k5);
        OP5(H, ddd, eee, aaa, bbb, ccc, X[14],  6, k5);
        OP5(H, ccc, ddd, eee, aaa, bbb, X[6] ,  6, k5);
        OP5(H, bbb, ccc, ddd, eee, aaa, X[9] , 14, k5);
        OP5(H, aaa, bbb, ccc, ddd, eee, X[11], 12, k5);
        OP5(H, eee, aaa, bbb, ccc, ddd, X[8] , 13, k5);
        OP5(H, ddd, eee, aaa, bbb, ccc, X[12],  5, k5);
        OP5(H, ccc, ddd, eee, aaa, bbb, X[2] , 14, k5);
        OP5(H, bbb, ccc, ddd, eee, aaa, X[10], 13, k5);
        OP5(H, aaa, bbb, ccc, ddd, eee, X[0] , 13, k5);
        OP5(H, eee, aaa, bbb, ccc, ddd, X[4] ,  7, k5);
        OP5(H, ddd, eee, aaa, bbb, ccc, X[13],  5, k5);
    } else {
        OP4(H, aa , bb , cc , dd , X[3] , 11, k4);
        OP4(H, dd , aa , bb , cc , X[10], 13, k4);
        OP4(H, cc , dd , aa , bb , X[14],  6, k4);
        OP4(H, bb , cc , dd , aa , X[4] ,  7, k4);
        OP4(H, aa , bb , cc , dd , X[9] , 14, k4);
        OP4(H, dd , aa , bb , cc , X[15],  9, k4);
        OP4(H, cc , dd , aa , bb , X[8] , 13, k4);
        OP4(H, bb , cc , dd , aa , X[1] , 15, k4);
        OP4(H, aa , bb , cc , dd , X[2] , 14, k4);
        OP4(H, dd , aa , bb , cc , X[7] ,  8, k4);
        OP4(H, cc , dd , aa , bb , X[0] , 13, k4);
        OP4(H, bb , cc , dd , aa , X[6] ,  6, k4);
        OP4(H, aa , bb , cc , dd , X[13],  5, k4);
        OP4(H, dd , aa , bb , cc , X[11], 12, k4);
        OP4(H, cc , dd , aa , bb , X[5] ,  7, k4);
        OP4(H, bb , cc , dd , aa , X[12],  5, k4);

        OP4(G, aaa, bbb, ccc, ddd, X[15],  9, k5);
        OP4(G, ddd, aaa, bbb, ccc, X[5] ,  7, k5);
        OP4(G, ccc, ddd, aaa, bbb, X[1] , 15, k5);
        OP4(G, bbb, ccc, ddd, aaa, X[3] , 11, k5);
        OP4(G, aaa, bbb, ccc, ddd, X[7] ,  8, k5);
        OP4(G, ddd, aaa, bbb, ccc, X[14],  6, k5);
        OP4(G, ccc, ddd, aaa, bbb, X[6] ,  6, k5);
        OP4(G, bbb, ccc, ddd, aaa, X[9] , 14, k5);
        OP4(G, aaa, bbb, ccc, ddd, X[11], 12, k5);
        OP4(G, ddd, aaa, bbb, ccc, X[8] , 13, k5);
        OP4(G, ccc, ddd, aaa, bbb, X[12],  5, k5);
        OP4(G, bbb, ccc, ddd, aaa, X[2] , 14, k5);
        OP4(G, aaa, bbb, ccc, ddd, X[10], 13, k5);
        OP4(G, ddd, aaa, bbb, ccc, X[0] , 13, k5);
        OP4(G, ccc, ddd, aaa, bbb, X[4] ,  7, k5);
        OP4(G, bbb, ccc, ddd, aaa, X[13],  5, k5);

        if (hashwidth == 256) {
            uint64_t tmp = cc; cc = ccc; ccc = tmp;
        }
    }

    /* round 4 */
    if (hashwidth == 160) {
        OP5(I, cc , dd , ee , aa , bb , X[1] , 11, k6);
        OP5(I, bb , cc , dd , ee , aa , X[9] , 12, k6);
        OP5(I, aa , bb , cc , dd , ee , X[11], 14, k6);
        OP5(I, ee , aa , bb , cc , dd , X[10], 15, k6);
        OP5(I, dd , ee , aa , bb , cc , X[0] , 14, k6);
        OP5(I, cc , dd , ee , aa , bb , X[8] , 15, k6);
        OP5(I, bb , cc , dd , ee , aa , X[12],  9, k6);
        OP5(I, aa , bb , cc , dd , ee , X[4] ,  8, k6);
        OP5(I, ee , aa , bb , cc , dd , X[13],  9, k6);
        OP5(I, dd , ee , aa , bb , cc , X[3] , 14, k6);
        OP5(I, cc , dd , ee , aa , bb , X[7] ,  5, k6);
        OP5(I, bb , cc , dd , ee , aa , X[15],  6, k6);
        OP5(I, aa , bb , cc , dd , ee , X[14],  8, k6);
        OP5(I, ee , aa , bb , cc , dd , X[5] ,  6, k6);
        OP5(I, dd , ee , aa , bb , cc , X[6] ,  5, k6);
        OP5(I, cc , dd , ee , aa , bb , X[2] , 12, k6);

        OP5(G, ccc, ddd, eee, aaa, bbb, X[8] , 15, k9);
        OP5(G, bbb, ccc, ddd, eee, aaa, X[6] ,  5, k9);
        OP5(G, aaa, bbb, ccc, ddd, eee, X[4] ,  8, k9);
        OP5(G, eee, aaa, bbb, ccc, ddd, X[1] , 11, k9);
        OP5(G, ddd, eee, aaa, bbb, ccc, X[3] , 14, k9);
        OP5(G, ccc, ddd, eee, aaa, bbb, X[11], 14, k9);
        OP5(G, bbb, ccc, ddd, eee, aaa, X[15],  6, k9);
        OP5(G, aaa, bbb, ccc, ddd, eee, X[0] , 14, k9);
        OP5(G, eee, aaa, bbb, ccc, ddd, X[5] ,  6, k9);
        OP5(G, ddd, eee, aaa, bbb, ccc, X[12],  9, k9);
        OP5(G, ccc, ddd, eee, aaa, bbb, X[2] , 12, k9);
        OP5(G, bbb, ccc, ddd, eee, aaa, X[13],  9, k9);
        OP5(G, aaa, bbb, ccc, ddd, eee, X[9] , 12, k9);
        OP5(G, eee, aaa, bbb, ccc, ddd, X[7] ,  5, k9);
        OP5(G, ddd, eee, aaa, bbb, ccc, X[10], 15, k9);
        OP5(G, ccc, ddd, eee, aaa, bbb, X[14],  8, k9);
    } else {
        OP4(I, aa , bb , cc , dd , X[1] , 11, k6);
        OP4(I, dd , aa , bb , cc , X[9] , 12, k6);
        OP4(I, cc , dd , aa , bb , X[11], 14, k6);
        OP4(I, bb , cc , dd , aa , X[10], 15, k6);
        OP4(I, aa , bb , cc , dd , X[0] , 14, k6);
        OP4(I, dd , aa , bb , cc , X[8] , 15, k6);
        OP4(I, cc , dd , aa , bb , X[12],  9, k6);
        OP4(I, bb , cc , dd , aa , X[4] ,  8, k6);
        OP4(I, aa , bb , cc , dd , X[13],  9, k6);
        OP4(I, dd , aa , bb , cc , X[3] , 14, k6);
        OP4(I, cc , dd , aa , bb , X[7] ,  5, k6);
        OP4(I, bb , cc , dd , aa , X[15],  6, k6);
        OP4(I, aa , bb , cc , dd , X[14],  8, k6);
        OP4(I, dd , aa , bb , cc , X[5] ,  6, k6);
        OP4(I, cc , dd , aa , bb , X[6] ,  5, k6);
        OP4(I, bb , cc , dd , aa , X[2] , 12, k6);

        OP4(F, aaa, bbb, ccc, ddd, X[8] , 15, k7);
        OP4(F, ddd, aaa, bbb, ccc, X[6] ,  5, k7);
        OP4(F, ccc, ddd, aaa, bbb, X[4] ,  8, k7);
        OP4(F, bbb, ccc, ddd, aaa, X[1] , 11, k7);
        OP4(F, aaa, bbb, ccc, ddd, X[3] , 14, k7);
        OP4(F, ddd, aaa, bbb, ccc, X[11], 14, k7);
        OP4(F, ccc, ddd, aaa, bbb, X[15],  6, k7);
        OP4(F, bbb, ccc, ddd, aaa, X[0] , 14, k7);
        OP4(F, aaa, bbb, ccc, ddd, X[5] ,  6, k7);
        OP4(F, ddd, aaa, bbb, ccc, X[12],  9, k7);
        OP4(F, ccc, ddd, aaa, bbb, X[2] , 12, k7);
        OP4(F, bbb, ccc, ddd, aaa, X[13],  9, k7);
        OP4(F, aaa, bbb, ccc, ddd, X[9] , 12, k7);
        OP4(F, ddd, aaa, bbb, ccc, X[7] ,  5, k7);
        OP4(F, ccc, ddd, aaa, bbb, X[10], 15, k7);
        OP4(F, bbb, ccc, ddd, aaa, X[14],  8, k7);

        if (hashwidth == 256) {
            uint64_t tmp = dd; dd = ddd; ddd = tmp;
        }
    }

    /* round 5 */
    if (hashwidth == 160) {
        OP5(J, bb , cc , dd , ee , aa , X[4] ,  9, k8);
        OP5(J, aa , bb , cc , dd , ee , X[0] , 15, k8);
        OP5(J, ee , aa , bb , cc , dd , X[5] ,  5, k8);
        OP5(J, dd , ee , aa , bb , cc , X[9] , 11, k8);
        OP5(J, cc , dd , ee , aa , bb , X[7] ,  6, k8);
        OP5(J, bb , cc , dd , ee , aa , X[12],  8, k8);
        OP5(J, aa , bb , cc , dd , ee , X[2] , 13, k8);
        OP5(J, ee , aa , bb , cc , dd , X[10], 12, k8);
        OP5(J, dd , ee , aa , bb , cc , X[14],  5, k8);
        OP5(J, cc , dd , ee , aa , bb , X[1] , 12, k8);
        OP5(J, bb , cc , dd , ee , aa , X[3] , 13, k8);
        OP5(J, aa , bb , cc , dd , ee , X[8] , 14, k8);
        OP5(J, ee , aa , bb , cc , dd , X[11], 11, k8);
        OP5(J, dd , ee , aa , bb , cc , X[6] ,  8, k8);
        OP5(J, cc , dd , ee , aa , bb , X[15],  5, k8);
        OP5(J, bb , cc , dd , ee , aa , X[13],  6, k8);

        OP5(F, bbb, ccc, ddd, eee, aaa, X[12],  8, k7);
        OP5(F, aaa, bbb, ccc, ddd, eee, X[15],  5, k7);
        OP5(F, eee, aaa, bbb, ccc, ddd, X[10], 12, k7);
        OP5(F, ddd, eee, aaa, bbb, ccc, X[4] ,  9, k7);
        OP5(F, ccc, ddd, eee, aaa, bbb, X[1] , 12, k7);
        OP5(F, bbb, ccc, ddd, eee, aaa, X[5] ,  5, k7);
        OP5(F, aaa, bbb, ccc, ddd, eee, X[8] , 14, k7);
        OP5(F, eee, aaa, bbb, ccc, ddd, X[7] ,  6, k7);
        OP5(F, ddd, eee, aaa, bbb, ccc, X[6] ,  8, k7);
        OP5(F, ccc, ddd, eee, aaa, bbb, X[2] , 13, k7);
        OP5(F, bbb, ccc, ddd, eee, aaa, X[13],  6, k7);
        OP5(F, aaa, bbb, ccc, ddd, eee, X[14],  5, k7);
        OP5(F, eee, aaa, bbb, ccc, ddd, X[0] , 15, k7);
        OP5(F, ddd, eee, aaa, bbb, ccc, X[3] , 13, k7);
        OP5(F, ccc, ddd, eee, aaa, bbb, X[9] , 11, k7);
        OP5(F, bbb, ccc, ddd, eee, aaa, X[11], 11, k7);
    }

    /* combine results */
    if (hashwidth == 128) {
        ddd += cc + ctx->state[1]; /* final result for MDbuf[0] */
        ctx->state[1] = ctx->state[2] + dd + aaa;
        ctx->state[2] = ctx->state[3] + aa + bbb;
        ctx->state[3] = ctx->state[0] + bb + ccc;
        ctx->state[0] = ddd;
    } else if (hashwidth == 160) {
        ddd += cc + ctx->state[1]; /* final result for MDbuf[0] */
        ctx->state[1] = ctx->state[2] + dd + eee;
        ctx->state[2] = ctx->state[3] + ee + aaa;
        ctx->state[3] = ctx->state[4] + aa + bbb;
        ctx->state[4] = ctx->state[0] + bb + ccc;
        ctx->state[0] = ddd;
    } else if (hashwidth == 256) {
        ctx->state[0] += aa;
        ctx->state[1] += bb;
        ctx->state[2] += cc;
        ctx->state[3] += dd;
        ctx->state[4] += aaa;
        ctx->state[5] += bbb;
        ctx->state[6] += ccc;
        ctx->state[7] += ddd;
    }

    return;
}

template <uint32_t hashwidth>
static void rmd_init( rmd_ctx * ctx ) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    if (hashwidth >= 160) {
        ctx->state[4] = 0xc3d2e1f0;
    }
    if (hashwidth == 256) {
        ctx->state[4] = 0x76543210;
        ctx->state[5] = 0xfedcba98;
        ctx->state[6] = 0x89abcdef;
        ctx->state[7] = 0x01234567;
    }
    ctx->curlen = 0;
    ctx->length = 0;
    return;
}

template <uint32_t hashwidth, bool bswap>
static void rmd_done( rmd_ctx * ctx, uint8_t * out ) {
    unsigned int i;

    /* increase the length of the message */
    ctx->length += ctx->curlen * 8;

    /* append the '1' bit */
    ctx->buf[ctx->curlen++] = (unsigned char)0x80;

    /*
     * if the length is currently above 56 bytes we append zeros then
     * compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (ctx->curlen > 56) {
        while (ctx->curlen < 64) {
            ctx->buf[ctx->curlen++] = (unsigned char)0;
        }
        rmd_compress<hashwidth, bswap>(ctx, ctx->buf);
        ctx->curlen = 0;
    }

    /* pad up to 56 bytes of zeroes */
    while (ctx->curlen < 56) {
        ctx->buf[ctx->curlen++] = (unsigned char)0;
    }

    /* store length */
    if (isBE()) {
        PUT_U64<true>(ctx->length, ctx->buf + 56, 0);
    } else {
        PUT_U64<false>(ctx->length, ctx->buf + 56, 0);
    }
    rmd_compress<hashwidth, bswap>(ctx, ctx->buf);

    /* copy output */
    for (i = 0; i < (hashwidth / 32); i++) {
        PUT_U32<bswap>(ctx->state[i], (uint8_t *)out, 4 * i);
    }
}

template <uint32_t hashwidth, bool bswap>
static void rmd_update( rmd_ctx * ctx, const uint8_t * data, size_t len ) {
    while (len > 0) {
        if ((ctx->length == 0) && (len >= sizeof(ctx->buf))) {
            rmd_compress<hashwidth, bswap>(ctx, data);
            ctx->length += 64 * 8;
            len         -= 64;
            data        += 64;
        } else {
            size_t n = 64 - ctx->curlen;
            if (n > len) { n = len; }
            memcpy(&ctx->buf[ctx->curlen], data, n);
            ctx->curlen += n;
            len         -= n;
            data        += n;
            if (ctx->curlen == sizeof(ctx->buf)) {
                rmd_compress<hashwidth, bswap>(ctx, ctx->buf);
                ctx->curlen  = 0;
                ctx->length += 64 * 8;
            }
        }
    }
}

/* Homegrown RMD seeding */
static void rmd_seed( rmd_ctx * ctx, uint64_t seed ) {
    const uint32_t seedlo = seed         & 0xFFFFFFFF;
    const uint32_t seedhi = (seed >> 32) & 0xFFFFFFFF;

    ctx->state[0] ^= seedlo;
    ctx->state[1] ^= seedlo + seedhi;
    ctx->state[2] ^= seedhi;
    ctx->state[3] ^= seedlo + seedhi;
}

template <bool bswap>
static void rmd128( const void * in, const size_t len, const seed_t seed, void * out ) {
    rmd_ctx ctx;

    rmd_init<128>(&ctx);
    rmd_seed(&ctx, (uint64_t)seed);
    rmd_update<128, bswap>(&ctx, (const uint8_t *)in, len);
    rmd_done<128, bswap>(&ctx, (uint8_t *)out);
}

template <bool bswap>
static void rmd160( const void * in, const size_t len, const seed_t seed, void * out ) {
    rmd_ctx ctx;

    rmd_init<160>(&ctx);
    rmd_seed(&ctx, (uint64_t)seed);
    rmd_update<160, bswap>(&ctx, (const uint8_t *)in, len);
    rmd_done<160, bswap>(&ctx, (uint8_t *)out);
}

template <bool bswap>
static void rmd256( const void * in, const size_t len, const seed_t seed, void * out ) {
    rmd_ctx ctx;

    rmd_init<256>(&ctx);
    rmd_seed(&ctx, (uint64_t)seed);
    rmd_update<256, bswap>(&ctx, (const uint8_t *)in, len);
    rmd_done<256, bswap>(&ctx, (uint8_t *)out);
}

static bool rmd_test( void ) {
    static const struct {
        const char *   msg;
        unsigned char  hash128[16];
        unsigned char  hash160[20];
        unsigned char  hash256[32];
    } tests[] = {
        {
            "",
            {
                0xcd, 0xf2, 0x62, 0x13, 0xa1, 0x50, 0xdc, 0x3e,
                0xcb, 0x61, 0x0f, 0x18, 0xf6, 0xb3, 0x8b, 0x46
            },
            {
                0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28,
                0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31
            },
            {
                0x02, 0xba, 0x4c, 0x4e, 0x5f, 0x8e, 0xcd, 0x18,
                0x77, 0xfc, 0x52, 0xd6, 0x4d, 0x30, 0xe3, 0x7a,
                0x2d, 0x97, 0x74, 0xfb, 0x1e, 0x5d, 0x02, 0x63,
                0x80, 0xae, 0x01, 0x68, 0xe3, 0xc5, 0x52, 0x2d
            }
        },
        {
            "a",
            {
                0x86, 0xbe, 0x7a, 0xfa, 0x33, 0x9d, 0x0f, 0xc7,
                0xcf, 0xc7, 0x85, 0xe7, 0x2f, 0x57, 0x8d, 0x33
            },
            {
                0x0b, 0xdc, 0x9d, 0x2d, 0x25, 0x6b, 0x3e, 0xe9, 0xda, 0xae,
                0x34, 0x7b, 0xe6, 0xf4, 0xdc, 0x83, 0x5a, 0x46, 0x7f, 0xfe
            },
            {
                0xf9, 0x33, 0x3e, 0x45, 0xd8, 0x57, 0xf5, 0xd9,
                0x0a, 0x91, 0xba, 0xb7, 0x0a, 0x1e, 0xba, 0x0c,
                0xfb, 0x1b, 0xe4, 0xb0, 0x78, 0x3c, 0x9a, 0xcf,
                0xcd, 0x88, 0x3a, 0x91, 0x34, 0x69, 0x29, 0x25
            }
        },
        {
            "abc",
            {
                0xc1, 0x4a, 0x12, 0x19, 0x9c, 0x66, 0xe4, 0xba,
                0x84, 0x63, 0x6b, 0x0f, 0x69, 0x14, 0x4c, 0x77
            },
            {
                0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04,
                0x4a, 0x8e, 0x98, 0xc6, 0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc
            },
            {
                0xaf, 0xbd, 0x6e, 0x22, 0x8b, 0x9d, 0x8c, 0xbb,
                0xce, 0xf5, 0xca, 0x2d, 0x03, 0xe6, 0xdb, 0xa1,
                0x0a, 0xc0, 0xbc, 0x7d, 0xcb, 0xe4, 0x68, 0x0e,
                0x1e, 0x42, 0xd2, 0xe9, 0x75, 0x45, 0x9b, 0x65
            }
        },
        {
            "message digest",
            {
                0x9e, 0x32, 0x7b, 0x3d, 0x6e, 0x52, 0x30, 0x62,
                0xaf, 0xc1, 0x13, 0x2d, 0x7d, 0xf9, 0xd1, 0xb8
            },
            {
                0x5d, 0x06, 0x89, 0xef, 0x49, 0xd2, 0xfa, 0xe5, 0x72, 0xb8,
                0x81, 0xb1, 0x23, 0xa8, 0x5f, 0xfa, 0x21, 0x59, 0x5f, 0x36
            },
            {
                0x87, 0xe9, 0x71, 0x75, 0x9a, 0x1c, 0xe4, 0x7a,
                0x51, 0x4d, 0x5c, 0x91, 0x4c, 0x39, 0x2c, 0x90,
                0x18, 0xc7, 0xc4, 0x6b, 0xc1, 0x44, 0x65, 0x55,
                0x4a, 0xfc, 0xdf, 0x54, 0xa5, 0x07, 0x0c, 0x0e
            }
        },
        {
            "abcdefghijklmnopqrstuvwxyz",
            {
                0xfd, 0x2a, 0xa6, 0x07, 0xf7, 0x1d, 0xc8, 0xf5,
                0x10, 0x71, 0x49, 0x22, 0xb3, 0x71, 0x83, 0x4e
            },
            {
                0xf7, 0x1c, 0x27, 0x10, 0x9c, 0x69, 0x2c, 0x1b, 0x56, 0xbb,
                0xdc, 0xeb, 0x5b, 0x9d, 0x28, 0x65, 0xb3, 0x70, 0x8d, 0xbc
            },
            {
                0x64, 0x9d, 0x30, 0x34, 0x75, 0x1e, 0xa2, 0x16,
                0x77, 0x6b, 0xf9, 0xa1, 0x8a, 0xcc, 0x81, 0xbc,
                0x78, 0x96, 0x11, 0x8a, 0x51, 0x97, 0x96, 0x87,
                0x82, 0xdd, 0x1f, 0xd9, 0x7d, 0x8d, 0x51, 0x33
            }
        },
        {
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            {
                0xd1, 0xe9, 0x59, 0xeb, 0x17, 0x9c, 0x91, 0x1f,
                0xae, 0xa4, 0x62, 0x4c, 0x60, 0xc5, 0xc7, 0x02
            },
            {
                0xb0, 0xe2, 0x0b, 0x6e, 0x31, 0x16, 0x64, 0x02, 0x86, 0xed,
                0x3a, 0x87, 0xa5, 0x71, 0x30, 0x79, 0xb2, 0x1f, 0x51, 0x89
            },
            {
                0x57, 0x40, 0xa4, 0x08, 0xac, 0x16, 0xb7, 0x20,
                0xb8, 0x44, 0x24, 0xae, 0x93, 0x1c, 0xbb, 0x1f,
                0xe3, 0x63, 0xd1, 0xd0, 0xbf, 0x40, 0x17, 0xf1,
                0xa8, 0x9f, 0x7e, 0xa6, 0xde, 0x77, 0xa0, 0xb8
            }
        }
    };

    int i;
    unsigned char tmp[32];
    bool          result = true;

    for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
        if (isLE()) {
            rmd128<false>(tests[i].msg, strlen(tests[i].msg), 0, tmp);
        } else {
            rmd128<true>(tests[i].msg, strlen(tests[i].msg), 0, tmp);
        }
        if (memcmp(tmp, tests[i].hash128, 16) != 0) {
            // printf("128 failure test %d\n", i);
            result = false;
        }
        if (isLE()) {
            rmd160<false>(tests[i].msg, strlen(tests[i].msg), 0, tmp);
        } else {
            rmd160<true>(tests[i].msg, strlen(tests[i].msg), 0, tmp);
        }
        if (memcmp(tmp, tests[i].hash160, 20) != 0) {
            // printf("160 failure test %d\n", i);
            result = false;
        }
        if (isLE()) {
            rmd256<false>(tests[i].msg, strlen(tests[i].msg), 0, tmp);
        } else {
            rmd256<true>(tests[i].msg, strlen(tests[i].msg), 0, tmp);
        }
        if (memcmp(tmp, tests[i].hash256, 32) != 0) {
            // printf("256 failure test %d\n", i);
            result = false;
        }
    }
    return result;
}

REGISTER_FAMILY(ripemd,
   $.src_url    = "https://github.com/libtom/libtomcrypt/blob/develop/src/hashes/rmd128.c",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(RIPEMD_128,
   $.desc       = "RIPE-MD 128",
   $.hash_flags =
         FLAG_HASH_NO_SEED              |
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW            |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 128,
   $.verification_LE = 0xC9B0B675,
   $.verification_BE = 0xD1DB09B5,
   $.initfn          = rmd_test,
   $.hashfn_native   = rmd128<false>,
   $.hashfn_bswap    = rmd128<true>
 );

REGISTER_HASH(RIPEMD_160,
   $.desc       = "RIPE-MD 160",
   $.hash_flags =
         FLAG_HASH_NO_SEED              |
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW            |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 160,
   $.verification_LE = 0x8613F5B2,
   $.verification_BE = 0x2265C3AA,
   $.initfn          = rmd_test,
   $.hashfn_native   = rmd160<false>,
   $.hashfn_bswap    = rmd160<true>
 );

REGISTER_HASH(RIPEMD_256,
   $.desc       = "RIPE-MD 256",
   $.hash_flags =
         FLAG_HASH_NO_SEED              |
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE         |
         FLAG_IMPL_INCREMENTAL          |
         FLAG_IMPL_VERY_SLOW            |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_LICENSE_MIT,
   $.bits = 256,
   $.verification_LE = 0x870A973A,
   $.verification_BE = 0xF2A877EE,
   $.initfn          = rmd_test,
   $.hashfn_native   = rmd256<false>,
   $.hashfn_bswap    = rmd256<true>
 );
