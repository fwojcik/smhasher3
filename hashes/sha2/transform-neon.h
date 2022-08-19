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

static const uint32_t K[] = {
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
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

template <bool bswap>
static void SHA256_Transform( uint32_t state[8], const uint8_t data[64] ) {
    uint32x4_t STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
    uint32x4_t MSG0, MSG1, MSG2, MSG3;
    uint32x4_t TMP0, TMP1, TMP2;

    /* Load state */
    STATE0 = vld1q_u32(&state[0]);
    STATE1 = vld1q_u32(&state[4]);

    /* Save state */
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    /* Load message */
    MSG0 =   vld1q_u32((const uint32_t *)(data +  0));
    MSG1 =   vld1q_u32((const uint32_t *)(data + 16));
    MSG2 =   vld1q_u32((const uint32_t *)(data + 32));
    MSG3 =   vld1q_u32((const uint32_t *)(data + 48));

    /* Reverse for little endian */
    if (bswap) {
        MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
        MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
        MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
        MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));
    }

    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x00]));

    /* Rounds 0-3 */
    MSG0   = vsha256su0q_u32(MSG0, MSG1);
    TMP2   = STATE0;
    TMP1   = vaddq_u32(MSG1, vld1q_u32(&K[0x04]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0   = vsha256su1q_u32(MSG0, MSG2, MSG3);

    /* Rounds 4-7 */
    MSG1   = vsha256su0q_u32(MSG1, MSG2);
    TMP2   = STATE0;
    TMP0   = vaddq_u32(MSG2, vld1q_u32(&K[0x08]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1   = vsha256su1q_u32(MSG1, MSG3, MSG0);

    /* Rounds 8-11 */
    MSG2   = vsha256su0q_u32(MSG2, MSG3);
    TMP2   = STATE0;
    TMP1   = vaddq_u32(MSG3, vld1q_u32(&K[0x0c]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2   = vsha256su1q_u32(MSG2, MSG0, MSG1);

    /* Rounds 12-15 */
    MSG3   = vsha256su0q_u32(MSG3, MSG0);
    TMP2   = STATE0;
    TMP0   = vaddq_u32(MSG0, vld1q_u32(&K[0x10]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3   = vsha256su1q_u32(MSG3, MSG1, MSG2);

    /* Rounds 16-19 */
    MSG0   = vsha256su0q_u32(MSG0, MSG1);
    TMP2   = STATE0;
    TMP1   = vaddq_u32(MSG1, vld1q_u32(&K[0x14]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0   = vsha256su1q_u32(MSG0, MSG2, MSG3);

    /* Rounds 20-23 */
    MSG1   = vsha256su0q_u32(MSG1, MSG2);
    TMP2   = STATE0;
    TMP0   = vaddq_u32(MSG2, vld1q_u32(&K[0x18]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1   = vsha256su1q_u32(MSG1, MSG3, MSG0);

    /* Rounds 24-27 */
    MSG2   = vsha256su0q_u32(MSG2, MSG3);
    TMP2   = STATE0;
    TMP1   = vaddq_u32(MSG3, vld1q_u32(&K[0x1c]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2   = vsha256su1q_u32(MSG2, MSG0, MSG1);

    /* Rounds 28-31 */
    MSG3   = vsha256su0q_u32(MSG3, MSG0);
    TMP2   = STATE0;
    TMP0   = vaddq_u32(MSG0, vld1q_u32(&K[0x20]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3   = vsha256su1q_u32(MSG3, MSG1, MSG2);

    /* Rounds 32-35 */
    MSG0   = vsha256su0q_u32(MSG0, MSG1);
    TMP2   = STATE0;
    TMP1   = vaddq_u32(MSG1, vld1q_u32(&K[0x24]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0   = vsha256su1q_u32(MSG0, MSG2, MSG3);

    /* Rounds 36-39 */
    MSG1   = vsha256su0q_u32(MSG1, MSG2);
    TMP2   = STATE0;
    TMP0   = vaddq_u32(MSG2, vld1q_u32(&K[0x28]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1   = vsha256su1q_u32(MSG1, MSG3, MSG0);

    /* Rounds 40-43 */
    MSG2   = vsha256su0q_u32(MSG2, MSG3);
    TMP2   = STATE0;
    TMP1   = vaddq_u32(MSG3, vld1q_u32(&K[0x2c]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2   = vsha256su1q_u32(MSG2, MSG0, MSG1);

    /* Rounds 44-47 */
    MSG3   = vsha256su0q_u32(MSG3, MSG0);
    TMP2   = STATE0;
    TMP0   = vaddq_u32(MSG0, vld1q_u32(&K[0x30]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3   = vsha256su1q_u32(MSG3, MSG1, MSG2);

    /* Rounds 48-51 */
    TMP2   = STATE0;
    TMP1   = vaddq_u32(MSG1, vld1q_u32(&K[0x34]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

    /* Rounds 52-55 */
    TMP2   = STATE0;
    TMP0   = vaddq_u32(MSG2, vld1q_u32(&K[0x38]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

    /* Rounds 56-59 */
    TMP2   = STATE0;
    TMP1   = vaddq_u32(MSG3, vld1q_u32(&K[0x3c]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

    /* Rounds 60-63 */
    TMP2   = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

    /* Combine state */
    STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
    STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

    /* Save state */
    vst1q_u32(&state[0], STATE0);
    vst1q_u32(&state[4], STATE1);
}
