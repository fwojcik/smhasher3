/*
 * AES code using ARM intrinsics
 *
 * This is free and unencumbered software released into the public
 * domain under The Unlicense (http://unlicense.org/).
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a
 * compiled binary, for any purpose, commercial or non-commercial, and
 * by any means.
 *
 * In jurisdictions that recognize copyright laws, the author or
 * authors of this software dedicate any and all copyright interest in
 * the software to the public domain. We make this dedication for the
 * benefit of the public at large and to the detriment of our heirs
 * and successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to
 * this software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */
template <int Nr>
static inline void AES_Encrypt_ARM( const uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t pt[16], uint8_t ct[16] ) {
    uint8x16_t      block = vld1q_u8(pt);

    // AES single round encryption
    block = vaeseq_u8(block, vld1q_u8(rk8 + 0 * 16));

    for (int i = 1; i < Nr; i++) {
        // AES mix columns
        block = vaesmcq_u8(block);
        // AES single round encryption
        block = vaeseq_u8(block, vld1q_u8(rk8 + i * 16));
    }

    // Final xor
    block = veorq_u8(block, vld1q_u8(rk8 + Nr * 16));

    vst1q_u8(ct, block);
}

template <int Nr>
static inline void AES_Decrypt_ARM( const uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t ct[16], uint8_t pt[16] ) {
    uint8x16_t      block = vld1q_u8(ct);

    // AES single round decryption
    block = vaesdq_u8(block, vld1q_u8(rk8 + 0 * 16));

    for (int i = 1; i < Nr; i++) {
        // AES inverse mix columns
        block = vaesimcq_u8(block);
        // AES single round decryption
        block = vaesdq_u8(block, vld1q_u8(rk8 + i * 16));
    }

    // Final xor
    block = veorq_u8(block, vld1q_u8(rk8 + Nr * 16));

    vst1q_u8(pt, block);
}

static inline void AES_EncryptRound_ARM( const uint8_t rk8[], uint8_t block[16] ) {
    uint8x16_t zero = vmovq_n_u8(0);
    uint8x16_t tmp = vld1q_u8(block);

    tmp = vaeseq_u8(tmp, zero);
    tmp = vaesmcq_u8(tmp);
    tmp = veorq_u8(tmp, vld1q_u8(rk8));
    vst1q_u8(block, tmp);
}

static inline void AES_DecryptRound_ARM( const uint8_t rk8[], uint8_t block[16] ) {
    uint8x16_t zero = vmovq_n_u8(0);
    uint8x16_t tmp = vld1q_u8(block);

    tmp = vaesdq_u8(tmp, zero);
    tmp = vaesimcq_u8(tmp);
    tmp = veorq_u8(tmp, vld1q_u8(rk8));
    vst1q_u8(block, tmp);
}
