/*
 * AES code using AESNI intrinsics
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
static inline __m128i _expand_key_helper( __m128i rkey, __m128i assist ) {
    __m128i temp;

    temp = _mm_slli_si128(rkey, 0x4);
    rkey = _mm_xor_si128(rkey, temp);
    temp = _mm_slli_si128(temp, 0x4);
    rkey = _mm_xor_si128(rkey, temp);
    temp = _mm_slli_si128(temp, 0x4);
    rkey = _mm_xor_si128(rkey, temp);

    temp = _mm_shuffle_epi32(assist, 0xff);
    rkey = _mm_xor_si128(rkey, temp);

    return rkey;
}

#define MKASSIST(x, y) x, _mm_aeskeygenassist_si128(x, y)

static int AES_KeySetup_Enc_AESNI( uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t cipherKey[], int keyBits ) {
    __m128i * round_keys = (__m128i *)rk8;

    round_keys[ 0] = _mm_loadu_si128((__m128i *)cipherKey);
    round_keys[ 1] = _expand_key_helper(MKASSIST(round_keys[0], 0x01));
    round_keys[ 2] = _expand_key_helper(MKASSIST(round_keys[1], 0x02));
    round_keys[ 3] = _expand_key_helper(MKASSIST(round_keys[2], 0x04));
    round_keys[ 4] = _expand_key_helper(MKASSIST(round_keys[3], 0x08));
    round_keys[ 5] = _expand_key_helper(MKASSIST(round_keys[4], 0x10));
    round_keys[ 6] = _expand_key_helper(MKASSIST(round_keys[5], 0x20));
    round_keys[ 7] = _expand_key_helper(MKASSIST(round_keys[6], 0x40));
    round_keys[ 8] = _expand_key_helper(MKASSIST(round_keys[7], 0x80));
    round_keys[ 9] = _expand_key_helper(MKASSIST(round_keys[8], 0x1b));
    round_keys[10] = _expand_key_helper(MKASSIST(round_keys[9], 0x36));
    return (keyBits == 128) ? 10 : (keyBits == 192) ? 12 : (keyBits == 256) ? 14 : 0;
}

static int AES_KeySetup_Dec_AESNI( uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t cipherKey[], int keyBits ) {
    __m128i * round_keys = (__m128i *)rk8;

    round_keys[10] = _mm_loadu_si128((__m128i *)cipherKey);
    round_keys[ 9] = _expand_key_helper(MKASSIST(round_keys[10], 0x01));
    round_keys[ 8] = _expand_key_helper(MKASSIST(round_keys[ 9], 0x02));
    round_keys[ 7] = _expand_key_helper(MKASSIST(round_keys[ 8], 0x04));
    round_keys[ 6] = _expand_key_helper(MKASSIST(round_keys[ 7], 0x08));
    round_keys[ 5] = _expand_key_helper(MKASSIST(round_keys[ 6], 0x10));
    round_keys[ 4] = _expand_key_helper(MKASSIST(round_keys[ 5], 0x20));
    round_keys[ 3] = _expand_key_helper(MKASSIST(round_keys[ 4], 0x40));
    round_keys[ 2] = _expand_key_helper(MKASSIST(round_keys[ 3], 0x80));
    round_keys[ 1] = _expand_key_helper(MKASSIST(round_keys[ 2], 0x1b));
    round_keys[ 0] = _expand_key_helper(MKASSIST(round_keys[ 1], 0x36));
    for (int i = 1; i < 10; i++) {
        round_keys[i] = _mm_aesimc_si128(round_keys[i]);
    }
    return (keyBits == 128) ? 10 : (keyBits == 192) ? 12 : (keyBits == 256) ? 14 : 0;
}

#undef MKASSIST

template <int Nr>
static inline void AES_Encrypt_AESNI( const uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t pt[16], uint8_t ct[16] ) {
    const __m128i * round_keys = (const __m128i *)rk8;
    __m128i         tmp;

    tmp = _mm_loadu_si128((const __m128i *)pt);

    tmp = _mm_xor_si128(tmp, round_keys[0]);

    for (int j = 1; j < Nr; j++) {
        tmp = _mm_aesenc_si128(tmp, round_keys[j]);
    }

    tmp = _mm_aesenclast_si128(tmp, round_keys[Nr]);

    _mm_storeu_si128((((__m128i *)ct)), tmp);
}

template <int Nr>
static inline void AES_Decrypt_AESNI( const uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t ct[16], uint8_t pt[16] ) {
    const __m128i * round_keys = (const __m128i *)rk8;
    __m128i         tmp;

    tmp = _mm_loadu_si128((const __m128i *)ct);

    tmp = _mm_xor_si128(tmp, round_keys[0]);

    for (int j = 1; j < Nr; j++) {
        tmp = _mm_aesdec_si128(tmp, round_keys[j]);
    }

    tmp = _mm_aesdeclast_si128(tmp, round_keys[Nr]);

    _mm_storeu_si128((((__m128i *)pt)), tmp);
}

static inline void AES_EncryptRound_AESNI( const uint8_t rk8[], uint8_t block[16] ) {
    const __m128i round_key = _mm_loadu_si128((const __m128i *)rk8);
    __m128i       tmp       = _mm_loadu_si128((__m128i *)block    );

    tmp = _mm_aesenc_si128(tmp, round_key);
    _mm_storeu_si128((((__m128i *)block)), tmp);
}

static void AES_DecryptRound_AESNI( const uint8_t rk8[], uint8_t block[16] ) {
    const __m128i round_key = _mm_loadu_si128((const __m128i *)rk8);
    __m128i       tmp       = _mm_loadu_si128((__m128i *)block    );

    tmp = _mm_aesdec_si128(tmp, round_key);
    _mm_storeu_si128((((__m128i *)block)), tmp);
}

static inline void AES_EncryptRoundNoMixCol_AESNI( const uint8_t rk8[], uint8_t block[16] ) {
    const __m128i round_key = _mm_loadu_si128((const __m128i *)rk8);
    __m128i       tmp       = _mm_loadu_si128((__m128i *)block    );

    tmp = _mm_aesenclast_si128(tmp, round_key);
    _mm_storeu_si128((((__m128i *)block)), tmp);
}

static void AES_DecryptRoundNoMixCol_AESNI( const uint8_t rk8[], uint8_t block[16] ) {
    const __m128i round_key = _mm_loadu_si128((const __m128i *)rk8);
    __m128i       tmp       = _mm_loadu_si128((__m128i *)block    );

    tmp = _mm_aesdeclast_si128(tmp, round_key);
    _mm_storeu_si128((((__m128i *)block)), tmp);
}
