/*
 * AES wrapper code
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

// Only 128-bit AES is currently supported!!

#include "Intrinsics.h"

#if defined(HAVE_X86_64_AES)
  #include "AES-aesni.h"
  #define AES_IMPL_STR "aesni"
#elif defined(HAVE_ARM_AES)
  #include "AES-arm.h"
  #include "AES-portable.h" // ARM doesn't have any AES keygen intrinsics
  #define AES_IMPL_STR "arm"
#elif defined(HAVE_PPC_AES)
  #include "AES-ppc.h"
  #include "AES-portable.h" // PPC doesn't really have any AES keygen intrinsics
  #define AES_IMPL_STR "ppc"
#else
  #include "AES-portable.h"
  #define AES_IMPL_STR "portable"
#endif

static int AES_KeySetup_Enc( uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t cipherKey[], int keyBits ) {
    // STATIC_ASSERT(keyBits == 128);
#if defined(HAVE_X86_64_AES)
    return AES_KeySetup_Enc_AESNI(rk8, cipherKey, keyBits);
#elif defined(HAVE_ARM_AES)
    return AES_KeySetup_Enc_portable(rk8, cipherKey, keyBits);
#else
    return AES_KeySetup_Enc_portable(rk8, cipherKey, keyBits);
#endif
}

static int AES_KeySetup_Dec( uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t cipherKey[], int keyBits ) {
    // STATIC_ASSERT(keyBits == 128);
#if defined(HAVE_X86_64_AES)
    return AES_KeySetup_Dec_AESNI(rk8, cipherKey, keyBits);
#elif defined(HAVE_ARM_AES)
    return AES_KeySetup_Dec_portable(rk8, cipherKey, keyBits);
#else
    return AES_KeySetup_Dec_portable(rk8, cipherKey, keyBits);
#endif
}

template <int Nr>
static void AES_Encrypt( const uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t pt[16], uint8_t ct[16] ) {
#if defined(HAVE_X86_64_AES)
    AES_Encrypt_AESNI<Nr>(rk8, pt, ct);
#elif defined(HAVE_ARM_AES)
    AES_Encrypt_ARM<Nr>(rk8, pt, ct);
#elif defined(HAVE_PPC_AES)
    AES_Encrypt_PPC<Nr>(rk8, pt, ct);
#else
    AES_Encrypt_portable<Nr>(rk8, pt, ct);
#endif
}

template <int Nr>
static void AES_Decrypt( const uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t ct[16], uint8_t pt[16] ) {
#if defined(HAVE_X86_64_AES)
    AES_Decrypt_AESNI<Nr>(rk8, ct, pt);
#elif defined(HAVE_ARM_AES)
    AES_Decrypt_ARM<Nr>(rk8, ct, pt);
#elif defined(HAVE_PPC_AES)
    AES_Decrypt_PPC<Nr>(rk8, ct, pt);
#else
    AES_Decrypt_portable<Nr>(rk8, ct, pt);
#endif
}

static void AES_EncryptRound( const uint8_t rk8[] /*16*/, uint8_t block[16] ) {
#if defined(HAVE_X86_64_AES)
    AES_EncryptRound_AESNI(rk8, block);
#elif defined(HAVE_ARM_AES)
    AES_EncryptRound_ARM(rk8, block);
#elif defined(HAVE_PPC_AES)
    AES_EncryptRound_PPC(rk8, block);
#else
    AES_EncryptRound_portable(rk8, block);
#endif
}

static void AES_DecryptRound( const uint8_t rk8[] /*16*/, uint8_t block[16] ) {
#if defined(HAVE_X86_64_AES)
    AES_DecryptRound_AESNI(rk8, block);
#elif defined(HAVE_ARM_AES)
    AES_DecryptRound_ARM(rk8, block);
#elif defined(HAVE_PPC_AES)
    AES_DecryptRound_PPC(rk8, block);
#else
    AES_DecryptRound_portable(rk8, block);
#endif
}

static void AES_EncryptRoundNoMixCol( const uint8_t rk8[] /*16*/, uint8_t block[16] ) {
#if defined(HAVE_X86_64_AES)
    AES_EncryptRoundNoMixCol_AESNI(rk8, block);
#elif defined(HAVE_ARM_AES)
    AES_EncryptRoundNoMixCol_ARM(rk8, block);
#elif defined(HAVE_PPC_AES)
    AES_EncryptRoundNoMixCol_PPC(rk8, block);
#else
    AES_EncryptRoundNoMixCol_portable(rk8, block);
#endif
}

static void AES_DecryptRoundNoMixCol( const uint8_t rk8[] /*16*/, uint8_t block[16] ) {
#if defined(HAVE_X86_64_AES)
    AES_DecryptRoundNoMixCol_AESNI(rk8, block);
#elif defined(HAVE_ARM_AES)
    AES_DecryptRoundNoMixCol_ARM(rk8, block);
#elif defined(HAVE_PPC_AES)
    AES_DecryptRoundNoMixCol_PPC(rk8, block);
#else
    AES_DecryptRoundNoMixCol_portable(rk8, block);
#endif
}

void TestAESWrappers( void );
