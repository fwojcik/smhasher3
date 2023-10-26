/*
 * AES code using PPC intrinsics
 *
 * Based on:
 *   ppc_simd.h - written and placed in public domain by Jeffrey Walton
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

template <int Nr>
static inline void AES_Encrypt_PPC( const uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t pt[16], uint8_t ct[16] ) {
    vec_t block = (vec_t)vec_vsx_ld(0, pt);

    block = vec_xor(block, (vec_t)vec_vsx_ld(0, rk8));

    for (int i = 1; i < Nr; i++) {
        block = vec_encrypt(block, (vec_t)vec_vsx_ld(i * 16, rk8));
    }

    block = vec_encryptlast(block, (vec_t)vec_vsx_ld(Nr * 16, rk8));

    vec_vsx_st((__vector unsigned char)block, 0, ct);
}

// This is surely not the best way to do this?!? But doing things the
// expected way (just passing the keys in to vec_decrypt()) does not
// produce the correct results.
template <int Nr>
static inline void AES_Decrypt_PPC( const uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t ct[16], uint8_t pt[16] ) {
    vec_t zero = { 0 };
    vec_t block = (vec_t)vec_vsx_ld(0, ct);

    block = vec_xor(block, (vec_t)vec_vsx_ld(0, rk8));

    for (int i = 1; i < Nr; i++) {
        block = vec_decrypt(block, zero);
        block = vec_xor(block, (vec_t)vec_vsx_ld(i * 16, rk8));
    }

    block = vec_decryptlast(block, zero);
    block = vec_xor(block, (vec_t)vec_vsx_ld(Nr * 16, rk8));

    vec_vsx_st((__vector unsigned char)block, 0, pt);
}

static inline void AES_EncryptRound_PPC( const uint8_t rk8[], uint8_t block[16] ) {
    vec_t tmp = (vec_t)vec_vsx_ld(0, block);

    tmp = vec_encrypt(tmp, (vec_t)vec_vsx_ld(0, rk8));
    vec_vsx_st((__vector unsigned char)tmp, 0, block);
}

static inline void AES_DecryptRound_PPC( const uint8_t rk8[], uint8_t block[16] ) {
    vec_t zero = { 0 };
    vec_t tmp = (vec_t)vec_vsx_ld(0, block);

    tmp = vec_decrypt(tmp, zero);
    tmp = vec_xor(tmp, (vec_t)vec_vsx_ld(0, rk8));
    vec_vsx_st((__vector unsigned char)tmp, 0, block);
}
