/*
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * Based on:
 *   @version 3.0 (December 2000)
 *   @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 *   @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 *   @author Paulo Barreto <paulo.barreto@terra.com.br>
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

extern const uint32_t Te0[256], Te1[256], Te2[256], Te3[256], Te4[256];
extern const uint32_t Td0[256], Td1[256], Td2[256], Td3[256], Td4[256];

/* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
static const uint32_t rcon[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000,
};

/* Endian-independent macros */
#define GETU32(pt) (                            \
                    ((uint32_t)(pt)[0] << 24) ^ \
                    ((uint32_t)(pt)[1] << 16) ^ \
                    ((uint32_t)(pt)[2] <<  8) ^ \
                    ((uint32_t)(pt)[3]      ) )
#define PUTU32(ct, st) {                 \
        (ct)[0] = (uint8_t)((st) >> 24); \
        (ct)[1] = (uint8_t)((st) >> 16); \
        (ct)[2] = (uint8_t)((st) >>  8); \
        (ct)[3] = (uint8_t)(st); }

/*
 * Expand the cipher key into the encryption key schedule.
 *
 * Returns the number of rounds for the given cipher key size.
 */
static int AES_KeySetup_Enc_portable( uint32_t rk[] /*4*(Nr + 1)*/, const uint8_t cipherKey[], int keyBits ) {
    int      i = 0;
    uint32_t temp;

    rk[0] = GETU32(cipherKey     );
    rk[1] = GETU32(cipherKey + 4 );
    rk[2] = GETU32(cipherKey + 8 );
    rk[3] = GETU32(cipherKey + 12);

    if (keyBits == 128) {
        for (;;) {
            temp  = rk[3];
            rk[4] = rk[0] ^
                    (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
                    (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
                    (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
                    (Te4[(temp >> 24)       ] & 0x000000ff) ^
                    rcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10) {
                return 10;
            }
            rk += 4;
        }
    }

    rk[4] = GETU32(cipherKey + 16);
    rk[5] = GETU32(cipherKey + 20);

    if (keyBits == 192) {
        for (;;) {
            temp  = rk[5];
            rk[6] = rk[0] ^
                    (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
                    (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
                    (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
                    (Te4[(temp >> 24)       ] & 0x000000ff) ^
                    rcon[i];
            rk[ 7] = rk[1] ^ rk[ 6];
            rk[ 8] = rk[2] ^ rk[ 7];
            rk[ 9] = rk[3] ^ rk[ 8];
            if (++i == 8) {
                return 12;
            }
            rk[10] = rk[4] ^ rk[ 9];
            rk[11] = rk[5] ^ rk[10];
            rk    += 6;
        }
    }

    rk[6] = GETU32(cipherKey + 24);
    rk[7] = GETU32(cipherKey + 28);

    if (keyBits == 256) {
        for (;;) {
            temp  = rk[7];
            rk[8] = rk[0] ^
                    (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
                    (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
                    (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
                    (Te4[(temp >> 24)       ] & 0x000000ff) ^
                    rcon[i];
            rk[ 9] = rk[1] ^ rk[ 8];
            rk[10] = rk[2] ^ rk[ 9];
            rk[11] = rk[3] ^ rk[10];
            if (++i == 7) {
                return 14;
            }
            temp   = rk[11];
            rk[12] = rk[4] ^
                    (Te4[(temp >> 24)       ] & 0xff000000) ^
                    (Te4[(temp >> 16) & 0xff] & 0x00ff0000) ^
                    (Te4[(temp >>  8) & 0xff] & 0x0000ff00) ^
                    (Te4[(temp      ) & 0xff] & 0x000000ff);
            rk[13] = rk[5] ^ rk[12];
            rk[14] = rk[6] ^ rk[13];
            rk[15] = rk[7] ^ rk[14];

            rk    += 8;
        }
    }

    return 0;
}

/*
 * Expand the cipher key into the decryption key schedule.
 *
 * Returns the number of rounds for the given cipher key size.
 */
static int AES_KeySetup_Dec_portable( uint32_t rk[] /*4*(Nr + 1)*/, const uint8_t cipherKey[], int keyBits ) {
    int      Nr, i, j;
    uint32_t temp;

    /* expand the cipher key: */
    Nr = AES_KeySetup_Dec_portable(rk, cipherKey, keyBits);

    /* invert the order of the round keys: */
    for (i = 0, j = 4 * Nr; i < j; i += 4, j -= 4) {
        temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
        temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
        temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
        temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
    }

    /* apply the inverse MixColumn transform to all round keys but the first and the last: */
    for (i = 1; i < Nr; i++) {
        rk   += 4;
        rk[0] =
                Td0[Te4[(rk[0] >> 24)       ] & 0xff] ^
                Td1[Te4[(rk[0] >> 16) & 0xff] & 0xff] ^
                Td2[Te4[(rk[0] >>  8) & 0xff] & 0xff] ^
                Td3[Te4[(rk[0]      ) & 0xff] & 0xff];
        rk[1] =
                Td0[Te4[(rk[1] >> 24)       ] & 0xff] ^
                Td1[Te4[(rk[1] >> 16) & 0xff] & 0xff] ^
                Td2[Te4[(rk[1] >>  8) & 0xff] & 0xff] ^
                Td3[Te4[(rk[1]      ) & 0xff] & 0xff];
        rk[2] =
                Td0[Te4[(rk[2] >> 24)       ] & 0xff] ^
                Td1[Te4[(rk[2] >> 16) & 0xff] & 0xff] ^
                Td2[Te4[(rk[2] >>  8) & 0xff] & 0xff] ^
                Td3[Te4[(rk[2]      ) & 0xff] & 0xff];
        rk[3] =
                Td0[Te4[(rk[3] >> 24)       ] & 0xff] ^
                Td1[Te4[(rk[3] >> 16) & 0xff] & 0xff] ^
                Td2[Te4[(rk[3] >>  8) & 0xff] & 0xff] ^
                Td3[Te4[(rk[3]      ) & 0xff] & 0xff];
    }

    return Nr;
}

template <int Nr>
static void AES_Encrypt_portable( const uint32_t rk[] /*4*(Nr + 1)*/, const uint8_t pt[16], uint8_t ct[16] ) {
    // STATIC_ASSERT(Nr >=1 && Nr <= 14);
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = GETU32(pt     ) ^ rk[0];
    s1 = GETU32(pt +  4) ^ rk[1];
    s2 = GETU32(pt +  8) ^ rk[2];
    s3 = GETU32(pt + 12) ^ rk[3];

    /* round 1: */
    if (Nr > 1) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[4];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[5];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[6];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[7];
    }
    /* round 2: */
    if (Nr > 2) {
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[ 8];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[ 9];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[10];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[11];
    }
    /* round 3: */
    if (Nr > 3) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[12];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[13];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[14];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[15];
    }
    /* round 4: */
    if (Nr > 4) {
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[16];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[17];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[18];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[19];
    }
    /* round 5: */
    if (Nr > 5) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[20];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[21];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[22];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[23];
    }
    /* round 6: */
    if (Nr > 6) {
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[24];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[25];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[26];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[27];
    }
    /* round 7: */
    if (Nr > 7) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[28];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[29];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[30];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[31];
    }
    /* round 8: */
    if (Nr > 8) {
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[32];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[33];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[34];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[35];
    }
    /* round 9: */
    if (Nr > 9) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[36];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[37];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[38];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[39];
    }
    /* round 10: */
    if (Nr > 10) {
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[40];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[41];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[42];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[43];
    }
    /* round 11: */
    if (Nr > 11) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[44];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[45];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[46];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[47];
    }
    /* round 12: */
    if (Nr > 12) {
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[48];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[49];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[50];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[51];
    }
    /* round 13: */
    if (Nr > 13) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[52];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[53];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[54];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[55];
    }

    rk += Nr << 2;

    if (Nr % 2) {
        t0 = s0;
        t1 = s1;
        t2 = s2;
        t3 = s3;
    }

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
            (Te4[(t0 >> 24)       ] & 0xff000000) ^
            (Te4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
            (Te4[(t2 >>  8) & 0xff] & 0x0000ff00) ^
            (Te4[(t3      ) & 0xff] & 0x000000ff) ^
            rk[0];
    s1 =
            (Te4[(t1 >> 24)       ] & 0xff000000) ^
            (Te4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
            (Te4[(t3 >>  8) & 0xff] & 0x0000ff00) ^
            (Te4[(t0      ) & 0xff] & 0x000000ff) ^
            rk[1];
    s2 =
            (Te4[(t2 >> 24)       ] & 0xff000000) ^
            (Te4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
            (Te4[(t0 >>  8) & 0xff] & 0x0000ff00) ^
            (Te4[(t1      ) & 0xff] & 0x000000ff) ^
            rk[2];
    s3 =
            (Te4[(t3 >> 24)       ] & 0xff000000) ^
            (Te4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
            (Te4[(t1 >>  8) & 0xff] & 0x0000ff00) ^
            (Te4[(t2      ) & 0xff] & 0x000000ff) ^
            rk[3];

    PUTU32(ct     , s0);
    PUTU32(ct +  4, s1);
    PUTU32(ct +  8, s2);
    PUTU32(ct + 12, s3);
}

template <int Nr>
static void AES_Decrypt_portable( const uint32_t rk[] /*4*(Nr + 1)*/, const uint8_t ct[16], uint8_t pt[16] ) {
    // STATIC_ASSERT(Nr >=1 && Nr <= 14);
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = GETU32(ct     ) ^ rk[0];
    s1 = GETU32(ct +  4) ^ rk[1];
    s2 = GETU32(ct +  8) ^ rk[2];
    s3 = GETU32(ct + 12) ^ rk[3];

    /* round 1: */
    if (Nr > 1) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[4];
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[5];
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[6];
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[7];
    }
    /* round 2: */
    if (Nr > 2) {
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[ 8];
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[ 9];
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[10];
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[11];
    }
    /* round 3: */
    if (Nr > 3) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[12];
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[13];
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[14];
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[15];
    }
    /* round 4: */
    if (Nr > 4) {
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[16];
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[17];
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[18];
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[19];
    }
    /* round 5: */
    if (Nr > 5) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[20];
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[21];
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[22];
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[23];
    }
    /* round 6: */
    if (Nr > 6) {
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[24];
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[25];
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[26];
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[27];
    }
    /* round 7: */
    if (Nr > 7) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[28];
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[29];
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[30];
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[31];
    }
    /* round 8: */
    if (Nr > 8) {
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[32];
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[33];
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[34];
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[35];
    }
    /* round 9: */
    if (Nr > 9) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[36];
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[37];
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[38];
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[39];
    }
    /* round 10: */
    if (Nr > 10) {
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[40];
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[41];
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[42];
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[43];
    }
    /* round 11: */
    if (Nr > 11) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[44];
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[45];
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[46];
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[47];
    }
    /* round 12: */
    if (Nr > 12) {
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[48];
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[49];
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[50];
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[51];
    }
    /* round 13: */
    if (Nr > 13) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[52];
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[53];
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[54];
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[55];
    }

    rk += Nr << 2;

    if (Nr % 2) {
        t0 = s0;
        t1 = s1;
        t2 = s2;
        t3 = s3;
    }

    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    s0 =
            (Td4[(t0 >> 24)       ] & 0xff000000) ^
            (Td4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
            (Td4[(t2 >>  8) & 0xff] & 0x0000ff00) ^
            (Td4[(t1      ) & 0xff] & 0x000000ff) ^
            rk[0];
    s1 =
            (Td4[(t1 >> 24)       ] & 0xff000000) ^
            (Td4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
            (Td4[(t3 >>  8) & 0xff] & 0x0000ff00) ^
            (Td4[(t2      ) & 0xff] & 0x000000ff) ^
            rk[1];
    s2 =
            (Td4[(t2 >> 24)       ] & 0xff000000) ^
            (Td4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
            (Td4[(t0 >>  8) & 0xff] & 0x0000ff00) ^
            (Td4[(t3      ) & 0xff] & 0x000000ff) ^
            rk[2];
    s3 =
            (Td4[(t3 >> 24)       ] & 0xff000000) ^
            (Td4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
            (Td4[(t1 >>  8) & 0xff] & 0x0000ff00) ^
            (Td4[(t0      ) & 0xff] & 0x000000ff) ^
            rk[3];

    PUTU32(pt     , s0);
    PUTU32(pt +  4, s1);
    PUTU32(pt +  8, s2);
    PUTU32(pt + 12, s3);
}

static void AES_EncryptRound_portable( const uint32_t rk[4], uint8_t block[16] ) {
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;

    s0 = GETU32(block     );
    s1 = GETU32(block +  4);
    s2 = GETU32(block +  8);
    s3 = GETU32(block + 12);

    t0 =
            (Te0[(s0 >> 24)       ] & 0xff000000) ^
            (Te1[(s1 >> 16) & 0xff] & 0x00ff0000) ^
            (Te2[(s2 >>  8) & 0xff] & 0x0000ff00) ^
            (Te3[(s3      ) & 0xff] & 0x000000ff) ^
            rk[0];
    t1 =
            (Te0[(s1 >> 24)       ] & 0xff000000) ^
            (Te1[(s2 >> 16) & 0xff] & 0x00ff0000) ^
            (Te2[(s3 >>  8) & 0xff] & 0x0000ff00) ^
            (Te3[(s0      ) & 0xff] & 0x000000ff) ^
            rk[1];
    t2 =
            (Te0[(s2 >> 24)       ] & 0xff000000) ^
            (Te1[(s3 >> 16) & 0xff] & 0x00ff0000) ^
            (Te2[(s0 >>  8) & 0xff] & 0x0000ff00) ^
            (Te3[(s1      ) & 0xff] & 0x000000ff) ^
            rk[2];
    t3 =
            (Te0[(s3 >> 24)       ] & 0xff000000) ^
            (Te1[(s0 >> 16) & 0xff] & 0x00ff0000) ^
            (Te2[(s1 >>  8) & 0xff] & 0x0000ff00) ^
            (Te3[(s2      ) & 0xff] & 0x000000ff) ^
            rk[3];

    PUTU32(block     , t0);
    PUTU32(block +  4, t1);
    PUTU32(block +  8, t2);
    PUTU32(block + 12, t3);
}

static void AES_DecryptRound_portable( const uint32_t rk[4], uint8_t block[16] ) {
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;

    s0 = GETU32(block     );
    s1 = GETU32(block +  4);
    s2 = GETU32(block +  8);
    s3 = GETU32(block + 12);

    t0 =
            Td0[(s0 >> 24)       ] ^
            Td1[(s3 >> 16) & 0xff] ^
            Td2[(s2 >>  8) & 0xff] ^
            Td3[(s1      ) & 0xff] ^
            rk[0];
    t1 =
            Td0[(s1 >> 24)       ] ^
            Td1[(s0 >> 16) & 0xff] ^
            Td2[(s3 >>  8) & 0xff] ^
            Td3[(s2      ) & 0xff] ^
            rk[1];
    t2 =
            Td0[(s2 >> 24)       ] ^
            Td1[(s1 >> 16) & 0xff] ^
            Td2[(s0 >>  8) & 0xff] ^
            Td3[(s3      ) & 0xff] ^
            rk[2];
    t3 =
            Td0[(s3 >> 24)       ] ^
            Td1[(s2 >> 16) & 0xff] ^
            Td2[(s1 >>  8) & 0xff] ^
            Td3[(s0      ) & 0xff] ^
            rk[3];

    PUTU32(block     , t0);
    PUTU32(block +  4, t1);
    PUTU32(block +  8, t2);
    PUTU32(block + 12, t3);
}
