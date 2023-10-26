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
#pragma once

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
static int AES_KeySetup_Enc_portable( uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t cipherKey[], int keyBits ) {
    int      i = 0;
    uint32_t temp;
    uint32_t tempkeys[60];
    uint32_t * rk = tempkeys;

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
                for (i = 0; i < 44; i++) {
                    PUTU32(rk8, tempkeys[i]);
                    rk8 += 4;
                }
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
                for (i = 0; i < 52; i++) {
                    PUTU32(rk8, tempkeys[i]);
                    rk8 += 4;
                }
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
                for (i = 0; i < 60; i++) {
                    PUTU32(rk8, tempkeys[i]);
                    rk8 += 4;
                }
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
static int AES_KeySetup_Dec_portable( uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t cipherKey[], int keyBits ) {
    int      Nr, i, j;
    uint32_t temp;
    uint8_t  temp8[16];

    /* expand the cipher key: */
    Nr = AES_KeySetup_Enc_portable(rk8, cipherKey, keyBits);

    /* invert the order of the round keys: */
    for (i = 0, j = 16 * Nr; i < j; i += 16, j -= 16) {
        memcpy(temp8,   &rk8[i], 16);
        memcpy(&rk8[i], &rk8[j], 16);
        memcpy(&rk8[j], temp8,   16);
    }

    /* apply the inverse MixColumn transform to all round keys but the first and the last: */
    for (i = 1; i < Nr; i++) {
        rk8  += 16;
        temp = GETU32(rk8);
        temp =
                Td0[Te4[(temp >> 24)       ] & 0xff] ^
                Td1[Te4[(temp >> 16) & 0xff] & 0xff] ^
                Td2[Te4[(temp >>  8) & 0xff] & 0xff] ^
                Td3[Te4[(temp      ) & 0xff] & 0xff];
        PUTU32(rk8, temp);
        temp = GETU32(rk8 + 4);
        temp =
                Td0[Te4[(temp >> 24)       ] & 0xff] ^
                Td1[Te4[(temp >> 16) & 0xff] & 0xff] ^
                Td2[Te4[(temp >>  8) & 0xff] & 0xff] ^
                Td3[Te4[(temp      ) & 0xff] & 0xff];
        PUTU32(rk8 + 4, temp);
        temp = GETU32(rk8 + 8);
        temp =
                Td0[Te4[(temp >> 24)       ] & 0xff] ^
                Td1[Te4[(temp >> 16) & 0xff] & 0xff] ^
                Td2[Te4[(temp >>  8) & 0xff] & 0xff] ^
                Td3[Te4[(temp      ) & 0xff] & 0xff];
        PUTU32(rk8 + 8, temp);
        temp = GETU32(rk8 + 12);
        temp =
                Td0[Te4[(temp >> 24)       ] & 0xff] ^
                Td1[Te4[(temp >> 16) & 0xff] & 0xff] ^
                Td2[Te4[(temp >>  8) & 0xff] & 0xff] ^
                Td3[Te4[(temp      ) & 0xff] & 0xff];
        PUTU32(rk8 + 12, temp);
    }

    return Nr;
}

template <int Nr>
static void AES_Encrypt_portable( const uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t pt[16], uint8_t ct[16] ) {
    // STATIC_ASSERT(Nr >=1 && Nr <= 14);
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = GETU32(pt     ) ^ GETU32(&rk8[0 * 4]);
    s1 = GETU32(pt +  4) ^ GETU32(&rk8[1 * 4]);
    s2 = GETU32(pt +  8) ^ GETU32(&rk8[2 * 4]);
    s3 = GETU32(pt + 12) ^ GETU32(&rk8[3 * 4]);

    /* round 1: */
    if (Nr > 1) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ GETU32(&rk8[4 * 4]);
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ GETU32(&rk8[5 * 4]);
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ GETU32(&rk8[6 * 4]);
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ GETU32(&rk8[7 * 4]);
    }
    /* round 2: */
    if (Nr > 2) {
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ GETU32(&rk8[ 8 * 4]);
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ GETU32(&rk8[ 9 * 4]);
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ GETU32(&rk8[10 * 4]);
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ GETU32(&rk8[11 * 4]);
    }
    /* round 3: */
    if (Nr > 3) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ GETU32(&rk8[12 * 4]);
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ GETU32(&rk8[13 * 4]);
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ GETU32(&rk8[14 * 4]);
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ GETU32(&rk8[15 * 4]);
    }
    /* round 4: */
    if (Nr > 4) {
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ GETU32(&rk8[16 * 4]);
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ GETU32(&rk8[17 * 4]);
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ GETU32(&rk8[18 * 4]);
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ GETU32(&rk8[19 * 4]);
    }
    /* round 5: */
    if (Nr > 5) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ GETU32(&rk8[20 * 4]);
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ GETU32(&rk8[21 * 4]);
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ GETU32(&rk8[22 * 4]);
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ GETU32(&rk8[23 * 4]);
    }
    /* round 6: */
    if (Nr > 6) {
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ GETU32(&rk8[24 * 4]);
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ GETU32(&rk8[25 * 4]);
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ GETU32(&rk8[26 * 4]);
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ GETU32(&rk8[27 * 4]);
    }
    /* round 7: */
    if (Nr > 7) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ GETU32(&rk8[28 * 4]);
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ GETU32(&rk8[29 * 4]);
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ GETU32(&rk8[30 * 4]);
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ GETU32(&rk8[31 * 4]);
    }
    /* round 8: */
    if (Nr > 8) {
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ GETU32(&rk8[32 * 4]);
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ GETU32(&rk8[33 * 4]);
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ GETU32(&rk8[34 * 4]);
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ GETU32(&rk8[35 * 4]);
    }
    /* round 9: */
    if (Nr > 9) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ GETU32(&rk8[36 * 4]);
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ GETU32(&rk8[37 * 4]);
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ GETU32(&rk8[38 * 4]);
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ GETU32(&rk8[39 * 4]);
    }
    /* round 10: */
    if (Nr > 10) {
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ GETU32(&rk8[40 * 4]);
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ GETU32(&rk8[41 * 4]);
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ GETU32(&rk8[42 * 4]);
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ GETU32(&rk8[43 * 4]);
    }
    /* round 11: */
    if (Nr > 11) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ GETU32(&rk8[44 * 4]);
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ GETU32(&rk8[45 * 4]);
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ GETU32(&rk8[46 * 4]);
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ GETU32(&rk8[47 * 4]);
    }
    /* round 12: */
    if (Nr > 12) {
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ GETU32(&rk8[48 * 4]);
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ GETU32(&rk8[49 * 4]);
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ GETU32(&rk8[50 * 4]);
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ GETU32(&rk8[51 * 4]);
    }
    /* round 13: */
    if (Nr > 13) {
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ GETU32(&rk8[52 * 4]);
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ GETU32(&rk8[53 * 4]);
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ GETU32(&rk8[54 * 4]);
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ GETU32(&rk8[55 * 4]);
    }

    rk8 += Nr << 4;

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
            GETU32(&rk8[0 * 4]);
    s1 =
            (Te4[(t1 >> 24)       ] & 0xff000000) ^
            (Te4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
            (Te4[(t3 >>  8) & 0xff] & 0x0000ff00) ^
            (Te4[(t0      ) & 0xff] & 0x000000ff) ^
            GETU32(&rk8[1 * 4]);
    s2 =
            (Te4[(t2 >> 24)       ] & 0xff000000) ^
            (Te4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
            (Te4[(t0 >>  8) & 0xff] & 0x0000ff00) ^
            (Te4[(t1      ) & 0xff] & 0x000000ff) ^
            GETU32(&rk8[2 * 4]);
    s3 =
            (Te4[(t3 >> 24)       ] & 0xff000000) ^
            (Te4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
            (Te4[(t1 >>  8) & 0xff] & 0x0000ff00) ^
            (Te4[(t2      ) & 0xff] & 0x000000ff) ^
            GETU32(&rk8[3 * 4]);

    PUTU32(ct     , s0);
    PUTU32(ct +  4, s1);
    PUTU32(ct +  8, s2);
    PUTU32(ct + 12, s3);
}

template <int Nr>
static void AES_Decrypt_portable( const uint8_t rk8[] /*16*(Nr + 1)*/, const uint8_t ct[16], uint8_t pt[16] ) {
    // STATIC_ASSERT(Nr >=1 && Nr <= 14);
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = GETU32(ct     ) ^ GETU32(&rk8[0 * 4]);
    s1 = GETU32(ct +  4) ^ GETU32(&rk8[1 * 4]);
    s2 = GETU32(ct +  8) ^ GETU32(&rk8[2 * 4]);
    s3 = GETU32(ct + 12) ^ GETU32(&rk8[3 * 4]);

    /* round 1: */
    if (Nr > 1) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ GETU32(&rk8[4 * 4]);
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ GETU32(&rk8[5 * 4]);
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ GETU32(&rk8[6 * 4]);
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ GETU32(&rk8[7 * 4]);
    }
    /* round 2: */
    if (Nr > 2) {
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ GETU32(&rk8[ 8 * 4]);
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ GETU32(&rk8[ 9 * 4]);
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ GETU32(&rk8[10 * 4]);
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ GETU32(&rk8[11 * 4]);
    }
    /* round 3: */
    if (Nr > 3) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ GETU32(&rk8[12 * 4]);
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ GETU32(&rk8[13 * 4]);
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ GETU32(&rk8[14 * 4]);
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ GETU32(&rk8[15 * 4]);
    }
    /* round 4: */
    if (Nr > 4) {
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ GETU32(&rk8[16 * 4]);
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ GETU32(&rk8[17 * 4]);
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ GETU32(&rk8[18 * 4]);
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ GETU32(&rk8[19 * 4]);
    }
    /* round 5: */
    if (Nr > 5) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ GETU32(&rk8[20 * 4]);
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ GETU32(&rk8[21 * 4]);
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ GETU32(&rk8[22 * 4]);
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ GETU32(&rk8[23 * 4]);
    }
    /* round 6: */
    if (Nr > 6) {
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ GETU32(&rk8[24 * 4]);
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ GETU32(&rk8[25 * 4]);
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ GETU32(&rk8[26 * 4]);
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ GETU32(&rk8[27 * 4]);
    }
    /* round 7: */
    if (Nr > 7) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ GETU32(&rk8[28 * 4]);
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ GETU32(&rk8[29 * 4]);
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ GETU32(&rk8[30 * 4]);
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ GETU32(&rk8[31 * 4]);
    }
    /* round 8: */
    if (Nr > 8) {
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ GETU32(&rk8[32 * 4]);
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ GETU32(&rk8[33 * 4]);
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ GETU32(&rk8[34 * 4]);
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ GETU32(&rk8[35 * 4]);
    }
    /* round 9: */
    if (Nr > 9) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ GETU32(&rk8[36 * 4]);
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ GETU32(&rk8[37 * 4]);
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ GETU32(&rk8[38 * 4]);
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ GETU32(&rk8[39 * 4]);
    }
    /* round 10: */
    if (Nr > 10) {
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ GETU32(&rk8[40 * 4]);
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ GETU32(&rk8[41 * 4]);
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ GETU32(&rk8[42 * 4]);
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ GETU32(&rk8[43 * 4]);
    }
    /* round 11: */
    if (Nr > 11) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ GETU32(&rk8[44 * 4]);
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ GETU32(&rk8[45 * 4]);
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ GETU32(&rk8[46 * 4]);
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ GETU32(&rk8[47 * 4]);
    }
    /* round 12: */
    if (Nr > 12) {
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >> 8) & 0xff] ^ Td3[t1 & 0xff] ^ GETU32(&rk8[48 * 4]);
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >> 8) & 0xff] ^ Td3[t2 & 0xff] ^ GETU32(&rk8[49 * 4]);
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >> 8) & 0xff] ^ Td3[t3 & 0xff] ^ GETU32(&rk8[50 * 4]);
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >> 8) & 0xff] ^ Td3[t0 & 0xff] ^ GETU32(&rk8[51 * 4]);
    }
    /* round 13: */
    if (Nr > 13) {
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >> 8) & 0xff] ^ Td3[s1 & 0xff] ^ GETU32(&rk8[52 * 4]);
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >> 8) & 0xff] ^ Td3[s2 & 0xff] ^ GETU32(&rk8[53 * 4]);
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >> 8) & 0xff] ^ Td3[s3 & 0xff] ^ GETU32(&rk8[54 * 4]);
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >> 8) & 0xff] ^ Td3[s0 & 0xff] ^ GETU32(&rk8[55 * 4]);
    }

    rk8 += Nr << 4;

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
            GETU32(&rk8[0 * 4]);
    s1 =
            (Td4[(t1 >> 24)       ] & 0xff000000) ^
            (Td4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
            (Td4[(t3 >>  8) & 0xff] & 0x0000ff00) ^
            (Td4[(t2      ) & 0xff] & 0x000000ff) ^
            GETU32(&rk8[1 * 4]);
    s2 =
            (Td4[(t2 >> 24)       ] & 0xff000000) ^
            (Td4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
            (Td4[(t0 >>  8) & 0xff] & 0x0000ff00) ^
            (Td4[(t3      ) & 0xff] & 0x000000ff) ^
            GETU32(&rk8[2 * 4]);
    s3 =
            (Td4[(t3 >> 24)       ] & 0xff000000) ^
            (Td4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
            (Td4[(t1 >>  8) & 0xff] & 0x0000ff00) ^
            (Td4[(t0      ) & 0xff] & 0x000000ff) ^
            GETU32(&rk8[3 * 4]);

    PUTU32(pt     , s0);
    PUTU32(pt +  4, s1);
    PUTU32(pt +  8, s2);
    PUTU32(pt + 12, s3);
}

static void AES_EncryptRound_portable( const uint8_t rk8[] /*16*/, uint8_t block[16] ) {
    uint32_t t0, t1, t2, t3;

    t0 = Te0[block[ 0]] ^ Te1[block[ 5]] ^ Te2[block[10]] ^ Te3[block[15]];
    t1 = Te0[block[ 4]] ^ Te1[block[ 9]] ^ Te2[block[14]] ^ Te3[block[ 3]];
    t2 = Te0[block[ 8]] ^ Te1[block[13]] ^ Te2[block[ 2]] ^ Te3[block[ 7]];
    t3 = Te0[block[12]] ^ Te1[block[ 1]] ^ Te2[block[ 6]] ^ Te3[block[11]];

    PUTU32(block     , t0);
    PUTU32(block +  4, t1);
    PUTU32(block +  8, t2);
    PUTU32(block + 12, t3);

    for (unsigned i = 0; i < 16; i++) {
        block[i] ^= rk8[i];
    }
}

static void AES_DecryptRound_portable( const uint8_t rk8[] /*16*/, uint8_t block[16] ) {
    uint32_t t0, t1, t2, t3;

    t0 = Td0[block[ 0]] ^ Td1[block[13]] ^ Td2[block[10]] ^ Td3[block[ 7]];
    t1 = Td0[block[ 4]] ^ Td1[block[ 1]] ^ Td2[block[14]] ^ Td3[block[11]];
    t2 = Td0[block[ 8]] ^ Td1[block[ 5]] ^ Td2[block[ 2]] ^ Td3[block[15]];
    t3 = Td0[block[12]] ^ Td1[block[ 9]] ^ Td2[block[ 6]] ^ Td3[block[ 3]];

    PUTU32(block     , t0);
    PUTU32(block +  4, t1);
    PUTU32(block +  8, t2);
    PUTU32(block + 12, t3);

    for (unsigned i = 0; i < 16; i++) {
        block[i] ^= rk8[i];
    }
}
