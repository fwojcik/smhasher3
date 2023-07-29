/*
 * ascon v1.2, XOF and XOFa variants
 * CC0 1.0 Universal
 *
 * Statement of Purpose
 *
 * The laws of most jurisdictions throughout the world automatically
 * confer exclusive Copyright and Related Rights (defined below) upon
 * the creator and subsequent owner(s) (each and all, an "owner") of
 * an original work of authorship and/or a database (each, a "Work").
 *
 * Certain owners wish to permanently relinquish those rights to a
 * Work for the purpose of contributing to a commons of creative,
 * cultural and scientific works ("Commons") that the public can
 * reliably and without fear of later claims of infringement build
 * upon, modify, incorporate in other works, reuse and redistribute as
 * freely as possible in any form whatsoever and for any purposes,
 * including without limitation commercial purposes. These owners may
 * contribute to the Commons to promote the ideal of a free culture
 * and the further production of creative, cultural and scientific
 * works, or to gain reputation or greater distribution for their Work
 * in part through the use and efforts of others.
 *
 * For these and/or other purposes and motivations, and without any
 * expectation of additional consideration or compensation, the person
 * associating CC0 with a Work (the "Affirmer"), to the extent that he
 * or she is an owner of Copyright and Related Rights in the Work,
 * voluntarily elects to apply CC0 to the Work and publicly distribute
 * the Work under its terms, with knowledge of his or her Copyright
 * and Related Rights in the Work and the meaning and intended legal
 * effect of CC0 on those rights.
 *
 * 1. Copyright and Related Rights. A Work made available under CC0
 * may be protected by copyright and related or neighboring rights
 * ("Copyright and Related Rights"). Copyright and Related Rights
 * include, but are not limited to, the following:
 *
 *   i. the right to reproduce, adapt, distribute, perform, display,
 *   communicate, and translate a Work;
 *
 *   ii. moral rights retained by the original author(s) and/or performer(s);
 *
 *   iii. publicity and privacy rights pertaining to a person's image
 *   or likeness depicted in a Work;
 *
 *   iv. rights protecting against unfair competition in regards to a
 *   Work, subject to the limitations in paragraph 4(a), below;
 *
 *   v. rights protecting the extraction, dissemination, use and reuse
 *   of data in a Work;
 *
 *   vi. database rights (such as those arising under Directive
 *   96/9/EC of the European Parliament and of the Council of 11 March
 *   1996 on the legal protection of databases, and under any national
 *   implementation thereof, including any amended or successor
 *   version of such directive); and
 *
 *   vii. other similar, equivalent or corresponding rights throughout
 *   the world based on applicable law or treaty, and any national
 *   implementations thereof.
 *
 * 2. Waiver. To the greatest extent permitted by, but not in
 * contravention of, applicable law, Affirmer hereby overtly, fully,
 * permanently, irrevocably and unconditionally waives, abandons, and
 * surrenders all of Affirmer's Copyright and Related Rights and
 * associated claims and causes of action, whether now known or
 * unknown (including existing as well as future claims and causes of
 * action), in the Work (i) in all territories worldwide, (ii) for the
 * maximum duration provided by applicable law or treaty (including
 * future time extensions), (iii) in any current or future medium and
 * for any number of copies, and (iv) for any purpose whatsoever,
 * including without limitation commercial, advertising or promotional
 * purposes (the "Waiver"). Affirmer makes the Waiver for the benefit
 * of each member of the public at large and to the detriment of
 * Affirmer's heirs and successors, fully intending that such Waiver
 * shall not be subject to revocation, rescission, cancellation,
 * termination, or any other legal or equitable action to disrupt the
 * quiet enjoyment of the Work by the public as contemplated by
 * Affirmer's express Statement of Purpose.
 *
 * 3. Public License Fallback. Should any part of the Waiver for any
 * reason be judged legally invalid or ineffective under applicable
 * law, then the Waiver shall be preserved to the maximum extent
 * permitted taking into account Affirmer's express Statement of
 * Purpose. In addition, to the extent the Waiver is so judged
 * Affirmer hereby grants to each affected person a royalty-free, non
 * transferable, non sublicensable, non exclusive, irrevocable and
 * unconditional license to exercise Affirmer's Copyright and Related
 * Rights in the Work (i) in all territories worldwide, (ii) for the
 * maximum duration provided by applicable law or treaty (including
 * future time extensions), (iii) in any current or future medium and
 * for any number of copies, and (iv) for any purpose whatsoever,
 * including without limitation commercial, advertising or promotional
 * purposes (the "License"). The License shall be deemed effective as
 * of the date CC0 was applied by Affirmer to the Work. Should any
 * part of the License for any reason be judged legally invalid or
 * ineffective under applicable law, such partial invalidity or
 * ineffectiveness shall not invalidate the remainder of the License,
 * and in such case Affirmer hereby affirms that he or she will not
 * (i) exercise any of his or her remaining Copyright and Related
 * Rights in the Work or (ii) assert any associated claims and causes
 * of action with respect to the Work, in either case contrary to
 * Affirmer's express Statement of Purpose.
 *
 * 4. Limitations and Disclaimers.
 *
 *   a. No trademark or patent rights held by Affirmer are waived,
 *   abandoned, surrendered, licensed or otherwise affected by this
 *   document.
 *
 *   b. Affirmer offers the Work as-is and makes no representations or
 *   warranties of any kind concerning the Work, express, implied,
 *   statutory or otherwise, including without limitation warranties
 *   of title, merchantability, fitness for a particular purpose, non
 *   infringement, or the absence of latent or other defects,
 *   accuracy, or the present or absence of errors, whether or not
 *   discoverable, all to the greatest extent permissible under
 *   applicable law.
 *
 *   c. Affirmer disclaims responsibility for clearing rights of other
 *   persons that may apply to the Work or any use thereof, including
 *   without limitation any person's Copyright and Related Rights in
 *   the Work. Further, Affirmer disclaims responsibility for
 *   obtaining any necessary consents, permissions or other rights
 *   required for any use of the Work.
 *
 *   d. Affirmer understands and acknowledges that Creative Commons is
 *   not a party to this document and has no duty or obligation with
 *   respect to this CC0 or use of the Work.
 *
 * For more information, please see
 * <http://creativecommons.org/publicdomain/zero/1.0/>
 */
#include "Platform.h"
#include "Hashlib.h"

// #define CRYPTO_VERSION "1.2.6"

//------------------------------------------------------------
typedef struct {
    uint64_t  x[5];
} state_t;

#define ASCON_HASH_RATE 8

#define MAX_P_ROUNDS    12
#define P_ROUNDS_XOF    12
#define P_ROUNDS_XOFA   8

static FORCE_INLINE void ROUND( state_t * s, uint8_t C ) {
    state_t t;

    /* round constant */
    s->x[2] ^= C;
    /* s-box layer */
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];
    t.x[0]   = s->x[0] ^ (~s->x[1] & s->x[2]);
    t.x[2]   = s->x[2] ^ (~s->x[3] & s->x[4]);
    t.x[4]   = s->x[4] ^ (~s->x[0] & s->x[1]);
    t.x[1]   = s->x[1] ^ (~s->x[2] & s->x[3]);
    t.x[3]   = s->x[3] ^ (~s->x[4] & s->x[0]);
    t.x[1]  ^= t.x[0];
    t.x[3]  ^= t.x[2];
    t.x[0]  ^= t.x[4];
    /* linear layer */
    s->x[2]  = t.x[2] ^ ROTR64(t.x [2],  6 -  1);
    s->x[3]  = t.x[3] ^ ROTR64(t.x [3], 17 - 10);
    s->x[4]  = t.x[4] ^ ROTR64(t.x [4], 41 -  7);
    s->x[0]  = t.x[0] ^ ROTR64(t.x [0], 28 - 19);
    s->x[1]  = t.x[1] ^ ROTR64(t.x [1], 61 - 39);
    s->x[2]  = t.x[2] ^ ROTR64(s->x[2],  1);
    s->x[3]  = t.x[3] ^ ROTR64(s->x[3], 10);
    s->x[4]  = t.x[4] ^ ROTR64(s->x[4],  7);
    s->x[0]  = t.x[0] ^ ROTR64(s->x[0], 19);
    s->x[1]  = t.x[1] ^ ROTR64(s->x[1], 39);
    s->x[2]  = ~s->x[2];
}

template <uint32_t rounds>
static FORCE_INLINE void P( state_t * s ) {
    if (rounds > MAX_P_ROUNDS) { return; }

    const uint8_t RC[MAX_P_ROUNDS] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
        0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
    };

    for (uint32_t r = (MAX_P_ROUNDS - rounds); r < MAX_P_ROUNDS; r++) {
        ROUND(s, RC[r]);
    }
}

// Homegrown seeding for SMHasher3
template <bool XOFa>
static FORCE_INLINE void ascon_initxof( state_t * s, uint64_t seed ) {
    if (XOFa) {
        s->x[0] = UINT64_C(0x44906568b77b9832);
        s->x[1] = UINT64_C(0xcd8d6cae53455532);
        s->x[2] = UINT64_C(0xf7b5212756422129) ^ seed;
        s->x[3] = UINT64_C(0x246885e1de0d225b) ^ seed;
        s->x[4] = UINT64_C(0xa8cb5ce33449973f);
    } else {
        s->x[0] = UINT64_C(0xb57e273b814cd416);
        s->x[1] = UINT64_C(0x2b51042562ae2420);
        s->x[2] = UINT64_C(0x66a3a7768ddf2218) ^ seed;
        s->x[3] = UINT64_C(0x5aad0a7a8153650c) ^ seed;
        s->x[4] = UINT64_C(0x4f3e0e32539493b6);
    }
}

template <bool XOFa, bool bswap>
static FORCE_INLINE void ascon_absorb( state_t * s, const uint8_t * in, uint64_t inlen ) {
    /* absorb full plaintext blocks */
    while (inlen >= ASCON_HASH_RATE) {
        s->x[0] ^= GET_U64<bswap>(in, 0);
        P<XOFa ? P_ROUNDS_XOFA : P_ROUNDS_XOF>(s);
        in      += ASCON_HASH_RATE;
        inlen   -= ASCON_HASH_RATE;
    }
    /* absorb final plaintext block */
    if (inlen) {
        uint64_t last = 0;
        memcpy(&last, in, inlen);
        s->x[0] ^= COND_BSWAP(last, bswap);
    }
    /* add padding */
    s->x[0] ^= UINT64_C(0x80) << (56 - 8 * inlen);
}

template <bool XOFa, bool bswap>
static void ascon_squeeze( state_t * s, uint8_t * out, uint64_t outlen ) {
    while (outlen > ASCON_HASH_RATE) {
        PUT_U64<bswap>(s->x[0], out, 0);
        P<XOFa ? P_ROUNDS_XOFA : P_ROUNDS_XOF>(s);
        out    += ASCON_HASH_RATE;
        outlen -= ASCON_HASH_RATE;
    }
    uint8_t buf[8];
    PUT_U64<bswap>(s->x[0], buf, 0);
    memcpy(out, buf, outlen);
}

//------------------------------------------------------------
template <uint64_t outbits, bool XOFa, bool bswap>
static void ascon_xof( const void * in, const size_t len, const seed_t seed, void * out ) {
    state_t s;

    ascon_initxof<XOFa>(&s, seed);
    ascon_absorb<XOFa, bswap>(&s, (const uint8_t *)in, (uint64_t)len);
    P<P_ROUNDS_XOF>(&s); // Always! Never P_ROUNDS_XOFA
    switch (outbits) {
    case  32: ascon_squeeze<XOFa, bswap>(&s, (uint8_t *)out,  4); break;
    case  64: ascon_squeeze<XOFa, bswap>(&s, (uint8_t *)out,  8); break;
    case 128: ascon_squeeze<XOFa, bswap>(&s, (uint8_t *)out, 16); break;
    case 160: ascon_squeeze<XOFa, bswap>(&s, (uint8_t *)out, 20); break;
    case 224: ascon_squeeze<XOFa, bswap>(&s, (uint8_t *)out, 28); break;
    case 256: ascon_squeeze<XOFa, bswap>(&s, (uint8_t *)out, 32); break;
    }
}

//------------------------------------------------------------
// KAT results were generated from the reference implementation of
// ascon using `./genkat_crypto_hash_asconxofv12_opt64` and
// `./genkat_crypto_hash_asconxofav12_opt64`.
#define KAT_NUM 17
static const uint8_t KAT[KAT_NUM][2][256 / 8] = {
    {
        {
            0x5D, 0x4C, 0xBD, 0xE6, 0x35, 0x0E, 0xA4, 0xC1, 0x74, 0xBD, 0x65, 0xB5, 0xB3, 0x32, 0xF8, 0x40,
            0x8F, 0x99, 0x74, 0x0B, 0x81, 0xAA, 0x02, 0x73, 0x5E, 0xAE, 0xFB, 0xCF, 0x0B, 0xA0, 0x33, 0x9E,
        },
        {
            0x7C, 0x10, 0xDF, 0xFD, 0x6B, 0xB0, 0x3B, 0xE2, 0x62, 0xD7, 0x2F, 0xBE, 0x1B, 0x0F, 0x53, 0x00,
            0x13, 0xC6, 0xC4, 0xEA, 0xDA, 0xAB, 0xDE, 0x27, 0x8D, 0x6F, 0x29, 0xD5, 0x79, 0xE3, 0x90, 0x8D,
        },
    },
    {
        {
            0xB2, 0xED, 0xBB, 0x27, 0xAC, 0x83, 0x97, 0xA5, 0x5B, 0xC8, 0x3D, 0x13, 0x7C, 0x15, 0x1D, 0xE9,
            0xED, 0xE0, 0x48, 0x33, 0x8F, 0xE9, 0x07, 0xF0, 0xD3, 0x62, 0x9E, 0x71, 0x78, 0x46, 0xFE, 0xDC,
        },
        {
            0x96, 0x54, 0x45, 0xC4, 0x6C, 0x8E, 0x9B, 0x94, 0x8E, 0xDF, 0xEF, 0x7B, 0x58, 0x79, 0xE0, 0x6A,
            0xB5, 0xF0, 0x23, 0x77, 0x0E, 0xA8, 0x92, 0xFA, 0x4B, 0x54, 0x52, 0x50, 0x08, 0x46, 0x7E, 0xA3,
        },
    },
    {
        {
            0xD1, 0x96, 0x46, 0x1C, 0x29, 0x9D, 0xB7, 0x14, 0xD7, 0x8C, 0x26, 0x79, 0x24, 0xB5, 0x78, 0x6E,
            0xE2, 0x6F, 0xC4, 0x3B, 0x3E, 0x64, 0x0D, 0xAA, 0x53, 0x97, 0xE3, 0x8E, 0x39, 0xD3, 0x9D, 0xC6,
        },
        {
            0x48, 0xEB, 0x41, 0xB7, 0xA4, 0x35, 0x2A, 0xFB, 0x89, 0x43, 0xB7, 0x65, 0x65, 0x48, 0x55, 0xB1,
            0xD7, 0x10, 0x4B, 0x22, 0xE9, 0x81, 0xE5, 0x12, 0x0D, 0xA9, 0x96, 0x25, 0x79, 0xA7, 0xBA, 0xE6,
        },
    },
    {
        {
            0x1D, 0x18, 0xB9, 0xDD, 0x8F, 0xF9, 0xA1, 0xBF, 0x59, 0x75, 0x1B, 0x88, 0xD3, 0x27, 0x66, 0xC5,
            0xE0, 0x54, 0x91, 0x0F, 0x49, 0x7B, 0xFF, 0x40, 0x92, 0xAF, 0xC4, 0x7F, 0x58, 0x85, 0x52, 0x3B,
        },
        {
            0x5C, 0xFD, 0x8A, 0xCE, 0x65, 0x3E, 0x21, 0x27, 0x57, 0xD4, 0xA4, 0xAC, 0x3B, 0x6F, 0xAD, 0x31,
            0xAB, 0xCB, 0xFA, 0x3F, 0x9E, 0x0F, 0x92, 0x24, 0x46, 0xF7, 0x6A, 0xF3, 0x72, 0xC5, 0x3E, 0xED,
        },
    },
    {
        {
            0x66, 0xFB, 0x74, 0x17, 0x47, 0x82, 0xAF, 0xED, 0x89, 0x84, 0x78, 0xAA, 0x72, 0x90, 0x58, 0xD5,
            0xC3, 0x0A, 0xF1, 0x9A, 0xF2, 0xF5, 0xD4, 0xE1, 0xCE, 0x65, 0xCD, 0x32, 0x05, 0x94, 0xEF, 0x66,
        },
        {
            0xE2, 0xFE, 0xE1, 0x11, 0xA8, 0xE4, 0xB6, 0x22, 0x46, 0x2F, 0x89, 0x7D, 0xA4, 0x8C, 0x02, 0xB8,
            0x07, 0xCA, 0xDD, 0xC2, 0x80, 0x17, 0x18, 0x6D, 0xC8, 0x56, 0xD8, 0xCF, 0x3D, 0xC2, 0x02, 0x48,
        },
    },
    {
        {
            0xF4, 0x73, 0xC7, 0xA7, 0xD9, 0xF1, 0x40, 0xAA, 0x1A, 0xFB, 0x2D, 0xD0, 0xA0, 0xEC, 0xC2, 0x63,
            0x5B, 0x01, 0x74, 0x94, 0x2A, 0x70, 0x94, 0xEC, 0x34, 0xF4, 0xD8, 0x02, 0x5B, 0x9F, 0xC3, 0x91,
        },
        {
            0x05, 0x2E, 0xA9, 0x65, 0x27, 0x96, 0xB2, 0xD7, 0xBA, 0x5B, 0x63, 0x05, 0xAD, 0x3E, 0x42, 0x91,
            0x27, 0x71, 0x30, 0x25, 0x29, 0xBA, 0xDF, 0x73, 0x51, 0x7C, 0x54, 0xC7, 0xDA, 0xD9, 0x5F, 0xDF,
        },
    },
    {
        {
            0xD7, 0x65, 0x8B, 0x24, 0xB9, 0x88, 0x60, 0x57, 0xB8, 0x82, 0x75, 0x18, 0xA2, 0xA3, 0x67, 0x15,
            0xA1, 0xB7, 0x32, 0x56, 0xE6, 0x5D, 0x04, 0x93, 0xDD, 0x0A, 0xF3, 0xE2, 0x73, 0x87, 0xDF, 0x40,
        },
        {
            0x30, 0xBC, 0x8D, 0x20, 0xC4, 0xAA, 0x4D, 0xF5, 0x39, 0xE9, 0xE6, 0xB5, 0x8A, 0x45, 0x2C, 0xAC,
            0x9E, 0x5E, 0x98, 0xF9, 0x4C, 0x6C, 0x90, 0xBF, 0x6C, 0x3B, 0xC9, 0xCF, 0x57, 0x3E, 0xB9, 0xED,
        },
    },
    {
        {
            0x1D, 0xB7, 0x47, 0x6C, 0xD7, 0x20, 0x64, 0xC6, 0x8E, 0x73, 0x6D, 0x82, 0x1E, 0xA6, 0xF0, 0xC9,
            0x36, 0x10, 0xFE, 0x22, 0x32, 0x67, 0x54, 0xF5, 0x36, 0x68, 0x36, 0x87, 0x1A, 0x6F, 0x5A, 0x10,
        },
        {
            0x00, 0x75, 0x5B, 0x9D, 0x72, 0xB2, 0x63, 0x2D, 0x88, 0xCB, 0x69, 0x45, 0xD5, 0x36, 0x38, 0x2C,
            0x1E, 0x0B, 0x49, 0x57, 0xB4, 0xA4, 0x4B, 0xB5, 0x1C, 0x14, 0x88, 0x6A, 0x6F, 0xB3, 0x1A, 0x45,
        },
    },
    {
        {
            0x18, 0x42, 0x7D, 0x2D, 0x29, 0xDF, 0x1E, 0x02, 0x02, 0x64, 0x9F, 0x03, 0x2F, 0x20, 0x80, 0x36,
            0x3F, 0xEC, 0x5D, 0xE7, 0x2E, 0xCA, 0xE1, 0x1B, 0x4F, 0x98, 0xCC, 0xC7, 0x58, 0x43, 0xE7, 0xCC,
        },
        {
            0x91, 0xC7, 0x2F, 0x62, 0x73, 0xB6, 0xED, 0x44, 0x4B, 0xF5, 0x60, 0xF2, 0xFA, 0xC9, 0x9E, 0x8F,
            0xED, 0xDD, 0xF3, 0x01, 0x62, 0x68, 0x8B, 0x86, 0x55, 0x3E, 0xB5, 0x7F, 0x1C, 0x98, 0xC2, 0x0E,
        },
    },
    {
        {
            0xCE, 0x60, 0x6E, 0x3F, 0xFC, 0xEE, 0x53, 0xB1, 0x13, 0xAA, 0x5A, 0x5C, 0xA3, 0xA1, 0x63, 0x76,
            0xA3, 0xDE, 0x36, 0x43, 0x52, 0x87, 0x5D, 0x33, 0x60, 0xE1, 0x31, 0x66, 0x6A, 0x56, 0x72, 0x48,
        },
        {
            0x7E, 0x79, 0x76, 0x8F, 0x37, 0xD2, 0x13, 0xB1, 0x1B, 0x41, 0x93, 0xE1, 0xD6, 0x2D, 0x33, 0x99,
            0x54, 0xA3, 0xB9, 0xE1, 0x6C, 0xCE, 0xF0, 0x5F, 0xD5, 0x74, 0xE1, 0x33, 0x06, 0x68, 0xB6, 0x28,
        },
    },
    {
        {
            0xAA, 0x1F, 0x11, 0xB1, 0x73, 0x85, 0xCC, 0xEB, 0xDC, 0x06, 0x5F, 0x20, 0xA6, 0x19, 0x5A, 0xB6,
            0x54, 0x0D, 0x98, 0xA1, 0xCA, 0xBE, 0x6D, 0xBB, 0x35, 0x81, 0x33, 0x3E, 0x70, 0x32, 0xD0, 0xDB,
        },
        {
            0xB1, 0x9D, 0x75, 0xF2, 0x26, 0x60, 0x8F, 0xBB, 0x58, 0x30, 0x72, 0x44, 0x49, 0x0A, 0xC6, 0x7E,
            0x96, 0x3A, 0x66, 0x44, 0x43, 0x94, 0x1F, 0xD6, 0xB1, 0xEE, 0x03, 0x71, 0xB7, 0x6F, 0x45, 0xF3,
        },
    },
    {
        {
            0xB7, 0x4A, 0xC0, 0x1F, 0xBE, 0xCE, 0xA5, 0x2A, 0x80, 0x11, 0xDD, 0x6F, 0x94, 0x71, 0x47, 0x39,
            0x56, 0x03, 0x4D, 0xF5, 0x47, 0xA7, 0x81, 0x13, 0x92, 0x4D, 0x73, 0x69, 0xB6, 0xB1, 0xDC, 0x0D,
        },
        {
            0x1C, 0x93, 0xD3, 0xA4, 0x48, 0xEC, 0x29, 0x44, 0xCC, 0x74, 0x05, 0x60, 0x08, 0xE5, 0x2B, 0x1D,
            0x8F, 0xCC, 0xA9, 0x78, 0x4C, 0x80, 0x63, 0x3B, 0xCB, 0xF5, 0x74, 0x5B, 0x57, 0xA2, 0xFD, 0x58,
        },
    },
    {
        {
            0x46, 0x50, 0xC5, 0x70, 0x93, 0x29, 0x66, 0x08, 0x25, 0xA9, 0xA5, 0xDA, 0xED, 0x9F, 0xA5, 0x0B,
            0xE5, 0xAB, 0xAB, 0xAA, 0x9D, 0x37, 0x32, 0x71, 0x9A, 0x01, 0xBF, 0x29, 0xD7, 0xBF, 0xE5, 0x43,
        },
        {
            0x20, 0x91, 0x42, 0xD4, 0xB9, 0x49, 0xBF, 0xFA, 0xC2, 0x8D, 0xB9, 0x79, 0xAF, 0x84, 0xC9, 0xC2,
            0x91, 0xF8, 0x75, 0x40, 0x41, 0x0F, 0x2C, 0xC6, 0xBF, 0x96, 0xAA, 0x63, 0x7B, 0x45, 0x85, 0x64,
        },
    },
    {
        {
            0x6E, 0x68, 0x23, 0xD3, 0xC0, 0x4E, 0xA3, 0xBC, 0x20, 0xB4, 0x3B, 0xEC, 0xEB, 0x5B, 0x42, 0x85,
            0x4E, 0xF8, 0x40, 0xEE, 0x47, 0x7B, 0x58, 0x70, 0x94, 0x49, 0xBB, 0x8D, 0x8F, 0x63, 0xEE, 0x78,
        },
        {
            0xF8, 0x4E, 0x89, 0xA3, 0xE9, 0x07, 0x0A, 0xAE, 0xFE, 0x86, 0x0D, 0x49, 0x83, 0x80, 0x7E, 0x07,
            0xD1, 0xFB, 0xF6, 0x5D, 0xAB, 0x2F, 0x1B, 0x81, 0x51, 0x34, 0x7F, 0x82, 0x8C, 0x9F, 0x0F, 0xC0,
        },
    },
    {
        {
            0x3D, 0x02, 0xF6, 0x79, 0xEF, 0x69, 0xD3, 0x3D, 0xF1, 0x7C, 0xC8, 0x04, 0x0A, 0xBC, 0xAC, 0xDD,
            0xF8, 0x13, 0x3A, 0x04, 0xE0, 0xD8, 0x9E, 0x3C, 0xF1, 0x0D, 0xAD, 0x74, 0xE0, 0x08, 0x04, 0xD9,
        },
        {
            0x82, 0xE2, 0x74, 0x4E, 0xE7, 0xD9, 0x32, 0x76, 0xD1, 0x74, 0xE9, 0x87, 0x7A, 0x42, 0x6A, 0x83,
            0x0D, 0xF9, 0x1A, 0xAE, 0x41, 0x24, 0x57, 0x6A, 0x7E, 0xC5, 0x2E, 0xE8, 0x47, 0xEB, 0x0B, 0xC0,
        },
    },
    {
        {
            0x39, 0x9E, 0x6B, 0xE5, 0x84, 0xDE, 0x50, 0x91, 0xF4, 0x97, 0x11, 0xED, 0x6C, 0x19, 0x5F, 0x0D,
            0xE0, 0xEE, 0x81, 0x11, 0x13, 0xC6, 0x8B, 0x37, 0x23, 0x99, 0xDB, 0xBF, 0xF2, 0x8F, 0x11, 0x73,
        },
        {
            0x75, 0xF6, 0x13, 0x59, 0xF0, 0x4C, 0x77, 0xFF, 0x4D, 0xE5, 0x8A, 0x10, 0xF9, 0xF8, 0x7B, 0x31,
            0xB5, 0xB8, 0xDA, 0x33, 0x73, 0xF6, 0x23, 0x0F, 0xE1, 0x73, 0x50, 0x33, 0x44, 0x6B, 0x99, 0x48,
        },
    },
    {
        {
            0xC8, 0x61, 0xA8, 0x9C, 0xFB, 0x13, 0x35, 0xF2, 0x78, 0xC9, 0x6C, 0xF7, 0xFF, 0xC9, 0x75, 0x3C,
            0x29, 0x0C, 0xBE, 0x1A, 0x4E, 0x18, 0x6D, 0x29, 0x23, 0xB4, 0x96, 0xBB, 0x4E, 0xA5, 0xE5, 0x19,
        },
        {
            0x94, 0x24, 0xB7, 0xAE, 0x5F, 0xA7, 0x2D, 0x3E, 0xE4, 0xA2, 0x66, 0x11, 0x2E, 0x7A, 0xBC, 0x40,
            0x92, 0xE8, 0x15, 0xAE, 0x29, 0xFA, 0xB2, 0x6D, 0xA6, 0x66, 0xC1, 0x48, 0x5B, 0xA9, 0x2B, 0xDC,
        },
    },
};

static bool ascon_xof_selftest( void ) {
    uint8_t input[KAT_NUM - 1];

    for (size_t i = 0; i < sizeof(input); i++) { input[i] = (uint8_t)i; }

    bool passed = true;
    for (int i = 0; i < KAT_NUM; i++) {
        uint8_t output[256 / 8];

        if (isLE()) {
            ascon_xof<256, true, true>(input, i, 0, output);
        } else {
            ascon_xof<256, true, false>(input, i, 0, output);
        }
        if (0 != memcmp(KAT[i][1], output, sizeof(output))) {
            printf("Mismatch with XOFa len %d\n  Expected:", i);
            for (int j = 0; j < 256 / 8; j++) { printf(" %02x", KAT[i][1][j]); }
            printf("\n  Found   :");
            for (int j = 0; j < 256 / 8; j++) { printf(" %02x", output[j]); }
            printf("\n\n");
            passed = false;
        }

        if (isLE()) {
            ascon_xof<256, false, true>(input, i, 0, output);
        } else {
            ascon_xof<256, false, false>(input, i, 0, output);
        }
        if (0 != memcmp(KAT[i][0], output, sizeof(output))) {
            printf("Mismatch with XOF len %d\n  Expected:", i);
            for (int j = 0; j < 256 / 8; j++) { printf(" %02x", KAT[i][0][j]); }
            printf("\n  Found   :");
            for (int j = 0; j < 256 / 8; j++) { printf(" %02x", output[j]); }
            printf("\n\n");
            passed = false;
        }
    }

    return passed;
}

//------------------------------------------------------------
REGISTER_FAMILY(ascon,
   $.src_url    = "https://github.com/ascon/ascon-c",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

REGISTER_HASH(ascon_XOF_32,
   $.desc       = "ascon v1.2 (XOF, 32 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_BE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 32,
   $.verification_LE = 0x1124BD16,
   $.verification_BE = 0xED22753E,
   $.initfn          = ascon_xof_selftest,
   $.hashfn_native   = ascon_xof<32, false, false>,
   $.hashfn_bswap    = ascon_xof<32, false, true>
 );

REGISTER_HASH(ascon_XOFa_32,
   $.desc       = "ascon v1.2 (XOFa, 32 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_BE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 32,
   $.verification_LE = 0x8F5BB129,
   $.verification_BE = 0x44EBDFB6,
   $.initfn          = ascon_xof_selftest,
   $.hashfn_native   = ascon_xof<32, true, false>,
   $.hashfn_bswap    = ascon_xof<32, true, true>
 );

REGISTER_HASH(ascon_XOF_64,
   $.desc       = "ascon v1.2 (XOF, 64 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_BE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 64,
   $.verification_LE = 0xCDAAB40E,
   $.verification_BE = 0xAC65EB36,
   $.initfn          = ascon_xof_selftest,
   $.hashfn_native   = ascon_xof<64, false, false>,
   $.hashfn_bswap    = ascon_xof<64, false, true>
 );

REGISTER_HASH(ascon_XOFa_64,
   $.desc       = "ascon v1.2 (XOFa, 64 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_BE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 64,
   $.verification_LE = 0x43ACD116,
   $.verification_BE = 0xACFB3C9F,
   $.initfn          = ascon_xof_selftest,
   $.hashfn_native   = ascon_xof<64, true, false>,
   $.hashfn_bswap    = ascon_xof<64, true, true>
 );

REGISTER_HASH(ascon_XOF_128,
   $.desc       = "ascon v1.2 (XOF, 128 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_BE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 128,
   $.verification_LE = 0x9B2F9305,
   $.verification_BE = 0x6C15FBDF,
   $.initfn          = ascon_xof_selftest,
   $.hashfn_native   = ascon_xof<128, false, false>,
   $.hashfn_bswap    = ascon_xof<128, false, true>
 );

REGISTER_HASH(ascon_XOFa_128,
   $.desc       = "ascon v1.2 (XOFa, 128 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_BE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 128,
   $.verification_LE = 0x5701888C,
   $.verification_BE = 0x10B381AE,
   $.initfn          = ascon_xof_selftest,
   $.hashfn_native   = ascon_xof<128, true, false>,
   $.hashfn_bswap    = ascon_xof<128, true, true>
 );

REGISTER_HASH(ascon_XOF_160,
   $.desc       = "ascon v1.2 (XOF, 160 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_BE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 160,
   $.verification_LE = 0x3B726110,
   $.verification_BE = 0x3215F456,
   $.initfn          = ascon_xof_selftest,
   $.hashfn_native   = ascon_xof<160, false, false>,
   $.hashfn_bswap    = ascon_xof<160, false, true>
 );

REGISTER_HASH(ascon_XOFa_160,
   $.desc       = "ascon v1.2 (XOFa, 160 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_BE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 160,
   $.verification_LE = 0xA4E9A794,
   $.verification_BE = 0x387FC024,
   $.initfn          = ascon_xof_selftest,
   $.hashfn_native   = ascon_xof<160, true, false>,
   $.hashfn_bswap    = ascon_xof<160, true, true>
 );

REGISTER_HASH(ascon_XOF_224,
   $.desc       = "ascon v1.2 (XOF, 224 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_BE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 224,
   $.verification_LE = 0x83EAEBCC,
   $.verification_BE = 0x9929AC99,
   $.initfn          = ascon_xof_selftest,
   $.hashfn_native   = ascon_xof<224, false, false>,
   $.hashfn_bswap    = ascon_xof<224, false, true>
 );

REGISTER_HASH(ascon_XOFa_224,
   $.desc       = "ascon v1.2 (XOFa, 224 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_BE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 224,
   $.verification_LE = 0x618744B2,
   $.verification_BE = 0x2D9AFDE5,
   $.initfn          = ascon_xof_selftest,
   $.hashfn_native   = ascon_xof<224, true, false>,
   $.hashfn_bswap    = ascon_xof<224, true, true>
 );

REGISTER_HASH(ascon_XOF_256,
   $.desc       = "ascon v1.2 (XOF, 256 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_BE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 256,
   $.verification_LE = 0xC6629453,
   $.verification_BE = 0x6D8F406F,
   $.initfn          = ascon_xof_selftest,
   $.hashfn_native   = ascon_xof<256, false, false>,
   $.hashfn_bswap    = ascon_xof<256, false, true>
 );

REGISTER_HASH(ascon_XOFa_256,
   $.desc       = "ascon v1.2 (XOFa, 256 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_BE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 256,
   $.verification_LE = 0x2ACF11FE,
   $.verification_BE = 0xE5CD2E9B,
   $.initfn          = ascon_xof_selftest,
   $.hashfn_native   = ascon_xof<256, true, false>,
   $.hashfn_bswap    = ascon_xof<256, true, true>
 );
