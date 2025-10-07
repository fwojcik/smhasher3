/*
 * ascon v1.3, CXOF and CXOFa variants
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

//------------------------------------------------------------
typedef struct {
    uint64_t  x[5];
} state_t;

#define ASCON_HASH_RATE  8

#define MAX_P_ROUNDS    12
#define P_ROUNDS_CXOF   12
#define P_ROUNDS_CXOFA   8

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

//------------------------------------------------------------

static thread_local state_t state;

template <bool CXOFa>
static uintptr_t ascon_initcxof( const seed_t seed ) {
    // Initialize state to what it would be after absorbing the length
    // value of 64 bits for a customization string
    if (CXOFa) {
        state.x[0] = UINT64_C(0xb5352e2a69c85f96);
        state.x[1] = UINT64_C(0xbe28346a26b60ca4);
        state.x[2] = UINT64_C(0x385576e5b51ed975);
        state.x[3] = UINT64_C(0xdda521f6919307e2);
        state.x[4] = UINT64_C(0x69d39255153eab67);
    } else {
        state.x[0] = UINT64_C(0xb65e8c9d67bc6780);
        state.x[1] = UINT64_C(0x79bf1171a2027f1d);
        state.x[2] = UINT64_C(0xd72ea2406f56555c);
        state.x[3] = UINT64_C(0x30a41a4af76e8b67);
        state.x[4] = UINT64_C(0x03b0a840426250ca);
    }
    // absorb the customization "string"
    state.x[0] ^= (uint64_t)seed;
    P<CXOFa ? P_ROUNDS_CXOFA : P_ROUNDS_CXOF>(&state);
    // add padding
    state.x[0] ^= UINT64_C(0x01);
    P<CXOFa ? P_ROUNDS_CXOFA : P_ROUNDS_CXOF>(&state);
    // add domain separation
    //
    // !!! This is what the spec says to do, but the reference
    // implementation doesn't do this.
    //
    // Spec: https://csrc.nist.gov/csrc/media/Events/2023/lightweight-cryptography-workshop-2023/documents/accepted-papers/01-additional-modes-for-ascon.pdf
    state.x[4] ^= UINT64_C(0x80) << 56;

    return (seed_t)(uintptr_t)(void *)&state;
}

//------------------------------------------------------------

template <bool CXOFa, bool bswap>
static FORCE_INLINE void ascon_absorb( state_t * s, const uint8_t * in, uint64_t inlen ) {
    /* absorb full plaintext blocks */
    while (inlen >= ASCON_HASH_RATE) {
        s->x[0] ^= GET_U64<bswap>(in, 0);
        P<CXOFa ? P_ROUNDS_CXOFA : P_ROUNDS_CXOF>(s);
        in      += ASCON_HASH_RATE;
        inlen   -= ASCON_HASH_RATE;
    }
    /* absorb final plaintext block */
    if (inlen) {
        uint64_t last = 0;
        memcpy(&last, in, inlen);
        last = COND_BSWAP(last, bswap);
        s->x[0] ^= last;
    }
    /* add padding */
    s->x[0] ^= UINT64_C(0x01) << (inlen * 8);
}

template <bool CXOFa, bool bswap>
static void ascon_squeeze( state_t * s, uint8_t * out, uint64_t outlen ) {
    while (outlen > ASCON_HASH_RATE) {
        PUT_U64<bswap>(s->x[0], out, 0);
        P<CXOFa ? P_ROUNDS_CXOFA : P_ROUNDS_CXOF>(s);
        out    += ASCON_HASH_RATE;
        outlen -= ASCON_HASH_RATE;
    }
    uint8_t buf[8];
    PUT_U64<bswap>(s->x[0], buf, 0);
    memcpy(out, buf, outlen);
}

//------------------------------------------------------------
template <uint64_t outbits, bool CXOFa, bool bswap>
static void ascon_cxof( const void * in, const size_t len, const seed_t seed, void * out ) {
    state_t * initstate = (state_t *)(void *)(uintptr_t)seed;
    state_t   s;

    memcpy(&s, initstate, sizeof(s));

    ascon_absorb<CXOFa, bswap>(&s, (const uint8_t *)in, (uint64_t)len);
    P<P_ROUNDS_CXOF>(&s); // Always! Never P_ROUNDS_CXOFA
    switch (outbits) {
    case  32: ascon_squeeze<CXOFa, bswap>(&s, (uint8_t *)out,  4); break;
    case  64: ascon_squeeze<CXOFa, bswap>(&s, (uint8_t *)out,  8); break;
    case 128: ascon_squeeze<CXOFa, bswap>(&s, (uint8_t *)out, 16); break;
    case 160: ascon_squeeze<CXOFa, bswap>(&s, (uint8_t *)out, 20); break;
    case 224: ascon_squeeze<CXOFa, bswap>(&s, (uint8_t *)out, 28); break;
    case 256: ascon_squeeze<CXOFa, bswap>(&s, (uint8_t *)out, 32); break;
    }
}

//------------------------------------------------------------
// KAT results were generated from the reference implementation,
// with the domain-separation step added
#define KAT_NUM 17
static const uint8_t KAT[KAT_NUM][256 / 8] = {
    {
        0x6f, 0x9d, 0x97, 0x42, 0xa7, 0x43, 0xfa, 0x74, 0xbc, 0x1f, 0x3f, 0xe4, 0x6c, 0x3f, 0x87, 0x91,
        0x21, 0x12, 0x74, 0x33, 0xb0, 0x88, 0x51, 0x38, 0xf3, 0x47, 0x45, 0x18, 0xab, 0xf6, 0xf1, 0x8a,
    },
    {
        0x81, 0x1e, 0x3c, 0x06, 0x4a, 0x9b, 0x99, 0x86, 0xfb, 0x7b, 0xf4, 0xe5, 0xa5, 0x18, 0x48, 0x4e,
        0x05, 0x29, 0x26, 0xc8, 0x1d, 0xab, 0x5e, 0x5e, 0x1f, 0xa6, 0x34, 0xff, 0xdd, 0xed, 0xe8, 0x54,
    },
    {
        0xd4, 0x93, 0x38, 0xfa, 0xdf, 0x31, 0xb0, 0xf2, 0xf7, 0x59, 0x2e, 0x57, 0x99, 0x56, 0xef, 0xe8,
        0xa7, 0x18, 0xa3, 0xe6, 0x6e, 0xfb, 0x1f, 0x82, 0xd0, 0x92, 0xd8, 0x42, 0x8e, 0x75, 0x6f, 0xc3,
    },
    {
        0x3c, 0xdb, 0x09, 0x1f, 0x46, 0x5a, 0x43, 0x8e, 0x4e, 0xdd, 0xc9, 0x2e, 0x7f, 0x12, 0xc5, 0x6e,
        0x5d, 0x89, 0xc0, 0x04, 0x61, 0x52, 0xc3, 0xe1, 0x02, 0xcc, 0x98, 0x6d, 0x4f, 0xec, 0x54, 0x38,
    },
    {
        0x0e, 0x76, 0x6e, 0x7d, 0x17, 0xdd, 0x12, 0x45, 0x84, 0x46, 0x0b, 0xcb, 0xfc, 0xc6, 0xac, 0xc4,
        0x2c, 0x04, 0xd9, 0xf8, 0x6f, 0x66, 0x3d, 0x2e, 0xd3, 0xd1, 0x86, 0x9e, 0x1d, 0x48, 0x10, 0x73,
    },
    {
        0x5a, 0x56, 0xb9, 0x6f, 0xca, 0x58, 0x38, 0x1c, 0x99, 0x58, 0x98, 0xe8, 0x4d, 0xb8, 0x4e, 0xc6,
        0x80, 0x30, 0x1b, 0x18, 0xcb, 0xff, 0x21, 0xe1, 0x69, 0xf2, 0x03, 0xf0, 0x29, 0xa3, 0x81, 0x91,
    },
    {
        0x92, 0x54, 0xe4, 0x83, 0x07, 0x38, 0xf6, 0x0d, 0xad, 0xa9, 0x94, 0x37, 0xee, 0x37, 0xec, 0x44,
        0x57, 0x8b, 0xaa, 0xba, 0x17, 0x39, 0xb4, 0xc6, 0xbd, 0x56, 0xdf, 0x3b, 0xf8, 0x54, 0x43, 0xa7,
    },
    {
        0x26, 0x0e, 0xe4, 0x66, 0x51, 0x18, 0x73, 0x4f, 0xc0, 0x7e, 0x43, 0xdf, 0x50, 0x7f, 0x74, 0xd8,
        0xd1, 0x9a, 0x7d, 0x4c, 0x30, 0x70, 0xaf, 0xdb, 0x06, 0xc8, 0x7f, 0x7e, 0x80, 0x57, 0x47, 0xfa,
    },
    {
        0x52, 0xdd, 0x3e, 0x40, 0x35, 0x2e, 0x46, 0x44, 0x31, 0x1f, 0x28, 0xd9, 0xa9, 0x26, 0x83, 0xb6,
        0xfa, 0x42, 0xd1, 0xad, 0x02, 0x19, 0x42, 0x50, 0x56, 0xeb, 0xb7, 0x3a, 0xf2, 0x77, 0x1d, 0x4f,
    },
    {
        0x90, 0xa3, 0x48, 0x91, 0x45, 0x21, 0x30, 0x3c, 0xf5, 0x03, 0xdf, 0x59, 0x3a, 0x46, 0x42, 0x08,
        0x0f, 0xab, 0x3c, 0xe2, 0x24, 0x9a, 0xb3, 0x50, 0xfc, 0xae, 0xf3, 0x97, 0xa8, 0x35, 0x7f, 0x94,
    },
    {
        0x54, 0x7c, 0x9a, 0x70, 0xa1, 0xaa, 0x4c, 0xf1, 0x4a, 0x95, 0xc7, 0x1a, 0xb7, 0x02, 0xe1, 0xc7,
        0x55, 0xdb, 0x37, 0xea, 0x94, 0xed, 0x0c, 0x37, 0x77, 0x71, 0x97, 0x8b, 0xed, 0x28, 0x9b, 0xbf,
    },
    {
        0x02, 0x9f, 0x18, 0x11, 0x5e, 0x33, 0xf4, 0xc6, 0x00, 0x4e, 0xbd, 0x04, 0x4f, 0x10, 0x55, 0xe6,
        0xcd, 0x62, 0xd5, 0xae, 0xd6, 0x44, 0x9d, 0xcf, 0xe1, 0xba, 0x62, 0x3d, 0x84, 0xb0, 0x0c, 0x9c,
    },
    {
        0xe6, 0x21, 0xd2, 0x39, 0x56, 0xcd, 0xa2, 0x70, 0xa8, 0x95, 0xfd, 0x02, 0x14, 0x84, 0x15, 0x33,
        0x2f, 0x7c, 0xfa, 0x65, 0x4b, 0x3b, 0xdf, 0xd4, 0x46, 0x96, 0x6b, 0xd6, 0x87, 0x9b, 0xd4, 0x59,
    },
    {
        0x13, 0x12, 0x90, 0xc5, 0x2d, 0xce, 0xf5, 0x15, 0x06, 0x8e, 0xec, 0x0c, 0x2f, 0x81, 0xda, 0x32,
        0x59, 0xdb, 0x3e, 0x86, 0x13, 0x0d, 0xc6, 0x7f, 0xb4, 0x65, 0xdc, 0x82, 0x63, 0xd5, 0x5b, 0xb4,
    },
    {
        0x7d, 0x5a, 0x96, 0x2a, 0x90, 0xb0, 0x46, 0x7f, 0xc0, 0xf3, 0xe4, 0x85, 0x87, 0x11, 0x1a, 0xe5,
        0x93, 0x10, 0xc9, 0x1e, 0x10, 0x60, 0x2d, 0x01, 0x3a, 0x00, 0xb8, 0xed, 0x4d, 0x34, 0xcf, 0x93,
    },
    {
        0x56, 0x18, 0x5a, 0x9b, 0x8e, 0xfa, 0x37, 0x95, 0xde, 0xcc, 0x08, 0x7c, 0x48, 0xb9, 0x15, 0xb1,
        0xd7, 0x1a, 0x2c, 0xe9, 0xed, 0x07, 0xcb, 0x0a, 0xc0, 0xaf, 0xf2, 0xe7, 0x05, 0x6c, 0x17, 0x0e,
    },
    {
        0x47, 0xc7, 0x8c, 0x73, 0x27, 0xfe, 0x70, 0xa1, 0xa8, 0x64, 0x46, 0xb1, 0x89, 0xae, 0x54, 0x5c,
        0x0f, 0x88, 0x3f, 0x11, 0xe3, 0xeb, 0x96, 0xfb, 0x48, 0xbe, 0x0f, 0x54, 0xad, 0xf8, 0x20, 0xc9,
    },
};

static bool ascon_cxof_selftest( void ) {
    uint8_t input[KAT_NUM - 1];

    for (size_t i = 0; i < sizeof(input); i++) { input[i] = (uint8_t)i; }

    // This is the customization value used by genkat_crypto_cxof_asconcxof128_ref
    const seed_t seed = ascon_initcxof<false>(UINT64_C(0x1716151413121110));

    bool passed = true;
    for (int i = 0; i < KAT_NUM; i++) {
        uint8_t output[256 / 8];

        if (isBE()) {
            ascon_cxof<256, false, true>(input, i, seed, output);
        } else {
            ascon_cxof<256, false, false>(input, i, seed, output);
        }
        if (0 != memcmp(KAT[i], output, sizeof(output))) {
            printf("Mismatch with XOF len %d\n  Expected:", i);
            for (int j = 0; j < 256 / 8; j++) { printf(" %02x", KAT[i][j]); }
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

REGISTER_HASH(ascon_CXOF_32,
   $.desc       = "ascon v1.3 (CXOF, 32 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 32,
   $.verification_LE = 0x890656D0,
   $.verification_BE = 0x767C165C,
   $.initfn          = ascon_cxof_selftest,
   $.seedfn          = ascon_initcxof<false>,
   $.hashfn_native   = ascon_cxof<32, false, false>,
   $.hashfn_bswap    = ascon_cxof<32, false, true>
 );

REGISTER_HASH(ascon_CXOFa_32,
   $.desc       = "ascon v1.3 (CXOFa, 32 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 32,
   $.verification_LE = 0x9921AAC3,
   $.verification_BE = 0xECD5F539,
   $.initfn          = ascon_cxof_selftest,
   $.seedfn          = ascon_initcxof<true>,
   $.hashfn_native   = ascon_cxof<32, true, false>,
   $.hashfn_bswap    = ascon_cxof<32, true, true>
 );

REGISTER_HASH(ascon_CXOF_64,
   $.desc       = "ascon v1.3 (CXOF, 64 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 64,
   $.verification_LE = 0xDE139DAD,
   $.verification_BE = 0x5EDDA2EE,
   $.initfn          = ascon_cxof_selftest,
   $.seedfn          = ascon_initcxof<false>,
   $.hashfn_native   = ascon_cxof<64, false, false>,
   $.hashfn_bswap    = ascon_cxof<64, false, true>
 );

REGISTER_HASH(ascon_CXOFa_64,
   $.desc       = "ascon v1.3 (CXOFa, 64 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 64,
   $.verification_LE = 0x6AE766D0,
   $.verification_BE = 0x704FCA71,
   $.initfn          = ascon_cxof_selftest,
   $.seedfn          = ascon_initcxof<true>,
   $.hashfn_native   = ascon_cxof<64, true, false>,
   $.hashfn_bswap    = ascon_cxof<64, true, true>
 );

REGISTER_HASH(ascon_CXOF_128,
   $.desc       = "ascon v1.3 (CXOF, 128 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 128,
   $.verification_LE = 0xE10FA58E,
   $.verification_BE = 0x0357385C,
   $.initfn          = ascon_cxof_selftest,
   $.seedfn          = ascon_initcxof<false>,
   $.hashfn_native   = ascon_cxof<128, false, false>,
   $.hashfn_bswap    = ascon_cxof<128, false, true>
 );

REGISTER_HASH(ascon_CXOFa_128,
   $.desc       = "ascon v1.3 (CXOFa, 128 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 128,
   $.verification_LE = 0x1BA0187E,
   $.verification_BE = 0xA9BB7F78,
   $.initfn          = ascon_cxof_selftest,
   $.seedfn          = ascon_initcxof<true>,
   $.hashfn_native   = ascon_cxof<128, true, false>,
   $.hashfn_bswap    = ascon_cxof<128, true, true>
 );

REGISTER_HASH(ascon_CXOF_160,
   $.desc       = "ascon v1.3 (CXOF, 160 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 160,
   $.verification_LE = 0x11322E56,
   $.verification_BE = 0x161721E7,
   $.initfn          = ascon_cxof_selftest,
   $.seedfn          = ascon_initcxof<false>,
   $.hashfn_native   = ascon_cxof<160, false, false>,
   $.hashfn_bswap    = ascon_cxof<160, false, true>
 );

REGISTER_HASH(ascon_CXOFa_160,
   $.desc       = "ascon v1.3 (CXOFa, 160 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 160,
   $.verification_LE = 0x4C497968,
   $.verification_BE = 0xD4B0BEE1,
   $.initfn          = ascon_cxof_selftest,
   $.seedfn          = ascon_initcxof<true>,
   $.hashfn_native   = ascon_cxof<160, true, false>,
   $.hashfn_bswap    = ascon_cxof<160, true, true>
 );

REGISTER_HASH(ascon_CXOF_224,
   $.desc       = "ascon v1.3 (CXOF, 224 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 224,
   $.verification_LE = 0x785D0A00,
   $.verification_BE = 0xBA5B0948,
   $.initfn          = ascon_cxof_selftest,
   $.seedfn          = ascon_initcxof<false>,
   $.hashfn_native   = ascon_cxof<224, false, false>,
   $.hashfn_bswap    = ascon_cxof<224, false, true>
 );

REGISTER_HASH(ascon_CXOFa_224,
   $.desc       = "ascon v1.3 (CXOFa, 224 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 224,
   $.verification_LE = 0x3E72C645,
   $.verification_BE = 0xE5CEE71E,
   $.initfn          = ascon_cxof_selftest,
   $.seedfn          = ascon_initcxof<true>,
   $.hashfn_native   = ascon_cxof<224, true, false>,
   $.hashfn_bswap    = ascon_cxof<224, true, true>
 );

REGISTER_HASH(ascon_CXOF_256,
   $.desc       = "ascon v1.3 (CXOF, 256 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 256,
   $.verification_LE = 0xA5E1BB45,
   $.verification_BE = 0xA7BE8CF9,
   $.initfn          = ascon_cxof_selftest,
   $.seedfn          = ascon_initcxof<false>,
   $.hashfn_native   = ascon_cxof<256, false, false>,
   $.hashfn_bswap    = ascon_cxof<256, false, true>
 );

REGISTER_HASH(ascon_CXOFa_256,
   $.desc       = "ascon v1.3 (CXOFa, 256 bits)",
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC          |
         FLAG_HASH_NO_SEED                |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_CANONICAL_LE           |
         FLAG_IMPL_VERY_SLOW              |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 256,
   $.verification_LE = 0xF16DB475,
   $.verification_BE = 0x079F8C42,
   $.initfn          = ascon_cxof_selftest,
   $.seedfn          = ascon_initcxof<true>,
   $.hashfn_native   = ascon_cxof<256, true, false>,
   $.hashfn_bswap    = ascon_cxof<256, true, true>
 );
