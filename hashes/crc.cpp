/*
 * CRC variants
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * Copyright (c) 2014-2021 Reini Urban
 *
 * This software is provided 'as-is', without any express or implied
 * warranty.  In no event will the author be held liable for any
 * damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any
 * purpose, including commercial applications, and to alter it and
 * redistribute it freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must
 * not claim that you wrote the original software. If you use this
 * software in a product, an acknowledgment in the product
 * documentation would be appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and must
 * not be misrepresented as being the original software.
 *
 * 3. This notice may not be removed or altered from any source
 * distribution.
 *
 * Mark Adler
 * madler@alumni.caltech.edu
 */
#include "Platform.h"
#include "Hashlib.h"

typedef struct {
    uint32_t  crc32_long[4][256];
    uint32_t  crc32_short[4][256];
} crc_hw_table;

#if defined(HAVE_X86_64_CRC32C)
  #include "Intrinsics.h"
  #define CRC_IMPL_STR "hwcrc_x64"

// Fancy hardware version

/*
 * Multiply a matrix times a vector over the Galois field of two
 * elements, GF(2).  Each element is a bit in an unsigned integer.
 * mat must have at least as many entries as the power of two for most
 * significant one bit in vec.
 */
static inline uint32_t gf2_matrix_times( uint32_t * mat, uint32_t vec ) {
    uint32_t sum;

    sum = 0;
    while (vec) {
        if (vec & 1) { sum ^= *mat; }
        vec >>= 1;
        mat++;
    }
    return sum;
}

/*
 * Multiply a matrix by itself over GF(2).  Both mat and square must
 * have 32 rows.
 */
static inline void gf2_matrix_square( uint32_t * square, uint32_t * mat ) {
    for (int n = 0; n < 32; n++) {
        square[n] = gf2_matrix_times(mat, mat[n]);
    }
}

/*
 * Construct an operator to apply len zeros to a crc.  len must be a
 * power of two.  If len is not a power of two, then the result is the
 * same as for the largest power of two less than len.  The result for
 * len == 0 is the same as for len == 1.  A version of this routine
 * could be easily written for any len, but that is not needed for
 * this application.
 */
template <uint32_t polynomial>
static void crc32_zeros_op( uint32_t * even, size_t len ) {
    uint32_t row;
    uint32_t odd[32]; /* odd-power-of-two zeros operator */

    /* put operator for one zero bit in odd */
    odd[0] = polynomial; /* CRC-32 polynomial */
    row    = 1;
    for (int n = 1; n < 32; n++) {
        odd[n] = row;
        row  <<= 1;
    }

    /* put operator for two zero bits in even */
    gf2_matrix_square(even, odd );

    /* put operator for four zero bits in odd */
    gf2_matrix_square(odd , even);

    /*
     * first square will put the operator for one zero byte (eight zero bits),
     * in even -- next square puts operator for two zero bytes in odd, and so
     * on, until len has been rotated down to zero
     */
    do {
        gf2_matrix_square(even, odd );
        len >>= 1;
        if (len == 0) { return; }
        gf2_matrix_square(odd , even);
        len >>= 1;
    } while (len);

    /* answer ended up in odd -- copy to even */
    for (int n = 0; n < 32; n++) {
        even[n] = odd[n];
    }
}

/*
 * Take a length and build four lookup tables for applying the zeros
 * operator for that length, byte-by-byte on the operand.
 */
static void crc32_zeros( uint32_t op[32], uint32_t zeros[][256] ) {
    uint32_t n;

    for (n = 0; n < 256; n++) {
        zeros[0][n] = gf2_matrix_times(op, n      );
        zeros[1][n] = gf2_matrix_times(op, n <<  8);
        zeros[2][n] = gf2_matrix_times(op, n << 16);
        zeros[3][n] = gf2_matrix_times(op, n << 24);
    }
}

// Block sizes for three-way parallel crc computation.
// HW_LONGBLOCK_LEN and HW_SHORTBLOCK_LEN must both be
// powers of two.
static const uint32_t HW_LONGBLOCK_LEN  = 8192;
static const uint32_t HW_SHORTBLOCK_LEN = 256;

/* Initialize tables for shifting crcs. */
template <uint32_t polynomial>
static void crc32_init_hw( crc_hw_table * tblp ) {
    uint32_t op[32];

    crc32_zeros_op<polynomial>(op, HW_LONGBLOCK_LEN);
    crc32_zeros(op, tblp->crc32_long);

    crc32_zeros_op<polynomial>(op, HW_SHORTBLOCK_LEN);
    crc32_zeros(op, tblp->crc32_short);
}

/* Apply the zeros operator table to crc. */
static inline uint32_t crc32_shift( const uint32_t zeros[][256], uint32_t crc ) {
    return zeros[0][crc & 0xff] ^ zeros[1][(crc >> 8) & 0xff] ^
           zeros[2][(crc >> 16) & 0xff] ^ zeros[3][crc >> 24];
}

/* Compute CRC-32C using the Intel hardware instruction. */
static uint32_t crc32c_hw( uint32_t crc, const crc_hw_table * tbl, const void * buf, size_t len ) {
    const uint8_t * next = (const uint8_t *)buf;
    const uint8_t * end;
    uint64_t        crc0, crc1, crc2; /* need to be 64 bits for crc32q */

    /* Pre-process the crc */
    crc0 = crc ^ 0xffffffff;

    /*
     * Compute the crc for up to seven leading bytes to bring the data
     * pointer to an eight-byte boundary.
     */
    while (len && ((uintptr_t)next & 7) != 0) {
        crc0 = _mm_crc32_u8(crc0, *next++);
        len--;
    }

    /*
     * Compute the crc on sets of HW_LONGBLOCK_LEN*3 bytes, executing
     * three independent crc instructions, each on HW_LONGBLOCK_LEN
     * bytes -- this is optimized for the Nehalem, Westmere, Sandy
     * Bridge, and Ivy Bridge architectures, which have a throughput
     * of one crc per cycle, but a latency of three cycles.
     */
    while (len >= HW_LONGBLOCK_LEN * 3) {
        crc1 = 0;
        crc2 = 0;
        end  = next + HW_LONGBLOCK_LEN;
        do {
            crc0  = _mm_crc32_u64(crc0, GET_U64<false>(next, 0));
            crc1  = _mm_crc32_u64(crc1, GET_U64<false>(next, HW_LONGBLOCK_LEN));
            crc2  = _mm_crc32_u64(crc2, GET_U64<false>(next, HW_LONGBLOCK_LEN + HW_LONGBLOCK_LEN));
            next += 8;
        } while (next < end);
        crc0  = crc32_shift(tbl->crc32_long, crc0) ^ crc1;
        crc0  = crc32_shift(tbl->crc32_long, crc0) ^ crc2;
        next += HW_LONGBLOCK_LEN * 2;
        len  -= HW_LONGBLOCK_LEN * 3;
    }

    /*
     * Do the same thing, but now on HW_SHORTBLOCK_LEN*3 blocks for
     * the remaining data less than a HW_LONGBLOCK_LEN*3 block.
     */
    while (len >= HW_SHORTBLOCK_LEN * 3) {
        crc1 = 0;
        crc2 = 0;
        end  = next + HW_SHORTBLOCK_LEN;
        do {
            crc0  = _mm_crc32_u64(crc0, GET_U64<false>(next, 0));
            crc1  = _mm_crc32_u64(crc1, GET_U64<false>(next, HW_SHORTBLOCK_LEN));
            crc2  = _mm_crc32_u64(crc2, GET_U64<false>(next, HW_SHORTBLOCK_LEN + HW_SHORTBLOCK_LEN));
            next += 8;
        } while (next < end);
        crc0  = crc32_shift(tbl->crc32_short, crc0) ^ crc1;
        crc0  = crc32_shift(tbl->crc32_short, crc0) ^ crc2;
        next += HW_SHORTBLOCK_LEN * 2;
        len  -= HW_SHORTBLOCK_LEN * 3;
    }

    /*
     * Compute the crc on the remaining eight-byte units less than a
     * HW_SHORTBLOCK_LEN*3 block.
     */
    end = next + (len - (len & 7));
    while (next < end) {
        crc0  = _mm_crc32_u64(crc0, GET_U64<false>(next, 0));
        next += 8;
    }
    len &= 7;

    /* Compute the crc for up to seven trailing bytes. */
    while (len) {
        crc0 = _mm_crc32_u8(crc0, *next++);
        len--;
    }

    /* return a post-processed crc */
    return (uint32_t)(crc0 ^ 0xffffffff);
}

#else
  #define CRC_IMPL_STR "sw"
#endif


typedef  uint32_t crc_sw_table[16][256];

/* Construct table for software CRC-32 calculation. */
static void crc32_init_sw( const uint32_t POLY, crc_sw_table crc32_table ) {
    uint32_t n, crc, k;

    for (n = 0; n < 256; n++) {
        crc = n;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc32_table[0][n] = crc;
    }
    for (n = 0; n < 256; n++) {
        crc = crc32_table[0][n];
        for (k = 1; k < 16; k++) {
            crc = crc32_table[0][crc & 0xff] ^ (crc >> 8);
            crc32_table[k][n] = crc;
        }
    }
}

// Table-driven software version
template <bool bswap>
static uint32_t crc32_sw( uint32_t crci, const crc_sw_table crc32_table, const void * buf, size_t len ) {
    const uint8_t * next = (const uint8_t *)buf;
    uint64_t        crc;

    crc = crci ^ 0xffffffff;

    while (len && ((uintptr_t)next & 7) != 0) {
        crc = crc32_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
    while (len >= 16) {
        uint64_t wd1, wd2;
        wd1  = GET_U64<bswap>(next, 0);
        wd2  = GET_U64<false>(next, 8); // byteswapping taken care of via table indexing!

        crc ^= wd1;
        if (bswap) {
            crc =
                    crc32_table[15][ crc        & 0xff] ^
                    crc32_table[14][(crc >>  8) & 0xff] ^
                    crc32_table[13][(crc >> 16) & 0xff] ^
                    crc32_table[12][(crc >> 24) & 0xff] ^
                    crc32_table[11][(crc >> 32) & 0xff] ^
                    crc32_table[10][(crc >> 40) & 0xff] ^
                    crc32_table[ 9][(crc >> 48) & 0xff] ^
                    crc32_table[ 8][ crc >> 56        ] ^
                    crc32_table[ 0][ wd2        & 0xff] ^
                    crc32_table[ 1][(wd2 >>  8) & 0xff] ^
                    crc32_table[ 2][(wd2 >> 16) & 0xff] ^
                    crc32_table[ 3][(wd2 >> 24) & 0xff] ^
                    crc32_table[ 4][(wd2 >> 32) & 0xff] ^
                    crc32_table[ 5][(wd2 >> 40) & 0xff] ^
                    crc32_table[ 6][(wd2 >> 48) & 0xff] ^
                    crc32_table[ 7][ wd2 >> 56        ];
        } else {
            crc =
                    crc32_table[15][ crc        & 0xff] ^
                    crc32_table[14][(crc >>  8) & 0xff] ^
                    crc32_table[13][(crc >> 16) & 0xff] ^
                    crc32_table[12][(crc >> 24) & 0xff] ^
                    crc32_table[11][(crc >> 32) & 0xff] ^
                    crc32_table[10][(crc >> 40) & 0xff] ^
                    crc32_table[ 9][(crc >> 48) & 0xff] ^
                    crc32_table[ 8][ crc >> 56        ] ^
                    crc32_table[ 7][ wd2        & 0xff] ^
                    crc32_table[ 6][(wd2 >>  8) & 0xff] ^
                    crc32_table[ 5][(wd2 >> 16) & 0xff] ^
                    crc32_table[ 4][(wd2 >> 24) & 0xff] ^
                    crc32_table[ 3][(wd2 >> 32) & 0xff] ^
                    crc32_table[ 2][(wd2 >> 40) & 0xff] ^
                    crc32_table[ 1][(wd2 >> 48) & 0xff] ^
                    crc32_table[ 0][ wd2 >> 56        ];
        }
        next += 16;
        len  -= 16;
    }

    while (len) {
        crc = crc32_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
    return (uint32_t)crc ^ 0xffffffff;
}

/* CRC-32 polynomials, each in reversed bit order. */
#define POLY_CRC32   0xEDB88320 // CRC-32   (gzip, bzip, SATA, MPEG-2, etc.)
#define POLY_CRC32C  0x82F63B78 // CRC-32c  (iSCSI, SCTP, ext4, etc.)
#define POLY_CRC32K  0xEB31D82E // CRC-32k  (Koopman)
#define POLY_CRC32K2 0x992C1A4C // CRC-32k2 (Koopman 2)
#define POLY_CRC32Q  0xD5828281 // CRC-32q  (aviation)

/*
 * For now, only store 1 set of tables at a time.
 */
static uint32_t     table_poly;
static crc_sw_table sw_tables;
#if defined(HAVE_X86_64_CRC32C)
static crc_hw_table hw_tables;
#endif

template <uint32_t polynomial>
static void CRC32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t crc = seed;

    if (polynomial != table_poly) {
        printf("CRC32 of poly %08x requested, but Init() was given %08x\n", polynomial, table_poly);
        exit(1);
    }
#if defined(HAVE_X86_64_CRC32C)
    if (polynomial == POLY_CRC32C) {
        crc = crc32c_hw(crc, &hw_tables, in, len);
    } else
#endif
    if (isLE()) {
        crc = crc32_sw<false>(crc, sw_tables, in, len);
    } else {
        crc = crc32_sw<true>(crc, sw_tables, in, len);
    }

    crc = COND_BSWAP(crc, isBE());
    memcpy(out, &crc, 4);
}

template <uint32_t polynomial>
static bool CRC32_init( void ) {
    table_poly = polynomial;
#if defined(HAVE_X86_64_CRC32C)
    if (polynomial == POLY_CRC32C) {
        crc32_init_hw<polynomial>(&hw_tables);
    } else
#endif
    crc32_init_sw(polynomial, sw_tables);

    return true;
}

REGISTER_FAMILY(crc,
   $.src_url    = "https://github.com/baruch/crcbench/blob/master/crc-mark-adler.c",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(CRC_32C,
   $.desc       = "CRC32-C (Castagnoli, 0x1EDC6F41 / 0x82F63B78)",
   $.impl       = CRC_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRC_BASED          |
         FLAG_HASH_LOOKUP_TABLE       |
         FLAG_HASH_ENDIAN_INDEPENDENT |
         FLAG_HASH_SMALL_SEED,
   $.impl_flags =
         FLAG_IMPL_INCREMENTAL        |
         FLAG_IMPL_CANONICAL_BOTH     |
         FLAG_IMPL_LICENSE_BSD,
   $.bits = 32,
   $.verification_LE = 0x6E6071BD,
   $.verification_BE = 0x6E6071BD,
   $.initfn          = CRC32_init<POLY_CRC32C>,
   $.hashfn_native   = CRC32<POLY_CRC32C>,
   $.hashfn_bswap    = CRC32<POLY_CRC32C>
 );
