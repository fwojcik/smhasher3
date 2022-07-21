/*
 * SMHasher3
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 *
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 *     This software is provided 'as-is', without any express or
 *     implied warranty.  In no event will the author be held liable
 *     for any damages arising from the use of this software.
 *
 *     Permission is granted to anyone to use this software for any
 *     purpose, including commercial applications, and to alter it and
 *     redistribute it freely, subject to the following restrictions:
 *
 *     1. The origin of this software must not be misrepresented; you
 *     must not claim that you wrote the original software. If you use
 *     this software in a product, an acknowledgment in the product
 *     documentation would be appreciated but is not required.
 *
 *     2. Altered source versions must be plainly marked as such, and
 *     must not be misrepresented as being the original software.
 *
 *     3. This notice may not be removed or altered from any source
 *     distribution.
 *
 *     Mark Adler
 *     madler@alumni.caltech.edu
 */
//-----------------------------------------------------------------------------
// We want the capability to verify that every test produces the same
// result on every platform.  To do this, we hash the results of every
// test to produce an overall verification value for the whole test
// suite. If two runs produce the same verification value, then every
// test in both run produced the same results.
//
// The goal of VCodes is to quickly verify that large amounts of data
// (test inputs, outputs, and results) match. That is to say that the
// data is unaltered in some sense. Some likely "corruptions" include
// data that is inserted or removed, or that differs only slightly
// numerically. Significant deviations are likely to produce test
// failures or differences that would be noticed some other way.
// Since VCodes were previously defined to be 32 bits, and since the
// entire VCode is always used (it will never be truncated), CRCs can
// fulfill this role quite well. CRC32c in particular has explicit
// hardware support in many popular architectures, making it one of
// the lowest-overhead options, both in terms of time and op count.
//-----------------------------------------------------------------------------
void VCODE_INIT( void );
uint32_t VCODE_FINALIZE( void );

// VCodes have 64-bit state to lessen the probability of internal
// state collisions. Since CRC HW support is commonly for 32-bits at
// most, two separate CRCs are stored.
typedef struct {
    uint32_t  data_hash;
    uint32_t  lens_hash;
} vcode_state_t;

#define VCODE_COUNT 3
extern vcode_state_t vcode_states[VCODE_COUNT];
extern uint32_t      g_doVCode;
extern uint32_t      g_inputVCode;
extern uint32_t      g_outputVCode;
extern uint32_t      g_resultVCode;

//-----------------------------------------------------------------------------
// HW CRC32c wrappers/accessors
#if defined(HAVE_ARM_ACLE)
  #include "Intrinsics.h"
  #define HWCRC_U64 __crc32cd
  #define HWCRC_U8  __crc32cb
#elif defined(HAVE_ARM64_ASM)

static inline uint32_t _hwcrc_asm64( uint32_t crc, uint64_t data ) {
    __asm__ __volatile__ ("crc32cx %w[c], %w[c], %x[v]\n"
             : [c] "+r"(crc)
             : [v] "r"(data));
    return crc;
}

static inline uint32_t _hwcrc_asm8( uint32_t crc, uint8_t data ) {
    __asm__ __volatile__ ("crc32cb %w[c], %w[c], %w[v]\n"
             : [c] "+r"(crc)
             : [v] "r"(data));
    return crc;
}

  #define HWCRC_U64 _hwcrc_asm64
  #define HWCRC_U8  _hwcrc_asm8
#elif defined(HAVE_X86_64_CRC32C)
  #include "Intrinsics.h"
  #define HWCRC_U64 _mm_crc32_u64
  #define HWCRC_U8  _mm_crc32_u8
#elif defined(HAVE_X86_64_ASM)

static inline uint32_t _hwcrc_asm64( uint64_t crc, uint64_t data ) {
    __asm__ __volatile__ ("crc32q %1, %0\n"
             : "+r"(crc)
             : "rm"(data));
    return (uint32_t)crc;
}

static inline uint32_t _hwcrc_asm8( uint32_t crc, uint8_t data ) {
    __asm__ __volatile__ ("crc32b %1, %0\n"
             : "+r"(crc)
             : "r"(data));
    return crc;
}

  #define HWCRC_U64 _hwcrc_asm64
  #define HWCRC_U8  _hwcrc_asm8
#endif

//-----------------------------------------------------------------------------
// Special-case inline-able CRC32c handling of 8-byte inputs
extern const uint32_t crc32c_sw_table[16][256];

// This is based on Mark Adler's implementation.
static inline uint32_t crc32c_update_sw_u64( uint32_t crc, uint64_t data ) {
    uint64_t crc64 = crc ^ data;

    crc64 =
            crc32c_sw_table[7][ crc64        & 0xff] ^
            crc32c_sw_table[6][(crc64 >>  8) & 0xff] ^
            crc32c_sw_table[5][(crc64 >> 16) & 0xff] ^
            crc32c_sw_table[4][(crc64 >> 24) & 0xff] ^
            crc32c_sw_table[3][(crc64 >> 32) & 0xff] ^
            crc32c_sw_table[2][(crc64 >> 40) & 0xff] ^
            crc32c_sw_table[1][(crc64 >> 48) & 0xff] ^
            crc32c_sw_table[0][ crc64 >> 56        ];
    return (uint32_t)crc64;
}

static inline void crc32c_update_u64( uint32_t * crcptr, uint64_t data ) {
    uint32_t crc = *crcptr;

#if defined(HWCRC_U64)
    crc     = HWCRC_U64(crc, data);
#else
    crc     = crc32c_update_sw_u64(crc, data);
#endif
    *crcptr = crc;
}

//-----------------------------------------------------------------------------
// Special-case inline-able handling of 8-or-fewer byte integer VCode inputs
static inline void VCODE_HASH_SMALL( const uint64_t data, unsigned idx ) {
    if (idx >= VCODE_COUNT) {
        return;
    }
    crc32c_update_u64(&vcode_states[idx].data_hash, data);
    crc32c_update_u64(&vcode_states[idx].lens_hash,    8);
}

template <typename T>
static inline void addVCodeInput( const T data ) {
    static_assert(std::is_integral<T>::value, "Non-integer data requires addVCode(const void *, size_t)");
    if (g_doVCode) { VCODE_HASH_SMALL((uint64_t)data, 0); }
}

template <typename T>
static inline void addVCodeOutput( const T data ) {
    static_assert(std::is_integral<T>::value, "Non-integer data requires addVCode(const void *, size_t)");
    if (g_doVCode) { VCODE_HASH_SMALL((uint64_t)data, 1); }
}

template <typename T>
static inline void addVCodeResult( const T data ) {
    static_assert(std::is_integral<T>::value, "Non-integer data requires addVCode(const void *, size_t)");
    if (g_doVCode) { VCODE_HASH_SMALL((uint64_t)data, 2); }
}

//-----------------------------------------------------------------------------
// General-purpose VCode input handling
void VCODE_HASH( const void * input, size_t len, unsigned idx );

static inline void addVCodeInput( const void * in, size_t len ) {
    if (g_doVCode) { VCODE_HASH(in, len, 0); }
}

static inline void addVCodeOutput( const void * in, size_t len ) {
    if (g_doVCode) { VCODE_HASH(in, len, 1); }
}

static inline void addVCodeResult( const void * in, size_t len ) {
    if (g_doVCode) { VCODE_HASH(in, len, 2); }
}
