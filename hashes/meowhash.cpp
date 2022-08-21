/*
 * MeowHash
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 * (C) Copyright 2018 Molly Rocket, Inc.
 *
 * This software is provided 'as-is', without any express or implied
 * warranty.  In no event will the authors be held liable for any
 * damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any
 * purpose, including commercial applications, and to alter it and
 * redistribute it freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must
 *    not claim that you wrote the original software. If you use this
 *    software in a product, an acknowledgment in the product
 *    documentation would be appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source
 *    distribution.
 */
/*
 * This code has been modified for use in SMHasher3 to use the provided
 * framework, to be clearer to read, to be able to byteswap the input
 * words, and to have a seeding function added.
 */
#include "Platform.h"
#include "Hashlib.h"

#if defined(HAVE_X86_64_AES) && defined(HAVE_SSE_4_1)

  #include "Intrinsics.h"

typedef __m128i meow_u128;

//------------------------------------------------------------
// #define MEOW_HASH_VERSION 5
// #define MEOW_HASH_VERSION_NAME "0.5/calico"

  #define MEOW_PAGESIZE 4096
  #define MEOW_PREFETCH 4096
  #define MEOW_PREFETCH_LIMIT 0x3ff

// fwojcik: Why is this needed?
  #if defined(_MSC_VER) && !defined(__clang__)
    #define INSTRUCTION_REORDER_BARRIER _ReadWriteBarrier()
  #else
    #define INSTRUCTION_REORDER_BARRIER
  #endif

//------------------------------------------------------------
  #define MeowU64From(A, I) (_mm_extract_epi64((A), (I)))
  #define MeowU32From(A, I) (_mm_extract_epi32((A), (I)))
  #define prefetcht0(A)      _mm_prefetch((char const *)(A), _MM_HINT_T0)
  #define movdqu_imm(B)      _mm_loadu_si128((meow_u128 *)(B))
  #define movdqu(A, B)       A = _mm_loadu_si128((meow_u128 *)(B))
  #define movq(A, B, C)      A = _mm_set_epi64x(C, B);
  #define aesdec(A, B)       A = _mm_aesdec_si128(A, B)
  #define pshufb(A, B)       A = _mm_shuffle_epi8(A, B)
  #define pxor(A, B)         A = _mm_xor_si128(A, B)
  #define paddq(A, B)        A = _mm_add_epi64(A, B)
  #define pand(A, B)         A = _mm_and_si128(A, B)
  #define palignr(A, B, i)   A = _mm_alignr_epi8(A, B, i)
// NOTE(casey): pxor_clear is a nonsense thing that is only here
// because compilers don't detect xor(a, a) is clearing a :(
  #define pxor_clear(A, B)   A = _mm_setzero_si128();

//------------------------------------------------------------
#define MEOW_MIX_REG(r1, r2, r3, r4, r5,  i1, i2, i3, i4) \
    aesdec(r1, r2);                                       \
    INSTRUCTION_REORDER_BARRIER;                          \
    paddq(r3, i1);                                        \
    pxor(r2, i2);                                         \
    aesdec(r2, r4);                                       \
    INSTRUCTION_REORDER_BARRIER;                          \
    paddq(r5, i3);                                        \
    pxor(r4, i4);

#define MEOW_MIX(r1, r2, r3, r4, r5, ptr)           \
    if (bswap) {                                    \
        MEOW_MIX_REG(r1, r2, r3, r4, r5,            \
                mm_bswap64(movdqu_imm((ptr) + 15)), \
                mm_bswap64(movdqu_imm((ptr) +  0)), \
                mm_bswap64(movdqu_imm((ptr) +  1)), \
                mm_bswap64(movdqu_imm((ptr) + 16))) \
    } else {                                        \
        MEOW_MIX_REG(r1, r2, r3, r4, r5,            \
                movdqu_imm((ptr) + 15),             \
                movdqu_imm((ptr) +  0),             \
                movdqu_imm((ptr) +  1),             \
                movdqu_imm((ptr) + 16))             \
    }

#define MEOW_SHUFFLE(r1, r2, r3, r4, r5, r6) \
    aesdec(r1, r4);                          \
    paddq(r2, r5);                           \
    pxor(r4, r6);                            \
    aesdec(r4, r2);                          \
    paddq(r5, r6);                           \
    pxor(r2, r3)

//------------------------------------------------------------
static const uint8_t MeowShiftAdjust[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
};

static const uint8_t MeowMaskLen[32] = {
    255, 255, 255, 255,
    255, 255, 255, 255,
    255, 255, 255, 255,
    255, 255, 255, 255,
      0,   0,   0,   0,
      0,   0,   0,   0,
      0,   0,   0,   0,
      0,   0,   0,   0
};

// NOTE(casey): The default seed is now a "nothing-up-our-sleeves"
// number for good measure.  You may verify that it is just an
// encoding of Pi.
static const uint8_t MeowDefaultSeed[128] = {
    0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
    0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34,
    0x4A, 0x40, 0x93, 0x82, 0x22, 0x99, 0xF3, 0x1D,
    0x00, 0x82, 0xEF, 0xA9, 0x8E, 0xC4, 0xE6, 0xC8,
    0x94, 0x52, 0x82, 0x1E, 0x63, 0x8D, 0x01, 0x37,
    0x7B, 0xE5, 0x46, 0x6C, 0xF3, 0x4E, 0x90, 0xC6,
    0xCC, 0x0A, 0xC2, 0x9B, 0x7C, 0x97, 0xC5, 0x0D,
    0xD3, 0xF8, 0x4D, 0x5B, 0x5B, 0x54, 0x70, 0x91,
    0x79, 0x21, 0x6D, 0x5D, 0x98, 0x97, 0x9F, 0xB1,
    0xBD, 0x13, 0x10, 0xBA, 0x69, 0x8D, 0xFB, 0x5A,
    0xC2, 0xFF, 0xD7, 0x2D, 0xBD, 0x01, 0xAD, 0xFB,
    0x7B, 0x8E, 0x1A, 0xFE, 0xD6, 0xA2, 0x67, 0xE9,
    0x6B, 0xA7, 0xC9, 0x04, 0x5F, 0x12, 0xC7, 0xF9,
    0x92, 0x4A, 0x19, 0x94, 0x7B, 0x39, 0x16, 0xCF,
    0x70, 0x80, 0x1F, 0x2E, 0x28, 0x58, 0xEF, 0xC1,
    0x66, 0x36, 0x92, 0x0D, 0x87, 0x15, 0x74, 0xE6
};

//------------------------------------------------------------
//
// NOTE(casey): Single block version
//
template <bool bswap>
static meow_u128 MeowHash( const void * Seed128Init, size_t Len, const void * SourceInit, uint64_t extraseed ) {
    const uint8_t * const SourceInit8 = (const uint8_t *)SourceInit;
    // NOTE(casey): xmm0-xmm7 are the hash accumulation lanes
    // NOTE(casey): xmm8-xmm15 hold values to be appended (residual, length)
    meow_u128 xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
    meow_u128 xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;

    const uint8_t * rax = (const uint8_t *)SourceInit;
    const uint8_t * rcx = (const uint8_t *)Seed128Init;

    //
    // NOTE(casey): Seed the eight hash registers
    //
    movdqu(xmm0, rcx + 0x00);
    movdqu(xmm1, rcx + 0x10);
    movdqu(xmm2, rcx + 0x20);
    movdqu(xmm3, rcx + 0x30);

    movdqu(xmm4, rcx + 0x40);
    movdqu(xmm5, rcx + 0x50);
    movdqu(xmm6, rcx + 0x60);
    movdqu(xmm7, rcx + 0x70);

    //
    // NOTE(casey): Hash all full 256-byte blocks
    //
    size_t BlockCount = (Len >> 8);
    if (BlockCount > MEOW_PREFETCH_LIMIT) {
        // NOTE(casey): For large input, modern Intel x64's can't hit
        // full speed without prefetching, so we use this loop
        while (BlockCount--) {
            prefetcht0(rax + MEOW_PREFETCH + 0x00);
            prefetcht0(rax + MEOW_PREFETCH + 0x40);
            prefetcht0(rax + MEOW_PREFETCH + 0x80);
            prefetcht0(rax + MEOW_PREFETCH + 0xc0);

            MEOW_MIX(xmm0, xmm4, xmm6, xmm1, xmm2, rax + 0x00);
            MEOW_MIX(xmm1, xmm5, xmm7, xmm2, xmm3, rax + 0x20);
            MEOW_MIX(xmm2, xmm6, xmm0, xmm3, xmm4, rax + 0x40);
            MEOW_MIX(xmm3, xmm7, xmm1, xmm4, xmm5, rax + 0x60);
            MEOW_MIX(xmm4, xmm0, xmm2, xmm5, xmm6, rax + 0x80);
            MEOW_MIX(xmm5, xmm1, xmm3, xmm6, xmm7, rax + 0xa0);
            MEOW_MIX(xmm6, xmm2, xmm4, xmm7, xmm0, rax + 0xc0);
            MEOW_MIX(xmm7, xmm3, xmm5, xmm0, xmm1, rax + 0xe0);

            rax += 0x100;
        }
    } else {
        // NOTE(casey): For small input, modern Intel x64's can't hit
        // full speed _with_ prefetching (because of port pressure),
        // so we use this loop.

        while (BlockCount--) {
            MEOW_MIX(xmm0, xmm4, xmm6, xmm1, xmm2, rax + 0x00);
            MEOW_MIX(xmm1, xmm5, xmm7, xmm2, xmm3, rax + 0x20);
            MEOW_MIX(xmm2, xmm6, xmm0, xmm3, xmm4, rax + 0x40);
            MEOW_MIX(xmm3, xmm7, xmm1, xmm4, xmm5, rax + 0x60);
            MEOW_MIX(xmm4, xmm0, xmm2, xmm5, xmm6, rax + 0x80);
            MEOW_MIX(xmm5, xmm1, xmm3, xmm6, xmm7, rax + 0xa0);
            MEOW_MIX(xmm6, xmm2, xmm4, xmm7, xmm0, rax + 0xc0);
            MEOW_MIX(xmm7, xmm3, xmm5, xmm0, xmm1, rax + 0xe0);

            rax += 0x100;
        }
    }

    //
    // NOTE(casey): Load any less-than-32-byte residual
    //
    pxor_clear(xmm9 , xmm9 );
    pxor_clear(xmm11, xmm11);

    //
    // TODO(casey): I need to put more thought into how the
    // end-of-buffer stuff is actually working out here, because I
    // _think_ it may be possible to remove the first branch (on Len8)
    // and let the mask zero out the result, but it would take a
    // little thought to make sure it couldn't read off the end of the
    // buffer due to the & 0xf on the align computation.
    //

    // NOTE(casey): First, we have to load the part that is _not_
    // 16-byte aligned
    const uint8_t * Last = SourceInit8 + (Len & ~0xf);
    uint32_t        Len8 =               (Len & 0xf );
    if (Len8) {
        // NOTE(casey): Load the mask early
        movdqu(xmm8 , &MeowMaskLen[0x10 - Len8]);

        const uint8_t * LastOk = (const uint8_t *)(((uintptr_t)(SourceInit8 + Len - 1) | (MEOW_PAGESIZE - 1)) - 16);
        uint32_t        Align  = (Last > LastOk) ? ((uintptr_t)Last) & 0xf : 0;
        movdqu(xmm10, &MeowShiftAdjust[Align]  );
        movdqu(xmm9 , Last - Align);
        pshufb(xmm9, xmm10);

        // NOTE(jeffr): and off the extra bytes
        pand(xmm9, xmm8);
    }

    // NOTE(casey): Next, we have to load the part that _is_ 16-byte
    // aligned
    if (Len & 0x10) {
        xmm11 = xmm9;
        movdqu(xmm9, Last - 0x10);
    }

    //
    // NOTE(casey): Construct the residual and length injests
    //
    xmm8  = xmm9;
    xmm10 = xmm9;
    palignr(xmm8 , xmm11, 15);
    palignr(xmm10, xmm11,  1);

    // NOTE(casey): We have room for a 128-bit nonce and a 64-bit none
    // here, but the decision was made to leave them zero'd so as not
    // to confuse people about hwo to use them or what security
    // implications they had.
    //
    // fwojcik: Homegrown seeding. The (presumed) place of the 64-bit
    // nonce is used for the 64-bit seed value for SMHasher3.
    pxor_clear(xmm12, xmm12);
    pxor_clear(xmm13, xmm13);
    pxor_clear(xmm14, xmm14);
    movq(xmm15, Len, extraseed);
    palignr(xmm12, xmm15, 15);
    palignr(xmm14, xmm15,  1);

    // NOTE(casey): To maintain the mix-down pattern, we always Meow
    // Mix the less-than-32-byte residual, even if it was empty
    MEOW_MIX_REG(xmm0, xmm4, xmm6, xmm1, xmm2, xmm8 , xmm9 , xmm10, xmm11);

    // NOTE(casey): Append the length, to avoid problems with our
    // 32-byte padding
    MEOW_MIX_REG(xmm1, xmm5, xmm7, xmm2, xmm3, xmm12, xmm13, xmm14, xmm15);

    //
    // NOTE(casey): Hash all full 32-byte blocks
    //
    uint32_t LaneCount = (Len >> 5) & 0x7;
    if (LaneCount == 0) { goto MixDown; }
    MEOW_MIX(xmm2, xmm6, xmm0, xmm3, xmm4, rax + 0x00); --LaneCount;
    if (LaneCount == 0) { goto MixDown; }
    MEOW_MIX(xmm3, xmm7, xmm1, xmm4, xmm5, rax + 0x20); --LaneCount;
    if (LaneCount == 0) { goto MixDown; }
    MEOW_MIX(xmm4, xmm0, xmm2, xmm5, xmm6, rax + 0x40); --LaneCount;
    if (LaneCount == 0) { goto MixDown; }
    MEOW_MIX(xmm5, xmm1, xmm3, xmm6, xmm7, rax + 0x60); --LaneCount;
    if (LaneCount == 0) { goto MixDown; }
    MEOW_MIX(xmm6, xmm2, xmm4, xmm7, xmm0, rax + 0x80); --LaneCount;
    if (LaneCount == 0) { goto MixDown; }
    MEOW_MIX(xmm7, xmm3, xmm5, xmm0, xmm1, rax + 0xa0); --LaneCount;
    if (LaneCount == 0) { goto MixDown; }
    MEOW_MIX(xmm0, xmm4, xmm6, xmm1, xmm2, rax + 0xc0); --LaneCount;

    //
    // NOTE(casey): Mix the eight lanes down to one 128-bit hash
    //
  MixDown:
    MEOW_SHUFFLE(xmm0, xmm1, xmm2, xmm4, xmm5, xmm6);
    MEOW_SHUFFLE(xmm1, xmm2, xmm3, xmm5, xmm6, xmm7);
    MEOW_SHUFFLE(xmm2, xmm3, xmm4, xmm6, xmm7, xmm0);
    MEOW_SHUFFLE(xmm3, xmm4, xmm5, xmm7, xmm0, xmm1);
    MEOW_SHUFFLE(xmm4, xmm5, xmm6, xmm0, xmm1, xmm2);
    MEOW_SHUFFLE(xmm5, xmm6, xmm7, xmm1, xmm2, xmm3);
    MEOW_SHUFFLE(xmm6, xmm7, xmm0, xmm2, xmm3, xmm4);
    MEOW_SHUFFLE(xmm7, xmm0, xmm1, xmm3, xmm4, xmm5);
    MEOW_SHUFFLE(xmm0, xmm1, xmm2, xmm4, xmm5, xmm6);
    MEOW_SHUFFLE(xmm1, xmm2, xmm3, xmm5, xmm6, xmm7);
    MEOW_SHUFFLE(xmm2, xmm3, xmm4, xmm6, xmm7, xmm0);
    MEOW_SHUFFLE(xmm3, xmm4, xmm5, xmm7, xmm0, xmm1);

    paddq(xmm0, xmm2);
    paddq(xmm1, xmm3);
    paddq(xmm4, xmm6);
    paddq(xmm5, xmm7);
    pxor(xmm0, xmm1);
    pxor(xmm4, xmm5);
    paddq(xmm0, xmm4);

    return xmm0;
}

//------------------------------------------------------------
template <bool bswap>
static void MeowHash32( const void * in, const size_t len, const seed_t seed, void * out ) {
    meow_u128 h = MeowHash<bswap>(MeowDefaultSeed, len, in, (uint64_t)seed);

    PUT_U32<bswap>(MeowU32From(h, 0), (uint8_t *)out, 0);
}

template <bool bswap>
static void MeowHash64( const void * in, const size_t len, const seed_t seed, void * out ) {
    meow_u128 h = MeowHash<bswap>(MeowDefaultSeed, len, in, (uint64_t)seed);

    PUT_U64<bswap>(MeowU64From(h, 0), (uint8_t *)out, 0);
}

template <bool bswap>
static void MeowHash128( const void * in, const size_t len, const seed_t seed, void * out ) {
    meow_u128 h = MeowHash<bswap>(MeowDefaultSeed, len, in, (uint64_t)seed);

    PUT_U64<bswap>(MeowU64From(h, 0), (uint8_t *)out, 0);
    PUT_U64<bswap>(MeowU64From(h, 1), (uint8_t *)out, 8);
}

#endif

//------------------------------------------------------------
REGISTER_FAMILY(meowhash,
   $.src_url    = "https://github.com/cmuratori/meow_hash",
   $.src_status = HashFamilyInfo::SRC_STABLEISH
 );

#if defined(HAVE_X86_64_AES) && defined(HAVE_SSE_4_1)

REGISTER_HASH(MeowHash__32,
   $.desc       = "MeowHash (0.5/calico, low 32 bits)",
   $.impl       = "aesni",
   $.hash_flags =
         FLAG_HASH_NO_SEED       |
         FLAG_HASH_AES_BASED,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB |
         FLAG_IMPL_LICENSE_ZLIB,
   $.bits = 32,
   $.verification_LE = 0xE9E94FF2,
   $.verification_BE = 0xD5BF086D,
   $.hashfn_native   = MeowHash32<false>,
   $.hashfn_bswap    = MeowHash32<true>
 );

REGISTER_HASH(MeowHash__64,
   $.desc       = "MeowHash (0.5/calico, low 64 bits)",
   $.impl       = "aesni",
   $.hash_flags =
         FLAG_HASH_NO_SEED       |
         FLAG_HASH_AES_BASED,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB |
         FLAG_IMPL_LICENSE_ZLIB,
   $.bits = 64,
   $.verification_LE = 0x4C9F52A6,
   $.verification_BE = 0xFA21003A,
   $.hashfn_native   = MeowHash64<false>,
   $.hashfn_bswap    = MeowHash64<true>
 );

REGISTER_HASH(MeowHash,
   $.desc       = "MeowHash (0.5/calico)",
   $.impl       = "aesni",
   $.hash_flags =
         FLAG_HASH_NO_SEED       |
         FLAG_HASH_AES_BASED,
   $.impl_flags =
         FLAG_IMPL_READ_PAST_EOB |
         FLAG_IMPL_LICENSE_ZLIB,
   $.bits = 128,
   $.verification_LE = 0x7C648489,
   $.verification_BE = 0x4FD0834C,
   $.hashfn_native   = MeowHash128<false>,
   $.hashfn_bswap    = MeowHash128<true>
 );

#endif
