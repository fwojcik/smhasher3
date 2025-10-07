/*
 * VMAC
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
 *
 * This work is based on:
 *     VMAC and VHASH Implementation by Ted Krovetz (tdk@acm.org) and Wei Dai.
 *     This implementation is hereby placed in the public domain.
 *     The authors offers no warranty. Use at your own risk.
 */
#include "Platform.h"
#include "Hashlib.h"

#include "Mathmult.h"

//-----------------------------------------------------------------------------
// Constants and masks
const uint64_t p64   = UINT64_C(0xfffffffffffffeff); /* 2^64 - 257 prime  */
const uint64_t m62   = UINT64_C(0x3fffffffffffffff); /* 62-bit mask       */
const uint64_t m63   = UINT64_C(0x7fffffffffffffff); /* 63-bit mask       */
const uint64_t m64   = UINT64_C(0xffffffffffffffff); /* 64-bit mask       */
const uint64_t mpoly = UINT64_C(0x1fffffff1fffffff); /* Poly key mask     */

//-----------------------------------------------------------------------------
// macros from Crypto++ for sharing inline assembly code between MSVC and GNU C
#if defined(__GNUC__)
// define these in two steps to allow arguments to be expanded
  #define GNU_AS2(x, y) #x ", " #y ";"
  #define GNU_AS3(x, y, z) #x ", " #y ", " #z ";"
  #define GNU_ASL(x) "\n" #x ":"
  #define GNU_ASJ(x, y, z) #x " " #y #z ";"
  #define AS2(x, y) GNU_AS2(x, y)
  #define AS3(x, y, z) GNU_AS3(x, y, z)
  #define ASS(x, y, a, b, c, d) #x ", " #y ", " #a "*64+" #b "*16+" #c "*4+" #d ";"
  #define ASL(x) GNU_ASL(x)
  #define ASJ(x, y, z) GNU_ASJ(x, y, z)
#else
  #define AS2(x, y) __asm { x, y }
  #define AS3(x, y, z) __asm { x, y, z }
  #define ASS(x, y, a, b, c, d) __asm { x, y, _MM_SHUFFLE(a, b, c, d) }
  #define ASL(x) __asm { \
      label ## x:        \
      }
  #define ASJ(x, y, z) __asm { x label ## y }
#endif

//-----------------------------------------------------------------------------

#define ADD128(rh, rl, ih, il) MathMult::add128(rl, rh, il, ih)

#define MUL64(rh, rl, i1, i2)  MathMult::mult64_128(rl, rh, i1, i2)

// PMUL is a special case of MUL where one carry bit is guaranteed to
// not be needed. We'll just ignore that for now.
#define PMUL64 MUL64

#define MUL32(i1, i2)    ((uint64_t)(uint32_t)(i1) * (uint32_t)(i2))

//-----------------------------------------------------------------------------
// For highest performance the L1 NH and L2 polynomial hashes should be
// carefully implemented to take advantage of one's target architecture.

//-----------------------------------------------------------------------------
// Portable code (64-bit/32-bit details are behind mathmult.h macros)

template <bool bswap>
static inline void nh_16_portable( const uint8_t * mp, const uint64_t * kp, size_t nw, uint64_t & rh, uint64_t & rl ) {
    // uint64_t th, tl;
    rh = rl = 0;
    for (size_t i = 0; i < nw; i += 2) {
        MathMult::fma64_128(rl, rh, (GET_U64<bswap>(mp, i * 8) + kp[i]), (GET_U64<bswap>(mp, i * 8 + 8) + kp[i + 1]));
    }
}

// Using fma64_128() here is a tiny bit slower because there is less
// freedom to reorder things and take advantage of more registers
template <bool bswap>
static inline void nh_vmac_nhbytes_portable( const uint8_t * mp, const uint64_t * kp,
        size_t nw, uint64_t & rh, uint64_t & rl ) {
    uint64_t th, tl;

    rh = rl = 0;
    for (size_t i = 0; i < nw; i += 8) {
        MUL64(th, tl, (GET_U64<bswap>(mp, (i + 0) * 8) + kp[i + 0]), (GET_U64<bswap>(mp, (i + 1) * 8) + kp[i + 1]));
        ADD128(rh, rl, th, tl);
        MUL64(th, tl, (GET_U64<bswap>(mp, (i + 2) * 8) + kp[i + 2]), (GET_U64<bswap>(mp, (i + 3) * 8) + kp[i + 3]));
        ADD128(rh, rl, th, tl);
        MUL64(th, tl, (GET_U64<bswap>(mp, (i + 4) * 8) + kp[i + 4]), (GET_U64<bswap>(mp, (i + 5) * 8) + kp[i + 5]));
        ADD128(rh, rl, th, tl);
        MUL64(th, tl, (GET_U64<bswap>(mp, (i + 6) * 8) + kp[i + 6]), (GET_U64<bswap>(mp, (i + 7) * 8) + kp[i + 7]));
        ADD128(rh, rl, th, tl);
    }
}

static inline void poly_step_portable( uint64_t & ah, uint64_t & al, const uint64_t & kh,
        const uint64_t & kl, const uint64_t & mh, const uint64_t & ml ) {
    uint64_t t1h, t1l, t2h, t2l, t3h, t3l, z = 0;

    /* compute ab*cd, put bd into result registers */
    PMUL64(t3h, t3l, al, kh     );
    PMUL64(t2h, t2l, ah, kl     );
    PMUL64(t1h, t1l, ah,  2 * kh);
    PMUL64(ah , al , al, kl     );
    /* add 2 * ac to result */
    ADD128(ah , al , t1h, t1l);
    /* add together ad + bc */
    ADD128(t2h, t2l, t3h, t3l);
    /* now (ah,al), (t2l,2*t2h) need summing */
    /* first add the high registers, carrying into t2h */
    ADD128(t2h, ah , z  , t2l);
    /* double t2h and add top bit of ah */
    t2h = 2 * t2h + (ah >> 63);
    ah &= m63;
    /* now add the low registers */
    ADD128(ah , al , mh , ml );
    ADD128(ah , al , z  , t2h);
}

//-----------------------------------------------------------------------------
// SSE2-based 32-bit ASM code

#if defined(HAVE_32BIT_PLATFORM) && defined(HAVE_SSE_2)
  #define VMAC_IMPL_STR "32bitsse2"

template <bool bswap>
static void nh_16_sse2( const uint8_t * mp, const uint64_t * kp, size_t nw, uint64_t & rh, uint64_t & rl ) {
    // This assembly version, using MMX registers, is just as fast as the
    // intrinsics version (which uses XMM registers) on the Intel Core 2,
    // but is much faster on the Pentium 4. In order to schedule multiplies
    // as early as possible, the loop interleaves operations for the current
    // block and the next block. To mask out high 32-bits, we use "movd"
    // to move the lower 32-bits to the stack and then back. Surprisingly,
    // this is faster than any other method.
  #if defined(__GNUC__)
    __asm__ __volatile__
    (
        ".intel_syntax noprefix;"
  #else
        AS2(mov     esi, mp )
        AS2(mov     edi, kp )
        AS2(mov     ecx, nw )
        AS2(mov     eax, &rl)
        AS2(mov     edx, &rh)
  #endif
        AS2(sub     esp,  12        )
        AS2(movq    mm6,   [esi]    )
        AS2(paddq   mm6,   [edi]    )
        AS2(movq    mm5,   [esi + 8])
        AS2(paddq   mm5,   [edi + 8])
        AS2(add     esi,  16        )
        AS2(add     edi,  16        )
        AS2(movq    mm4, mm6        )
        ASS(    pshufw  mm2, mm6, 1, 0, 3, 2)
        AS2(    pmuludq mm6, mm5)
        ASS(    pshufw  mm3, mm5, 1, 0, 3, 2)
        AS2(pmuludq mm5    , mm2)
        AS2(pmuludq mm2    , mm3)
        AS2(pmuludq mm3    , mm4)
        AS2(pxor    mm7    , mm7)
        AS2(movd    [esp]  , mm6)
        AS2(psrlq   mm6    ,  32)
        AS2(movd    [esp+4], mm5)
        AS2(psrlq   mm5    ,  32)
        AS2(sub     ecx    ,   2)
        ASJ(    jz,     1, f)
        ASL(0)
        AS2(movq    mm0,   [esi]    )
        AS2(paddq   mm0,   [edi]    )
        AS2(movq    mm1,   [esi + 8])
        AS2(paddq   mm1,   [edi + 8])
        AS2(add     esi,  16        )
        AS2(add     edi,  16        )
        AS2(movq    mm4, mm0        )
        AS2(paddq   mm5, mm2        )
        ASS(    pshufw  mm2, mm0, 1, 0, 3, 2)
        AS2(pmuludq mm0    , mm1)
        AS2(movd    [esp+8], mm3)
        AS2(psrlq   mm3    ,  32)
        AS2(paddq   mm5    , mm3)
        ASS(    pshufw  mm3, mm1, 1, 0, 3, 2)
        AS2(pmuludq mm1    , mm2        )
        AS2(pmuludq mm2    , mm3        )
        AS2(pmuludq mm3    , mm4        )
        AS2(movd    mm4    ,   [esp]    )
        AS2(paddq   mm7    , mm4        )
        AS2(movd    mm4    ,   [esp + 4])
        AS2(paddq   mm6    , mm4        )
        AS2(movd    mm4    ,   [esp + 8])
        AS2(paddq   mm6    , mm4        )
        AS2(movd    [esp]  , mm0        )
        AS2(psrlq   mm0    ,  32        )
        AS2(paddq   mm6    , mm0        )
        AS2(movd    [esp+4], mm1        )
        AS2(psrlq   mm1    ,  32        )
        AS2(paddq   mm5    , mm1        )
        AS2(sub     ecx    ,   2        )
        ASJ(    jnz,    0, b)
        ASL(1)
        AS2(paddq   mm5    , mm2        )
        AS2(movd    [esp+8], mm3        )
        AS2(psrlq   mm3    ,  32        )
        AS2(paddq   mm5    , mm3        )
        AS2(movd    mm4    ,   [esp]    )
        AS2(paddq   mm7    , mm4        )
        AS2(movd    mm4    ,   [esp + 4])
        AS2(paddq   mm6    , mm4        )
        AS2(movd    mm4    ,   [esp + 8])
        AS2(paddq   mm6    , mm4        )

        ASS(    pshufw  mm0, mm7, 3, 2, 1, 0)
        AS2(psrlq   mm7    ,  32)
        AS2(paddq   mm6    , mm7)
        AS2(punpckldq   mm0, mm6)
        AS2(psrlq   mm6    ,  32)
        AS2(paddq   mm5    , mm6)
        AS2(movq    [eax]  , mm0)
        AS2(movq    [edx]  , mm5)
        AS2(add     esp    ,  12)
  #if defined(__GNUC__)
        ".att_syntax prefix;"
        :
        : "S" (mp), "D" (kp), "c" (nw), "a" (&rl), "d" (&rh)
        : "memory", "cc"
    );
  #else
  #endif
}

static void poly_step_sse2( uint64_t & ah, uint64_t & al, const uint64_t & kh,
        const uint64_t & kl, const uint64_t & mh, const uint64_t & ml ) {
    // This code tries to schedule the multiplies as early as possible to overcome
    // the long latencies on the Pentium 4. It also minimizes "movq" instructions
    // which are very expensive on the P4.

  #define a0 [eax + 0]
  #define a1 [eax + 4]
  #define a2 [ebx + 0]
  #define a3 [ebx + 4]
  #define k0 [ecx + 0]
  #define k1 [ecx + 4]
  #define k2 [edx + 0]
  #define k3 [edx + 4]

  #if defined(__GNUC__)
    uint32_t temp;
    __asm__ __volatile__
    (
        "mov %%ebx, %0;"
        "mov %1, %%ebx;"
        ".intel_syntax noprefix;"
  #else
        AS2(mov     ebx, &ah)
        AS2(mov     edx, &kh)
        AS2(mov     eax, &al)
        AS2(mov     ecx, &kl)
        AS2(mov     esi, &mh)
        AS2(mov     edi, &ml)
  #endif

        AS2(movd    mm0    ,  a3        )
        AS2(movq    mm4    , mm0        )
        AS2(pmuludq mm0    ,  k3        ) // a3*k3
        AS2(movd    mm1    ,  a0        )
        AS2(pmuludq mm1    ,  k2        ) // a0*k2
        AS2(movd    mm2    ,  a1        )
        AS2(movd    mm6    ,  k1        )
        AS2(pmuludq mm2    , mm6        ) // a1*k1
        AS2(movd    mm3    ,  a2        )
        AS2(movq    mm5    , mm3        )
        AS2(movd    mm7    ,  k0        )
        AS2(pmuludq mm3    , mm7        ) // a2*k0
        AS2(pmuludq mm4    , mm7        ) // a3*k0
        AS2(pmuludq mm5    , mm6        ) // a2*k1
        AS2(psllq   mm0    ,   1        )
        AS2(paddq   mm0    ,   [esi]    )
        AS2(paddq   mm0    , mm1        )
        AS2(movd    mm1    ,  a1        )
        AS2(paddq   mm4    , mm5        )
        AS2(movq    mm5    , mm1        )
        AS2(pmuludq mm1    ,  k2        ) // a1*k2
        AS2(paddq   mm0    , mm2        )
        AS2(movd    mm2    ,  a0        )
        AS2(paddq   mm0    , mm3        )
        AS2(movq    mm3    , mm2        )
        AS2(pmuludq mm2    ,  k3        ) // a0*k3
        AS2(pmuludq mm3    , mm7        ) // a0*k0
        AS2(movd    esi    , mm0        )
        AS2(psrlq   mm0    ,  32        )
        AS2(pmuludq mm7    , mm5        ) // a1*k0
        AS2(pmuludq mm5    ,  k3        ) // a1*k3
        AS2(paddq   mm0    , mm1        )
        AS2(movd    mm1    ,  a2        )
        AS2(pmuludq mm1    ,  k2        ) // a2*k2
        AS2(paddq   mm0    , mm2        )
        AS2(paddq   mm0    , mm4        )
        AS2(movq    mm4    , mm0        )
        AS2(movd    mm2    ,  a3        )
        AS2(pmuludq mm2    , mm6        ) // a3*k1
        AS2(pmuludq mm6    ,  a0        ) // a0*k1
        AS2(psrlq   mm0    ,  31        )
        AS2(paddq   mm0    , mm3        )
        AS2(movd    mm3    ,   [edi]    )
        AS2(paddq   mm0    , mm3        )
        AS2(movd    mm3    ,  a2        )
        AS2(pmuludq mm3    ,  k3        ) // a2*k3
        AS2(paddq   mm5    , mm1        )
        AS2(movd    mm1    ,  a3        )
        AS2(pmuludq mm1    ,  k2        ) // a3*k2
        AS2(paddq   mm5    , mm2        )
        AS2(movd    mm2    ,   [edi + 4])
        AS2(psllq   mm5    ,   1        )
        AS2(paddq   mm0    , mm5        )
        AS2(movq    mm5    , mm0        )
        AS2(psllq   mm4    ,  33        )
        AS2(psrlq   mm0    ,  32        )
        AS2(paddq   mm6    , mm7        )
        AS2(movd    mm7    , esi        )
        AS2(paddq   mm0    , mm6        )
        AS2(paddq   mm0    , mm2        )
        AS2(paddq   mm3    , mm1        )
        AS2(psllq   mm3    ,   1        )
        AS2(paddq   mm0    , mm3        )
        AS2(psrlq   mm4    ,   1        )
        AS2(punpckldq   mm5, mm0        )
        AS2(psrlq   mm0    ,  32        )
        AS2(por     mm4    , mm7        )
        AS2(paddq   mm0    , mm4        )
        AS2(movq    a0     , mm5        )
        AS2(movq    a2     , mm0        )
  #if defined(__GNUC__)
        ".att_syntax prefix;"
        "mov %0, %%ebx;"
        : "=m" (temp)
        : "m" (&ah), "D" (&ml), "d" (&kh), "a" (&al), "S" (&mh), "c" (&kl)
        : "memory", "cc"
    );
  #else
  #endif

  #undef a0
  #undef a1
  #undef a2
  #undef a3
  #undef k0
  #undef k1
  #undef k2
  #undef k3
}

#else
  #define VMAC_IMPL_STR "portable"
#endif

//-----------------------------------------------------------------------------
// Wrapper implementations
template <bool bswap>
static void nh_16( const uint8_t * mp, const uint64_t * kp, size_t nw, uint64_t & rh, uint64_t & rl ) {
#if defined(HAVE_32BIT_PLATFORM) && defined(HAVE_SSE_2)
    nh_16_sse2<bswap>(mp, kp, nw, rh, rl);
#else
    nh_16_portable<bswap>(mp, kp, nw, rh, rl);
#endif
}

template <bool bswap>
static void nh_vmac_nhbytes( const uint8_t * mp, const uint64_t * kp, size_t nw, uint64_t & rh, uint64_t & rl ) {
#if defined(HAVE_32BIT_PLATFORM) && defined(HAVE_SSE_2)
    nh_16_sse2<bswap>(mp, kp, nw, rh, rl);
#else
    nh_vmac_nhbytes_portable<bswap>(mp, kp, nw, rh, rl);
#endif
}

static void poly_step( uint64_t & ah, uint64_t & al, const uint64_t & kh, const uint64_t & kl,
        const uint64_t & mh, const uint64_t & ml ) {
#if defined(HAVE_32BIT_PLATFORM) && defined(HAVE_SSE_2)
    poly_step_sse2(ah, al, kh, kl, mh, ml);
#else
    poly_step_portable(ah, al, kh, kl, mh, ml);
#endif
}

//-----------------------------------------------------------------------------
#define VMAC_TAG_LEN   64
#define VMAC_KEY_LEN  128
#define VMAC_NHBYTES  128

//-----------------------------------------------------------------------------
#include "AES.h"

typedef uint8_t aes_key[16 * (VMAC_KEY_LEN / 32 + 7)];

#define aes_encryption(in,out,key) \
    AES_Encrypt<10>(key,           \
            (const uint8_t *)(in), \
            (uint8_t *)(out))

#define aes_key_setup(user_key,key)      \
    AES_KeySetup_Enc(key,                \
            (const uint8_t *)(user_key), \
            VMAC_KEY_LEN)

//-----------------------------------------------------------------------------
typedef struct {
    uint64_t  nhkey[(VMAC_NHBYTES / 8) + 2 * (VMAC_TAG_LEN / 64 - 1)];
    uint64_t  polykey[2 * VMAC_TAG_LEN / 64];
    uint64_t  l3key[2 * VMAC_TAG_LEN / 64];
    aes_key   cipher_key;
} vmac_ctx_t;

//-----------------------------------------------------------------------------
#if defined(_MSC_VER)
  #if !defined(_WIN64)
    #define _mmm_empty _mm_empty();
  #else // _WIN64
    #define _mmm_empty
  #endif // _WIN64
#else // _MSC_VER
  #define _mmm_empty __asm volatile ("emms" ::: "memory");
#endif // _MSC_VER

static void vhash_abort( vmac_ctx_t * ctx ) {
    unused(ctx);
#if defined(HAVE_32BIT_PLATFORM) && defined(HAVE_SSE_2)
    _mmm_empty /* SSE2 version of poly_step uses mmx instructions */
#endif
}

#undef _mmm_empty

template <bool bswap>
static void vmac_set_key( uint8_t user_key[], vmac_ctx_t * ctx ) {
    uint64_t in[2] = { 0 }, out[2];
    uint32_t i;

    aes_key_setup(user_key, ctx->cipher_key);

    /* Fill nh key */
    ((uint8_t *)in)[0] = 0x80;
    for (i = 0; i < sizeof(ctx->nhkey) / 8; i += 2) {
        aes_encryption((uint8_t *)in, (uint8_t *)out, ctx->cipher_key);
        ctx->nhkey[i    ]    = GET_U64<bswap>((uint8_t *)out, 0);
        ctx->nhkey[i + 1]    = GET_U64<bswap>((uint8_t *)out, 8);
        ((uint8_t *)in)[15] += 1;
    }

    /* Fill poly key */
    ((uint8_t *)in)[0] = 0xC0;
    in             [1] =    0;
    for (i = 0; i < sizeof(ctx->polykey) / 8; i += 2) {
        aes_encryption((uint8_t *)in, (uint8_t *)out, ctx->cipher_key);
        // "& mpoly" code is moved into vhash() due to new seeding
        ctx->polykey[i    ]  = GET_U64<bswap>((uint8_t *)out, 0);
        ctx->polykey[i + 1]  = GET_U64<bswap>((uint8_t *)out, 8);
        ((uint8_t *)in)[15] += 1;
    }

    /* Fill ip key */
    ((uint8_t *)in)[0] = 0xE0;
    in             [1] =    0;
    for (i = 0; i < sizeof(ctx->l3key) / 8; i += 2) {
        do {
            aes_encryption((uint8_t *)in, (uint8_t *)out, ctx->cipher_key);
            ctx->l3key[i    ]    = GET_U64<bswap>((uint8_t *)out, 0);
            ctx->l3key[i + 1]    = GET_U64<bswap>((uint8_t *)out, 8);
            ((uint8_t *)in)[15] += 1;
        } while (ctx->l3key[i] >= p64 || ctx->l3key[i + 1] >= p64);
    }
}

static uint64_t l3hash( uint64_t p1, uint64_t p2, uint64_t k1, uint64_t k2, uint64_t len ) {
    uint64_t rh, rl, t, z = 0;

    /* fully reduce (p1,p2)+(len,0) mod p127 */
    t   = p1 >> 63;
    p1 &= m63;
    ADD128(p1, p2, len, t);
    /* At this point, (p1,p2) is at most 2^127+(len<<64) */
    t   = (p1 > m63) + ((p1 == m63) && (p2 == m64));
    ADD128(p1, p2, z  , t);
    p1 &= m63;

    /* compute (p1,p2)/(2^64-2^32) and (p1,p2)%(2^64-2^32) */
    t   = (p2 >> 32) + p1;
    t  += (t  >> 32);
    t  += (uint32_t)t > 0xfffffffeu;
    p1 += (t  >> 32);
    p2 += (p1 << 32);

    /* compute (p1+k1)%p64 and (p2+k2)%p64 */
    p1 += k1;
    p1 += (0 - (p1 < k1)) & 257;
    p2 += k2;
    p2 += (0 - (p2 < k2)) & 257;

    /* compute (p1+k1)*(p2+k2)%p64 */
    MUL64(rh, rl, p1, p2);
    t    = rh >> 56;
    ADD128(t, rl, z, rh);
    rh <<= 8;
    ADD128(t, rl, z, rh);
    t   += t << 8;
    rl  += t;
    rl  += (0 - (rl < t      )) & 257;
    rl  += (0 - (rl > p64 - 1)) & 257;
    return rl;
}

// Homegrown (unofficial) seeding
template <bool bswap>
static uint64_t vhash( const uint8_t * mptr, size_t mbytes, uint64_t seed, vmac_ctx_t * ctx ) {
    uint64_t         rh, rl;
    const uint64_t * kptr = ctx->nhkey;
    size_t           i, remaining;
    uint64_t         ch, cl;
    uint64_t         pkh = (ctx->polykey[0] ^ ROTR64(seed, 24)) & mpoly;
    uint64_t         pkl = (ctx->polykey[1] ^ seed            ) & mpoly;

    i         = mbytes / VMAC_NHBYTES;
    remaining = mbytes % VMAC_NHBYTES;

    if (i) {
        nh_vmac_nhbytes<bswap>(mptr, kptr, VMAC_NHBYTES / 8, ch, cl);
        ch &= m62;
        ADD128(ch, cl, pkh, pkl);
        i--;
    } else if (remaining) {
        alignas(16) uint8_t buf[VMAC_NHBYTES];
        memcpy(buf, mptr, remaining);
        memset(buf + remaining, 0, sizeof(buf) - remaining);
        nh_16<bswap>(buf, kptr, 2 * ((remaining + 15) / 16), ch, cl);
        ch &= m62;
        ADD128(ch, cl, pkh, pkl);
        goto do_l3;
    } else {
        ch = pkh; cl = pkl;
        goto do_l3;
    }

    while (i--) {
        mptr += VMAC_NHBYTES;
        nh_vmac_nhbytes<bswap>(mptr, kptr, VMAC_NHBYTES / 8, rh, rl);
        rh   &= m62;
        poly_step(ch, cl, pkh, pkl, rh, rl);
    }
    if (remaining) {
        alignas(16) uint8_t buf[VMAC_NHBYTES];
        memcpy(buf, mptr + VMAC_NHBYTES, remaining);
        memset(buf + remaining, 0, sizeof(buf) - remaining);
        nh_16<bswap>(buf, kptr, 2 * ((remaining + 15) / 16), rh, rl);
        rh &= m62;
        poly_step(ch, cl, pkh, pkl, rh, rl);
    }

  do_l3:
    vhash_abort(ctx);
    remaining *= 8;
    return l3hash(ch, cl, ctx->l3key[0], ctx->l3key[1], remaining);
}

//-----------------------------------------------------------------------------

class VHASH_initializer {
  public:
    alignas(16) vmac_ctx_t ctx;

    VHASH_initializer() {
        alignas(4) uint8_t key[1 + VMAC_KEY_LEN / 8] = "abcdefghijklmnop";
        if (isBE()) {
            vmac_set_key<false>(key, &ctx);
        } else {
            vmac_set_key<true>(key, &ctx);
        }
    }

    ~VHASH_initializer() {}
}; // class VHASH_initializer

// WARNING: this is shared across CPUs, and so must be read-only
// during hashing!!
// Making this thread-local has a sizable performance hit.
static VHASH_initializer vhi;

template <bool bswap>
static void VHASH32( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint32_t hash = vhash<bswap>((const uint8_t *)in, len, (uint64_t)seed, &(vhi.ctx));

    PUT_U32<bswap>(hash, (uint8_t *)out, 0);
}

template <bool bswap>
static void VHASH64( const void * in, const size_t len, const seed_t seed, void * out ) {
    uint64_t hash = vhash<bswap>((const uint8_t *)in, len, (uint64_t)seed, &(vhi.ctx));

    PUT_U64<bswap>(hash, (uint8_t *)out, 0);
}

//-----------------------------------------------------------------------------

REGISTER_FAMILY(vmac,
   $.src_url    = "https://www.fastcrypto.org/vmac/",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

REGISTER_HASH(VHASH__32,
   $.desc       = "VHASH low 32 bits, by Ted Krovetz and Wei Dai",
   $.impl       = VMAC_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128        |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_ASM                    |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 32,
   $.verification_LE = 0x613E4735,
   $.verification_BE = 0x8797E01C,
   $.hashfn_native   = VHASH32<false>,
   $.hashfn_bswap    = VHASH32<true>
 );

REGISTER_HASH(VHASH,
   $.desc       = "VHASH, by Ted Krovetz and Wei Dai",
   $.impl       = VMAC_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC,
   $.impl_flags =
         FLAG_IMPL_MULTIPLY_64_128        |
         FLAG_IMPL_ROTATE                 |
         FLAG_IMPL_ASM                    |
         FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
   $.bits = 64,
   $.verification_LE = 0x7417A00F,
   $.verification_BE = 0x81C8B066,
   $.hashfn_native   = VHASH64<false>,
   $.hashfn_bswap    = VHASH64<true>
 );
