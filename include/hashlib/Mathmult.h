/*
 * Multiplication and addition routines for >=64-bit math,
 * in terms of <=64-bit variables.
 *
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (C) 2023       jason
 * Copyright (c) 2016 Vladimir Makarov <vmakarov@gcc.gnu.org>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Some of this is based off of code from PMP Multilinear hashes:
 *
 *     Copyright (C) 2021-2022  Frank J. T. Wojcik
 *     Copyright (c) 2014-2021 Reini Urban
 *     Copyright (c) 2014, Dmytro Ivanchykhin, Sergey Ignatchenko, Daniel Lemire
 *     All rights reserved.
 *
 *     Redistribution and use in source and binary forms, with or without
 *     modification, are permitted provided that the following conditions are met:
 *
 *     1. Redistributions of source code must retain the above copyright notice, this
 *        list of conditions and the following disclaimer.
 *     2. Redistributions in binary form must reproduce the above copyright notice,
 *        this list of conditions and the following disclaimer in the documentation
 *        and/or other materials provided with the distribution.
 *
 *     THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *     ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *     WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *     DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 *     ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *     (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *     LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *     ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *     (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *     SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * There are several places here which have different versions of this code
 * for clang, all of which check for that via "defined(__clang__)".
 *
 * This is because clang does not work well with asm constraints. One
 * example is that, given the option, clang has some sort of preference for
 * memory operands. It may spill a register to the stack, and operate on
 * the stack copy. Or it may spill to the stack, operate on the register,
 * and then spill the new value to the stack again, without ever reading or
 * operating on the stack copy even once. Therefore, clang is not given the
 * option of memory operands.
 *
 * This is still true for clang trunk as of July 2023. You can see more
 * about this issue at:
 *    http://stackoverflow.com/questions/16850309/
 *    https://github.com/llvm/llvm-project/issues/20571
 *    https://godbolt.org/z/Wr3EvKnhn
 */

namespace MathMult {

// 32x32->64 multiplication [rhi:rlo = a * b]
static FORCE_INLINE void mult32_64( uint32_t & rlo, uint32_t & rhi, uint32_t a, uint32_t b ) {
    // XXX Are either of these asm blocks better than just the plain code?
#if 0 && defined(HAVE_ARM_ASM)
    __asm__ ("UMULL %w0, %w1, %w2, %w3"
             : "+r" (rlo), "+r" (rhi)
             : "r" (a), "r" (b)
             : "cc", "memory"
    );
#elif 0 && defined(HAVE_X86_64_ASM)
    __asm__ ("mull  %[b]"
             : "=d" (rhi), "=a" (rlo)
             : "%1" (a), [b] "rm" (b)
    );
#else
    uint64_t r = (uint64_t)a * (uint64_t)b;
    rhi = (uint32_t)(r >> 32);
    rlo = (uint32_t)r;
#endif
}

// 32x32->64 multiplication [r64 = a32 * b32]
static FORCE_INLINE void mult32_64( uint64_t & r64, uint32_t a32, uint32_t b32 ) {
#if defined(_MSC_VER) && defined(_M_IX86)
    r64 = __emulu(a32, b32);
#else
    r64 = (uint64_t)a32 * (uint64_t)b32;
#endif
}

// 96-bit addition [rhi:rmi:rlo += addhi:addmi:addlo]
static FORCE_INLINE void add96( uint32_t & rlo, uint32_t & rmi, uint32_t & rhi, const uint32_t & addlo,
        const uint32_t & addmi, const uint32_t & addhi ) {
#if defined(HAVE_ARM_ASM)
    __asm__ ("ADDS %w0, %w3, %w0\n\t"
             "ADCS %w1, %w4, %w1\n\t"
             "ADC  %w2, %w5, %w2"
             : "+r" (rlo), "+r" (rmi), "+r" (rhi)
             : "r" (addlo), "r" (addmi), "r" (addhi)
             : "cc"
    );
#elif defined(HAVE_X86_64_ASM)
    __asm__ ("addl %3, %0\n\t"
             "adcl %4, %1\n\t"
             "adcl %5, %2"
  #if defined(__clang__)
             : "+r" (rlo),   "+r" (rmi),   "+r" (rhi)
             : "re" (addlo), "re" (addmi), "re" (addhi)
  #else
             : "+g,g,g,g,r,r,r,r" (rlo),  "+g,g,r,r,g,g,r,r" (rmi),  "+g,r,g,r,g,r,g,r" (rhi)
             : "re,re,re,re,m,m,m,m" (addlo), "re,re,m,m,re,re,m,m" (addmi), "re,m,re,m,re,m,re,m" (addhi)
  #endif
             : "cc"
    );
#else
    uint64_t w = (((uint64_t)rmi  ) << 32) + ((uint64_t)rlo  );
    uint64_t r = (((uint64_t)addmi) << 32) + ((uint64_t)addlo) + w;
    rhi += addhi + (r < w);
    rmi  = (uint32_t)(r >> 32);
    rlo  = (uint32_t)(r      );
#endif
}

// 64-bit fused multiply addition [r64 += a * b]
static FORCE_INLINE void fma32_64( uint64_t & r64, uint32_t a, uint32_t b ) {
#if defined(HAVE_ARM_ASM)
    //uint64_t ret;
    __asm__("umaddl %x0, %w1, %w2, %x3" : "=r" (r64) : "r" (a), "r" (b), "r" (r64));
    //r64 = ret;
#else
    uint64_t v;
    MathMult::mult32_64(v, a, b);
    r64 += v;
#endif
}

// 96-bit fused multiply addition [rhi:rmi:rlo += a * b]
static FORCE_INLINE void fma32_96( uint32_t & rlo, uint32_t & rmi, uint32_t & rhi, uint32_t a, uint32_t b ) {
// These #defines are not correct; some arm seems to not support this
#if 0 && defined(HAVE_ARM_ASM)
    uint32_t tmphi, tmplo;
    __asm__ ("UMULL %w3, %w4, %w5, %w6\n\t"
             "ADDS  %w0, %w3, %w0\n\t"
             "ADCS  %w1, %w4, %w1\n\t"
             "ADC   %w2, %w2, #0x0"
             : "+r" (rlo), "+r" (rmi), "+r" (rhi), "=r" (tmplo), "=r" (tmphi)
             : "r" (a), "r" (b)
             : "cc"
    );
#elif defined(HAVE_X86_64_ASM)
    uint32_t tmplo, tmphi;
    __asm__ ("mull %6\n\t"
             "addl %%eax, %0\n\t"
             "adcl %%edx, %1\n\t"
             "adcl $0, %2"
  #if defined(__clang__)
             : "+r" (rlo), "+r" (rmi), "+r" (rhi), "=a" (tmplo), "=d" (tmphi)
             : "%a" (a), "r" (b)
  #else
             : "+g" (rlo), "+g" (rmi), "+g" (rhi), "=a" (tmplo), "=d" (tmphi)
             : "%a" (a), "rm" (b)
  #endif
             : "cc"
    );
#else
    uint32_t tmplo, tmpmi, tmphi = 0;
    mult32_64(tmplo, tmpmi, a, b);
    add96(rlo, rmi, rhi, tmplo, tmpmi, tmphi);
#endif
}

// 64x64->128 multiplication [rhi:rlo = a * b]
static FORCE_INLINE void mult64_128( uint64_t & rlo, uint64_t & rhi, uint64_t a, uint64_t b ) {
#if defined(HAVE_UMUL128)
    rlo = _umul128(a, b, &rhi);
#elif defined(HAVE_UMULH)
    rlo = a * b;
    rhi = __umulh(a, b);
#elif defined(HAVE_ARM64_ASM)
    /*
     * AARCH64 needs 2 insns to calculate 128-bit result of the
     * multiplication.  If we use a generic code we actually call a
     * function doing 128x128->128 bit multiplication. The function
     * is very slow.
     */
    rlo = a * b;
    __asm__ ("umulh %0, %1, %2"
             : "=r" (rhi)
             : "r" (a), "r" (b)
    );
#elif defined(HAVE_PPC_ASM)
    rlo = a * b;
    __asm__ ("mulhdu %0, %1, %2"
             : "=r" (rhi)
             : "r" (a), "r" (b)
    );
#elif defined(HAVE_AVX2) && defined(HAVE_X86_64_ASM)
    /*
     * We want to use AVX2 insn MULX instead of generic x86-64 MULQ
     * where it is possible.  Although on modern Intel processors MULQ
     * takes 3-cycles vs. 4 for MULX, MULX permits more freedom in
     * insn scheduling as it uses less fixed registers.
     */
    __asm__ ("mulxq %3, %1, %0"
  #if defined(__clang__)
             : "=r" (rhi), "=r" (rlo)
             : "%d" (a), "r" (b)
  #else
             : "=r" (rhi), "=r" (rlo)
             : "%d" (a), "rm" (b)
  #endif
    );
#elif defined(HAVE_X86_64_ASM)
    __asm__ ("mulq %3"
  #if defined(__clang__)
             : "=d" (rhi), "=a" (rlo)
             : "%1" (a), "r" (b)
  #else
             : "=d" (rhi), "=a" (rlo)
             : "%1" (a), "rm" (b)
  #endif
             : "cc"
    );
#elif defined(HAVE_INT128)
    // Maybe move this before the other x64 ASM methods?
    // Seems like it's more compiler-friendly, but it produces slower code.
    uint128_t r = (uint128_t)a * (uint128_t)b;
    rhi = (uint64_t)(r >> 64);
    rlo = (uint64_t)r;
#else
    /*
     * Implementation of 64x64->128-bit multiplication by four
     * 32x32->64 bit multiplication.
     */
    uint64_t ahi = a >> 32, bhi = b >> 32;
    uint64_t alo = (uint32_t)a, blo = (uint32_t)b;
    uint64_t tmphi   = ahi * bhi;
    uint64_t tmpmi_0 = ahi * blo;
    uint64_t tmpmi_1 = alo * bhi;
    uint64_t tmplo   = alo * blo;
    uint64_t t, carry = 0;

    t      = (tmpmi_0 << 32   ) + tmplo;
    carry += (t        < tmplo);
    rlo    = (tmpmi_1 << 32   ) + t;
    carry += (rlo      < t    );
    rhi    = (tmpmi_0 >> 32   ) + (tmpmi_1 >> 32) + tmphi + carry;
#endif
}

// 64x64->128 multiplication with no cross-lane carry [rhi:rlo ~= a * b]
static FORCE_INLINE void mult64_128_nocarry( uint64_t & rlo, uint64_t & rhi, uint64_t a, uint64_t b ) {
    /*
     * Implementation of 64x64->128-bit multiplication by four
     * 32x32->64 bit multiplication, excluding the carry bits.  This
     * is a bit faster in the absence of a real 128-bit multiply
     * instruction, and almost as good for hashing.
     */
    uint64_t ahi = a >> 32, bhi = b >> 32;
    uint64_t alo = (uint32_t)a, blo = (uint32_t)b;
    uint64_t tmphi   = ahi * bhi;
    uint64_t tmpmi_0 = ahi * blo;
    uint64_t tmpmi_1 = alo * bhi;
    uint64_t tmplo   = alo * blo;

    rlo = tmplo + (tmpmi_0 << 32) + (tmpmi_1 << 32);
    rhi = tmphi + (tmpmi_0 >> 32) + (tmpmi_1 >> 32);
}

// 128-bit addition special case [rhi:rlo += 0:addlo]
static FORCE_INLINE void add128( uint64_t & rlo, uint64_t & rhi, uint64_t addlo ) {
#if defined(HAVE_X86_64_ASM)
    __asm__ ("addq %2, %0\n\t"
             "adcq $0, %1"
  #if defined(DEBUG)
             : "+r" (rlo), "+r" (rhi)
             : "r" (addlo)
  #elif defined(__clang__)
             : "+r" (rlo), "+r" (rhi)
             : "re" (addlo)
  #else
             : "+g,r" (rlo), "+g,g" (rhi)
             : "re,m" (addlo)
  #endif
             : "cc"
    );
#else
    rlo += addlo;
    rhi += (rlo < addlo);
#endif
}

// 128-bit addition [rhi:rlo += addhi:addlo]
static FORCE_INLINE void add128( uint64_t & rlo, uint64_t & rhi, uint64_t addlo, uint64_t addhi ) {
#if defined(HAVE_PPC_ASM)
    __asm__ ("addc %1, %1, %3\n\t"
             "adde %0, %0, %2"
             : "+r" (rhi), "+r" (rlo)
             : "r" (addhi), "r" (addlo)
    );
#elif defined(HAVE_X86_64_ASM)
    __asm__ ("addq %2, %0\n\t"
             "adcq %3, %1"
  #if defined(DEBUG)
             : "+r" (rlo), "+r" (rhi)
             : "r" (addlo), "r" (addhi)
  #elif defined(__clang__)
             : "+r" (rlo), "+r" (rhi)
             : "re" (addlo), "re" (addhi)
  #else
             : "+g,g,r,r" (rlo), "+g,r,g,r" (rhi)
             : "re,re,m,m" (addlo), "re,m,re,m" (addhi)
  #endif
             : "cc"
    );
#else
    rlo += addlo;
    rhi += (rlo < addlo);
    rhi += addhi;
#endif
}

// 192-bit addition [rhi:rmi:rlo += addhi:addmi:addlo]
static FORCE_INLINE void add192( uint64_t & rlo, uint64_t & rmi, uint64_t & rhi, const uint64_t & addlo,
        const uint64_t & addmi, const uint64_t & addhi ) {
#if defined(HAVE_X86_64_ASM)
    __asm__ ("addq %3, %0\n\t"
             "adcq %4, %1\n\t"
             "adcq %5, %2"
  #if defined(DEBUG)
             : "+r" (rlo), "+r" (rmi), "+r" (rhi)
             : "r" (addlo), "r" (addmi), "r" (addhi)
  #elif defined(__clang__)
             : "+r" (rlo), "+r" (rmi), "+r" (rhi)
             : "re" (addlo), "re" (addmi), "re" (addhi)
  #else
             : "+g,g,g,g,r,r,r,r" (rlo), "+g,g,r,r,g,g,r,r" (rmi), "+g,r,g,r,g,r,g,r" (rhi)
             : "re,re,re,re,m,m,m,m" (addlo), "re,re,m,m,re,re,m,m" (addmi), "re,m,re,m,re,m,re,m" (addhi)
  #endif
             : "cc"
    );
#else
    rlo += addlo;
    rmi += (rlo < addlo);
    rmi += addmi;
    rhi += (rmi < addmi);
    rhi += addhi;
#endif
}

// 128-bit fused multiply addition [rhi:rlo += a * b]
static FORCE_INLINE void fma64_128( uint64_t & rlo, uint64_t & rhi, uint64_t a, uint64_t b ) {
#if defined(HAVE_AVX2) && defined(HAVE_X86_64_ASM)
    uint64_t tmplo, tmphi;
    __asm__ ("mulxq %5, %2, %3\n\t"
             "addq %2, %0\n\t"
             "adcq %3, %1"
  #if defined(DEBUG)
             : "+r" (rlo), "+r" (rhi), "=r" (tmplo), "=r" (tmphi)
             : "d" (a), "r" (b)
  #elif defined(__clang__)
             : "+r" (rlo), "+r" (rhi), "=r" (tmplo), "=r" (tmphi)
             : "%d" (a), "r" (b)
  #else
             : "+g" (rlo), "+g" (rhi), "=r" (tmplo), "=r" (tmphi)
             : "%d" (a), "rm" (b)
  #endif
             : "cc");
#elif defined(HAVE_X86_64_ASM)
    uint64_t tmplo, tmphi;
    __asm__ ("mulq %5\n\t"
             "addq %%rax, %0\n\t"
             "adcq %%rdx, %1"
  #if defined(DEBUG)
             : "+r" (rlo), "+r" (rhi), "=a" (tmplo), "=d" (tmphi)
             : "a" (a), "r" (b)
  #elif defined(__clang__)
             : "+r" (rlo), "+r" (rhi), "=a" (tmplo), "=d" (tmphi)
             : "%a" (a), "r" (b)
  #else
             : "+g" (rlo), "+g" (rhi), "=a" (tmplo), "=d" (tmphi)
             : "%a" (a), "rm" (b)
  #endif
             : "cc");
#else
    uint64_t tmplo, tmphi;
    mult64_128(tmplo, tmphi, a, b);
    add128(rlo, rhi, tmplo, tmphi);
#endif
}

// 192-bit fused multiply addition [rhi:rmi:rlo += a * b]
static FORCE_INLINE void fma64_192( uint64_t & rlo, uint64_t & rmi, uint64_t & rhi, uint64_t a, uint64_t b ) {
#if defined(HAVE_AVX2) && defined(HAVE_X86_64_ASM)
    uint64_t tmplo, tmphi;
    __asm__ ("mulxq %6, %3, %4\n\t"
             "addq %3, %0\n\t"
             "adcq %4, %1\n\t"
             "adcq $0, %2"
  #if defined(DEBUG)
             : "+r" (rlo), "+r" (rmi), "+r" (rhi), "=r" (tmplo), "=r" (tmphi)
             : "d" (a), "r" (b)
  #elif defined(__clang__)
             : "+r" (rlo), "+r" (rmi), "+r" (rhi), "=r" (tmplo), "=r" (tmphi)
             : "%d" (a), "r" (b)
  #else
             : "+g" (rlo), "+g" (rmi), "+g" (rhi), "=r" (tmplo), "=r" (tmphi)
             : "%d" (a), "rm" (b)
  #endif
             : "cc");
#elif defined(HAVE_X86_64_ASM)
    uint64_t tmplo, tmphi;
    __asm__ ("mulq %6\n\t"
             "addq %%rax, %0\n\t"
             "adcq %%rdx, %1\n\t"
             "adcq $0, %2"
  #if defined(DEBUG)
             : "+r" (rlo), "+r" (rmi), "+r" (rhi), "=a" (tmplo), "=d" (tmphi)
             : "a" (a), "r" (b)
  #elif defined(__clang__)
             : "+r" (rlo), "+r" (rmi), "+r" (rhi), "=a" (tmplo), "=d" (tmphi)
             : "%a" (a), "r" (b)
  #else
             : "+g" (rlo), "+g" (rmi), "+g" (rhi), "=a" (tmplo), "=d" (tmphi)
             : "%a" (a), "rm" (b)
  #endif
             : "cc");
#else
    uint64_t tmplo, tmpmi, tmphi = 0;
    mult64_128(tmplo, tmpmi, a, b);
    add192(rlo, rmi, rhi, tmplo, tmpmi, tmphi);
#endif
}

// 128x128->128 multiplication [rhi:rlo = ahi:alo * bhi:blo]
static FORCE_INLINE void mult128_128( uint64_t & rlo, uint64_t & rhi, uint64_t alo,
        uint64_t ahi, uint64_t blo, uint64_t bhi ) {
#if defined(HAVE_INT128)
    uint128_t r = (((uint128_t)ahi) << 64) + (uint128_t)alo;
    uint128_t c = (((uint128_t)bhi) << 64) + (uint128_t)blo;
    r   = r * c;
    rhi = (uint64_t)(r >> 64);
    rlo = (uint64_t)r;
#else
    mult64_128(rlo, rhi, alo, blo);
    rhi += bhi * alo;
    rhi += blo * ahi;
#endif
}

} // namespace MathMult
