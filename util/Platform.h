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
 *     Copyright (c) 2011-2013 Austin Appleby
 *     Copyright (c) 2016      Leonid Yuriev
 *     Copyright (c) 2016      Mahmoud Al-Qudsi
 *     Copyright (c) 2016-2021 Reini Urban
 *     Copyright (c) 2019      Yann Collet
 *
 *     Permission is hereby granted, free of charge, to any person
 *     obtaining a copy of this software and associated documentation
 *     files (the "Software"), to deal in the Software without
 *     restriction, including without limitation the rights to use,
 *     copy, modify, merge, publish, distribute, sublicense, and/or
 *     sell copies of the Software, and to permit persons to whom the
 *     Software is furnished to do so, subject to the following
 *     conditions:
 *
 *     The above copyright notice and this permission notice shall be
 *     included in all copies or substantial portions of the Software.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *     HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *     WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *     FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 *     OTHER DEALINGS IN THE SOFTWARE.
 */
//-----------------------------------------------------------------------------
// Platform-specific functions and macros

#pragma once

#if defined(__aarch64__) && defined(HAVE_INT64)
// fixme: bad system call with threads (8 cpu octocore)
# define NCPU 0
#elif !defined NCPU
# define NCPU 4
#endif

#if NCPU > 1
#include <thread>
void SetThreadAffinity ( std::thread &t, int cpu );
# if __APPLE__
#  include <mach/mach.h>
#  include <mach/thread_act.h>
# endif
#endif
void SetAffinity ( int cpu );

#ifndef __x86_64__
 #if defined(__x86_64) || defined(_M_AMD64) || defined(_M_X64)
  #define  __x86_64__
 #endif
#endif

#ifndef HAVE_INT64
 #if (__WORDSIZE >= 64) || defined(HAVE_SSE42)
  #define HAVE_INT64
 #endif
#endif

//-----------------------------------------------------------------------------
// Microsoft Visual Studio

#if defined(_MSC_VER)

#define FORCE_INLINE	__forceinline
#define	NEVER_INLINE  __declspec(noinline)
#define ALIGNED(n)    __declspec(align(n))

#include <stdlib.h>
#include <math.h>   // Has to be included before intrin.h or VC complains about 'ceil'
#include <intrin.h> // for __rdtsc
#include <stdint.h>

#define ROTL32(x,y)	_rotl(x,y)
#define ROTL64(x,y)	_rotl64(x,y)
#define ROTR32(x,y)	_rotr(x,y)
#define ROTR64(x,y)	_rotr64(x,y)

#pragma warning(disable : 4127) // "conditional expression is constant" in the if()s for avalanchetest
#pragma warning(disable : 4100)
#pragma warning(disable : 4702)

#pragma intrinsic(__rdtsc)
// Read Time Stamp Counter
#define rdtsc()       __rdtsc()
#define timer_start() __rdtsc()
#define timer_end()   __rdtsc()

#define popcount4(x) __popcnt(x)
#ifdef HAVE_BIT32
#define popcount8(x)  __popcnt(x)
#else
#define popcount8(x)  __popcnt64(x)
#endif

// Assumes x is not 0!!!
#ifdef HAVE_INT64
#define clz4(x) __lzcnt(x)
#define clz8(x) __lzcnt64(x)
#else
static inline uint32_t clz4(uint32_t x)
{
  uint32_t idx;
  _BitScanReverse(&idx, x);
  return 31 ^ idx;
}
static inline uint32_t clz4(uint64_t x)
{
  uint32_t idx;
  _BitScanReverse64(&idx, x);
  return 31 ^ idx;
}
#endif

#ifdef _WIN32
static char* strndup(char const *s, size_t n)
{
  size_t const len = strnlen(s, n);
  char *p = (char*) malloc(len + 1);
  if (p == NULL) return NULL;
  memcpy(p, s, len);
  p[len] = '\0';
  return p;
}
#endif

#define likely(x) (x)
#define assume(x) (__assume(x))

//-----------------------------------------------------------------------------
// Other compilers

#else	//	!defined(_MSC_VER)

#if !defined (__i386__) && !defined (__x86_64__)
#include <cstddef>
#endif
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#if NCPU > 1
#include <pthread.h>
#endif

#define	FORCE_INLINE inline __attribute__((always_inline))
#define	NEVER_INLINE __attribute__((noinline))
#define ALIGNED(n)   __attribute__ ((aligned(n)))

#define popcount4(x) __builtin_popcount(x)
#ifdef HAVE_BIT32
#define popcount8(x) __builtin_popcountll(x)
#else
#define popcount8(x) __builtin_popcountl(x)
#endif

// Assumes x is not 0!!!
#define clz4(x) __builtin_clz(x)
#ifdef HAVE_BIT32
#define clz8(x) __builtin_clzll(x)
#else
#define clz8(x) __builtin_clzl(x)
#endif

inline uint32_t rotl32 ( uint32_t x, int8_t r )
{
  return (x << r) | (x >> (32 - r));
}

inline uint64_t rotl64 ( uint64_t x, int8_t r )
{
  return (x << r) | (x >> (64 - r));
}

inline uint32_t rotr32 ( uint32_t x, int8_t r )
{
  return (x >> r) | (x << (32 - r));
}

inline uint64_t rotr64 ( uint64_t x, int8_t r )
{
  return (x >> r) | (x << (64 - r));
}

#define	ROTL32(x,y)	rotl32(x,y)
#define ROTL64(x,y)	rotl64(x,y)
#define	ROTR32(x,y)	rotr32(x,y)
#define ROTR64(x,y)	rotr64(x,y)

__inline__ uint64_t timeofday()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)((tv.tv_sec) * 1000000 + tv.tv_usec);
}

__inline__ uint64_t rdtsc()
{
#ifdef _MSC_VER
    return __rdtsc();
#elif defined (__i386__) || defined (__x86_64__)
    return __builtin_ia32_rdtsc();
#elif defined(__ARM_ARCH) && (__ARM_ARCH >= 6) && defined(HAVE_INT32)
  // V6 is the earliest arch that has a standard cyclecount (some say V7)
  uint32_t pmccntr;
  uint32_t pmuseren;
  uint32_t pmcntenset;
  // Read the user mode perf monitor counter access permissions.
  asm volatile("mrc p15, 0, %0, c9, c14, 0" : "=r"(pmuseren));
  if (pmuseren & 1) {  // Allows reading perfmon counters for user mode code.
    asm volatile("mrc p15, 0, %0, c9, c12, 1" : "=r"(pmcntenset));
    if (pmcntenset & 0x80000000ul) {  // Is it counting?
      asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(pmccntr));
      // The counter is set up to count every 64th cycle
      return static_cast<int64_t>(pmccntr) * 64;  // Should optimize to << 6
    }
  }
  return timeofday();
#elif defined(__aarch64__) && defined(HAVE_INT64)
  uint64_t pmccntr;
  uint64_t pmuseren = 1UL;
  // Read the user mode perf monitor counter access permissions.
  //asm volatile("mrs cntv_ctl_el0,  %0" : "=r" (pmuseren));
  if (pmuseren & 1) {  // Allows reading perfmon counters for user mode code.
    asm volatile("mrs %0, cntvct_el0" : "=r" (pmccntr));
    return (uint64_t)(pmccntr) * 64;  // Should optimize to << 6
  }
  return timeofday();
#else
  return timeofday();
#endif
}

// see https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf 3.2.1 The Improved Benchmarking Method
__inline__ uint64_t timer_start()
{
#if defined (__i386__) || (defined(__x86_64__) && defined (HAVE_BIT32))
  uint32_t cycles_high, cycles_low;
  __asm__ volatile
      ("cpuid\n\t"
       "rdtsc\n\t"
       "mov %%edx, %0\n\t"
       "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
       "%eax", "%ebx", "%ecx", "%edx");
    return ((uint64_t)cycles_high << 32) | cycles_low;
#elif defined __x86_64__
  uint32_t cycles_high, cycles_low;
  __asm__ volatile
      ("cpuid\n\t"
       "rdtsc\n\t"
       "mov %%edx, %0\n\t"
       "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
       "%rax", "%rbx", "%rcx", "%rdx");
  return ((uint64_t)cycles_high << 32) | cycles_low;
#else
  return rdtsc();
#endif
}

__inline__ uint64_t timer_end()
{
#if defined (__i386__) || (defined(__x86_64__) && defined (HAVE_BIT32))
  uint32_t cycles_high, cycles_low;
  __asm__ volatile
      ("rdtscp\n\t"
       "mov %%edx, %0\n\t"
       "mov %%eax, %1\n\t"
       "cpuid\n\t": "=r" (cycles_high), "=r" (cycles_low)::
       "%eax", "%ebx", "%ecx", "%edx");
    return ((uint64_t)cycles_high << 32) | cycles_low;
#elif defined __x86_64__
  uint32_t cycles_high, cycles_low;
  __asm__ volatile
      ("rdtscp\n\t"
       "mov %%edx, %0\n\t"
       "mov %%eax, %1\n\t"
       "cpuid\n\t": "=r" (cycles_high), "=r" (cycles_low)::
       "%rax", "%rbx", "%rcx", "%rdx");
  return ((uint64_t)cycles_high << 32) | cycles_low;
#else
  return rdtsc();
#endif
}

#define likely(x) __builtin_expect(!!(x), 1)
/* Should work for gcc, clang, and icc at least */
#define assume(x) do { if (!(x)) __builtin_unreachable(); } while (0)

#include <strings.h>
#define _stricmp strcasecmp

#endif	//	!defined(_MSC_VER)

//-----------------------------------------------------------------------------

#ifdef DEBUG
#undef assume
#define assume(x) assert(x)
#define verify(x) assert(x)
#else
#include <stdio.h>
static void warn_if ( bool x, const char * s, const char * fn, uint64_t ln )
{
  if (!x)
    printf("Statement %s is not true: %s:%d\n", s, fn, ln);
}
#define verify(x) warn_if(x, #x, __FILE__, __LINE__)
#endif

#ifndef __WORDSIZE
# ifdef HAVE_BIT32
#  define __WORDSIZE 32
# else
#  define __WORDSIZE 64
# endif
#endif
