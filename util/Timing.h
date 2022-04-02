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

#define NSEC_PER_SEC 1000000000ULL

//-----------------------------------------------------------------------------
// Microsoft Visual Studio

#if defined(_MSC_VER)

#include <math.h>   // Has to be included before intrin.h or VC complains about 'ceil'
#include <intrin.h> // for __rdtsc

#pragma intrinsic(__rdtsc)
// Read Time Stamp Counter
#define rdtsc()       __rdtsc()
#define timer_start() __rdtsc()
#define timer_end()   __rdtsc()

// From portable-snippets
FORCE_INLINE static size_t monotonic_clock(void) {
  LARGE_INTEGER t, f;
  size_t result;

  if (QueryPerformanceCounter(&t) == 0)
    return -12;

  QueryPerformanceFrequency(&f);
  result = t.QuadPart / f.QuadPart * NSEC_PER_SEC;
  if (f.QuadPart > NSEC_PER_SEC) {
      result += (t.QuadPart % f.QuadPart) / (f.QuadPart / NSEC_PER_SEC);
  } else {
      result += (t.QuadPart % f.QuadPart) * (NSEC_PER_SEC / f.QuadPart);
  }
  return result;
}

//-----------------------------------------------------------------------------
// Other compilers

#else	//	!defined(_MSC_VER)

#include <sys/time.h>

FORCE_INLINE uint64_t timeofday() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)((tv.tv_sec) * 1000000 + tv.tv_usec);
}

FORCE_INLINE uint64_t rdtsc() {
#if defined (HAVE_X86_32) || defined (HAVE_X86_64)
    return __builtin_ia32_rdtsc();
#elif defined(__ARM_ARCH) && (__ARM_ARCH >= 6)
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
      return static_cast<uint64_t>(pmccntr) * 64;  // Should optimize to << 6
    }
  }
  return timeofday();
#elif defined(__aarch64__) && defined(HAVE_64BIT_PLATFORM)
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
FORCE_INLINE uint64_t timer_start() {
#if defined (HAVE_X86_32) || (defined(HAVE_X86_64) && defined (HAVE_32BIT_PLATFORM))
  uint32_t cycles_high, cycles_low;
  __asm__ volatile
      ("cpuid\n\t"
       "rdtsc\n\t"
       "mov %%edx, %0\n\t"
       "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
       "%eax", "%ebx", "%ecx", "%edx");
    return ((uint64_t)cycles_high << 32) | cycles_low;
#elif defined HAVE_X86_64
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

FORCE_INLINE uint64_t timer_end() {
#if defined (HAVE_X86_32) || (defined(HAVE_X86_64) && defined (HAVE_32BIT_PLATFORM))
  uint32_t cycles_high, cycles_low;
  __asm__ volatile
      ("rdtscp\n\t"
       "mov %%edx, %0\n\t"
       "mov %%eax, %1\n\t"
       "cpuid\n\t": "=r" (cycles_high), "=r" (cycles_low)::
       "%eax", "%ebx", "%ecx", "%edx");
    return ((uint64_t)cycles_high << 32) | cycles_low;
#elif defined(HAVE_X86_64)
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

#include <time.h>
// From portable-snippets
FORCE_INLINE static size_t monotonic_clock(void) {
  struct timespec ts;
  size_t result;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return -10;

  result = ts.tv_sec * NSEC_PER_SEC;
  result += ts.tv_nsec;

  return result;
}

#endif	//	!defined(_MSC_VER)
