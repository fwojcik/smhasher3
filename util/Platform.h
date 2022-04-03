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

#ifdef HAVE_THREADS
#include <thread>
# if __APPLE__
#  include <mach/mach.h>
#  include <mach/thread_act.h>
# endif
extern unsigned g_NCPU;
#else
extern const unsigned g_NCPU;
#endif

void DisableThreads(void);

#if !defined(HAVE_X86_64)
  #if defined(__x86_64) || defined(_M_AMD64) || defined(_M_X64)
    #define HAVE_X86_64
  #elif defined(__i386__)
    #define HAVE_X86_32
  #endif
#endif

//-----------------------------------------------------------------------------
// Microsoft Visual Studio

#if defined(_MSC_VER)

#include <stdlib.h>
#include <stdint.h>

#define FORCE_INLINE	__forceinline
#define	NEVER_INLINE  __declspec(noinline)
#define RESTRICT __restrict

#define ROTL32(x,y)	_rotl(x,y)
#define ROTL64(x,y)	_rotl64(x,y)
#define ROTR32(x,y)	_rotr(x,y)
#define ROTR64(x,y)	_rotr64(x,y)

#pragma warning(disable : 4127) // "conditional expression is constant" in the if()s for avalanchetest
#pragma warning(disable : 4100)
#pragma warning(disable : 4702)

#define popcount4(x) __popcnt(x)
#ifdef HAVE_32BIT_PLATFORM
#define popcount8(x)  __popcnt(x)
#else
#define popcount8(x)  __popcnt64(x)
#endif

// Assumes x is not 0!!!
#ifdef HAVE_64BIT_PLATFORM
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
#define unreachable() (__assume(0))
#define prefetch(ptr) do { (void)(ptr); } while (0)

//-----------------------------------------------------------------------------
// Other compilers

#else	//	!defined(_MSC_VER)

#if !defined (HAVE_X86_64) && !defined (HAVE_X86_32)
#include <cstddef>
#endif

#include <cstdlib>
#include <cstdint>

#ifdef HAVE_THREADS
#include <pthread.h>
#endif

#define	FORCE_INLINE inline __attribute__((always_inline))
#define	NEVER_INLINE __attribute__((noinline))
#define RESTRICT __restrict

#define popcount4(x) __builtin_popcount(x)
#ifdef HAVE_32BIT_PLATFORM
#define popcount8(x) __builtin_popcountll(x)
#else
#define popcount8(x) __builtin_popcountl(x)
#endif

// Assumes x is not 0!!!
#define clz4(x) __builtin_clz(x)
#ifdef HAVE_32BIT_PLATFORM
#define clz8(x) __builtin_clzll(x)
#else
#define clz8(x) __builtin_clzl(x)
#endif

// Deliberately unsafe! Assumes r is not 0 or >=8*sizeof(x)
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

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
/* Should work for gcc, clang, and icc at least */
#define assume(x) do { if (!(x)) __builtin_unreachable(); } while (0)
#define unreachable() __builtin_unreachable()
#define prefetch(ptr) __builtin_prefetch(ptr)

#include <strings.h>
#define _stricmp strcasecmp

#endif	//	!defined(_MSC_VER)

//-----------------------------------------------------------------------------
#include <cstdio>

static FORCE_INLINE bool isLE(void) {
    const uint32_t   value = 0xb000000e;
    const void *      addr = static_cast<const void *>(&value);
    const uint8_t *   lsb  = static_cast<const uint8_t *>(addr);
    return ((*lsb) == 0x0e);
}

static FORCE_INLINE bool isBE(void) {
    const uint32_t   value = 0xb000000e;
    const void *      addr = static_cast<const void *>(&value);
    const uint8_t *   lsb  = static_cast<const uint8_t *>(addr);
    return ((*lsb) == 0xb0);
}

// FIXME Make this code properly portable
template < typename T >
static FORCE_INLINE T BSWAP(T value) {
    switch(sizeof(T)) {
    case 2:  value = __builtin_bswap16((uint16_t)value); break;
    case 4:  value = __builtin_bswap32((uint32_t)value); break;
    case 8:  value = __builtin_bswap64((uint64_t)value); break;
#if 0
#ifdef HAVE_INT128
    case 16: value = __builtin_bswap128((uint128_t)value); break;
#endif
#endif
    default: break;
    }
    return value;
}

template < typename T >
static FORCE_INLINE T COND_BSWAP(T value, bool doit) {
    if (!doit || (sizeof(T) < 2)) { return value; }
    return BSWAP(value);
}

//-----------------------------------------------------------------------------
// 32-bit integer manipulation functions. These move data in
// alignment-safe ways, with optional byte swapping.
#include <cstring>

template < bool bswap >
static FORCE_INLINE uint64_t GET_U64(const uint8_t * b, const uint32_t i) {
    uint64_t n;
    memcpy(&n, &b[i], 8);
    n = COND_BSWAP(n, bswap);
    return n;
}

template < bool bswap >
static FORCE_INLINE uint32_t GET_U32(const uint8_t * b, const uint32_t i) {
    uint32_t n;
    memcpy(&n, &b[i], 4);
    n = COND_BSWAP(n, bswap);
    return n;
}

template < bool bswap >
static FORCE_INLINE uint16_t GET_U16(const uint8_t * b, const uint32_t i) {
    uint16_t n;
    memcpy(&n, &b[i], 2);
    n = COND_BSWAP(n, bswap);
    return n;
}

template < bool bswap >
static FORCE_INLINE void PUT_U32(uint32_t n, uint8_t * b, const uint32_t i) {
    n = COND_BSWAP(n, bswap);
    memcpy(&b[i], &n, 4);
}

template < bool bswap >
static FORCE_INLINE void PUT_U64(uint64_t n, uint8_t * b, const uint32_t i) {
    n = COND_BSWAP(n, bswap);
    memcpy(&b[i], &n, 8);
}
