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
 *     Copyright (c) 2011-2012 Austin Appleby
 *     Copyright (c) 2016      Mahmoud Al-Qudsi
 *     Copyright (c) 2019-2021 Reini Urban
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
#include "Platform.h"

#include <stdio.h>

void testRDTSC ( void )
{
  int64_t temp = rdtsc();
  printf("%ld",(long)temp);
}

#if defined(_WIN32)

#include <windows.h>

void SetAffinity ( int cpu )
{
  SetProcessAffinityMask(GetCurrentProcess(),cpu);
  SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
}

#ifdef HAVE_THREADS
void SetThreadAffinity ( std::thread &t, int cpu )
{
  SetThreadIdealProcessor(t.native_handle(), (DWORD)cpu);
}
#endif

#else

#include <sched.h>

void SetAffinity ( int /*cpu*/ )
{
#if !defined(__CYGWIN__) && !defined(__APPLE__) && !defined(__FreeBSD__)
  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(2,&mask);
  if( sched_setaffinity(0,sizeof(mask),&mask) == -1)
  {
    printf("WARNING: Could not set CPU affinity\n");
  }
#endif
}

#ifdef HAVE_THREADS
void SetThreadAffinity ( std::thread &t, int cpu )
{
#if !defined(__CYGWIN__) && !defined(__APPLE__) && !defined(__FreeBSD__)
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpu, &cpuset);
  pthread_setaffinity_np(t.native_handle(), sizeof(cpu_set_t), &cpuset);
#elif defined(__APPLE__)
  thread_affinity_policy_data_t policy = { cpu };
  thread_policy_set(pthread_mach_thread_np(t.native_handle()), THREAD_AFFINITY_POLICY,
                    (thread_policy_t)&policy, 1);
#endif
}
#endif

#endif
