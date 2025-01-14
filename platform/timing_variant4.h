#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <math.h>   // Has to be included before intrin.h or VC complains about "ceil"
#include <intrin.h> // for __rdtsc

#pragma intrinsic(__rdtsc)

static FORCE_INLINE void cycle_timer_init() {
}

static FORCE_INLINE uint64_t cycle_timer_start() {
    return __rdtsc();
}

static FORCE_INLINE uint64_t cycle_timer_end() {
    return __rdtsc();
}
