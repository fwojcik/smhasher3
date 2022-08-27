#include <cstdio>
#include "isa.h"

/*
 * Due to gcc bug 99754 (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=99754), we make
 * sure this fails on gcc 11.x if x<3. Earlier gcc versions don't have these
 * intrinsics at all, and gcc 12 and up don't have that bug.
 *
 * It'd be much better to test the actual functionality of the intrinsics to detect
 * the bug, but I don't know how to do that at compile-time, and we can't count on
 * running code due to supporting cross-compilation.
 */
#if defined(__GNUC__) && !defined(__clang__) && !defined(__INTEL_COMPILER) && (__GNUC__ == 11) && (__GNUC_MINOR__ < 3)
#error "Ignoring 16- and 32-bit loadu intrinsics due to gcc bug 99754"
#endif

int16_t val16[20];
int32_t val32[20];

uint32_t state[5];
int main(void) {
    __m128i FOO = _mm_set_epi64x(UINT64_C(0x0001020304050607), UINT64_C(0x08090a0b0c0d0e0f));
    __m128i BAR = _mm_loadu_si16(val16);
    __m128i BAZ = _mm_loadu_si32(val32);
    _mm_storeu_si128((__m128i*) state, BAR);
}
