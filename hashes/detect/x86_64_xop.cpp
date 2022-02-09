#include <cstdio>
#if defined(_MSC_VER)
# include <ammintrin.h>
# define WIN32_LEAN_AND_MEAN
# include <Windows.h>
typedef UINT32 uint32_t;
typedef UINT8 uint8_t;
#else
# include <stdint.h>
# include <x86intrin.h>
#endif
uint32_t state[5];
int main(void) {
    __m128i FOO = _mm_set_epi64x(0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL);
    __m128i BAR = _mm_roti_epi64(FOO, 5);
    _mm_storeu_si128((__m128i*) state, BAR);
}
