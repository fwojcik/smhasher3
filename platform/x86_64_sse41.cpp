#include <cstdio>
#include "isa.h"

uint32_t state[5];
int main(void) {
    __m128i FOO = _mm_set_epi64x(UINT64_C(0x0001020304050607), UINT64_C(0x08090a0b0c0d0e0f));
    __m128i BAR = _mm_blend_epi16(FOO, FOO, 0xD);
    _mm_storeu_si128((__m128i*) state, BAR);
}
