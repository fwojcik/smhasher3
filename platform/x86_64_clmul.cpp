#include <cstdio>
#include "isa.h"

uint32_t state[5];
int main(void) {
    __m128i FOO = _mm_set_epi64x(UINT64_C(0x0001020304050607), UINT64_C(0x08090a0b0c0d0e0f));
    FOO = _mm_clmulepi64_si128(FOO, FOO, 0x10);
    _mm_storeu_si128((__m128i*) state, FOO);
}
