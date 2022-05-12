#include <cstdio>
#include "isa.h"

uint32_t state[5];
int main(void) {
    __m128i MASK = _mm_set_epi64x(UINT64_C(0x0001020304050607), UINT64_C(0x08090a0b0c0d0e0f));
    __m128i A = MASK;
    __m128i B = _mm_sha256rnds2_epu32(A, MASK, MASK);
    _mm_storeu_si128((__m128i*) state, B);
}
