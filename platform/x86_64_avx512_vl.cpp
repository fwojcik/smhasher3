#include <cstdio>
#include "isa.h"

uint32_t state[80];
int main(void) {
    __m128i foo = _mm_set1_epi32(0x04050607);
    foo = _mm_ror_epi32(foo, 13);
    _mm_store_si128((__m128i *)(state+8), foo);
}
