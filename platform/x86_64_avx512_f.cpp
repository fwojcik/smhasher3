#include <cstdio>
#include "isa.h"

uint32_t state[80];
int main(void) {
    __m512i FOO  = _mm512_set1_epi32(0x04050607);
    __m512i vals = _mm512_loadu_si512((const __m512i *)state);
    vals = _mm512_min_epi32(vals, FOO);
    vals = _mm512_add_epi32(vals, FOO);
    _mm512_storeu_si512((__m512i *)(state+8), vals);
}
