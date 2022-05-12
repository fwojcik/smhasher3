#include <cstdio>
#include "isa.h"

uint32_t state[30];
int main(void) { 
    __m256i FOO  = _mm256_set1_epi32(0x04050607);
    __m256i vals = _mm256_loadu_si256((const __m256i *)state);
    _mm256_zeroupper();
    vals = _mm256_permute2f128_si256(FOO, vals, 0x3);
    _mm256_storeu_si256((__m256i*) state, vals);
}
