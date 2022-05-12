// MSVC only
#include <cstdio>
#include <inttypes.h>

#include "isa.h"

int main(void) {
    uint64_t x = UINT64_C(0xfedcba98fedcba98);
    uint64_t y = UINT64_C(0xffeeddccbbaa9988);
    uint64_t high;
    uint64_t low = _umul128(x, y, &high);
    printf("0x%I64x 0x%I64x 0x%I64x 0x%I64x\n", x, y, low, high);
}
