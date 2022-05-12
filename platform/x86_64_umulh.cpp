// MSVC only
#include <cstdio>
#include <inttypes.h>

#include "isa.h"

int main(void) {
    uint64_t x = UINT64_C(0xfedcba98fedcba98);
    uint64_t y = UINT64_C(0xffeeddccbbaa9988);
    uint64_t low = x * y;
    uint64_t high = __umulh(x, y);
    printf("0x%I64x 0x%I64x 0x%I64x 0x%I64x\n", x, y, low, high);
}
