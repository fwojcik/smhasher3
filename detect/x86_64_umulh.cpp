// MSVC only
#include <cstdio>
#include <cstdint>
#include <immintrin.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
typedef UINT64 uint64_t;

int main(void) {
    uint64_t x = UINT64_C(0xfedcba98fedcba98);
    uint64_t y = UINT64_C(0xffeeddccbbaa9988);
    uint64_t low = x * y;
    uint64_t high = __umulh(x, y);
    printf("0x%I64x 0x%I64x 0x%I64x 0x%I64x\n", x, y, low, high);
}
