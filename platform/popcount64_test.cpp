#include <cstdio>
#include <cassert>

#include "curvariant.h"

int main(int argc, const char *argv[]) {
    constexpr uint64_t i64 = UINT64_C(0xf0f00f0f12345678);
#if defined(_NO_POPCOUNT8_ASSERT)
    const int count = popcount8(i64);
    printf("count %d\n", count);
#else
    static_assert(popcount8(i64) == (1+1+2+1+2+2+3+1+4+4+4+4), "popcount8() worked");
#endif
    printf("OK!\n");
}
