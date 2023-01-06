#include <cstdio>
#include <cassert>

#include "curvariant.h"

int main(int argc, const char *argv[]) {
    constexpr uint32_t i32 = 0x12345678;
#if defined(_NO_POPCOUNT4_ASSERT)
    const int count = popcount4(i32);
    printf("count %d\n", count);
#else
    static_assert(popcount4(i32) == (1+1+2+1+2+2+3+1), "popcount4() worked");
#endif
    printf("OK!\n");
}
