#include <cstdio>
#include <cassert>

#include "curvariant.h"

int main(int argc, const char *argv[]) {
    constexpr uint64_t i64 = 0x80;
#if defined(_NO_CLZ8_ASSERT)
    const int count = clz8(i64);
    printf("count %d\n", count);
#else
    static_assert(clz8(i64) == 24+32, "clz8() worked");
#endif
    printf("OK!\n");
}
