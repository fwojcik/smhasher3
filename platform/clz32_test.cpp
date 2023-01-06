#include <cstdio>
#include <cassert>

#include "curvariant.h"

int main(int argc, const char *argv[]) {
    constexpr uint32_t i32 = 0x80;
#if defined(_NO_CLZ4_ASSERT)
    const int count = clz4(i32);
    printf("count %d\n", count);
#else
    static_assert(clz4(i32) == 24, "clz4() worked");
#endif
    printf("OK!\n");
}
