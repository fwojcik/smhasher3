#include <cstdio>

#include "curvariant.h"

int main(void) {
#if defined(HAVE_INT128)
    constexpr int128_t s = ((int128_t)(1 << 16)) << 72;
    static_assert(s != 0, "s acted like a 128-bit integer");
    static_assert((s >> 88) == 1, "s acted like a 128-bit integer");
    constexpr uint128_t u = s;
    static_assert(u != 0, "u acted like a 128-bit integer");
    static_assert(s == u, "u acted like a 128-bit integer");
#endif
    printf("OK!\n");
}
