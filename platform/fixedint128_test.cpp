#include <cstdio>

#include "curvariant.h"

int main(void) {
#if defined(HAVE_INT128)
    constexpr int128_t s = ((int128_t)(1 << 16)) << 72;
    static_assert(s != 0, "nope");
    static_assert((s >> 88) == 1, "nope");
    constexpr uint128_t u = s;
    static_assert(u != 0, "nope");
    static_assert(s == u, "nope");
#endif
    printf("OK!\n");
}
