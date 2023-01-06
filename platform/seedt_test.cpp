#include <cstdio>

#include "curvariant.h"

// seed_t must be large enough to be able to hold a 64-bit integer
// value OR an integer representation of a pointer.
//
// This could be done via std::conditional instead of via CMake
// generation-time detection, but this lets us avoid needing to
// include the type_traits header just for this one thing.

int main(int argc, const char *argv[]) {
    static_assert(sizeof(seed_t) >= sizeof(uint64_t), "seed_t can fit a 64-bit integer");
    static_assert(sizeof(seed_t) >= sizeof(uintptr_t), "seed_t can fit a pointer integer");
    printf("OK!\n");
}
