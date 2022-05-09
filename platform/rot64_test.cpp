#include <cstdio>
#include <cassert>

#include "curvariant.h"

int main(void) {
    uint64_t val1 = UINT64_C(0x1234567812345678);
    uint64_t val2 = ROTL64(val1, 53);
    uint64_t val3 = ROTR64(val2, 53);
    assert(val1 == val3);
}
