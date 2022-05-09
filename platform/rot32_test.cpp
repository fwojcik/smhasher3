#include <cstdio>
#include <cassert>

#include "curvariant.h"

int main(void) {
    uint32_t val1 = 0x12345678;
    uint32_t val2 = ROTL32(val1, 12);
    uint32_t val3 = ROTR32(val2, 12);
    assert(val1 == val3);
}
