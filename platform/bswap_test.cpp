#include <cstdio>
#include <cassert>

#include "curvariant.h"

int main(void) {
    uint16_t val16 = 0x1234;
    assert(BSWAP16(val16) == 0x3412);
    assert(BSWAP16(BSWAP16(val16)) == 0x1234);

    uint32_t val32 = 0x12345678;
    assert(BSWAP32(val32) == 0x78563412);
    assert(BSWAP32(BSWAP32(val32)) == 0x12345678);

    uint64_t val64 = UINT64_C(0x123456789abcdef1);
    assert(BSWAP64(val64) == UINT64_C(0xf1debc9a78563412));
    assert(BSWAP64(BSWAP64(val64)) == UINT64_C(0x123456789abcdef1));
}
