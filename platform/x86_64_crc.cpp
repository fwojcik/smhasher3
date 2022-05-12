#include <cstdio>
#include "isa.h"

uint32_t crc0;
int main(void) {
    crc0 = _mm_crc32_u32(crc0, 0x02030405);
}
