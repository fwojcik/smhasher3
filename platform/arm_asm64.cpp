#include "isa.h"

uint64_t rhi, a, b;

int main(void) {
    __asm__("umulh %0, %1, %2\n"
            : "=r" (rhi)
            : "r" (a), "r" (b)
            );
}
