#include "isa.h"

uint32_t r, a, b;
uint64_t rhi, rlo, addhi, addlo;

int main(void) {
    rlo = a * b;
    __asm__("mulhdu %0, %1, %2\n"
            : "=r" (r)
            : "r" (a), "r" (b)
            );

    __asm__("addc %1, %1, %3\n"
            "adde %0, %0, %2\n"
            : "+r" (rhi), "+r" (rlo)
            : "r" (addhi), "r" (addlo)
            );

}
