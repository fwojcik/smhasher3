#include "isa.h"

uint32_t rlo, rmi, rhi, a, b, addlo, addmi, addhi;

int main(void) {
    __asm__("ADDS %w0, %w3, %w0\n"
            "ADCS %w1, %w4, %w1\n"
            "ADC  %w2, %w5, %w2\n"
            : "+r" (rlo), "+r" (rmi), "+r" (rhi)
            : "r" (addlo), "r" (addmi), "r" (addhi)
            : "cc"
            );
}
