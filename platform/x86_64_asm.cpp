#include <cstdio>
#include "isa.h"

uint32_t multasm32(
             uint32_t var1, uint32_t var2, uint32_t var3,
             uint32_t var4, uint32_t var5, uint32_t var6) {
    __asm__("addl %3, %0\n"
            "adcl %4, %1\n"
            "adcl %5, %2\n"
            : "+r" (var1), "+r" (var2), "+r" (var3)
            : "g" (var4), "g" (var5), "g" (var6)
            : "cc"
            );
    __asm__("mull  %[b]\n"
            : "=d" (var1), "=a" (var2)
            : "1" (var3), [b] "rm" (var4)
            );
    return var1+var2+var3+var4+var5+var6;
}

uint64_t multasm64(
             uint64_t var1, uint64_t var2, uint64_t var3,
             uint64_t var4, uint64_t var5, uint64_t var6,
             uint64_t var7, uint64_t var8, uint64_t var9) {
    __asm__("addq %3, %0\n"
            "adcq %4, %1\n"
            "adcq %5, %2\n"
            : "+r" (var5), "+r" (var6), "+r" (var7)
            : "g" (var8), "g" (var9), "g" (var1)
            : "cc"
            );
    __asm__("mulq %[b]\n"
            : "=d" (var2), "=a" (var3)
            : "1" (var4), [b] "rm" (var5)
            );
    __asm__("addq %2, %0\n"
            "adcq $0, %1\n"
            : "+r" (var6), "+r" (var7)
            : "m" (var8)
            : "cc"
            );
#if defined(__AVX2__)
   __asm__("mulxq %3, %0, %1\n"
            : "=r" (var9), "=r" (var1)
            : "%d" (var2), "rm" (var3)
            );
#endif
    return var1+var2+var3+var4+var5+var6+var7+var8+var9;
}

int main(void) {
}
