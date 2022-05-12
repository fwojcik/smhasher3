FORCE_INLINE uint64_t timer_start() {
    uint32_t cycles_high, cycles_low;
    __asm__ volatile
        ("cpuid\n\t"
         "rdtsc\n\t"
         "mov %%edx, %0\n\t"
         "mov %%eax, %1\n\t" :
         "=r" (cycles_high), "=r" (cycles_low) ::
         "%eax", "%ebx", "%ecx", "%edx");
    return ((uint64_t)cycles_high << 32) | cycles_low;
}

FORCE_INLINE uint64_t timer_end() {
    uint32_t cycles_high, cycles_low;
    __asm__ volatile
        ("rdtscp\n\t"
         "mov %%edx, %0\n\t"
         "mov %%eax, %1\n\t"
         "cpuid\n\t" :
         "=r" (cycles_high), "=r" (cycles_low) ::
         "%eax", "%ebx", "%ecx", "%edx");
    return ((uint64_t)cycles_high << 32) | cycles_low;
}
