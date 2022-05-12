FORCE_INLINE uint64_t timer_start() {
    uint64_t cycles_high, cycles_low;
    __asm__ volatile
        ("cpuid\n\t"
         "rdtsc\n\t"
         "mov %%rdx, %0\n\t"
         "mov %%rax, %1\n\t" :
         "=r" (cycles_high), "=r" (cycles_low) ::
         "%rax", "%rbx", "%rcx", "%rdx");
    return (cycles_high << 32) | cycles_low;
}

FORCE_INLINE uint64_t timer_end() {
    uint64_t cycles_high, cycles_low;
    __asm__ volatile
        ("rdtscp\n\t"
         "mov %%rdx, %0\n\t"
         "mov %%rax, %1\n\t"
         "cpuid\n\t" :
         "=r" (cycles_high), "=r" (cycles_low) ::
         "%rax", "%rbx", "%rcx", "%rdx");
    return (cycles_high << 32) | cycles_low;
}
