static FORCE_INLINE void cycle_timer_init() {
}

static FORCE_INLINE uint64_t cycle_timer_start() {
    uint64_t cycles_high, cycles_low;
    __asm__ volatile
        ("cpuid\n\t"
         "rdtsc" :
         "=d" (cycles_high), "=a" (cycles_low) ::
         "%rbx", "%rcx");
    return (cycles_high << 32) | cycles_low;
}

static FORCE_INLINE uint64_t cycle_timer_end() {
    uint64_t cycles_high, cycles_low;
    __asm__ volatile
        ("rdtscp\n\t"
         "mov %%rdx, %0\n\t"
         "mov %%rax, %1\n\t"
         "cpuid" :
         "=g" (cycles_high), "=g" (cycles_low) ::
         "%rax", "%rbx", "%rcx", "%rdx");
    return (cycles_high << 32) | cycles_low;
}
