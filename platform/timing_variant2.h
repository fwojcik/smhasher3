static FORCE_INLINE void cycle_timer_init() {
}

static FORCE_INLINE uint64_t cycle_timer_start() {
    uint32_t cycles_high, cycles_low;
    __asm__ volatile
        ("cpuid\n\t"
         "rdtsc" :
         "=d" (cycles_high), "=a" (cycles_low) ::
         "%ebx", "%ecx");
    return ((uint64_t)cycles_high << 32) | cycles_low;
}

static FORCE_INLINE uint64_t cycle_timer_end() {
    uint32_t cycles_high, cycles_low;
    __asm__ volatile
        ("rdtscp\n\t"
         "mov %%edx, %0\n\t"
         "mov %%eax, %1\n\t"
         "cpuid" :
         "=g" (cycles_high), "=g" (cycles_low) ::
         "%eax", "%ebx", "%ecx", "%edx");
    return ((uint64_t)cycles_high << 32) | cycles_low;
}
