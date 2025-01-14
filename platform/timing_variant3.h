static FORCE_INLINE void cycle_timer_init() {
}

static FORCE_INLINE uint64_t cycle_timer_start() {
    return __builtin_ia32_rdtsc();
}

static FORCE_INLINE uint64_t cycle_timer_end() {
    return __builtin_ia32_rdtsc();
}
