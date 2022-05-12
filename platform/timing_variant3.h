FORCE_INLINE uint64_t timer_start() {
    return __builtin_ia32_rdtsc();
}

FORCE_INLINE uint64_t timer_end() {
    return __builtin_ia32_rdtsc();
}
