static FORCE_INLINE void cycle_timer_init() {
}

static FORCE_INLINE uint64_t cycle_timer_start() {
    return monotonic_clock();
}

static FORCE_INLINE uint64_t cycle_timer_end() {
    return monotonic_clock();
}
