FORCE_INLINE uint64_t cycle_timer_start() {
    return monotonic_clock();
}

FORCE_INLINE uint64_t cycle_timer_end() {
    return monotonic_clock();
}
