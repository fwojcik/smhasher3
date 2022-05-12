FORCE_INLINE uint64_t timer_start() {
    return monotonic_clock();
}

FORCE_INLINE uint64_t timer_end() {
    return monotonic_clock();
}
