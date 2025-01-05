FORCE_INLINE uint64_t cycle_timer_start() {
    return __builtin_readcyclecounter();
}

FORCE_INLINE uint64_t cycle_timer_end() {
    return __builtin_readcyclecounter();
}
