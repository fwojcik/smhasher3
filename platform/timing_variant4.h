FORCE_INLINE uint64_t timer_start() {
    return __builtin_readcyclecounter();
}

FORCE_INLINE uint64_t timer_end() {
    return __builtin_readcyclecounter();
}
