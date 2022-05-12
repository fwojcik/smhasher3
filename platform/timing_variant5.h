// For now, this skips checking access permission

FORCE_INLINE uint64_t rdarmcnt() {
    uint64_t pmccntr;
    asm volatile("mrs %0, cntvct_el0" : "=r" (pmccntr));
    return (uint64_t)(pmccntr) * 64;
}

FORCE_INLINE uint64_t timer_start() {
    return rdarmcnt();
}

FORCE_INLINE uint64_t timer_end() {
    return rdarmcnt();
}
