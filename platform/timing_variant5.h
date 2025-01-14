// For ARM systems, there is seemingly no way to generically get actual CPU
// cycle counts as a regular user. There are OS-specific ways. There are
// HW-specific ways. There are ways that require some sort of elevated
// access (root privs or wheel group membership). But nothing reliably
// usable by SMHasher3.This also seems true of PPC and some other platforms.
//
// To emulate such a measuring tool, this will estimate the number of
// cycles (instructions, basically) per nanosecond, and then measure
// nanoseconds and convert to cycles.
//
// See https://gitlab.com/fwojcik/smhasher3/-/issues/87 for more. This
// approach is by James Price and was taken from:
// https://uob-hpc.github.io/2017/11/22/arm-clock-freq.html,
// except that no opcode is used in the asm statement; it is only used to
// prevent the compiler from optimizing the additions away. This approach
// should work on any platform, assuming the compiler accepts gcc-style asm
// statements.

extern double cycle_timer_mult;

static NEVER_INLINE void cycle_timer_init() {
    const uint64_t NUM_INSTR = UINT64_C(1000000000);
    uint64_t start, end, count = 0;

    start = monotonic_clock();

    while (count < NUM_INSTR) {
#define INST0 asm volatile ("":[i] "+r" (count)::"cc"); count++;
#define INST1 INST0 INST0 INST0 INST0   INST0 INST0 INST0 INST0 \
              INST0 INST0 INST0 INST0   INST0 INST0 INST0 INST0
#define INST2 INST1 INST1 INST1 INST1   INST1 INST1 INST1 INST1 \
              INST1 INST1 INST1 INST1   INST1 INST1 INST1 INST1
#define INST3 INST2 INST2 INST2 INST2   INST2 INST2 INST2 INST2 \
              INST2 INST2 INST2 INST2   INST2 INST2 INST2 INST2

        INST3;
    }

    end = monotonic_clock();

    // Units are cycles / nanosecond
    cycle_timer_mult = (double)count / (double)(end - start);
#if 0
    printf("Instructions executed = %ld\n", count);
    printf("Runtime (ns)          = %ld\n", end - start);
    printf("Estimated frequency   = %.2lf GHz\n", cycle_timer_mult);
#endif
}

static FORCE_INLINE uint64_t cycle_timer_start() {
    return monotonic_clock() * cycle_timer_mult;
}

static FORCE_INLINE uint64_t cycle_timer_end() {
    return monotonic_clock() * cycle_timer_mult;
}
