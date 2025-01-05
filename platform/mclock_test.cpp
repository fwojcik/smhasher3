
#include <cstdio>

#include "curvariant.h"

// These are for the PRIu64 macro below
#define __STDC_FORMAT_MACROS 1 // Some older gcc installations need this
#include <cinttypes>

volatile unsigned state;

int main(void) {
    unsigned sum = 0;
    uint64_t start, end;

    state = 1;

    start = monotonic_clock();
    for (unsigned i = 1; i <= (1 << 24); i++) {
        sum += state * i;
    }
    end = monotonic_clock();

    uint64_t delta = end - start;
    printf("Sum:  %u\nTime taken (ns): %" PRIu64 "\n", sum, delta);
}
