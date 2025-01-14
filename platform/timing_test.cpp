#include <cstdio>

#include "curvariant.h"

volatile int state;

int main(void) {
    int sum = 0;
    uint64_t start, end;

    cycle_timer_init();

    start = cycle_timer_start();
    for (int i = 1; i <= (1 << 24); i++) {
        sum += state * i;
    }
    end = cycle_timer_end();

    unsigned long avg = (end - start) >> 24;
    printf("Cycles taken: %ld\n", avg);
}
