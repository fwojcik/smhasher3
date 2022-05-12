#include <cstdio>

#include "curvariant.h"

volatile int state;

int main(void) {
    int sum = 0;
    uint64_t start, end;

    start = monotonic_clock();
    for (int i = 1; i <= (1 << 24); i++) {
        sum += state * i;
    }
    end = monotonic_clock();

    unsigned long delta = end - start;
    printf("Sum:  %d\nTime taken: %ld\n", sum, delta);
}
