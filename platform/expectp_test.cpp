#include <cstdio>

#include "curvariant.h"

volatile int state;

int main(void) {
    if (expectp(state == 0, 0.93)) {
        printf("IS zero\n");
    } else {
        printf("NOT zero\n");
    }
}
