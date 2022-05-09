#include <cstdio>

#include "curvariant.h"

volatile int state;

int main(void) {
    if (likely(state == 0)) {
        printf("IS zero\n");
    } else {
        printf("NOT zero\n");
    }
}
