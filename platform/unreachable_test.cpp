#include <cstdio>

#include "curvariant.h"

volatile int state;

int main(void) {
    if (state == 0) {
        printf("IS zero\n");
    } else if (state == 1) {
        printf("NOT zero\n");
    } else {
        unreachable();
    }
}
