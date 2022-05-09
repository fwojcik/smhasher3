#include <cstdio>

#include "curvariant.h"

volatile int state;

NEVER_INLINE int foo(int a) {
    int r = 0;
    for (int i = 1; i < a; i++) {
        r += i * i * state;
    }
    return r;
}

int main(int argc, const char *argv[]) {
    int sum = (argc > 3) ? foo(8) : foo(5);
    if (sum == 0) {
        printf("IS zero\n");
    } else {
        printf("NOT zero\n");
    }
}
