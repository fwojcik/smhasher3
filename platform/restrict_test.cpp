#include <cstdio>

#include "curvariant.h"

unsigned state[32];

int foo(unsigned * RESTRICT a, unsigned * RESTRICT b) {
    int r = 0;
    for (int i = 1; i < 20; i++) {
        r += i * i * (*a++) * (*b);
    }
    return r;
}

int main(int argc, const char *argv[]) {
    unsigned x = argc;
    int sum = foo(state, &x);
    if (sum == 0) {
        printf("IS zero\n");
    } else {
        printf("NOT zero\n");
    }
}
