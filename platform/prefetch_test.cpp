#include <cstdio>

#include "curvariant.h"

const unsigned char * ptr;

int main(void) {
    unsigned long sum = 0;
    for (int i = 0; i < 1024; i++) {
        prefetch(&ptr[i + 8]);
        sum += ptr[i];
    }
    printf("Sum is %ld\n", sum);
}
