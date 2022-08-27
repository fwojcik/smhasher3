#include <cstdio>
#include <cstdlib>

#include "curvariant.h"

#if defined(HAVE_GENERIC_VECTOR)
typedef int v4si VECTOR_SIZE(16);
#endif

int main(void) {
#if defined(HAVE_GENERIC_VECTOR)
    v4si a = {5,-6,7,-8};
    v4si b = {0,1,-2,-3};
    v4si x = {0,-6,-14,24};
    v4si c = a * b;
    v4si r = (c == x);
    for (int i = 0; i < 4; i++) {
        if (r[i] != -1) {
            printf("Vector math failed!\n");
            exit(1);
        }
    }
    printf("Vector math OK\n");
    exit(0);
#else
    printf("Vector math unsupported!\n");
    exit(0);
#endif
}
