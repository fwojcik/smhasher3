#include <cstdio>
#include <cstdlib>

#include "curvariant.h"

#if defined(HAVE_GENERIC_VECTOR)
typedef int v4si VECTOR_SIZE(16);
#endif

int main(void) {
#if defined(HAVE_GENERIC_VECTOR) && defined(HAVE_GENERIC_VECTOR_SHUFFLE)
    v4si a =  {5,-6,7,-8};
    v4si b =  {0,1,-2,-3};
    v4si m1 = {0,3,0,1};
    v4si m2 = {2,4,5,6};
    v4si x1 = {5,-8,5,-6};
    v4si x2 = {0,-3,0,1};
    v4si x3 = {7,0,1,-2};
    v4si r1 = VECTOR_SHUFFLE_1(a, m1);
    v4si r2 = VECTOR_SHUFFLE_1(b, m1);
    v4si r3 = VECTOR_SHUFFLE_2(a, b, m2);
    for (int i = 0; i < 4; i++) {
        if (r1[i] != x1[i]) {
            printf("Vector math failed!\n");
            exit(1);
        }
        if (r2[i] != x2[i]) {
            printf("Vector math failed!\n");
            exit(1);
        }
        if (r3[i] != x3[i]) {
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
