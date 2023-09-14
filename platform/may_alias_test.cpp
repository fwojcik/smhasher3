#include <cstdio>

#include "curvariant.h"

typedef uint16_t MAY_ALIAS uint16a_t;

int main(int argc, const char *argv[]) {
    uint32_t a = 0x12345678;
    uint16a_t * b = (uint16a_t *)&a;
    b[1] = 0;
    printf("%08x\n", a);
}
