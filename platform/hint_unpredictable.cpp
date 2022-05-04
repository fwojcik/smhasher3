#include <cstdio>
#if defined(_MSC_VER)
# define WIN32_LEAN_AND_MEAN
# include <Windows.h>
typedef UINT32 uint32_t;
typedef UINT8 uint8_t;
#else
# include <stdint.h>
#endif

volatile uint32_t state;

int main(void) {
    if (__builtin_unpredictable(state == 0)) {
        printf("IS zero\n");
    } else {
        printf("NOT zero\n");
    }
}
