#include <cstdio>
#if defined(_MSC_VER)
# include <math.h>   // Has to be included before intrin.h or VC complains about 'ceil'
# include <intrin.h>
# include <immintrin.h>
# define WIN32_LEAN_AND_MEAN
# include <Windows.h>
typedef UINT64 uint64_t;
#else
# include <stdint.h>
# include <immintrin.h>
#endif
int main(void) {
}
