#include <cstdio>
#if defined(_MSC_VER)
# include <immintrin.h>
# define WIN32_LEAN_AND_MEAN
# include <Windows.h>
typedef UINT32 uint32_t;
#else
# include <stdint.h>
# include <immintrin.h>
#endif
uint32_t crc0;
int main(void) {
    crc0 = _mm_crc32_u32(crc0, 0x02030405);
}
