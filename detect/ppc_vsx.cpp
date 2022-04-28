#include <cstdint>

# undef vector
# undef pixel
# undef bool
#if defined(__s390x__)
#  include <s390intrin.h>
#else
#  include <altivec.h>
#endif

#if defined(__ibmxl__) || (defined(_AIX) && defined(__xlC__))
typedef  __vector unsigned char vec_t;
#else
typedef  __vector unsigned long long vec_t;
#endif

void FOO(const uint8_t * input1, const uint8_t * input2, uint8_t * output) {
    vec_t block = (vec_t)vec_vsx_ld(0, input1);
    block = vec_xor(block, (vec_t)vec_vsx_ld(0, input2));
    block = vec_add(block, (vec_t)vec_vsx_ld(0, input2));
    vec_vsx_st((__vector unsigned char)block, 0, output);
}

uint8_t buf1[16];
uint8_t buf2[16];
uint8_t buf3[16];

int main(void) {
    FOO(buf1, buf2, buf3);
}
