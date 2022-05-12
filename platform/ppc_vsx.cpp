#define HAVE_PPC_VSX
#include "isa.h"

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
