#if defined(_MSC_VER)
#  include <arm_neon.h>
#else
# include <stdint.h>
# include <arm_neon.h>
# if defined(HAVE_ARM_ACLE)
#  include <arm_acle.h>
# endif
#endif

int main(void) {
    uint32x4_t A, C;
    A = vsha256su0q_u32(A, C);
    C = vsha256hq_u32(A, C, A);
    A = vsha256h2q_u32(A, C, A);
    C = vsha256su1q_u32(A, C, A);
}
