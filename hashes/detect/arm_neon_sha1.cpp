#if defined(_MSC_VER)
#  include <arm_neon.h>
#else
# include <stdint.h>
# include <arm_neon.h>
# if defined(NEW_HAVE_ARM_ACLE)
#  include <arm_acle.h>
# endif
#endif

int main(void) {
    uint32x4_t A, C;
    uint32_t B;
    A = vsha1cq_u32(A, B, C);
}
