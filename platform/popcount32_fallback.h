#define _NO_POPCOUNT4_ASSERT
static inline int _popcount32(uint32_t x) {
    const uint32_t m = 0x33333333;
    x = x - ((x >> 1) & 0x55555555);
    x = (x & m) + ((x >> 2) & m);
    x = (x + (x >> 4)) & 0x0f0f0f0f;
    return (x * 0x01010101) >> 24;
}
#define popcount4(x) _popcount32(x)
