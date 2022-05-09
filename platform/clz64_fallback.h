#define _NO_CLZ8_ASSERT
static inline int _clz64(uint64_t x) {
    static const uint8_t debruijn[64] = {
        63,  5, 62,  4, 16, 10, 61,  3,
        24, 15, 36,  9, 30, 21, 60,  2,
        12, 26, 23, 14, 45, 35, 43,  8,
        33, 29, 52, 20, 49, 41, 59,  1,
         6, 17, 11, 25, 37, 31, 22, 13,
        27, 46, 44, 34, 53, 50, 42,  7,
        18, 38, 32, 28, 47, 54, 51, 19,
        39, 48, 55, 40, 56, 57, 58,  0,
    };
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    return (int)debruijn[(uint64_t)(x * UINT64_C(0x03f6eaf2cd271461)) >> 58];
}
#define clz8(x) _clz64(x)
