#define _NO_CLZ4_ASSERT
static inline int _clz32(uint32_t x) {
    static const uint8_t debruijn[32] = {
        31, 22, 30, 21, 18, 10, 29,  2,
        20, 17, 15, 13,  9,  6, 28,  1,
        23, 19, 11,  3, 16, 14,  7, 24,
        12,  4,  8, 25,  5, 26, 27,  0,
    };
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return (int)debruijn[(uint32_t)(x * 0x07C4ACDD) >> 27];
}
#define clz4(x) _clz32(x)
