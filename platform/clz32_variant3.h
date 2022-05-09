#define _NO_CLZ4_ASSERT
static inline int _clz32(uint32_t x) {
    uint32_t idx;
    _BitScanReverse(&idx, x);
    return 31 ^ idx;
}
#define clz4(x) _clz32(x)
