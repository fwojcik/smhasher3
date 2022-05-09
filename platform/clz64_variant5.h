#define _NO_CLZ8_ASSERT
static inline int _clz64(uint64_t x) {
    uint32_t idx;
    _BitScanReverse64(&idx, x);
    return 63 ^ idx;
}
#define clz8(x) _clz64(x)
