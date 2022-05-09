#define _NO_POPCOUNT8_ASSERT
static inline int _popcount64(uint64_t x) {
    const uint64_t m = UINT64_C(0x3333333333333333);
    x = x - ((x >> 1) & UINT64_C(0x5555555555555555));
    x = (x & m) + ((x >> 2) & m);
    x = (x + (x >> 4)) & UINT64_C(0x0f0f0f0f0f0f0f0f);
    return (x * UINT64_C(0x0101010101010101)) >> 56;
}
#define popcount8(x) _popcount64(x)
