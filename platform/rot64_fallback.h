static inline uint64_t _rotl64(uint64_t v, uint8_t n) {
    return (v << n) | (v >> ((-n) & 63));
}
static inline uint64_t _rotr64(uint64_t v, uint8_t n) {
    return (v >> n) | (v << ((-n) & 63));
}
#define ROTL64(v, n) _rotl64(v, n)
#define ROTR64(v, n) _rotr64(v, n)
