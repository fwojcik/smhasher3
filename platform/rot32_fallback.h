static inline uint32_t _rotl32(uint32_t v, uint8_t n) {
    return (v << n) | (v >> ((-n) & 31));
}
static inline uint32_t _rotr32(uint32_t v, uint8_t n) {
    return (v >> n) | (v << ((-n) & 31));
}
#define ROTL32(v, n) _rotl32(v, n)
#define ROTR32(v, n) _rotr32(v, n)
