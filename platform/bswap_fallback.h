static inline uint16_t _bswap16(uint16_t v) {
    return ((v & (uint16_t)0xFF00) >> 8) |
           ((v & (uint16_t)0x00FF) << 8) ;
}
static inline uint32_t _bswap32(uint32_t v) {
    return ((v & (uint32_t)0xFF000000) >> 24) |
           ((v & (uint32_t)0x00FF0000) >>  8) |
           ((v & (uint32_t)0x0000FF00) <<  8) |
           ((v & (uint32_t)0x000000FF) << 24) ;
}
static inline uint64_t _bswap64(uint64_t v) {
    return ((v & UINT64_C(0xFF00000000000000)) >> 56) |
           ((v & UINT64_C(0x00FF000000000000)) >> 40) |
           ((v & UINT64_C(0x0000FF0000000000)) >> 24) |
           ((v & UINT64_C(0x000000FF00000000)) >>  8) |
           ((v & UINT64_C(0x00000000FF000000)) <<  8) |
           ((v & UINT64_C(0x0000000000FF0000)) << 24) |
           ((v & UINT64_C(0x000000000000FF00)) << 40) |
           ((v & UINT64_C(0x00000000000000FF)) << 56) ;
}
#define BSWAP16(x) _bswap16(x)
#define BSWAP32(x) _bswap32(x)
#define BSWAP64(x) _bswap64(x)
