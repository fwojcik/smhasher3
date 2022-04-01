//----------
// These are _not_ hash functions (even though people tend to use crc32 as one...)

void aesrng_init(uint64_t seed);
void aesrng_seed(uint64_t seed, uint64_t hint = 0);
void aesrng32(const void *key, int len, uint32_t seed, void *out);
void aesrng64(const void *key, int len, uint32_t seed, void *out);
void aesrng128(const void *key, int len, uint32_t seed, void *out);
void aesrng160(const void *key, int len, uint32_t seed, void *out);
void aesrng224(const void *key, int len, uint32_t seed, void *out);
void aesrng256(const void *key, int len, uint32_t seed, void *out);
