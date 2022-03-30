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
//----------
// General purpose hashes

static inline uint8_t fletcher_bad_seeds(std::vector<uint64_t> &seeds)
{
  seeds = std::vector<uint64_t> { UINT64_C(0) };
  return true;
}
uint64_t fletcher2(const char *key, int len, uint64_t seed);
inline void fletcher2_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint64_t *) out = fletcher2((const char *)key, len, (uint64_t)seed);
}
uint64_t fletcher4(const char *key, int len, uint64_t seed);
inline void fletcher4_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint64_t *) out = fletcher4((const char *)key, len, (uint64_t)seed);
}
uint32_t Bernstein(const char *key, int len, uint32_t seed);
static inline uint8_t Bernstein_bad_seeds(std::vector<uint32_t> &seeds)
{
  seeds = std::vector<uint32_t> { UINT32_C(0) };
  return true;
}
inline void Bernstein_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint32_t *) out = Bernstein((const char *)key, len, seed);
}
uint32_t sdbm(const char *key, int len, uint32_t hash);
static inline uint8_t sdbm_bad_seeds(std::vector<uint32_t> &seeds)
{
  seeds = std::vector<uint32_t> { UINT32_C(0) };
  return true;
}
inline void sdbm_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint32_t *) out = sdbm((const char *)key, len, seed);
}
uint32_t x17(const char *key, int len, uint32_t h);
inline void x17_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint32_t *) out = x17((const char *)key, len, seed);
}
uint32_t JenkinsOOAT(const char *key, int len, uint32_t hash);
inline void JenkinsOOAT_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint32_t *) out = JenkinsOOAT((const char *)key, len, seed);
}
uint32_t JenkinsOOAT_perl(const char *key, int len, uint32_t hash);
inline void JenkinsOOAT_perl_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint32_t *) out = JenkinsOOAT_perl((const char *)key, len, seed);
}
uint32_t GoodOAAT(const char *key, int len, uint32_t hash);
inline void GoodOAAT_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint32_t *) out = GoodOAAT((const char *)key, len, seed);
}
uint32_t MicroOAAT(const char *key, int len, uint32_t hash);
inline void MicroOAAT_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint32_t *) out = MicroOAAT((const char *)key, len, seed);
}
uint32_t lookup3(const char *key, int len, uint32_t hash);
inline void lookup3_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint32_t *) out = lookup3((const char *)key, len, seed);
}
uint32_t MurmurOAAT(const char *key, int len, uint32_t hash);
inline void MurmurOAAT_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint32_t *) out = MurmurOAAT((const char *)key, len, seed);
}
uint32_t Crap8(const uint8_t * key, uint32_t len, uint32_t seed);
inline void Crap8_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint32_t *) out = Crap8((const uint8_t *)key, len, seed);
}

//----------
// Used internally as C++
uint32_t MurmurOAAT ( const char * key, int len, uint32_t seed );
