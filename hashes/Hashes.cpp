#define _HASHES_CPP
#include "Platform.h"
#include "Types.h"
#include "Random.h"
#include "VCode.h"

#include "Hashes.h"

#include <cassert>
//#include <emmintrin.h>
//#include <xmmintrin.h>

// ----------------------------------------------------------------------------
// for internal use
#define VCODE_COUNT 3
static XXH32_state_t vcode_states[VCODE_COUNT];

void VCODE_HASH(const void * input, size_t len, unsigned idx) {
    if (idx >= VCODE_COUNT)
        return;
    XXH32_update(&vcode_states[idx], input, len);
}

static uint32_t VCODE_MASK = 0x0;

void VCODE_INIT(void) {
    for (int i = 0; i < VCODE_COUNT; i++) {
        XXH32_reset(&vcode_states[i], i);
    }
    // This sets VCODE_MASK such that VCODE_FINALIZE() will report a
    // vcode of 0x00000001 if no testing was done.
    VCODE_MASK = VCODE_FINALIZE() ^ 0x1;
}

extern uint32_t g_inputVCode;
extern uint32_t g_outputVCode;
extern uint32_t g_resultVCode;
uint32_t VCODE_FINALIZE(void) {
    if (!g_doVCode) return 1;

    g_inputVCode = XXH32_digest(&vcode_states[0]);
    g_outputVCode = XXH32_digest(&vcode_states[1]);
    g_resultVCode = XXH32_digest(&vcode_states[2]);

    XXH32_state_t finalvcode;
    XXH32_reset(&finalvcode, VCODE_COUNT);

    XXH32_update(&finalvcode, &g_inputVCode,  sizeof(g_inputVCode));
    XXH32_update(&finalvcode, &g_outputVCode, sizeof(g_outputVCode));
    XXH32_update(&finalvcode, &g_resultVCode, sizeof(g_resultVCode));

    return VCODE_MASK ^ XXH32_digest(&finalvcode);
}

// ----------------------------------------------------------------------------
//fake / bad hashes

//-----------------------------------------------------------------------------
//One - byte - at - a - time hash based on Murmur 's mix

// objsize: 0x540-0x56f: 47
uint32_t MurmurOAAT(const char *key, int len, uint32_t hash)
{
  const uint8_t *data = (const uint8_t *)key;
  const uint8_t *const end = &data[len];

  while (data < end) {
    hash ^= *data++;
    hash *= 0x5bd1e995;
    hash ^= hash >> 15;
  }

  return hash;
}

//-----------------------------------------------------------------------------

// objsize: 0x1090-0x10df: 79
uint32_t
x17(const char *key, int len, uint32_t h)
{
  uint8_t *data = (uint8_t *)key;
  const uint8_t *const end = &data[len];

  while (data < end) {
    h = 17 * h + (*data++ - ' ');
  }
  return h ^ (h >> 16);
}

//64bit, ZFS
//note the original fletcher2 assumes 128bit aligned data, and
//can hereby advance the inner loop by 2 64bit words.
//both fletcher's return 4 words, 256 bit. Both are nevertheless very weak hashes.
// objsize: 0x1120-0x1218: 248
uint64_t
fletcher2(const char *key, int len, uint64_t seed)
{
  uint64_t *dataw = (uint64_t *)key;
  const uint64_t *const endw = &((const uint64_t*)key)[len/8];
  uint64_t A = seed, B = 0;
  for (; dataw < endw; dataw++) {
    A += *dataw;
    B += A;
  }
  if (len & 7) {
    uint8_t *datac = (uint8_t*)dataw; //byte stepper
    const uint8_t *const endc = &((const uint8_t*)key)[len];
    for (; datac < endc; datac++) {
      A += *datac;
      B += A;
    }
  }
  return B;
}

//64bit, ZFS
// objsize: 0x1220-0x1393: 371
uint64_t
fletcher4(const char *key, int len, uint64_t seed)
{
  uint32_t *dataw = (uint32_t *)key;
  const uint32_t *const endw = &((const uint32_t*)key)[len/4];
  uint64_t A = seed, B = 0, C = 0, D = 0;
  while (dataw < endw) {
    A += *dataw++;
    B += A;
    C += B;
    D += C;
  }
  if (len & 3) {
    uint8_t *datac = (uint8_t*)dataw; //byte stepper
    const uint8_t *const endc = &((const uint8_t*)key)[len];
    while (datac < endc) {
      A += *datac++;
      B += A;
      C += B;
      D += C;
    }
  }
  return D;
}

//-----------------------------------------------------------------------------

//also used in perl5 as djb2
// objsize: 0x13a0-0x13c9: 41
uint32_t
Bernstein(const char *key, int len, uint32_t seed)
{
  const uint8_t  *data = (const uint8_t *)key;
  const uint8_t *const end = &data[len];
  while (data < end) {
    //seed = ((seed << 5) + seed) + *data++;
    seed = 33 * seed + *data++;
  }
  return seed;
}

//as used in perl5
// objsize: 0x13a0-0x13c9: 41
uint32_t
sdbm(const char *key, int len, uint32_t hash)
{
  unsigned char  *str = (unsigned char *)key;
  const unsigned char *const end = (const unsigned char *)str + len;
  //note that perl5 adds the seed to the end of key, which looks like cargo cult
  while (str < end) {
    hash = (hash << 6) + (hash << 16) - hash + *str++;
  }
  return hash;
}

//as used in perl5 as one_at_a_time_hard
// objsize: 0x1400-0x1499: 153
uint32_t
JenkinsOOAT(const char *key, int len, uint32_t hash)
{
  unsigned char  *str = (unsigned char *)key;
  const unsigned char *const end = (const unsigned char *)str + len;
  uint64_t	  s = (uint64_t) hash;
  unsigned char  *seed = (unsigned char *)&s;
  //unsigned char seed[8];
  //note that perl5 adds the seed to the end of key, which looks like cargo cult
  while (str < end) {
    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += *str++;
  }

  hash += (hash << 10);
  hash ^= (hash >> 6);
  hash += seed[4];

  hash += (hash << 10);
  hash ^= (hash >> 6);
  hash += seed[5];

  hash += (hash << 10);
  hash ^= (hash >> 6);
  hash += seed[6];

  hash += (hash << 10);
  hash ^= (hash >> 6);
  hash += seed[7];

  hash += (hash << 10);
  hash ^= (hash >> 6);

  hash += (hash << 3);
  hash ^= (hash >> 11);
  hash = hash + (hash << 15);

  return hash;
}

//as used in perl5 until 5.17(one_at_a_time_old)
// objsize: 0x14a0-0x14e1: 65
uint32_t JenkinsOOAT_perl(const char *key, int len, uint32_t hash)
{
  unsigned char  *str = (unsigned char *)key;
  const unsigned char *const end = (const unsigned char *)str + len;
  while (str < end) {
    hash += *str++;
    hash += (hash << 10);
    hash ^= (hash >> 6);
  }
  hash += (hash << 3);
  hash ^= (hash >> 11);
  hash = hash + (hash << 15);
  return hash;
}

//------------------------------------------------
// One of a smallest non-multiplicative One-At-a-Time function
// that passes whole SMHasher.
// Author: Sokolov Yura aka funny-falcon <funny.falcon@gmail.com>
// objsize: 0x14f0-0x15dd: 237
uint32_t
GoodOAAT(const char *key, int len, uint32_t seed) {
#define grol(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define gror(x,n) (((x)>>(n))|((x)<<(32-(n))))
  unsigned char  *str = (unsigned char *)key;
  const unsigned char *const end = (const unsigned char *)str + len;
  uint32_t h1 = seed ^ 0x3b00;
  uint32_t h2 = grol(seed, 15);
  for (;str != end; str++) {
    h1 += str[0];
    h1 += h1 << 3; // h1 *= 9
    h2 += h1;
    // the rest could be as in MicroOAAT: h1 = grol(h1, 7)
    // but clang doesn't generate ROTL instruction then.
    h2 = grol(h2, 7);
    h2 += h2 << 2; // h2 *= 5
  }
  h1 ^= h2;
  /* now h1 passes all collision checks,
   * so it is suitable for hash-tables with prime numbers. */
  h1 += grol(h2, 14);
  h2 ^= h1; h2 += gror(h1, 6);
  h1 ^= h2; h1 += grol(h2, 5);
  h2 ^= h1; h2 += gror(h1, 8);
  return h2;
#undef grol
#undef gror
}

// MicroOAAT suitable for hash-tables using prime numbers.
// It passes all collision checks.
// Author: Sokolov Yura aka funny-falcon <funny.falcon@gmail.com>
// objsize: 0x15e0-0x1624: 68
uint32_t
MicroOAAT(const char *key, int len, uint32_t seed) {
#define grol(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define gror(x,n) (((x)>>(n))|((x)<<(32-(n))))
  unsigned char  *str = (unsigned char *)key;
  const unsigned char *const end = (const unsigned char *)str + len;
  uint32_t h1 = seed ^ 0x3b00;
  uint32_t h2 = grol(seed, 15);
  while (str < end) {
    h1 += *str++;
    h1 += h1 << 3; // h1 *= 9
    h2 -= h1;
    // unfortunately, clang produces bad code here,
    // cause it doesn't generate rotl instruction.
    h1 = grol(h1, 7);
  }
  return h1 ^ h2;
#undef grol
#undef gror
}

//-----------------------------------------------------------------------------
//Crap8 hash from http://www.team5150.com / ~andrew / noncryptohashzoo / Crap8.html

// objsize: 0x1630-0x1786: 342
uint32_t
Crap8(const uint8_t * key, uint32_t len, uint32_t seed)
{
#define c8fold( a, b, y, z ) { p = (uint32_t)(a) * (uint64_t)(b); y ^= (uint32_t)p; z ^= (uint32_t)(p >> 32); }
#define c8mix( in ) { h *= m; c8fold( in, m, k, h ); }

  const uint32_t  m = 0x83d2e73b, n = 0x97e1cc59, *key4 = (const uint32_t *)key;
  uint32_t	  h = len + seed, k = n + len;
  uint64_t	  p;

  while (len >= 8) {
    c8mix(key4[0]) c8mix(key4[1]) key4 += 2;
    len -= 8;
  }
  if (len >= 4) {
    c8mix(key4[0]) key4 += 1;
    len -= 4;
  }
  if (len) {
    c8mix(key4[0] & ((1 << (len * 8)) - 1))
  }
  c8fold(h ^ k, n, k, k)
  return k;
}

extern "C" {
#ifdef HAVE_SSE2
  void		  hasshe2 (const void *input, int len, uint32_t seed, void *out);
#endif
}

#if defined(HAVE_SSE2)
void
hasshe2_test(const void *input, int len, uint32_t seed, void *out)
{
  if (!len) {
    *(uint32_t *) out = 0;
    return;
  }
  if (len % 16) {
    //add pad NUL
    len += 16 - (len % 16);
  }
  // objsize: 0-1bd: 445
  hasshe2(input, len, seed, out);
}
#endif

#if 0 && defined(__x86_64__) && (defined(__linux__) || defined(__APPLE__))
/* asm */
extern "C" {
  int fhtw_hash(const void* key, int key_len);
}
void
fhtw_test(const void *input, int len, uint32_t seed, void *out)
{
  *(uint32_t *) out = fhtw_hash(input, len);
}
#endif

/* https://github.com/floodyberry/siphash */
void
siphash_test(const void *input, int len, uint32_t seed, void *out)
{
  /* 128bit state, filled with a 32bit seed */
  unsigned char	key[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  if (!len) {
    *(uint32_t *) out = 0;
    return;
  }
  memcpy(key, &seed, sizeof(seed));
  // objsize: 0-0x42f: 1071
  *(uint64_t *) out = siphash(key, (const unsigned char *)input, (size_t) len);
}
void
siphash13_test(const void *input, int len, uint32_t seed, void *out)
{
  unsigned char	key[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  if (!len) {
    *(uint32_t *) out = 0;
    return;
  }
  memcpy(key, &seed, sizeof(seed));
  // objsize: 0x450-0x75a: 778
  *(uint64_t *) out = siphash13(key, (const unsigned char *)input, (size_t) len);
}
void
halfsiphash_test(const void *input, int len, uint32_t seed, void *out)
{
  unsigned char	key[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  if (!len) {
    *(uint32_t *) out = 0;
    return;
  }
  memcpy(key, &seed, sizeof(seed));
  // objsize: 0x780-0xa3c: 700
  *(uint32_t *) out = halfsiphash(key, (const unsigned char *)input, (size_t) len);
}

/* https://github.com/gamozolabs/falkhash */
#if defined(__SSE4_2__) && defined(__x86_64__)
extern "C" {
  uint64_t falkhash_test(uint8_t *data, uint64_t len, uint32_t seed, void *out);
}
void
falkhash_test_cxx(const void *input, int len, uint32_t seed, void *out)
{
  uint64_t hash[2] = {0ULL, 0ULL};
  if (!len) {
    *(uint32_t *) out = 0;
    return;
  }
  // objsize: 0-0x108: 264
  falkhash_test((uint8_t *)input, (uint64_t)len, seed, hash);
  *(uint64_t *) out = hash[0];
}
#endif

#if defined(HAVE_SSE42) && defined(__x86_64__)

#include "clhash.h"
static char clhash_random[RANDOM_BYTES_NEEDED_FOR_CLHASH];
void clhash_test (const void * key, int len, uint32_t seed, void * out) {
  memcpy(clhash_random, &seed, 4);
  // objsize: 0-0x711: 1809  
  *(uint64_t*)out = clhash(&clhash_random, (char*)key, (size_t)len);
}
void clhash_init()
{
  void* data = get_random_key_for_clhash(UINT64_C(0xb3816f6a2c68e530), 711);
  memcpy(clhash_random, data, RANDOM_BYTES_NEEDED_FOR_CLHASH);
}
bool clhash_bad_seeds(std::vector<uint64_t> &seeds)
{
  seeds = std::vector<uint64_t> { UINT64_C(0) };
  return true;
}
void clhash_seed_init(size_t &seed)
{
  // reject bad seeds
  const std::vector<uint64_t> bad_seeds = { UINT64_C(0) };
  while (std::find(bad_seeds.begin(), bad_seeds.end(), (uint64_t)seed) != bad_seeds.end())
    seed++;
  memcpy(clhash_random, &seed, sizeof(seed));
}

#endif

#include "halftime-hash.hpp"

alignas(64) static uint64_t
    halftime_hash_random[8 * ((halftime_hash::kEntropyBytesNeeded / 64) + 1)];

void halftime_hash_style64_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint64_t *)out =
      halftime_hash::HalftimeHashStyle64(halftime_hash_random, (char *)key, (size_t)len);
}

void halftime_hash_style128_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint64_t *)out =
      halftime_hash::HalftimeHashStyle128(halftime_hash_random, (char *)key, (size_t)len);
}

void halftime_hash_style256_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint64_t *)out =
      halftime_hash::HalftimeHashStyle256(halftime_hash_random, (char *)key, (size_t)len);
}

void halftime_hash_style512_test(const void *key, int len, uint32_t seed, void *out) {
  *(uint64_t *)out =
      halftime_hash::HalftimeHashStyle512(halftime_hash_random, (char *)key, (size_t)len);
}

void halftime_hash_init() {
  size_t seed =
#ifdef HAVE_BIT32
    0xcc70c4c1ULL;
#else
    0xcc70c4c1798e4a6fUL; // 64bit only
#endif
  halftime_hash_seed_init(seed);
}

// romu random number generator for seeding the HalftimeHash entropy

// TODO: align and increase size of outut random array

#if defined(__AVX512F__)

#include <immintrin.h>

void romuQuad32simd(const __m512i seeds[4], uint64_t *output, size_t count) {
  __m512i wState = seeds[0], xState = seeds[1], yState = seeds[2],
       zState = seeds[3];
  const auto m = _mm512_set1_epi32(3323815723u);
  for (size_t i = 0; i < count; i += 8) {
    __m512i wp = wState, xp = xState, yp = yState, zp = zState;
    wState = _mm512_mullo_epi32(m, zp);
    xState = _mm512_add_epi32(zp, _mm512_rol_epi32(wp, 26));
    yState = _mm512_sub_epi32(yp, xp);
    zState = _mm512_add_epi32(yp, wp);
    zState = _mm512_rol_epi32(zState, 9);
    _mm512_store_epi64(&output[i], xp);
  }
}

void halftime_hash_seed_init(size_t &seed) {
  __m512i seeds[4] = {
      {
          (long long)seed ^ (long long)0x9a9b4c4e44dd48d1,
          (long long)seed ^ (long long)0xf8b0cd76a61945b1,
          (long long)seed ^ (long long)0x86268b0ae8494ce2,
          (long long)seed ^ (long long)0x7d31e5469df4484d,
          (long long)seed ^ (long long)0x62cb7b3e5e334aab,
          (long long)seed ^ (long long)0xc4c4065529834f39,
          (long long)seed ^ (long long)0xcc7972121c52411f,
          (long long)seed ^ (long long)0x7e08efb9ea5a434f,
      },
      {
          (long long)seed ^ (long long)0xccbc1ec6f244430c,
          (long long)seed ^ (long long)0xecf76d38f32b4296,
          (long long)seed ^ (long long)0xdf061d7c86664fa2,
          (long long)seed ^ (long long)0x08e0da9580d44252,
          (long long)seed ^ (long long)0xd074f3685aeb4f71,
          (long long)seed ^ (long long)0x3f83eb99126d4a74,
          (long long)seed ^ (long long)0xb5d24f61b4f540fa,
          (long long)seed ^ (long long)0x33f248aa4b3c4aaf,
      },
      {
          (long long)seed ^ (long long)0xd292ecaddb1c4dc1,
          (long long)seed ^ (long long)0x94489307a0d041ed,
          (long long)seed ^ (long long)0x25a4752be4bd4b84,
          (long long)seed ^ (long long)0xa1d4010ab16c4b96,
          (long long)seed ^ (long long)0x87175e8421534efa,
          (long long)seed ^ (long long)0x0df85252bb894d2b,
          (long long)seed ^ (long long)0x1d43b52179374cb4,
          (long long)seed ^ (long long)0x5586b8bf3d4f4ca7,
      },
      {
          (long long)seed ^ (long long)0x7275e2473e0f4618,
          (long long)seed ^ (long long)0x2340093a933a4191,
          (long long)seed ^ (long long)0x849ec473349843ac,
          (long long)seed ^ (long long)0x9b8873c068ac4e41,
          (long long)seed ^ (long long)0x3b8a6084e4ec44a7,
          (long long)seed ^ (long long)0x341dadfa6e524396,
          (long long)seed ^ (long long)0xb735256ca12649e9,
          (long long)seed ^ (long long)0x1bd21c39a0694d4f,
      },
  };
  romuQuad32simd(seeds, halftime_hash_random,
                 sizeof(halftime_hash_random) / sizeof(halftime_hash_random[0]));
}

#else

void halftime_hash_seed_init(size_t &seed)
{
#define ROTL(d,lrot) ((d<<(lrot)) | (d>>(8*sizeof(d)-(lrot))))
  uint64_t wState = seed, xState= 0xecfc1357d65941ae, yState=0xbe1927f97b8c43f1,
    zState=0xf4d4beb14ae042bb;
  for (unsigned i = 0; i < sizeof(halftime_hash_random) / sizeof(halftime_hash_random[0]);
       ++i) {
    const uint64_t wp = wState, xp = xState, yp = yState, zp = zState;
    wState = 15241094284759029579u * zp;  // a-mult
    xState = zp + ROTL(wp, 52);           // b-rotl, c-add
    yState = yp - xp;                     // d-sub
    zState = yp + wp;                     // e-add
    zState = ROTL(zState, 19);            // f-rotl
    halftime_hash_random[i] = xp;
  }
#undef ROTL
}
#endif


// Multiply shift from
// Thorup "High Speed Hashing for Integers and Strings" 2018
// https://arxiv.org/pdf/1504.06804.pdf
//
static inline uint8_t  take08(const uint8_t *p){ uint8_t  v; memcpy(&v, p, 1); return v; }
static inline uint16_t take16(const uint8_t *p){ uint16_t v; memcpy(&v, p, 2); return v; }
static inline uint32_t take32(const uint8_t *p){ uint32_t v; memcpy(&v, p, 4); return v; }
static inline uint64_t take64(const uint8_t *p){ uint64_t v; memcpy(&v, p, 8); return v; }
#ifdef __SIZEOF_INT128__
   const static int MULTIPLY_SHIFT_RANDOM_WORDS = 1<<8;
   static __uint128_t multiply_shift_random[MULTIPLY_SHIFT_RANDOM_WORDS];
   const static __uint128_t multiply_shift_r = ((__uint128_t)0x75f17d6b3588f843 << 64) | 0xb13dea7c9c324e51;
   void multiply_shift(const void * key, int len_bytes, uint32_t seed, void * out) {
      const uint8_t* buf = (const uint8_t*) key;
      const int len = len_bytes/8;

      // The output is 64 bits, and we consider the input 64 bit as well,
      // so our intermediate values are 128.
      // We mix in len_bytes in the basis, since smhasher considers two keys
      // of different length to be different, even if all the extra bits are 0.
      // This is needed for the AppendZero test.
      uint64_t h = (seed + len_bytes) * multiply_shift_r >> 64;
      for (int i = 0; i < len; i++, buf += 8)
         h += multiply_shift_random[i % MULTIPLY_SHIFT_RANDOM_WORDS] * take64(buf) >> 64;

      // Now get the last bytes
      int remaining_bytes = len_bytes & 7;
      if (remaining_bytes) {
         uint64_t last = 0;
         if (remaining_bytes & 4) {last = take32(buf); buf += 4;}
         if (remaining_bytes & 2) {last = (last << 16) | take16(buf); buf += 2;}
         if (remaining_bytes & 1) {last = (last << 8) | take08(buf);}
         h += multiply_shift_random[len % MULTIPLY_SHIFT_RANDOM_WORDS] * last >> 64;
      }

      *(uint64_t*)out = h;
   }
   void multiply_shift_seed_init_slow(uint32_t seed) {
      Rand r(seed);
      for (int i = 0; i < MULTIPLY_SHIFT_RANDOM_WORDS; i++) {
         multiply_shift_random[i] = r.rand_u128();
         if (!multiply_shift_random[i])
           multiply_shift_random[i]++;
         // We don't need an odd multiply, when we add the seed in the beginning
         //multiply_shift_random[i] |= 1;
      }
   }
   bool multiply_shift_bad_seeds(std::vector<uint64_t> &seeds) {
     // all seeds & 0xfffffff0
     seeds = std::vector<uint64_t> { UINT64_C(0xfffffff0), UINT64_C(0x1fffffff0) };
     return true;
   }
   void multiply_shift_seed_init(uint32_t &seed) {
     // The seeds we get are not random values, but just something like 1, 2 or 3.
     // So we xor it with a random number to get something slightly more reasonable.
     // But skip really bad seed patterns: 0x...fffffff0
     if ((seed & 0xfffffff0ULL) == 0xfffffff0ULL)
       seed++;
     multiply_shift_random[0] = (__uint128_t)seed ^ multiply_shift_r;
   }
   void multiply_shift_init() {
      multiply_shift_seed_init_slow(0);
   }

   // Vector multiply-shift (3.4) from Thorup's notes.
   void pair_multiply_shift(const void * key, int len_bytes, uint32_t seed, void * out) {
      const uint8_t* buf = (const uint8_t*) key;
      int len = len_bytes/8;

      uint64_t h = (__uint128_t)(seed + len_bytes) * multiply_shift_r >> 64;
      for (int i = 0; i < len/2; i++, buf += 16)
         h += (multiply_shift_random[2*i & MULTIPLY_SHIFT_RANDOM_WORDS-1] + take64(buf+8))
            * (multiply_shift_random[2*i+1 & MULTIPLY_SHIFT_RANDOM_WORDS-1] + take64(buf)) >> 64;

      // Make sure we have the last word, if the number of words is odd
      if (len & 1) {
         h += multiply_shift_random[len-1 & MULTIPLY_SHIFT_RANDOM_WORDS-1] * take64(buf) >> 64;
         buf += 8;
      }

      // Get the last bytes when things are unaligned
      int remaining_bytes = len_bytes & 7;
      if (remaining_bytes) {
         uint64_t last = 0;
         if (remaining_bytes & 4) {last = take32(buf); buf += 4;}
         if (remaining_bytes & 2) {last = (last << 16) | take16(buf); buf += 2;}
         if (remaining_bytes & 1) {last = (last << 8) | take08(buf);}
         h += multiply_shift_random[len & MULTIPLY_SHIFT_RANDOM_WORDS-1] * last >> 64;
      }

      *(uint64_t*)out = h;
   }
#endif


//TODO MSVC
#ifdef HAVE_INT64
#ifndef _MSC_VER
static uint8_t tsip_key[16];
void tsip_init()
{
  Rand r(729176);
  uint64_t rv = r.rand_u64();
  memcpy(&tsip_key[0], &rv, 8);
  rv = r.rand_u64();
  memcpy(&tsip_key[8], &rv, 8);
}
void tsip_test(const void *bytes, int len, uint32_t seed, void *out)
{
  memcpy(&tsip_key[0], &seed, 4);
  memcpy(&tsip_key[8], &seed, 4);
  *(uint64_t*)out = tsip(tsip_key, (const unsigned char*)bytes, (uint64_t)len);
}

#endif /* !MSVC */
#endif /* HAVE_INT64 */

#ifdef HAVE_SSE2
#  ifdef __AVX2__
#   define FARSH_AVX2
#  elif defined HAVE_SSE42
#   define FARSH_SSE2
#  endif
# include "farsh.c"

// objsize: 0-3b0: 944
void farsh32_test ( const void * key, int len, unsigned seed, void * out )
{
  farsh_n(key,len,0,1,seed,out);
}
void farsh64_test ( const void * key, int len, unsigned seed, void * out )
{
  farsh_n(key,len,0,2,seed,out);
}
void farsh128_test ( const void * key, int len, unsigned seed, void * out )
{
  farsh_n(key,len,0,4,seed,out);
}
void farsh256_test ( const void * key, int len, unsigned seed, void * out )
{
  farsh_n(key,len,0,8,seed,out);
}
#endif

#include "hash-garage/nmhash.h"
// objsize: 4202f0-420c7d: 2445
void nmhash32_test ( const void * key, int len, uint32_t seed, void * out ) {
  *(uint32_t*)out = NMHASH32 (key, (const size_t) len, seed);
}
// objsize: 466100-4666d6: 1494
void nmhash32x_test ( const void * key, int len, uint32_t seed, void * out ) {
  *(uint32_t*)out = NMHASH32X (key, (const size_t) len, seed);
}
