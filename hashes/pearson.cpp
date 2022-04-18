/*
 * Pearson hashing
 * This is free and unencumbered software released into the public
 * domain under The Unlicense (http://unlicense.org/).
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a
 * compiled binary, for any purpose, commercial or non-commercial, and
 * by any means.
 *
 * In jurisdictions that recognize copyright laws, the author or
 * authors of this software dedicate any and all copyright interest in
 * the software to the public domain. We make this dedication for the
 * benefit of the public at large and to the detriment of our heirs
 * and successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to
 * this software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */
#include "Platform.h"
#include "Types.h"
#include "Hashlib.h"

#if defined(NEW_HAVE_SSSE3)
#include "lib/Intrinsics.h"
#endif

// AES S-Box table -- allows for eventually supported hardware accelerated look-up
static const uint8_t t[256] ={
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static uint16_t t16[65536];

bool pearson_hash_init (void) {
#if !defined(NEW_HAVE_SSSE3)
  size_t i;

  for (i = 0; i < 65536; i++)
    t16[i] = (t[i >> 8] << 8) + t[(uint8_t)i];
#endif
  return true;
}

static void pearson_hash_256_portable(uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in) {
  size_t i;
  /* initial values -  astonishingly, assembling using SHIFTs and ORs (in register)
   * works faster on well pipelined CPUs than loading the 64-bit value from memory.
   * however, there is one advantage to loading from memory: as we also store back to
   * memory at the end, we do not need to care about endianess! */
  uint8_t upper[8] = { 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08 };
  uint8_t lower[8] = { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

  uint64_t upper_hash_mask = GET_U64<false>(upper, 0);
  uint64_t lower_hash_mask = GET_U64<false>(lower, 0);
  uint64_t high_upper_hash_mask = upper_hash_mask + UINT64_C(0x1010101010101010);
  uint64_t high_lower_hash_mask = lower_hash_mask + UINT64_C(0x1010101010101010);

  // The one nod to endianness is that the hash_in value needs be in
  // little-endian format always, to match up with the byte ordering
  // of upper[] and lower[] above.
  hash_in = COND_BSWAP(hash_in, isBE());
  uint64_t upper_hash = hash_in;
  uint64_t lower_hash = hash_in;
  uint64_t high_upper_hash = hash_in;
  uint64_t high_lower_hash = hash_in;

  for (i = 0; i < len; i++) {
    // broadcast the character, xor into hash, make them different permutations
    uint64_t c = (uint8_t)in[i];
    c |= c <<  8;
    c |= c << 16;
    c |= c << 32;
    upper_hash ^= c ^ upper_hash_mask;
    lower_hash ^= c ^ lower_hash_mask;
    high_upper_hash ^= c ^ high_upper_hash_mask;
    high_lower_hash ^= c ^ high_lower_hash_mask;

    // table lookup
    uint64_t h = 0;
    uint16_t x;
    x = upper_hash; x = t16[x]; upper_hash >>= 16; h  = x; h = ROTR64 (h, 16);
    x = upper_hash; x = t16[x]; upper_hash >>= 16; h |= x; h = ROTR64 (h, 16);
    x = upper_hash; x = t16[x]; upper_hash >>= 16; h |= x; h = ROTR64 (h, 16);
    x = upper_hash; x = t16[x];                  ; h |= x; h = ROTR64 (h, 16);
    upper_hash = h;

    h = 0;
    x = lower_hash; x = t16[x]; lower_hash >>= 16; h  = x; h = ROTR64 (h, 16);
    x = lower_hash; x = t16[x]; lower_hash >>= 16; h |= x; h = ROTR64 (h, 16);
    x = lower_hash; x = t16[x]; lower_hash >>= 16; h |= x; h = ROTR64 (h, 16);
    x = lower_hash; x = t16[x];                  ; h |= x; h = ROTR64 (h, 16);
    lower_hash = h;

    h = 0;
    x = high_upper_hash; x = t16[x]; high_upper_hash >>= 16; h  = x; h = ROTR64 (h, 16);
    x = high_upper_hash; x = t16[x]; high_upper_hash >>= 16; h |= x; h = ROTR64 (h, 16);
    x = high_upper_hash; x = t16[x]; high_upper_hash >>= 16; h |= x; h = ROTR64 (h, 16);
    x = high_upper_hash; x = t16[x];                       ; h |= x; h = ROTR64 (h, 16);
    high_upper_hash = h;

    h = 0;
    x = high_lower_hash; x = t16[x]; high_lower_hash >>= 16; h  = x; h = ROTR64 (h, 16);
    x = high_lower_hash; x = t16[x]; high_lower_hash >>= 16; h |= x; h = ROTR64 (h, 16);
    x = high_lower_hash; x = t16[x]; high_lower_hash >>= 16; h |= x; h = ROTR64 (h, 16);
    x = high_lower_hash; x = t16[x];                       ; h |= x; h = ROTR64 (h, 16);
    high_lower_hash = h;
  }
  // store output
  PUT_U64<false>(high_upper_hash, out, 0);
  PUT_U64<false>(high_lower_hash, out, 8);
  PUT_U64<false>(upper_hash, out, 16);
  PUT_U64<false>(lower_hash, out, 24);
}

static void pearson_hash_128_portable(uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in) {
  size_t i;
  /* initial values -  astonishingly, assembling using SHIFTs and ORs (in register)
   * works faster on well pipelined CPUs than loading the 64-bit value from memory.
   * however, there is one advantage to loading from memory: as we also store back to
   * memory at the end, we do not need to care about endianess! */
  uint8_t upper[8] = { 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08 };
  uint8_t lower[8] = { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

  uint64_t upper_hash_mask = GET_U64<false>(upper, 0);
  uint64_t lower_hash_mask = GET_U64<false>(lower, 0);

  // The one nod to endianness is that the hash_in value needs be in
  // little-endian format always, to match up with the byte ordering
  // of upper[] and lower[] above.
  hash_in = COND_BSWAP(hash_in, isBE());
  uint64_t upper_hash = hash_in;
  uint64_t lower_hash = hash_in;

  for (i = 0; i < len; i++) {
    // broadcast the character, xor into hash, make them different permutations
    uint64_t c = (uint8_t)in[i];
    c |= c <<  8;
    c |= c << 16;
    c |= c << 32;
    upper_hash ^= c ^ upper_hash_mask;
    lower_hash ^= c ^ lower_hash_mask;

    // table lookup
    uint64_t h = 0;
    uint16_t x;
    x = upper_hash; x = t16[x]; upper_hash >>= 16; h  = x; h = ROTR64 (h,16);
    x = upper_hash; x = t16[x]; upper_hash >>= 16; h |= x; h = ROTR64 (h,16);
    x = upper_hash; x = t16[x]; upper_hash >>= 16; h |= x; h = ROTR64 (h,16);
    x = upper_hash; x = t16[x];                  ; h |= x; h = ROTR64 (h,16);
    upper_hash = h;

    h = 0;
    x = lower_hash; x = t16[x]; lower_hash >>= 16; h  = x; h = ROTR64 (h, 16);
    x = lower_hash; x = t16[x]; lower_hash >>= 16; h |= x; h = ROTR64 (h, 16);
    x = lower_hash; x = t16[x]; lower_hash >>= 16; h |= x; h = ROTR64 (h, 16);
    x = lower_hash; x = t16[x];                  ; h |= x; h = ROTR64 (h, 16);
    lower_hash = h;
  }
  // store output
  PUT_U64<false>(upper_hash, out, 0);
  PUT_U64<false>(lower_hash, out, 8);
}

static void pearson_hash_64_portable(uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in) {
  size_t i;
  uint64_t hash_mask = UINT64_C(0x0706050403020100);
  uint64_t hash = hash_in;

  for (i = 0; i < len; i++) {
    // broadcast the character, xor into hash, make them different permutations
    uint64_t c = (uint8_t)in[i];
    c |= c <<  8;
    c |= c << 16;
    c |= c << 32;
    hash ^= c ^ hash_mask;
    // table lookup

    uint64_t h = 0;
    h   = (t16[(uint16_t)(hash >> 16)] << 16) + t16[(uint16_t)hash];
    h <<= 32;
    h |= (uint32_t)((t16[(uint16_t)(hash >> 48)] << 16)) + t16[(uint16_t)(hash >> 32)];
    hash = ROTR64(h, 32);
  }
  // store output
  if (isBE()) {
    PUT_U64<true>(hash, out, 0);
  } else {
    PUT_U64<false>(hash, out, 0);
  }
}

#if defined(NEW_HAVE_AES_X86_64)

static void pearson_hash_256_aesni(uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in) {
  size_t i;

  uint8_t upper[8] = { 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08 };
  uint8_t lower[8] = { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

  uint64_t upper_hash_mask = *(uint64_t*)&upper;
  uint64_t lower_hash_mask = *(uint64_t*)&lower;

  __m128i tmp = _mm_set1_epi8(0x10);

  __m128i hash_mask = _mm_set_epi64 ((__m64)lower_hash_mask, (__m64)upper_hash_mask);
  __m128i high_hash_mask = _mm_xor_si128 (tmp, hash_mask);
  __m128i hash= _mm_set_epi64x(hash_in, hash_in);
  __m128i high_hash= _mm_set_epi64x(hash_in, hash_in);

  // table lookup preparation
  __m128i ZERO = _mm_setzero_si128();
  __m128i ISOLATE_SBOX_MASK = _mm_set_epi32(0x0306090C, 0x0F020508, 0x0B0E0104, 0x070A0D00);

  for (i = 0; i < len; i++) {
    // broadcast the character, xor into hash, make them different permutations
    __m128i cc = _mm_set1_epi8 (in[i]);
    hash = _mm_xor_si128 (hash, cc);
    high_hash = _mm_xor_si128 (high_hash, cc);
    hash = _mm_xor_si128 (hash, hash_mask);
    high_hash = _mm_xor_si128 (high_hash, high_hash_mask);

    // table lookup
    hash = _mm_shuffle_epi8(hash, ISOLATE_SBOX_MASK);           // re-order along AES round
    high_hash = _mm_shuffle_epi8(high_hash, ISOLATE_SBOX_MASK); // re-order along AES round
    hash = _mm_aesenclast_si128(hash, ZERO);
    high_hash = _mm_aesenclast_si128(high_hash, ZERO);
  }

  // store output
  _mm_store_si128 ((__m128i*)out , high_hash);
  _mm_store_si128 ((__m128i*)&out[16] , hash);
}

static void pearson_hash_128_aesni(uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in) {
  size_t i;

  uint8_t upper[8] = { 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08 };
  uint8_t lower[8] = { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

  uint64_t upper_hash_mask = *(uint64_t*)&upper;
  uint64_t lower_hash_mask = *(uint64_t*)&lower;

  __m128i hash_mask = _mm_set_epi64 ((__m64)lower_hash_mask, (__m64)upper_hash_mask);
  __m128i hash = _mm_set_epi64x(hash_in, hash_in);

  // table lookup preparation
  __m128i ZERO = _mm_setzero_si128();
  __m128i ISOLATE_SBOX_MASK = _mm_set_epi32(0x0306090C, 0x0F020508, 0x0B0E0104, 0x070A0D00);

  for (i = 0; i < len; i++) {
    // broadcast the character, xor into hash, make them different permutations
    __m128i cc = _mm_set1_epi8 (in[i]);
    hash = _mm_xor_si128 (hash, cc);
    hash = _mm_xor_si128 (hash, hash_mask);

    // table lookup
    hash = _mm_shuffle_epi8(hash, ISOLATE_SBOX_MASK); // re-order along AES round
    hash = _mm_aesenclast_si128(hash, ZERO);
  }
  // store output
  _mm_store_si128 ((__m128i*)out , hash);
}

static void pearson_hash_64_aesni(uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in) {
  size_t i;
  __m128i hash_mask = _mm_cvtsi64_si128(UINT64_C(0x0706050403020100));
  __m128i hash = _mm_cvtsi64_si128(hash_in);

  // table lookup preparation
  __m128i ZERO = _mm_setzero_si128();
  __m128i ISOLATE_SBOX_MASK = _mm_set_epi32(0x0306090C, 0x0F020508, 0x0B0E0104, 0x070A0D00);

  for (i = 0; i < len; i++) {
    // broadcast the character, xor into hash, make them different permutations
    __m128i cc = _mm_set1_epi8 (in[i]);
    hash = _mm_xor_si128 (hash, cc);
    hash = _mm_xor_si128 (hash, hash_mask);

    // table lookup
    hash = _mm_shuffle_epi8(hash, ISOLATE_SBOX_MASK); // re-order along AES round
    hash = _mm_aesenclast_si128(hash, ZERO);
  }

  // store output
  _mm_storel_epi64((__m128i*)out , hash);
}

#elif defined(NEW_HAVE_SSSE3)

static void pearson_hash_256_ssse3(uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in) {
  size_t i;

  uint8_t upper[8] = { 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08 };
  uint8_t lower[8] = { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

  uint64_t upper_hash_mask = *(uint64_t*)&upper;
  uint64_t lower_hash_mask = *(uint64_t*)&lower;

  __m128i tmp = _mm_set1_epi8(0x10);

  __m128i hash_mask = _mm_set_epi64 ((__m64)lower_hash_mask, (__m64)upper_hash_mask);
  __m128i high_hash_mask = _mm_xor_si128 (tmp, hash_mask);
  __m128i hash= _mm_set_epi64x(hash_in, hash_in);
  __m128i high_hash= _mm_set_epi64x(hash_in, hash_in);

  // table lookup preparation
  __m128i const p16  = _mm_set1_epi8 (0x10);
  __m128i lut_result  = _mm_xor_si128 (lut_result, lut_result);
  __m128i high_lut_result  = _mm_xor_si128 (high_lut_result, high_lut_result);
  __m128i selected_entries;
  __m128i high_selected_entries;
  __m128i table_line;

  for (i = 0; i < len; i++) {
    // broadcast the character, xor into hash, make them different permutations
    __m128i cc = _mm_set1_epi8 (in[i]);
    hash = _mm_xor_si128 (hash, cc);
    high_hash = _mm_xor_si128 (high_hash, cc);
    hash = _mm_xor_si128 (hash, hash_mask);
    high_hash = _mm_xor_si128 (high_hash, high_hash_mask);

    // table lookup
    size_t j;
    __m128i lut_index = hash;
    __m128i high_lut_index = high_hash;
    lut_result = _mm_xor_si128 (lut_result, lut_result);
    high_lut_result = _mm_xor_si128 (lut_result, lut_result);
    for (j = 0; j < 256; j += 16) {
      table_line = _mm_load_si128 ((__m128i *)&t[j]);
      selected_entries = _mm_min_epu8 (lut_index, p16);
      selected_entries = _mm_cmpeq_epi8 (selected_entries, p16);
      selected_entries = _mm_or_si128 (selected_entries, lut_index);
      selected_entries = _mm_shuffle_epi8 (table_line, selected_entries);
      high_selected_entries = _mm_min_epu8 (high_lut_index, p16);
      high_selected_entries = _mm_cmpeq_epi8 (high_selected_entries, p16);
      high_selected_entries = _mm_or_si128 (high_selected_entries, high_lut_index);
      high_selected_entries = _mm_shuffle_epi8 (table_line, high_selected_entries);
      lut_result  = _mm_or_si128 (lut_result, selected_entries);
      lut_index = _mm_sub_epi8 (lut_index, p16);
      high_lut_result  = _mm_or_si128 (high_lut_result, high_selected_entries);
      high_lut_index = _mm_sub_epi8 (high_lut_index, p16);
    }
    hash = lut_result;
    high_hash = high_lut_result;
  }

  // store output
  _mm_store_si128 ((__m128i*)out , high_hash);
  _mm_store_si128 ((__m128i*)&out[16] , hash);
}

static void pearson_hash_128_ssse3(uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in) {
  size_t i;

  uint8_t upper[8] = { 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08 };
  uint8_t lower[8] = { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };

  uint64_t upper_hash_mask = *(uint64_t*)&upper;
  uint64_t lower_hash_mask = *(uint64_t*)&lower;

  __m128i hash_mask = _mm_set_epi64 ((__m64)lower_hash_mask, (__m64)upper_hash_mask);
  __m128i hash = _mm_set_epi64x(hash_in, hash_in);

  // table lookup preparation
  __m128i const p16  = _mm_set1_epi8 (0x10);
  __m128i lut_result  = _mm_xor_si128 (lut_result, lut_result);
  __m128i selected_entries;
  __m128i table_line;

  for (i = 0; i < len; i++) {
    // broadcast the character, xor into hash, make them different permutations
    __m128i cc = _mm_set1_epi8 (in[i]);
    hash = _mm_xor_si128 (hash, cc);
    hash = _mm_xor_si128 (hash, hash_mask);

    // table lookup
    size_t j;
    __m128i lut_index = hash;
    lut_result = _mm_xor_si128 (lut_result, lut_result);
    for (j = 0; j < 256; j += 16) {
      table_line = _mm_load_si128 ((__m128i *)&t[j]);
      selected_entries = _mm_min_epu8 (lut_index, p16);
      selected_entries = _mm_cmpeq_epi8 (selected_entries, p16);
      selected_entries = _mm_or_si128 (selected_entries, lut_index);
      selected_entries = _mm_shuffle_epi8 (table_line, selected_entries);
      lut_result  = _mm_or_si128 (lut_result, selected_entries);
      lut_index = _mm_sub_epi8 (lut_index, p16);
    }
    hash = lut_result;
  }
  // store output
  _mm_store_si128 ((__m128i*)out , hash);
}

static void pearson_hash_64_ssse3(uint8_t * out, const uint8_t * in, size_t len, uint64_t hash_in) {
  size_t i;
  __m128i hash_mask = _mm_cvtsi64_si128(UINT64_C(0x0706050403020100));
  __m128i hash = _mm_cvtsi64_si128 (hash_in);

  // table lookup preparation
  __m128i const p16  = _mm_set1_epi8 (0x10);
  __m128i lut_result  = _mm_xor_si128 (lut_result, lut_result);

  for (i = 0; i < len; i++) {
    // broadcast the character, xor into hash, make them different permutations
    __m128i cc = _mm_set1_epi8 (in[i]);
    hash = _mm_xor_si128 (hash, cc);
    hash = _mm_xor_si128 (hash, hash_mask);

    // table lookup
    size_t j;
    __m128i lut_index = hash;
    lut_result = _mm_xor_si128 (lut_result, lut_result);
    for (j = 0; j < 256; j += 16) {
      __m128i table_line = _mm_load_si128 ((__m128i *)&t[j]);
      __m128i selected_entries = _mm_min_epu8 (lut_index, p16);
      selected_entries = _mm_cmpeq_epi8 (selected_entries, p16);
      selected_entries = _mm_or_si128 (selected_entries, lut_index);
      selected_entries = _mm_shuffle_epi8 (table_line, selected_entries);
      lut_result  = _mm_or_si128 (lut_result, selected_entries);
      lut_index = _mm_sub_epi8 (lut_index, p16);
    }
    hash = lut_result;
  }

  // store output
  _mm_storel_epi64((__m128i*)out , hash);
}
#endif

void pearson64(const void * in, const size_t len, const seed_t seed, void * out) {
#if defined(NEW_HAVE_AES_X86_64)
  pearson_hash_64_aesni((uint8_t *)out, (const uint8_t *)in, len, (uint64_t)seed);
#elif defined(NEW_HAVE_SSSE3)
  pearson_hash_64_ssse3((uint8_t *)out, (const uint8_t *)in, len, (uint64_t)seed);
#else
  pearson_hash_64_portable((uint8_t *)out, (const uint8_t *)in, len, (uint64_t)seed);
#endif
}

void pearson128(const void * in, const size_t len, const seed_t seed, void * out) {
#if defined(NEW_HAVE_AES_X86_64)
  pearson_hash_128_aesni((uint8_t *)out, (const uint8_t *)in, len, (uint64_t)seed);
#elif defined(NEW_HAVE_SSSE3)
  pearson_hash_128_ssse3((uint8_t *)out, (const uint8_t *)in, len, (uint64_t)seed);
#else
  pearson_hash_128_portable((uint8_t *)out, (const uint8_t *)in, len, (uint64_t)seed);
#endif
}

void pearson256(const void * in, const size_t len, const seed_t seed, void * out) {
#if defined(NEW_HAVE_AES_X86_64)
  pearson_hash_256_aesni((uint8_t *)out, (const uint8_t *)in, len, (uint64_t)seed);
#elif defined(NEW_HAVE_SSSE3)
  pearson_hash_256_ssse3((uint8_t *)out, (const uint8_t *)in, len, (uint64_t)seed);
#else
  pearson_hash_256_portable((uint8_t *)out, (const uint8_t *)in, len, (uint64_t)seed);
#endif
}

REGISTER_FAMILY(pearson,
  $.src_url = "https://github.com/Logan007/pearson",
  $.src_status = HashFamilyInfo::SRC_STABLEISH
);

REGISTER_HASH(pearson_64,
  $.desc = "Pearson hash, 8 lanes using AES sbox",
  $.hash_flags =
	      0,
  $.impl_flags =
        FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
  $.bits = 64,
  $.verification_LE = 0x12E4C8CD,
  $.verification_BE = 0x12E4C8CD,
  $.hashfn_native = pearson64,
  $.hashfn_bswap = pearson64,
  $.initfn = pearson_hash_init
);

REGISTER_HASH(pearson_128,
  $.desc = "Pearson hash, 16 lanes using AES sbox",
  $.hash_flags =
	      0,
  $.impl_flags =
        FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
  $.bits = 128,
  $.verification_LE = 0xDC5048A3,
  $.verification_BE = 0xDC5048A3,
  $.hashfn_native = pearson128,
  $.hashfn_bswap = pearson128,
  $.initfn = pearson_hash_init
);

REGISTER_HASH(pearson_256,
  $.desc = "Pearson hash, 32 lanes using AES sbox",
  $.hash_flags =
	      0,
  $.impl_flags =
        FLAG_IMPL_LICENSE_PUBLIC_DOMAIN,
  $.bits = 256,
  $.verification_LE = 0xA9B1DE02,
  $.verification_BE = 0xA9B1DE02,
  $.hashfn_native = pearson256,
  $.hashfn_bswap = pearson256,
  $.initfn = pearson_hash_init
);
