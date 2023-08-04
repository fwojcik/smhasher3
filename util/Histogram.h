/*
 * SMHasher3
 * Copyright (C) 2021-2023  Frank J. T. Wojcik
 * Copyright (C) 2023       jason
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 */

#if defined(HAVE_AVX2) || defined(HAVE_SSE_4_1)
  #include "Intrinsics.h"
#endif

// This will add the value of each bit (0 or 1) of the hash value to the
// corresponding entry in the histogram array of 32-bit unsigned integers, where
// cursor points to the 0'th histogram entry (corresponding to the LSB of hash). The
// size of the hash is assumed to be divisible by 32 bits. Returns a pointer to the
// first histogram entry beyond those for the given hash value.

template <typename hashtype>
static inline uint32_t * HistogramHashBits( const hashtype & hash, uint32_t * cursor ) {
    const int hashbytes = hashtype::len;

#if defined(HAVE_AVX2)
    const __m256i ONE  = _mm256_set1_epi32(1);
    const __m256i MASK = _mm256_setr_epi32(1 << 0, 1 << 1, 1 << 2, 1 << 3, 1 << 4, 1 << 5, 1 << 6, 1 << 7);
    for (unsigned oWord = 0; oWord < (hashbytes / 4); oWord++) {
        // Get the next 32-bit chunk of the hash difference
        uint32_t word;
        memcpy(&word, ((const uint8_t *)&hash) + 4 * oWord, 4);

        // Expand it out into 4 sets of 8 32-bit integer words, with
        // each integer being zero or one.
        __m256i base  = _mm256_set1_epi32(word);
        __m256i incr1 = _mm256_min_epu32(_mm256_and_si256(base, MASK), ONE);
        base = _mm256_srli_epi32(base, 8);
        __m256i incr2 = _mm256_min_epu32(_mm256_and_si256(base, MASK), ONE);
        base = _mm256_srli_epi32(base, 8);
        __m256i incr3 = _mm256_min_epu32(_mm256_and_si256(base, MASK), ONE);
        base = _mm256_srli_epi32(base, 8);
        __m256i incr4 = _mm256_min_epu32(_mm256_and_si256(base, MASK), ONE);

        // Add these into the counts in the histogram.
        __m256i cnt1 = _mm256_loadu_si256((const __m256i *)cursor);
        cnt1    = _mm256_add_epi32(cnt1, incr1);
        _mm256_storeu_si256((__m256i *)cursor, cnt1);
        cursor += 8;
        __m256i cnt2 = _mm256_loadu_si256((const __m256i *)cursor);
        cnt2    = _mm256_add_epi32(cnt2, incr2);
        _mm256_storeu_si256((__m256i *)cursor, cnt2);
        cursor += 8;
        __m256i cnt3 = _mm256_loadu_si256((const __m256i *)cursor);
        cnt3    = _mm256_add_epi32(cnt3, incr3);
        _mm256_storeu_si256((__m256i *)cursor, cnt3);
        cursor += 8;
        __m256i cnt4 = _mm256_loadu_si256((const __m256i *)cursor);
        cnt4    = _mm256_add_epi32(cnt4, incr4);
        _mm256_storeu_si256((__m256i *)cursor, cnt4);
        cursor += 8;
    }
#elif defined(HAVE_SSE_4_1)
    const __m128i ONE  = _mm_set1_epi32(1);
    const __m128i MASK = _mm_setr_epi32(1 << 0, 1 << 1, 1 << 2, 1 << 3);
    for (unsigned oWord = 0; oWord < (hashbytes / 4); oWord++) {
        // Get the next 32-bit chunk of the hash difference
        uint32_t word;
        memcpy(&word, ((const uint8_t *)&hash) + 4 * oWord, 4);

        // Expand it out into 8 sets of 4 32-bit integer words, with
        // each integer being zero or one, and add them into the
        // counts in the histogram.
        __m128i base = _mm_set1_epi32(word);
        for (unsigned i = 0; i < 8; i++) {
            __m128i incr = _mm_min_epu32(_mm_and_si128(base, MASK), ONE);
            __m128i cnt  = _mm_loadu_si128((const __m128i *)cursor);
            cnt     = _mm_add_epi32(cnt, incr);
            _mm_storeu_si128((__m128i *)cursor, cnt);
            base    = _mm_srli_epi32(base, 4);
            cursor += 4;
        }
    }
#else
    for (unsigned oByte = 0; oByte < hashbytes; oByte++) {
        uint8_t byte = hash[oByte];
        for (unsigned oBit = 0; oBit < 8; oBit++) {
            (*cursor++) += byte & 1;
            byte       >>= 1;
        }
    }
#endif
    return cursor;
}

// This will add the value of each bit (0 or 1) of the hash value to the
// corresponding entry in the histogram array of 32-bit unsigned integers, but it
// starts with the given startbit of the hash value. Cursor must point to the
// histogram array entry corresponding to that starting bit. The size of the hash is
// assumed to be divisible by 32 bits. Returns a pointer to the first histogram entry
// beyond those for the given hash value. While this reads from and writes to memory
// before the cursor pointer, it will always write back the bytes unchanged. But callers
// must ensure that memory is valid to read+write.

template <typename hashtype>
static inline uint32_t * HistogramHashBits( const hashtype & hash, uint32_t * cursor, size_t startbit ) {
    const int hashbytes = hashtype::len;

#if defined(HAVE_AVX2)
    const __m256i ONE       = _mm256_set1_epi32(1);
    const __m256i MASK      = _mm256_setr_epi32(1 << 0, 1 << 1, 1 << 2, 1 << 3, 1 << 4, 1 << 5, 1 << 6, 1 << 7);
    const size_t  startWord = startbit / 32;
    startbit &= 31;
    // Align the cursor to the start of the chunk of 32 integer counters
    cursor   -= startbit;
    for (unsigned oWord = startWord; oWord < (hashbytes / 4); oWord++) {
        // Get the next 32-bit chunk of the hash difference
        uint32_t word;
        memcpy(&word, ((const uint8_t *)&hash) + 4 * oWord, 4);
        // Mask off the bits before startbit
        word >>= startbit;
        word <<= startbit;

        // Expand it out into 4 sets of 8 32-bit integer words, with
        // each integer being zero or one.
        __m256i base  = _mm256_set1_epi32(word);
        __m256i incr1 = _mm256_min_epu32(_mm256_and_si256(base, MASK), ONE);
        base = _mm256_srli_epi32(base, 8);
        __m256i incr2 = _mm256_min_epu32(_mm256_and_si256(base, MASK), ONE);
        base = _mm256_srli_epi32(base, 8);
        __m256i incr3 = _mm256_min_epu32(_mm256_and_si256(base, MASK), ONE);
        base = _mm256_srli_epi32(base, 8);
        __m256i incr4 = _mm256_min_epu32(_mm256_and_si256(base, MASK), ONE);

        // Add these into the counts in the histogram.
        __m256i cnt1 = _mm256_loadu_si256((const __m256i *)cursor);
        cnt1     = _mm256_add_epi32(cnt1, incr1);
        _mm256_storeu_si256((__m256i *)cursor, cnt1);
        cursor  += 8;
        __m256i cnt2 = _mm256_loadu_si256((const __m256i *)cursor);
        cnt2     = _mm256_add_epi32(cnt2, incr2);
        _mm256_storeu_si256((__m256i *)cursor, cnt2);
        cursor  += 8;
        __m256i cnt3 = _mm256_loadu_si256((const __m256i *)cursor);
        cnt3     = _mm256_add_epi32(cnt3, incr3);
        _mm256_storeu_si256((__m256i *)cursor, cnt3);
        cursor  += 8;
        __m256i cnt4 = _mm256_loadu_si256((const __m256i *)cursor);
        cnt4     = _mm256_add_epi32(cnt4, incr4);
        _mm256_storeu_si256((__m256i *)cursor, cnt4);
        cursor  += 8;
        // For all other times through the loop, leave the word variable unchanged
        startbit = 0;
    }
#elif defined(HAVE_SSE_4_1)
    const __m128i ONE       = _mm_set1_epi32(1);
    const __m128i MASK      = _mm_setr_epi32(1 << 0, 1 << 1, 1 << 2, 1 << 3);
    const size_t  startWord = startbit / 32;
    startbit &= 31;
    // Align the cursor to the start of the chunk of 32 integer counters
    cursor   -= startbit;
    for (unsigned oWord = startWord; oWord < (hashbytes / 4); oWord++) {
        // Get the next 32-bit chunk of the hash difference
        uint32_t word;
        memcpy(&word, ((const uint8_t *)&hash) + 4 * oWord, 4);
        // Mask off the bits before startbit
        word >>= startbit;
        word <<= startbit;

        // Expand it out into 8 sets of 4 32-bit integer words, with
        // each integer being zero or one, and add them into the
        // counts in the histogram.
        __m128i base = _mm_set1_epi32(word);
        for (unsigned i = 0; i < 8; i++) {
            __m128i incr = _mm_min_epu32(_mm_and_si128(base, MASK), ONE);
            __m128i cnt  = _mm_loadu_si128((const __m128i *)cursor);
            cnt     = _mm_add_epi32(cnt, incr);
            _mm_storeu_si128((__m128i *)cursor, cnt);
            base    = _mm_srli_epi32(base, 4);
            cursor += 4;
        }
        // For all other times through the loop, leave the word variable unchanged
        startbit = 0;
    }
#else
    const size_t startByte = startbit / 8;
    startbit &= 7;
    // Align the cursor to the start of the chunk of 8 integer counters
    cursor   -= startbit;
    for (unsigned oByte = startByte; oByte < hashbytes; oByte++) {
        uint8_t byte = hash[oByte];
        // Mask off the bits before startbit
        byte >>= startbit;
        byte <<= startbit;
        for (unsigned oBit = 0; oBit < 8; oBit++) {
            (*cursor++) += byte & 1;
            byte       >>= 1;
        }
        // For all other times through the loop, leave the word variable unchanged
        startbit = 0;
    }
#endif
    return cursor;
}
