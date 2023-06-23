/*
 * BLAKE3 hashes
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * based on:
 *     BLAKE3 source code package - official C implementations
 * used under terms of CC0.
 */
#include "Platform.h"
#include "Hashlib.h"

static const uint32_t IV         [8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372,
    0xA54FF53A, 0x510E527F, 0x9B05688C,
    0x1F83D9AB, 0x5BE0CD19
};

static const uint8_t MSG_SCHEDULE[7][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 },
    { 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1 },
    { 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6 },
    { 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4 },
    { 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7 },
    { 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13 },
};

// internal flags
enum blake3_flags {
    CHUNK_START         = 1 << 0,
    CHUNK_END           = 1 << 1,
    PARENT              = 1 << 2,
    ROOT                = 1 << 3,
    KEYED_HASH          = 1 << 4,
    DERIVE_KEY_CONTEXT  = 1 << 5,
    DERIVE_KEY_MATERIAL = 1 << 6,
};

#define BLAKE3_KEY_LEN 32
#define BLAKE3_OUT_LEN 32
#define BLAKE3_BLOCK_LEN 64
#define BLAKE3_CHUNK_LEN 1024
#define BLAKE3_MAX_DEPTH 54

static FORCE_INLINE uint32_t counter_low( uint64_t counter ) { return (uint32_t)counter; }

static FORCE_INLINE uint32_t counter_high( uint64_t counter ) {
    return (uint32_t)(counter >> 32);
}

static FORCE_INLINE uint64_t round_down_to_power_of_2( uint64_t x ) {
    return UINT64_C(1) << (63 ^ clz8(x | 1));
}

static FORCE_INLINE size_t left_len( size_t content_len ) {
    // Subtract 1 to reserve at least one byte for the right side. content_len
    // should always be greater than BLAKE3_CHUNK_LEN.
    size_t full_chunks = (content_len - 1) / BLAKE3_CHUNK_LEN;

    return round_down_to_power_of_2(full_chunks) * BLAKE3_CHUNK_LEN;
}

static FORCE_INLINE void store32( void * dst, uint32_t w ) {
    uint8_t * p = (uint8_t *)dst;

    p[0] = (uint8_t)(w >>  0);
    p[1] = (uint8_t)(w >>  8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
}

static FORCE_INLINE void store_cv_words( uint8_t bytes_out[32], uint32_t cv_words[8] ) {
    store32(&bytes_out[0 * 4], cv_words[0]);
    store32(&bytes_out[1 * 4], cv_words[1]);
    store32(&bytes_out[2 * 4], cv_words[2]);
    store32(&bytes_out[3 * 4], cv_words[3]);
    store32(&bytes_out[4 * 4], cv_words[4]);
    store32(&bytes_out[5 * 4], cv_words[5]);
    store32(&bytes_out[6 * 4], cv_words[6]);
    store32(&bytes_out[7 * 4], cv_words[7]);
}

typedef struct {
    uint32_t  cv[8];
    uint64_t  chunk_counter;
    uint8_t   buf[BLAKE3_BLOCK_LEN];
    uint8_t   buf_len;
    uint8_t   blocks_compressed;
    uint8_t   flags;
} blake3_chunk_state;

typedef struct {
    uint32_t            key[8];
    blake3_chunk_state  chunk;
    uint8_t             cv_stack_len;
    uint8_t             cv_stack[(BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN];
} blake3_hasher;

typedef struct {
    uint32_t  input_cv[8];
    uint64_t  counter;
    uint8_t   block[BLAKE3_BLOCK_LEN];
    uint8_t   block_len;
    uint8_t   flags;
} output_t;

static void blake3_compress_in_place( uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN],
        uint8_t block_len, uint64_t counter, uint8_t flags );
static void blake3_compress_xof( const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN],
        uint8_t block_len, uint64_t counter, uint8_t flags, uint8_t out[64] );

static FORCE_INLINE void chunk_state_init( blake3_chunk_state * self, const uint32_t key[8], uint8_t flags ) {
    memcpy(self->cv, key, BLAKE3_KEY_LEN);
    memset(self->buf, 0, BLAKE3_BLOCK_LEN);
    self->chunk_counter     = 0;
    self->buf_len           = 0;
    self->blocks_compressed = 0;
    self->flags = flags;
}

static FORCE_INLINE void chunk_state_reset( blake3_chunk_state * self, const uint32_t key[8], uint64_t chunk_counter ) {
    memcpy(self->cv, key, BLAKE3_KEY_LEN);
    self->chunk_counter     = chunk_counter;
    self->blocks_compressed = 0;
    memset(self->buf, 0, BLAKE3_BLOCK_LEN);
    self->buf_len = 0;
}

static FORCE_INLINE output_t make_output( const uint32_t input_cv[8], const uint8_t block[BLAKE3_BLOCK_LEN],
        uint8_t block_len, uint64_t counter, uint8_t flags ) {
    output_t ret;

    memcpy(ret.input_cv, input_cv,               32);
    memcpy(ret.block   , block   , BLAKE3_BLOCK_LEN);
    ret.block_len = block_len;
    ret.counter   = counter;
    ret.flags     = flags;
    return ret;
}

static FORCE_INLINE uint8_t chunk_state_maybe_start_flag( const blake3_chunk_state * self ) {
    if (self->blocks_compressed == 0) {
        return CHUNK_START;
    } else {
        return 0;
    }
}

static FORCE_INLINE size_t chunk_state_fill_buf( blake3_chunk_state * self, const uint8_t * input, size_t input_len ) {
    size_t take = BLAKE3_BLOCK_LEN - ((size_t)self->buf_len);

    if (take > input_len) {
        take = input_len;
    }
    uint8_t * dest = self->buf     + ((size_t)self->buf_len);
    memcpy(dest, input, take);
    self->buf_len += (uint8_t)take;
    return take;
}

static FORCE_INLINE output_t chunk_state_output( const blake3_chunk_state * self ) {
    uint8_t block_flags =
            self->flags | chunk_state_maybe_start_flag(self) | CHUNK_END;

    return make_output(self->cv, self->buf, self->buf_len, self->chunk_counter, block_flags);
}

static FORCE_INLINE output_t parent_output( const uint8_t block[BLAKE3_BLOCK_LEN],
        const uint32_t key[8], uint8_t flags ) {
    return make_output(key, block, BLAKE3_BLOCK_LEN, 0, flags | PARENT);
}

static FORCE_INLINE size_t chunk_state_len( const blake3_chunk_state * self ) {
    return (BLAKE3_BLOCK_LEN * (size_t)self->blocks_compressed) +
           ((size_t)self->buf_len);
}

static FORCE_INLINE void output_root_bytes( const output_t * self, uint8_t * out, size_t out_len ) {
    uint64_t output_block_counter = 0;
    size_t   offset_within_block  = 0;
    uint8_t  wide_buf[64];

    while (out_len > 0) {
        blake3_compress_xof(self->input_cv, self->block, self->block_len,
                output_block_counter, self->flags | ROOT, wide_buf);
        size_t available_bytes = 64 - offset_within_block;
        size_t memcpy_len;
        if (out_len > available_bytes) {
            memcpy_len = available_bytes;
        } else {
            memcpy_len = out_len;
        }
        memcpy(out, wide_buf + offset_within_block, memcpy_len);
        out     += memcpy_len;
        out_len -= memcpy_len;
        output_block_counter += 1;
        offset_within_block   = 0;
    }
}

static FORCE_INLINE void output_chaining_value( const output_t * self, uint8_t cv[32] ) {
    uint32_t cv_words[8];

    memcpy(cv_words, self->input_cv, 32);
    blake3_compress_in_place(cv_words, self->block, self->block_len, self->counter, self->flags);
    store_cv_words(cv, cv_words);
}

static FORCE_INLINE void hasher_merge_cv_stack( blake3_hasher * self, uint64_t total_len ) {
    size_t post_merge_stack_len = (size_t)popcount8(total_len);

    while (self->cv_stack_len > post_merge_stack_len) {
        uint8_t * parent_node =
                &self->cv_stack[(self->cv_stack_len - 2) * BLAKE3_OUT_LEN];
        output_t output       = parent_output(parent_node, self->key, self->chunk.flags);
        output_chaining_value(&output, parent_node);
        self->cv_stack_len -= 1;
    }
}

static FORCE_INLINE void hasher_push_cv( blake3_hasher * self,
        uint8_t new_cv[BLAKE3_OUT_LEN], uint64_t chunk_counter ) {
    hasher_merge_cv_stack(self, chunk_counter);
    memcpy(&self->cv_stack[self->cv_stack_len * BLAKE3_OUT_LEN], new_cv, BLAKE3_OUT_LEN);
    self->cv_stack_len += 1;
}

static FORCE_INLINE void chunk_state_update( blake3_chunk_state * self, const uint8_t * input, size_t input_len ) {
    if (self->buf_len > 0) {
        size_t take = chunk_state_fill_buf(self, input, input_len);
        input     += take;
        input_len -= take;
        if (input_len > 0) {
            blake3_compress_in_place(self->cv, self->buf, BLAKE3_BLOCK_LEN, self->chunk_counter,
                    self->flags | chunk_state_maybe_start_flag(self));
            self->blocks_compressed += 1;
            self->buf_len = 0;
            memset(self->buf, 0, BLAKE3_BLOCK_LEN);
        }
    }

    while (input_len > BLAKE3_BLOCK_LEN) {
        blake3_compress_in_place(self->cv, input, BLAKE3_BLOCK_LEN, self->chunk_counter,
                self->flags | chunk_state_maybe_start_flag(self));
        self->blocks_compressed += 1;
        input     += BLAKE3_BLOCK_LEN;
        input_len -= BLAKE3_BLOCK_LEN;
    }

    size_t take = chunk_state_fill_buf(self, input, input_len);
    input     += take;
    input_len -= take;
}

static void blake3_hasher_init( blake3_hasher * self ) {
    memcpy(self->key, IV, BLAKE3_KEY_LEN);
    chunk_state_init(&self->chunk, IV, 0);
    self->cv_stack_len = 0;
}

// Home-grown SMHasher3 seeding
static void blake3_seed( blake3_hasher * hasher, uint64_t seed ) {
    const uint32_t seedlo = seed         & 0xFFFFFFFF;
    const uint32_t seedhi = (seed >> 32) & 0xFFFFFFFF;

    hasher->key[0]      ^= seedlo;
    hasher->chunk.cv[0] ^= seedlo;
    hasher->key[1]      ^= seedhi;
    hasher->chunk.cv[1] ^= seedhi;
}

//
// These includes each define the following functions:
//
//   void blake3_compress_xof(const uint32_t cv[8],
//                            const uint8_t block[BLAKE3_BLOCK_LEN],
//                            uint8_t block_len, uint64_t counter, uint8_t flags,
//                            uint8_t out[64]);
//
//   void blake3_compress_in_place(uint32_t cv[8],
//                                 const uint8_t block[BLAKE3_BLOCK_LEN],
//                                 uint8_t block_len, uint64_t counter,
//                                 uint8_t flags);
//
//   FORCE_INLINE void hash_one(const uint8_t *input, size_t blocks,
//                              const uint32_t key[8], uint64_t counter,
//                              uint8_t flags, uint8_t flags_start,
//                              uint8_t flags_end, uint8_t out[BLAKE3_OUT_LEN]);
//
//   void blake3_hash_many(const uint8_t *const *inputs, size_t num_inputs,
//                         size_t blocks, const uint32_t key[8],
//                         uint64_t counter, bool increment_counter,
//                         uint8_t flags, uint8_t flags_start,
//                         uint8_t flags_end, uint8_t *out);
//
// and the following integer #defines
//
//     #define SIMD_DEGREE_OR_2
//     #define SIMD_DEGREE
//
#if defined(HAVE_SSE_4_1)
  #include "Intrinsics.h"
  #include "blake3/compress-sse41.h"
  #define BLAKE3_IMPL_STR "sse41"
#elif defined(HAVE_SSE_2)
  #include "Intrinsics.h"
  #include "blake3/compress-sse2.h"
  #define BLAKE3_IMPL_STR "sse2"
#else
  #include "blake3/compress-portable.h"
  #define BLAKE3_IMPL_STR "portable"
#endif

static FORCE_INLINE size_t compress_parents_parallel( const uint8_t * child_chaining_values, size_t num_chaining_values,
        const uint32_t key[8], uint8_t flags, uint8_t * out ) {
    const uint8_t * parents_array[SIMD_DEGREE_OR_2];
    size_t          parents_array_len = 0;

    while (num_chaining_values - (2 * parents_array_len) >= 2) {
        parents_array[parents_array_len] =
                &child_chaining_values[2 * parents_array_len * BLAKE3_OUT_LEN];
        parents_array_len += 1;
    }

    blake3_hash_many(parents_array, parents_array_len, 1, key, 0, // Parents always use counter 0.
            false, flags | PARENT, 0,                             // Parents have no start flags.
            0,                                                    // Parents have no end flags.
            out);

    // If there's an odd child left over, it becomes an output.
    if (num_chaining_values > 2 * parents_array_len) {
        memcpy(&out[parents_array_len * BLAKE3_OUT_LEN], &child_chaining_values[2 * parents_array_len * BLAKE3_OUT_LEN],
                BLAKE3_OUT_LEN);
        return parents_array_len + 1;
    } else {
        return parents_array_len;
    }
}

static FORCE_INLINE size_t compress_chunks_parallel( const uint8_t * input, size_t input_len,
        const uint32_t key[8], uint64_t chunk_counter, uint8_t flags, uint8_t * out ) {
    const uint8_t * chunks_array[SIMD_DEGREE];
    size_t          input_position   = 0;
    size_t          chunks_array_len = 0;

    while (input_len - input_position >= BLAKE3_CHUNK_LEN) {
        chunks_array[chunks_array_len] = &input[input_position];
        input_position   += BLAKE3_CHUNK_LEN;
        chunks_array_len += 1;
    }

    blake3_hash_many(chunks_array, chunks_array_len, BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN,
            key, chunk_counter, true, flags, CHUNK_START, CHUNK_END, out);

    // Hash the remaining partial chunk, if there is one. Note that the empty
    // chunk (meaning the empty message) is a different codepath.
    if (input_len > input_position) {
        uint64_t counter = chunk_counter + (uint64_t)chunks_array_len;
        blake3_chunk_state chunk_state;
        chunk_state_init(&chunk_state, key, flags);
        chunk_state.chunk_counter = counter;
        chunk_state_update(&chunk_state, &input[input_position], input_len - input_position);
        output_t output = chunk_state_output(&chunk_state);
        output_chaining_value(&output, &out[chunks_array_len * BLAKE3_OUT_LEN]);
        return chunks_array_len + 1;
    } else {
        return chunks_array_len;
    }
}

static size_t blake3_compress_subtree_wide( const uint8_t * input, size_t input_len, const uint32_t key[8],
        uint64_t chunk_counter, uint8_t flags, uint8_t * out ) {
    // Note that the single chunk case does *not* bump the SIMD degree up to 2
    // when it is 1. If this implementation adds multi-threading in the future,
    // this gives us the option of multi-threading even the 2-chunk case, which
    // can help performance on smaller platforms.
    if (input_len <= SIMD_DEGREE * BLAKE3_CHUNK_LEN) {
        return compress_chunks_parallel(input, input_len, key, chunk_counter, flags, out);
    }

    // With more than simd_degree chunks, we need to recurse. Start by dividing
    // the input into left and right subtrees. (Note that this is only optimal
    // as long as the SIMD degree is a power of 2. If we ever get a SIMD degree
    // of 3 or something, we'll need a more complicated strategy.)
    size_t          left_input_len      = left_len(input_len);
    size_t          right_input_len     = input_len - left_input_len;
    const uint8_t * right_input         = &input[left_input_len];
    uint64_t        right_chunk_counter =
            chunk_counter + (uint64_t)(left_input_len / BLAKE3_CHUNK_LEN);

    uint8_t cv_array[2 * SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN];
    size_t  degree = SIMD_DEGREE;
    if ((left_input_len > BLAKE3_CHUNK_LEN) && (degree == 1)) {
        // The special case: We always use a degree of at least two, to make
        // sure there are two outputs. Except, as noted above, at the chunk
        // level, where we allow degree=1. (Note that the 1-chunk-input case is
        // a different codepath.)
        degree = 2;
    }
    uint8_t * right_cvs = &cv_array[degree * BLAKE3_OUT_LEN];

    // Recurse! If this implementation adds multi-threading support in the
    // future, this is where it will go.
    size_t left_n  = blake3_compress_subtree_wide(input      , left_input_len , key, chunk_counter, flags, cv_array);
    size_t right_n = blake3_compress_subtree_wide(right_input, right_input_len,
            key, right_chunk_counter, flags, right_cvs);

    // The special case again. If simd_degree=1, then we'll have left_n=1 and
    // right_n=1. Rather than compressing them into a single output, return
    // them directly, to make sure we always have at least two outputs.
    if (left_n == 1) {
        memcpy(out, cv_array, 2 * BLAKE3_OUT_LEN);
        return 2;
    }

    // Otherwise, do one layer of parent node compression.
    size_t num_chaining_values = left_n + right_n;
    return compress_parents_parallel(cv_array, num_chaining_values, key, flags, out);
}

static FORCE_INLINE void compress_subtree_to_parent_node( const uint8_t * input, size_t input_len,
        const uint32_t key[8], uint64_t chunk_counter, uint8_t flags, uint8_t out[2 * BLAKE3_OUT_LEN] ) {
    uint8_t cv_array[SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN];
    size_t  num_cvs = blake3_compress_subtree_wide(input, input_len, key, chunk_counter, flags, cv_array);
    // If MAX_SIMD_DEGREE is greater than 2 and there's enough input,
    // compress_subtree_wide() returns more than 2 chaining values. Condense
    // them into 2 by forming parent nodes repeatedly.
    uint8_t out_array[SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN / 2];

    // The second half of this loop condition is always true, and we just
    // asserted it above. But GCC can't tell that it's always true, and if NDEBUG
    // is set on platforms where SIMD_DEGREE_OR_2 == 2, GCC emits spurious
    // warnings here. GCC 8.5 is particularly sensitive, so if you're changing
    // this code, test it against that version.
    while (num_cvs > 2 && num_cvs <= SIMD_DEGREE_OR_2) {
        num_cvs = compress_parents_parallel(cv_array, num_cvs, key, flags, out_array);
        memcpy(cv_array, out_array, num_cvs * BLAKE3_OUT_LEN);
    }
    memcpy(out, cv_array, 2 * BLAKE3_OUT_LEN);
}

static void blake3_hasher_update( blake3_hasher * self, const void * input, size_t input_len ) {
    // Explicitly checking for zero avoids causing UB by passing a null pointer
    // to memcpy. This comes up in practice with things like:
    //   std::vector<uint8_t> v;
    //   blake3_hasher_update(&hasher, v.data(), v.size());
    if (input_len == 0) {
        return;
    }

    const uint8_t * input_bytes = (const uint8_t *)input;

    // If we have some partial chunk bytes in the internal chunk_state, we need
    // to finish that chunk first.
    if (chunk_state_len(&self->chunk) > 0) {
        size_t take = BLAKE3_CHUNK_LEN - chunk_state_len(&self->chunk);
        if (take > input_len) {
            take = input_len;
        }
        chunk_state_update(&self->chunk, input_bytes, take);
        input_bytes += take;
        input_len   -= take;
        // If we've filled the current chunk and there's more coming, finalize this
        // chunk and proceed. In this case we know it's not the root.
        if (input_len > 0) {
            output_t output = chunk_state_output(&self->chunk);
            uint8_t  chunk_cv[32];
            output_chaining_value(&output, chunk_cv);
            hasher_push_cv(self, chunk_cv, self->chunk.chunk_counter);
            chunk_state_reset(&self->chunk, self->key, self->chunk.chunk_counter + 1);
        } else {
            return;
        }
    }

    // Now the chunk_state is clear, and we have more input. If there's more than
    // a single chunk (so, definitely not the root chunk), hash the largest whole
    // subtree we can, with the full benefits of SIMD (and maybe in the future,
    // multi-threading) parallelism. Two restrictions:
    // - The subtree has to be a power-of-2 number of chunks. Only subtrees along
    //   the right edge can be incomplete, and we don't know where the right edge
    //   is going to be until we get to finalize().
    // - The subtree must evenly divide the total number of chunks up until this
    //   point (if total is not 0). If the current incomplete subtree is only
    //   waiting for 1 more chunk, we can't hash a subtree of 4 chunks. We have
    //   to complete the current subtree first.
    // Because we might need to break up the input to form powers of 2, or to
    // evenly divide what we already have, this part runs in a loop.
    while (input_len > BLAKE3_CHUNK_LEN) {
        size_t   subtree_len  = round_down_to_power_of_2(input_len);
        uint64_t count_so_far = self->chunk.chunk_counter * BLAKE3_CHUNK_LEN;
        // Shrink the subtree_len until it evenly divides the count so far. We know
        // that subtree_len itself is a power of 2, so we can use a bitmasking
        // trick instead of an actual remainder operation. (Note that if the caller
        // consistently passes power-of-2 inputs of the same size, as is hopefully
        // typical, this loop condition will always fail, and subtree_len will
        // always be the full length of the input.)
        //
        // An aside: We don't have to shrink subtree_len quite this much. For
        // example, if count_so_far is 1, we could pass 2 chunks to
        // compress_subtree_to_parent_node. Since we'll get 2 CVs back, we'll still
        // get the right answer in the end, and we might get to use 2-way SIMD
        // parallelism. The problem with this optimization, is that it gets us
        // stuck always hashing 2 chunks. The total number of chunks will remain
        // odd, and we'll never graduate to higher degrees of parallelism. See
        // https://github.com/BLAKE3-team/BLAKE3/issues/69.
        while ((((uint64_t)(subtree_len - 1)) & count_so_far) != 0) {
            subtree_len /= 2;
        }
        // The shrunken subtree_len might now be 1 chunk long. If so, hash that one
        // chunk by itself. Otherwise, compress the subtree into a pair of CVs.
        uint64_t subtree_chunks = subtree_len / BLAKE3_CHUNK_LEN;
        if (subtree_len <= BLAKE3_CHUNK_LEN) {
            blake3_chunk_state chunk_state;
            chunk_state_init(&chunk_state, self->key, self->chunk.flags);
            chunk_state.chunk_counter = self->chunk.chunk_counter;
            chunk_state_update(&chunk_state, input_bytes, subtree_len);
            output_t output = chunk_state_output(&chunk_state);
            uint8_t  cv[BLAKE3_OUT_LEN];
            output_chaining_value(&output, cv);
            hasher_push_cv(self, cv, chunk_state.chunk_counter);
        } else {
            // This is the high-performance happy path, though getting here depends
            // on the caller giving us a long enough input.
            uint8_t cv_pair[2 * BLAKE3_OUT_LEN];
            compress_subtree_to_parent_node(input_bytes, subtree_len, self->key,
                    self->chunk.chunk_counter, self->chunk.flags, cv_pair);
            hasher_push_cv(self, cv_pair, self->chunk.chunk_counter);
            hasher_push_cv(self, &cv_pair[BLAKE3_OUT_LEN], self->chunk.chunk_counter + (subtree_chunks / 2));
        }
        self->chunk.chunk_counter += subtree_chunks;
        input_bytes += subtree_len;
        input_len   -= subtree_len;
    }

    // If there's any remaining input less than a full chunk, add it to the chunk
    // state. In that case, also do a final merge loop to make sure the subtree
    // stack doesn't contain any unmerged pairs. The remaining input means we
    // know these merges are non-root. This merge loop isn't strictly necessary
    // here, because hasher_push_chunk_cv already does its own merge loop, but it
    // simplifies blake3_hasher_finalize below.
    if (input_len > 0) {
        chunk_state_update(&self->chunk, input_bytes, input_len);
        hasher_merge_cv_stack(self, self->chunk.chunk_counter);
    }
}

static void blake3_hasher_finalize( const blake3_hasher * self, uint8_t * out, size_t out_len ) {
    // Explicitly checking for zero avoids causing UB by passing a null pointer
    // to memcpy. This comes up in practice with things like:
    //   std::vector<uint8_t> v;
    //   blake3_hasher_finalize(&hasher, v.data(), v.size());
    if (out_len == 0) {
        return;
    }

    // If the subtree stack is empty, then the current chunk is the root.
    if (self->cv_stack_len == 0) {
        output_t output = chunk_state_output(&self->chunk);
        output_root_bytes(&output, out, out_len);
        return;
    }

    // If there are any bytes in the chunk state, finalize that chunk
    // and do a roll-up merge between that chunk hash and every subtree
    // in the stack. In this case, the extra merge loop at the end of
    // blake3_hasher_update guarantees that none of the subtrees in the
    // stack need to be merged with each other first. Otherwise, if
    // there are no bytes in the chunk state, then the top of the stack
    // is a chunk hash, and we start the merge from that.
    output_t output;
    size_t   cvs_remaining;
    if (chunk_state_len(&self->chunk) > 0) {
        cvs_remaining = self->cv_stack_len;
        output        = chunk_state_output(&self->chunk);
    } else {
        // There are always at least 2 CVs in the stack in this case.
        cvs_remaining = self->cv_stack_len - 2;
        output        = parent_output(&self->cv_stack[cvs_remaining * 32], self->key, self->chunk.flags);
    }
    while (cvs_remaining > 0) {
        cvs_remaining -= 1;
        uint8_t parent_block[BLAKE3_BLOCK_LEN];
        memcpy(parent_block, &self->cv_stack[cvs_remaining * 32], 32);
        output_chaining_value(&output, &parent_block[32]);
        output = parent_output(parent_block, self->key, self->chunk.flags);
    }
    output_root_bytes(&output, out, out_len);
}

template <uint32_t outbits>
static void BLAKE3( const void * in, const size_t len, const seed_t seed, void * out ) {
    blake3_hasher hasher;

    blake3_hasher_init(&hasher);
    blake3_seed(&hasher, seed);
    blake3_hasher_update(&hasher, in, len);
    blake3_hasher_finalize(&hasher, (uint8_t *)out, (outbits >= 256) ? 32 : (outbits + 7) / 8);
}

REGISTER_FAMILY(blake3,
   $.src_url    = "https://github.com/BLAKE3-team/BLAKE3",
   $.src_status = HashFamilyInfo::SRC_FROZEN
 );

// The NO_SEED flag is not actually true, but need to replace
// homegrown with real seeding.
REGISTER_HASH(blake3,
   $.desc       = "BLAKE 3, 256-bit digest",
   $.impl       = BLAKE3_IMPL_STR,
   $.hash_flags =
         FLAG_HASH_CRYPTOGRAPHIC        |
         FLAG_HASH_NO_SEED              |
         FLAG_HASH_LOOKUP_TABLE         |
         FLAG_HASH_ENDIAN_INDEPENDENT,
   $.impl_flags =
         FLAG_IMPL_LICENSE_MIT          |
         FLAG_IMPL_CANONICAL_BOTH       |
         FLAG_IMPL_VERY_SLOW            |
         FLAG_IMPL_ROTATE               |
         FLAG_IMPL_INCREMENTAL,
   $.bits = 256,
   $.verification_LE = 0x50E4CD91,
   $.verification_BE = 0x50E4CD91,
   $.hashfn_native   = BLAKE3<256>,
   $.hashfn_bswap    = BLAKE3<256>
 );
