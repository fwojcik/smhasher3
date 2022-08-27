/*
 * Stand-alone hash verification code generator for SMHasher3
 * Copyright (C) 2022  Frank J. T. Wojcik
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
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef uint64_t seed_t;

// This program lets you compute the verification code for a hash in a way that is
// completely stand-alone and external from all of SMHasher3. This can help verify
// that a hash implementation is working correctly after it has been ported to (or
// from) that framework.
//
// This code is standard C99, and should compile and work under C++ also.
//
// This program only works on native endianness.

//--------------------------------------------------
// Step 1: bring in your hash implementation here
#include "myhash.h"
#include "myhash.c"

//--------------------------------------------------
// Step 2: specify how many bits it outputs

const uint32_t hashbits = 64;

//--------------------------------------------------
// Step 3: if it needs an initialization function for seeding, add that here. If it
// needs to return a pointer which is to be passed to the hash, then cast it via
// "return (seed_t)(uintptr_t)(void *)mypointer;". If it doesn't need any kind of
// initialization, then leave this as-is.

seed_t HASH_INIT( seed_t seed ) {
    return seed;
}

//--------------------------------------------------
// Step 4: fill in this wrapper for your hash. Output bytes should be written to out
// in native byte-order, or hash-specified byte order if any. Any value returned from
// HASH_INIT() will be passed here as seed. If HASH_INIT returned a pointer, you can
// recover it via "(mypointer_type *)(void *)(uintptr_t)seed".

void HASH( const void * in, const size_t len, const seed_t seed, void * out ) {
}

//--------------------------------------------------
// Step 5: compile and run this program. That's it!

//--------------------------------------------------

uint32_t ComputedVerifyImpl( void ) {
    const uint32_t hashbytes = hashbits / 8;

    uint8_t * key    = (uint8_t *)calloc(256      ,   1);
    uint8_t * hashes = (uint8_t *)calloc(hashbytes, 256);
    uint8_t * total  = (uint8_t *)calloc(hashbytes,   1);

    // Hash keys of the form {}, {0}, {0,1}, {0,1,2}... up to N=255, using
    // 256-N as the seed
    for (int i = 0; i < 256; i++) {
        seed_t seed = 256 - i;
        seed = HASH_INIT(seed);
        HASH(key, i, seed, &hashes[i * hashbytes]);
        key[i] = (uint8_t)i;
    }

    // Then hash the result array
    seed_t seed = 0;
    seed = HASH_INIT(0);
    HASH(hashes, hashbytes * 256, seed, total);

    // The first four bytes of that hash, interpreted as a little-endian
    // integer, is our verification value
    uint32_t verification = (total[0] << 0) | (total[1] << 8) |
            (total[2] << 16) | (total[3] << 24);

    free(total );
    free(hashes);
    free(key   );

    return verification;
}

int main( void ) {
    if ((sizeof(uintptr_t) > sizeof(seed_t)) || (sizeof(uint64_t) > sizeof(seed_t))) {
        printf("Please re-typedef seed_t so it is large enough for a uint64_t and a uintptr_t.\n");
        exit(1);
    }

    printf("Native-endian verification code: 0x%08X\n", ComputedVerifyImpl());
}
