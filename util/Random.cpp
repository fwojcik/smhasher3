/*
 * SMHasher3
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
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
#include "Platform.h"
#include "Random.h"

#include <cassert>

//-----------------------------------------------------------------------------
// Fill a buffer with 4 * PARALLEL random uint64_t values, updating the
// counter in keyvals[0] to reflect the number of values generated.
//
// This is the Threefry-4x64-14 CBRNG as documented in:
//   "Parallel random numbers: as easy as 1, 2, 3", by John K. Salmon,
//     Mark A. Moraes, Ron O. Dror, and David E. Shaw
//     https://www.thesalmons.org/john/random123/papers/random123sc11.pdf
static void threefry( void * buf, uint64_t * keyvals ) {
    uint64_t tmpbuf[Rand::BUFLEN];

    static_assert(Rand::RANDS_PER_ROUND == 4, "Threefry outputs 4 u64s per call");
    static_assert(Rand::BUFLEN == (PARALLEL * Rand::RANDS_PER_ROUND),
            "Rand buffer can hold current PARALLEL setting");

    // This strange construction involving many for() loops from [0,
    // PARALLEL) allows most compilers to vectorize this sequence of
    // operations when the platform supports that. It is exactly
    // equivalent to a single for() loop containing all the STATE()
    // statements inside of it.
#define STATE(j) tmpbuf[i + PARALLEL * j]
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) = keyvals[0] + i;
        STATE(1) = keyvals[1];
        STATE(2) = keyvals[2];
        STATE(3) = keyvals[3];
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 14); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 16); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 52); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 57); STATE(1) ^= STATE(2);
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 23); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 40); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3),  5); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 37); STATE(1) ^= STATE(2);
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) += keyvals[1];
        STATE(1) += keyvals[2];
        STATE(2) += keyvals[3];
        STATE(3) += keyvals[4] ^ (keyvals[0] + i);
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(3) += 1;
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 25); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 33); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 46); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 12); STATE(1) ^= STATE(2);
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 58); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 22); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 32); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 32); STATE(1) ^= STATE(2);
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) += keyvals[2];
        STATE(1) += keyvals[3];
        STATE(2) += keyvals[4] ^ (keyvals[0] + i);
        STATE(3) += keyvals[0] + i;
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(3) += 2;
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 14); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 16); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 52); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 57); STATE(1) ^= STATE(2);
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 23); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 40); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3),  5); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 37); STATE(1) ^= STATE(2);
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) += keyvals[3];
        STATE(1) += keyvals[4] ^ (keyvals[0] + i);
        STATE(2) += keyvals[0] + i;
        STATE(3) += keyvals[1];
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(3) += 3;
    }
    for (uint64_t i = 0; i < PARALLEL; i++) {
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 25); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 33); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 46); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 12); STATE(1) ^= STATE(2);
        STATE(0) += STATE(1); STATE(1) = ROTL64(STATE(1), 58); STATE(1) ^= STATE(0);
        STATE(2) += STATE(3); STATE(3) = ROTL64(STATE(3), 22); STATE(3) ^= STATE(2);
        STATE(0) += STATE(3); STATE(3) = ROTL64(STATE(3), 32); STATE(3) ^= STATE(0);
        STATE(2) += STATE(1); STATE(1) = ROTL64(STATE(1), 32); STATE(1) ^= STATE(2);
    }

    // Update the counter to reflect that we've generated PARALLEL values.
    keyvals[0] += PARALLEL;

    // This reorders the state values so that the output bytes don't depend
    // on the value of PARALLEL. This usually gets vectorized also.
    uint8_t * rngbuf = static_cast<uint8_t *>(buf);
    for (uint64_t i = 0; i < PARALLEL; i++) {
        for (uint64_t j = 0; j < 4; j++) {
            uint64_t tmp = COND_BSWAP(STATE(j), isBE());
            memcpy(&rngbuf[j * 8 + i * 32], &tmp, sizeof(uint64_t));
        }
    }
#undef STATE
}

//-----------------------------------------------------------------------------

void Rand::refill_buf( void * buf ) {
    threefry(buf, xseed);
}

// Fill the user's buffer from our cache of random data as much as
// possible, and then generate the next random values directly into the
// user's buffer until it is almost full. Finally, refill our cache if
// needed, and then copy any remaining needed values from our cache.
//
// This keeps the Rand object invariant that the internal cache is never
// filled until some random data is needed.
void Rand::rand_n( void * buf, size_t bytes ) {
    if (bytes == 0) {
        return;
    }
    // If the user seek()ed to a point where refill_buf() needs to skip
    // some output bytes, and so can't write to buf directly, then rngbuf[]
    // needs to be filled first.
    if (bufidx > BUFLEN) {
        refill_buf(rngbuf);
        bufidx -= BUFLEN;
    }

    uint8_t * out         = static_cast<uint8_t *>(buf);
    size_t    curbufbytes = sizeof(rngbuf[0]) * (BUFLEN - bufidx);

    if (likely(bytes > curbufbytes)) {
        memcpy(out, &rngbuf[bufidx], curbufbytes);
        out   += curbufbytes;
        bytes -= curbufbytes;
        while (bytes > sizeof(rngbuf)) {
            refill_buf(out);
            out   += sizeof(rngbuf);
            bytes -= sizeof(rngbuf);
        }
        refill_buf(rngbuf);
        bufidx = 0;
    }

    memcpy(out, &rngbuf[bufidx], bytes);
    bufidx += (bytes + sizeof(rngbuf[0]) - 1) / sizeof(rngbuf[0]);

    assert(bufidx <= BUFLEN);
}

//-----------------------------------------------------------------------------
